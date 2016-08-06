//! API Set Resolution and Code Injection Module
//!
//! This module provides functionality for resolving Windows API sets and
//! performing code injection operations in a safe, idiomatic Rust manner.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::{Arc, RwLock, Once};

use crate::error::{MapperError, NtStatus};

/// Represents a resolved API entry point
#[derive(Debug, Clone)]
pub struct ApiEntry {
    /// The module containing this API
    pub module_name: String,
    /// The function name
    pub function_name: String,
    /// Resolved address (if available)
    pub address: Option<usize>,
    /// Whether this is a forwarded export
    pub is_forwarded: bool,
    /// Forward target if applicable
    pub forward_target: Option<String>,
}

/// API Set schema version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSetSchemaVersion {
    V2,
    V4,
    V6,
    Unknown(u32),
}

impl From<u32> for ApiSetSchemaVersion {
    fn from(value: u32) -> Self {
        match value {
            2 => ApiSetSchemaVersion::V2,
            4 => ApiSetSchemaVersion::V4,
            6 => ApiSetSchemaVersion::V6,
            v => ApiSetSchemaVersion::Unknown(v),
        }
    }
}

/// Represents an API set namespace entry
#[derive(Debug, Clone)]
pub struct ApiSetEntry {
    pub name: String,
    pub hosts: Vec<ApiSetHost>,
    pub is_sealed: bool,
}

/// Host module for an API set
#[derive(Debug, Clone)]
pub struct ApiSetHost {
    pub import_name: Option<String>,
    pub host_name: String,
}

/// Strategy trait for API resolution
pub trait ResolutionStrategy: Send + Sync {
    fn resolve(&self, module: &str, function: &str) -> Result<ApiEntry, MapperError>;
    fn name(&self) -> &'static str;
}

/// Direct resolution using GetProcAddress
pub struct DirectResolution;

impl ResolutionStrategy for DirectResolution {
    fn resolve(&self, module: &str, function: &str) -> Result<ApiEntry, MapperError> {
        let module_wide: Vec<u16> = OsStr::new(module)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        let func_cstr = CString::new(function)
            .map_err(|_| MapperError::InvalidParameter("Invalid function name".into()))?;
        
        let handle = unsafe { GetModuleHandleW(module_wide.as_ptr()) };
        if handle.is_null() {
            return Err(MapperError::ModuleNotFound(module.to_string()));
        }
        
        let addr = unsafe { GetProcAddress(handle, func_cstr.as_ptr()) };
        
        Ok(ApiEntry {
            module_name: module.to_string(),
            function_name: function.to_string(),
            address: if addr.is_null() { None } else { Some(addr as usize) },
            is_forwarded: false,
            forward_target: None,
        })
    }
    
    fn name(&self) -> &'static str {
        "DirectResolution"
    }
}

/// Manual PE parsing resolution
pub struct ManualResolution {
    cache: RwLock<HashMap<String, usize>>,
}

impl ManualResolution {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }
    
    fn parse_export_directory(&self, base: usize) -> Result<Vec<(String, usize)>, MapperError> {
        let dos_header = unsafe { &*(base as *const ImageDosHeader) };
        
        if dos_header.e_magic != 0x5A4D {
            return Err(MapperError::InvalidFormat("Invalid DOS signature".into()));
        }
        
        let nt_headers = unsafe {
            &*((base + dos_header.e_lfanew as usize) as *const ImageNtHeaders64)
        };
        
        if nt_headers.signature != 0x00004550 {
            return Err(MapperError::InvalidFormat("Invalid NT signature".into()));
        }
        
        let export_dir_rva = nt_headers.optional_header.data_directory[0].virtual_address as usize;
        if export_dir_rva == 0 {
            return Ok(Vec::new());
        }
        
        let export_dir = unsafe {
            &*((base + export_dir_rva) as *const ImageExportDirectory)
        };
        
        let mut exports = Vec::new();
        let names = unsafe {
            std::slice::from_raw_parts(
                (base + export_dir.address_of_names as usize) as *const u32,
                export_dir.number_of_names as usize,
            )
        };
        
        let ordinals = unsafe {
            std::slice::from_raw_parts(
                (base + export_dir.address_of_name_ordinals as usize) as *const u16,
                export_dir.number_of_names as usize,
            )
        };
        
        let functions = unsafe {
            std::slice::from_raw_parts(
                (base + export_dir.address_of_functions as usize) as *const u32,
                export_dir.number_of_functions as usize,
            )
        };
        
        for i in 0..export_dir.number_of_names as usize {
            let name_ptr = (base + names[i] as usize) as *const i8;
            let name = unsafe { CStr::from_ptr(name_ptr) }
                .to_string_lossy()
                .into_owned();
            
            let ordinal = ordinals[i] as usize;
            let func_rva = functions[ordinal] as usize;
            
            exports.push((name, base + func_rva));
        }
        
        Ok(exports)
    }
}

impl ResolutionStrategy for ManualResolution {
    fn resolve(&self, module: &str, function: &str) -> Result<ApiEntry, MapperError> {
        let cache_key = format!("{}!{}", module, function);
        
        if let Ok(cache) = self.cache.read() {
            if let Some(&addr) = cache.get(&cache_key) {
                return Ok(ApiEntry {
                    module_name: module.to_string(),
                    function_name: function.to_string(),
                    address: Some(addr),
                    is_forwarded: false,
                    forward_target: None,
                });
            }
        }
        
        let module_wide: Vec<u16> = OsStr::new(module)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        let handle = unsafe { GetModuleHandleW(module_wide.as_ptr()) };
        if handle.is_null() {
            return Err(MapperError::ModuleNotFound(module.to_string()));
        }
        
        let exports = self.parse_export_directory(handle as usize)?;
        
        for (name, addr) in exports {
            if name == function {
                if let Ok(mut cache) = self.cache.write() {
                    cache.insert(cache_key, addr);
                }
                
                return Ok(ApiEntry {
                    module_name: module.to_string(),
                    function_name: function.to_string(),
                    address: Some(addr),
                    is_forwarded: false,
                    forward_target: None,
                });
            }
        }
        
        Err(MapperError::FunctionNotFound(function.to_string()))
    }
    
    fn name(&self) -> &'static str {
        "ManualResolution"
    }
}

/// API resolver with configurable strategy
pub struct ApiResolver {
    strategy: Arc<dyn ResolutionStrategy>,
    api_set_map: RwLock<HashMap<String, ApiSetEntry>>,
    initialized: bool,
}

impl ApiResolver {
    pub fn new(strategy: Arc<dyn ResolutionStrategy>) -> Self {
        Self {
            strategy,
            api_set_map: RwLock::new(HashMap::new()),
            initialized: false,
        }
    }
    
    pub fn with_direct_resolution() -> Self {
        Self::new(Arc::new(DirectResolution))
    }
    
    pub fn with_manual_resolution() -> Self {
        Self::new(Arc::new(ManualResolution::new()))
    }
    
    /// Initialize the API set map from the PEB
    pub fn initialize(&mut self) -> Result<(), MapperError> {
        let api_set_map = self.parse_api_set_schema()?;
        
        if let Ok(mut map) = self.api_set_map.write() {
            *map = api_set_map;
        }
        
        self.initialized = true;
        Ok(())
    }
    
    fn parse_api_set_schema(&self) -> Result<HashMap<String, ApiSetEntry>, MapperError> {
        let mut result = HashMap::new();
        
        let peb = get_peb()?;
        let api_set_map_ptr = unsafe { (*peb).api_set_map };
        
        if api_set_map_ptr.is_null() {
            return Ok(result);
        }
        
        let header = unsafe { &*(api_set_map_ptr as *const ApiSetNamespaceHeader) };
        let version = ApiSetSchemaVersion::from(header.version);
        
        match version {
            ApiSetSchemaVersion::V6 => {
                self.parse_api_set_v6(api_set_map_ptr as usize, &mut result)?;
            }
            ApiSetSchemaVersion::V4 => {
                self.parse_api_set_v4(api_set_map_ptr as usize, &mut result)?;
            }
            _ => {
                return Err(MapperError::UnsupportedVersion(format!("{:?}", version)));
            }
        }
        
        Ok(result)
    }
    
    fn parse_api_set_v6(
        &self,
        base: usize,
        result: &mut HashMap<String, ApiSetEntry>,
    ) -> Result<(), MapperError> {
        let header = unsafe { &*(base as *const ApiSetNamespaceV6) };
        
        for i in 0..header.count {
            let entry_offset = header.entry_offset as usize + (i as usize * std::mem::size_of::<ApiSetNamespaceEntryV6>());
            let entry = unsafe { &*((base + entry_offset) as *const ApiSetNamespaceEntryV6) };
            
            let name = self.read_unicode_string(base, entry.name_offset as usize, entry.name_length as usize)?;
            let mut hosts = Vec::new();
            
            for j in 0..entry.value_count {
                let value_offset = entry.value_offset as usize + (j as usize * std::mem::size_of::<ApiSetValueEntryV6>());
                let value = unsafe { &*((base + value_offset) as *const ApiSetValueEntryV6) };
                
                let host_name = self.read_unicode_string(base, value.value_offset as usize, value.value_length as usize)?;
                let import_name = if value.name_length > 0 {
                    Some(self.read_unicode_string(base, value.name_offset as usize, value.name_length as usize)?)
                } else {
                    None
                };
                
                hosts.push(ApiSetHost { import_name, host_name });
            }
            
            result.insert(name.clone(), ApiSetEntry {
                name,
                hosts,
                is_sealed: (entry.flags & 1) != 0,
            });
        }
        
        Ok(())
    }
    
    fn parse_api_set_v4(
        &self,
        base: usize,
        result: &mut HashMap<String, ApiSetEntry>,
    ) -> Result<(), MapperError> {
        let header = unsafe { &*(base as *const ApiSetNamespaceV4) };
        
        for i in 0..header.count {
            let entry_offset = header.entry_offset as usize + (i as usize * std::mem::size_of::<ApiSetNamespaceEntryV4>());
            let entry = unsafe { &*((base + entry_offset) as *const ApiSetNamespaceEntryV4) };
            
            let name = self.read_unicode_string(base, entry.name_offset as usize, entry.name_length as usize)?;
            let mut hosts = Vec::new();
            
            for j in 0..entry.value_count {
                let value_offset = entry.value_offset as usize + (j as usize * std::mem::size_of::<ApiSetValueEntryV4>());
                let value = unsafe { &*((base + value_offset) as *const ApiSetValueEntryV4) };
                
                let host_name = self.read_unicode_string(base, value.value_offset as usize, value.value_length as usize)?;
                
                hosts.push(ApiSetHost {
                    import_name: None,
                    host_name,
                });
            }
            
            result.insert(name.clone(), ApiSetEntry {
                name,
                hosts,
                is_sealed: false,
            });
        }
        
        Ok(())
    }
    
    fn read_unicode_string(&self, base: usize, offset: usize, length: usize) -> Result<String, MapperError> {
        let ptr = (base + offset) as *const u16;
        let slice = unsafe { std::slice::from_raw_parts(ptr, length / 2) };
        String::from_utf16(slice)
            .map_err(|_| MapperError::InvalidFormat("Invalid UTF-16 string".into()))
    }
    
    /// Resolve an API set name to its host module
    pub fn resolve_api_set(&self, api_set_name: &str) -> Option<String> {
        let normalized = self.normalize_api_set_name(api_set_name);
        
        if let Ok(map) = self.api_set_map.read() {
            if let Some(entry) = map.get(&normalized) {
                return entry.hosts.first().map(|h| h.host_name.clone());
            }
        }
        
        None
    }
    
    fn normalize_api_set_name(&self, name: &str) -> String {
        let lower = name.to_lowercase();
        let without_ext = lower.trim_end_matches(".dll");
        
        if let Some(pos) = without_ext.rfind('-') {
            without_ext[..pos].to_string()
        } else {
            without_ext.to_string()
        }
    }
    
    /// Resolve a function from a module
    pub fn resolve(&self, module: &str, function: &str) -> Result<ApiEntry, MapperError> {
        let actual_module = if module.starts_with("api-") || module.starts_with("ext-") {
            self.resolve_api_set(module)
                .ok_or_else(|| MapperError::ModuleNotFound(module.to_string()))?
        } else {
            module.to_string()
        };
        
        self.strategy.resolve(&actual_module, function)
    }
    
    /// Get the current resolution strategy name
    pub fn strategy_name(&self) -> &'static str {
        self.strategy.name()
    }
}

/// Code injection context
pub struct InjectionContext {
    target_pid: u32,
    process_handle: *mut std::ffi::c_void,
    allocated_regions: Vec<AllocatedRegion>,
}

struct AllocatedRegion {
    base: usize,
    size: usize,
}

impl InjectionContext {
    /// Create a new injection context for a target process
    pub fn new(target_pid: u32) -> Result<Self, MapperError> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_ALL_ACCESS,
                0,
                target_pid,
            )
        };
        
        if handle.is_null() {
            return Err(MapperError::ProcessAccessDenied(target_pid));
        }
        
        Ok(Self {
            target_pid,
            process_handle: handle,
            allocated_regions: Vec::new(),
        })
    }
    
    /// Allocate memory in the target process
    pub fn allocate(&mut self, size: usize, protection: u32) -> Result<usize, MapperError> {
        let addr = unsafe {
            VirtualAllocEx(
                self.process_handle,
                ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                protection,
            )
        };
        
        if addr.is_null() {
            return Err(MapperError::AllocationFailed(size));
        }
        
        let base = addr as usize;
        self.allocated_regions.push(AllocatedRegion { base, size });
        
        Ok(base)
    }
    
    /// Write data to the target process
    pub fn write(&self, address: usize, data: &[u8]) -> Result<usize, MapperError> {
        let mut bytes_written: usize = 0;
        
        let result = unsafe {
            WriteProcessMemory(
                self.process_handle,
                address as *mut std::ffi::c_void,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                &mut bytes_written,
            )
        };
        
        if result == 0 {
            return Err(MapperError::WriteFailed(address));
        }
        
        Ok(bytes_written)
    }
    
    /// Read data from the target process
    pub fn read(&self, address: usize, size: usize) -> Result<Vec<u8>, MapperError> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read: usize = 0;
        
        let result = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                &mut bytes_read,
            )
        };
        
        if result == 0 {
            return Err(MapperError::ReadFailed(address));
        }
        
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    
    /// Change memory protection in the target process
    pub fn protect(&self, address: usize, size: usize, protection: u32) -> Result<u32, MapperError> {
        let mut old_protection: u32 = 0;
        
        let result = unsafe {
            VirtualProtectEx(
                self.process_handle,
                address as *mut std::ffi::c_void,
                size,
                protection,
                &mut old_protection,
            )
        };
        
        if result == 0 {
            return Err(MapperError::ProtectionFailed(address));
        }
        
        Ok(old_protection)
    }
    
    /// Create a remote thread in the target process
    pub fn create_remote_thread(&self, start_address: usize, parameter: usize) -> Result<*mut std::ffi::c_void, MapperError> {
        let mut thread_id: u32 = 0;
        
        let handle = unsafe {
            CreateRemoteThread(
                self.process_handle,
                ptr::null_mut(),
                0,
                std::mem::transmute(start_address),
                parameter as *mut std::ffi::c_void,
                0,
                &mut thread_id,
            )
        };
        
        if handle.is_null() {
            return Err(MapperError::ThreadCreationFailed);
        }
        
        Ok(handle)
    }
    
    /// Free allocated memory in the target process
    pub fn free(&mut self, address: usize) -> Result<(), MapperError> {
        let result = unsafe {
            VirtualFreeEx(
                self.process_handle,
                address as *mut std::ffi::c_void,
                0,
                MEM_RELEASE,
            )
        };
        
        if result == 0 {
            return Err(MapperError::FreeFailed(address));
        }
        
        self.allocated_regions.retain(|r| r.base != address);
        Ok(())
    }
    
    /// Get the target process ID
    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }
}

impl Drop for InjectionContext {
    fn drop(&mut self) {
        for region in &self.allocated_regions {
            unsafe {
                VirtualFreeEx(
                    self.process_handle,
                    region.base as *mut std::ffi::c_void,
                    0,
                    MEM_RELEASE,
                );
            }
        }
        
        if !self.process_handle.is_null() {
            unsafe { CloseHandle(self.process_handle) };
        }
    }
}

/// Shellcode builder for code injection
pub struct ShellcodeBuilder {
    code: Vec<u8>,
    relocations: Vec<Relocation>,
}

struct Relocation {
    offset: usize,
    target: RelocationTarget,
}

enum RelocationTarget {
    Absolute(usize),
    Relative(usize),
}

impl ShellcodeBuilder {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            relocations: Vec::new(),
        }
    }
    
    /// Append raw bytes
    pub fn emit(&mut self, bytes: &[u8]) -> &mut Self {
        self.code.extend_from_slice(bytes);
        self
    }
    
    /// Emit a 64-bit absolute address (with relocation)
    pub fn emit_absolute_address(&mut self, address: usize) -> &mut Self {
        let offset = self.code.len();
        self.code.extend_from_slice(&(address as u64).to_le_bytes());
        self.relocations.push(Relocation {
            offset,
            target: RelocationTarget::Absolute(address),
        });
        self
    }
    
    /// Emit a relative call
    pub fn emit_call(&mut self, target: usize) -> &mut Self {
        self.code.push(0xE8);
        let offset = self.code.len();
        self.code.extend_from_slice(&0i32.to_le_bytes());
        self.relocations.push(Relocation {
            offset,
            target: RelocationTarget::Relative(target),
        });
        self
    }
    
    /// Emit a relative jump
    pub fn emit_jmp(&mut self, target: usize) -> &mut Self {
        self.code.push(0xE9);
        let offset = self.code.len();
        self.code.extend_from_slice(&0i32.to_le_bytes());
        self.relocations.push(Relocation {
            offset,
            target: RelocationTarget::Relative(target),
        });
        self
    }
    
    /// Build the final shellcode with relocations applied
    pub fn build(mut self, base_address: usize) -> Vec<u8> {
        for reloc in &self.relocations {
            match reloc.target {
                RelocationTarget::Absolute(addr) => {
                    let bytes = (addr as u64).to_le_bytes();
                    self.code[reloc.offset..reloc.offset + 8].copy_from_slice(&bytes);
                }
                RelocationTarget::Relative(target) => {
                    let rip = base_address + reloc.offset + 4;
                    let delta = (target as i64) - (rip as i64);
                    let bytes = (delta as i32).to_le_bytes();
                    self.code[reloc.offset..reloc.offset + 4].copy_from_slice(&bytes);
                }
            }
        }
        
        self.code
    }
    
    /// Get the current size
    pub fn len(&self) -> usize {
        self.code.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }
}

impl Default for ShellcodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Windows API declarations
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[repr(C)]
struct ApiSetNamespaceHeader {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
}

#[repr(C)]
struct ApiSetNamespaceV6 {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    entry_offset: u32,
    hash_offset: u32,
    hash_factor: u32,
}

#[repr(C)]
struct ApiSetNamespaceEntryV6 {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    hashed_length: u32,
    value_offset: u32,
    value_count: u32,
}

#[repr(C)]
struct ApiSetValueEntryV6 {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    value_offset: u32,
    value_length: u32,
}

#[repr(C)]
struct ApiSetNamespaceV4 {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    entry_offset: u32,
}

#[repr(C)]
struct ApiSetNamespaceEntryV4 {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    alias_offset: u32,
    alias_length: u32,
    value_offset: u32,
    value_count: u32,
}

#[repr(C)]
struct ApiSetValueEntryV4 {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    value_offset: u32,
    value_length: u32,
}

#[repr(C)]
struct Peb {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: [u8; 1],
    reserved3: [*mut std::ffi::c_void; 2],
    ldr: *mut std::ffi::c_void,
    process_parameters: *mut std::ffi::c_void,
    reserved4: [*mut std::ffi::c_void; 3],
    atl_thunk_s_list_ptr: *mut std::ffi::c_void,
    reserved5: *mut std::ffi::c_void,
    reserved6: u32,
    reserved7: *mut std::ffi::c_void,
    reserved8: u32,
    atl_thunk_s_list_ptr32: u32,
    reserved9: [*mut std::ffi::c_void; 45],
    reserved10: [u8; 96],
    post_process_init_routine: *mut std::ffi::c_void,
    reserved11: [u8; 128],
    reserved12: [*mut std::ffi::c_void; 1],
    session_id: u32,
    api_set_map: *mut std::ffi::c_void,
}

fn get_peb() -> Result<*const Peb, MapperError> {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: *const Peb;
        unsafe {
            std::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
                options(nostack, nomem