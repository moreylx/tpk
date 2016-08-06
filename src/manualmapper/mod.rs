//! Manual Mapper Module
//! 
//! Provides functionality for manual PE mapping and code injection
//! into target processes using low-level Windows NT APIs.

mod injector;
mod pe_parser;
mod relocations;
mod imports;

pub use injector::ManualMapper;
pub use pe_parser::PeImage;

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Arc;
use std::collections::HashMap;

/// Memory protection flags for allocated regions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryProtection {
    NoAccess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    WriteCopy = 0x08,
    Execute = 0x10,
    ExecuteRead = 0x20,
    ExecuteReadWrite = 0x40,
    ExecuteWriteCopy = 0x80,
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400,
}

impl MemoryProtection {
    pub fn as_raw(&self) -> u32 {
        *self as u32
    }
    
    pub fn from_section_characteristics(characteristics: u32) -> Self {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
        const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
        
        let executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        let writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        
        match (executable, readable, writable) {
            (true, true, true) => MemoryProtection::ExecuteReadWrite,
            (true, true, false) => MemoryProtection::ExecuteRead,
            (true, false, true) => MemoryProtection::ExecuteWriteCopy,
            (true, false, false) => MemoryProtection::Execute,
            (false, true, true) => MemoryProtection::ReadWrite,
            (false, true, false) => MemoryProtection::ReadOnly,
            (false, false, true) => MemoryProtection::WriteCopy,
            (false, false, false) => MemoryProtection::NoAccess,
        }
    }
}

/// Allocation type flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AllocationType {
    Commit = 0x1000,
    Reserve = 0x2000,
    Reset = 0x80000,
    ResetUndo = 0x1000000,
    LargePages = 0x20000000,
    Physical = 0x400000,
    TopDown = 0x100000,
    WriteWatch = 0x200000,
}

impl AllocationType {
    pub fn as_raw(&self) -> u32 {
        *self as u32
    }
}

/// Represents a remote memory allocation in a target process
#[derive(Debug)]
pub struct RemoteAllocation {
    process_handle: SafeHandle,
    base_address: NonNull<c_void>,
    size: usize,
    freed: bool,
}

impl RemoteAllocation {
    /// Creates a new remote allocation tracker
    /// 
    /// # Safety
    /// The caller must ensure the base_address points to valid allocated memory
    /// in the target process
    pub unsafe fn new(
        process_handle: SafeHandle,
        base_address: *mut c_void,
        size: usize,
    ) -> Result<Self, MapperError> {
        let base = NonNull::new(base_address)
            .ok_or(MapperError::AllocationFailed)?;
        
        Ok(Self {
            process_handle,
            base_address: base,
            size,
            freed: false,
        })
    }
    
    pub fn base(&self) -> *mut c_void {
        self.base_address.as_ptr()
    }
    
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// Manually free the allocation before drop
    pub fn free(&mut self) -> Result<(), MapperError> {
        if self.freed {
            return Ok(());
        }
        
        // TODO: Call NtFreeVirtualMemory
        self.freed = true;
        Ok(())
    }
}

impl Drop for RemoteAllocation {
    fn drop(&mut self) {
        if !self.freed {
            let _ = self.free();
        }
    }
}

/// Configuration for the manual mapping operation
#[derive(Debug, Clone)]
pub struct MapperConfig {
    /// Whether to erase PE headers after mapping
    pub erase_headers: bool,
    /// Whether to hide the mapped module from PEB
    pub hide_from_peb: bool,
    /// Whether to execute TLS callbacks
    pub execute_tls: bool,
    /// Custom entry point offset (None uses DllMain)
    pub custom_entry: Option<usize>,
    /// Additional flags for allocation
    pub allocation_flags: u32,
}

impl Default for MapperConfig {
    fn default() -> Self {
        Self {
            erase_headers: true,
            hide_from_peb: true,
            execute_tls: true,
            custom_entry: None,
            allocation_flags: AllocationType::Commit as u32 | AllocationType::Reserve as u32,
        }
    }
}

/// Injection method strategy
pub trait InjectionStrategy: Send + Sync {
    /// Execute code in the target process
    fn execute(
        &self,
        process: &ProcessContext,
        entry_point: *const c_void,
        parameter: *const c_void,
    ) -> Result<u32, MapperError>;
    
    /// Name of the injection method
    fn name(&self) -> &'static str;
}

/// Thread hijacking injection strategy
pub struct ThreadHijackStrategy {
    timeout_ms: u32,
}

impl ThreadHijackStrategy {
    pub fn new(timeout_ms: u32) -> Self {
        Self { timeout_ms }
    }
}

impl InjectionStrategy for ThreadHijackStrategy {
    fn execute(
        &self,
        process: &ProcessContext,
        entry_point: *const c_void,
        parameter: *const c_void,
    ) -> Result<u32, MapperError> {
        // TODO: Implement thread hijacking
        // 1. Enumerate threads
        // 2. Suspend a suitable thread
        // 3. Get/Set thread context
        // 4. Redirect execution
        // 5. Resume thread
        Err(MapperError::NotImplemented)
    }
    
    fn name(&self) -> &'static str {
        "ThreadHijack"
    }
}

/// Remote thread creation strategy
pub struct RemoteThreadStrategy {
    wait_for_completion: bool,
}

impl RemoteThreadStrategy {
    pub fn new(wait_for_completion: bool) -> Self {
        Self { wait_for_completion }
    }
}

impl InjectionStrategy for RemoteThreadStrategy {
    fn execute(
        &self,
        process: &ProcessContext,
        entry_point: *const c_void,
        parameter: *const c_void,
    ) -> Result<u32, MapperError> {
        // TODO: Implement NtCreateThreadEx
        Err(MapperError::NotImplemented)
    }
    
    fn name(&self) -> &'static str {
        "RemoteThread"
    }
}

/// APC injection strategy
pub struct ApcInjectionStrategy;

impl InjectionStrategy for ApcInjectionStrategy {
    fn execute(
        &self,
        process: &ProcessContext,
        entry_point: *const c_void,
        parameter: *const c_void,
    ) -> Result<u32, MapperError> {
        // TODO: Implement APC injection via NtQueueApcThread
        Err(MapperError::NotImplemented)
    }
    
    fn name(&self) -> &'static str {
        "ApcInjection"
    }
}

/// Process context containing handles and metadata
#[derive(Debug)]
pub struct ProcessContext {
    handle: SafeHandle,
    pid: u32,
    is_wow64: bool,
    base_address: Option<*const c_void>,
    loaded_modules: HashMap<String, ModuleInfo>,
}

impl ProcessContext {
    /// Open a process by PID
    pub fn open(pid: u32, access: u32) -> Result<Self, MapperError> {
        // TODO: Implement NtOpenProcess
        Err(MapperError::NotImplemented)
    }
    
    /// Attach to current process
    pub fn current() -> Self {
        Self {
            handle: SafeHandle::invalid(), // TODO: Use GetCurrentProcess
            pid: std::process::id(),
            is_wow64: cfg!(target_pointer_width = "32"),
            base_address: None,
            loaded_modules: HashMap::new(),
        }
    }
    
    pub fn pid(&self) -> u32 {
        self.pid
    }
    
    pub fn is_wow64(&self) -> bool {
        self.is_wow64
    }
    
    pub fn handle(&self) -> &SafeHandle {
        &self.handle
    }
    
    /// Read memory from the target process
    pub fn read_memory(&self, address: *const c_void, buffer: &mut [u8]) -> Result<usize, MapperError> {
        // TODO: Implement NtReadVirtualMemory
        Err(MapperError::NotImplemented)
    }
    
    /// Write memory to the target process
    pub fn write_memory(&self, address: *mut c_void, buffer: &[u8]) -> Result<usize, MapperError> {
        // TODO: Implement NtWriteVirtualMemory
        Err(MapperError::NotImplemented)
    }
    
    /// Allocate memory in the target process
    pub fn allocate(
        &self,
        size: usize,
        protection: MemoryProtection,
        allocation_type: u32,
    ) -> Result<RemoteAllocation, MapperError> {
        // TODO: Implement NtAllocateVirtualMemory
        Err(MapperError::AllocationFailed)
    }
    
    /// Change memory protection
    pub fn protect(
        &self,
        address: *mut c_void,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Result<MemoryProtection, MapperError> {
        // TODO: Implement NtProtectVirtualMemory
        Err(MapperError::NotImplemented)
    }
    
    /// Query information about a memory region
    pub fn query_memory(&self, address: *const c_void) -> Result<MemoryBasicInfo, MapperError> {
        // TODO: Implement NtQueryVirtualMemory
        Err(MapperError::NotImplemented)
    }
    
    /// Enumerate loaded modules in the target process
    pub fn enumerate_modules(&mut self) -> Result<&HashMap<String, ModuleInfo>, MapperError> {
        if !self.loaded_modules.is_empty() {
            return Ok(&self.loaded_modules);
        }
        
        // TODO: Walk PEB->Ldr->InLoadOrderModuleList
        Err(MapperError::NotImplemented)
    }
    
    /// Find a module by name
    pub fn find_module(&mut self, name: &str) -> Result<Option<&ModuleInfo>, MapperError> {
        self.enumerate_modules()?;
        Ok(self.loaded_modules.get(&name.to_lowercase()))
    }
}

/// Information about a loaded module
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: *const c_void,
    pub size: usize,
    pub entry_point: *const c_void,
    pub full_path: String,
}

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryBasicInfo {
    pub base_address: *const c_void,
    pub allocation_base: *const c_void,
    pub allocation_protect: MemoryProtection,
    pub region_size: usize,
    pub state: u32,
    pub protect: MemoryProtection,
    pub memory_type: u32,
}

/// Observer trait for mapping events
pub trait MappingObserver: Send + Sync {
    fn on_allocation(&self, base: *const c_void, size: usize) {}
    fn on_sections_mapped(&self, count: usize) {}
    fn on_relocations_applied(&self, count: usize) {}
    fn on_imports_resolved(&self, count: usize) {}
    fn on_tls_executed(&self, callback_count: usize) {}
    fn on_entry_called(&self, entry: *const c_void) {}
    fn on_error(&self, error: &MapperError) {}
    fn on_complete(&self, base: *const c_void) {}
}

/// Default no-op observer
pub struct NullObserver;
impl MappingObserver for NullObserver {}

/// Logging observer for debugging
pub struct LoggingObserver {
    prefix: String,
}

impl LoggingObserver {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefix: prefix.into() }
    }
}

impl MappingObserver for LoggingObserver {
    fn on_allocation(&self, base: *const c_void, size: usize) {
        eprintln!("[{}] Allocated {:?} ({} bytes)", self.prefix, base, size);
    }
    
    fn on_sections_mapped(&self, count: usize) {
        eprintln!("[{}] Mapped {} sections", self.prefix, count);
    }
    
    fn on_relocations_applied(&self, count: usize) {
        eprintln!("[{}] Applied {} relocations", self.prefix, count);
    }
    
    fn on_imports_resolved(&self, count: usize) {
        eprintln!("[{}] Resolved {} imports", self.prefix, count);
    }
    
    fn on_entry_called(&self, entry: *const c_void) {
        eprintln!("[{}] Calling entry point at {:?}", self.prefix, entry);
    }
    
    fn on_error(&self, error: &MapperError) {
        eprintln!("[{}] Error: {:?}", self.prefix, error);
    }
    
    fn on_complete(&self, base: *const c_void) {
        eprintln!("[{}] Mapping complete at {:?}", self.prefix, base);
    }
}

/// Builder for creating ManualMapper instances
pub struct MapperBuilder {
    config: MapperConfig,
    strategy: Option<Arc<dyn InjectionStrategy>>,
    observer: Option<Arc<dyn MappingObserver>>,
}

impl MapperBuilder {
    pub fn new() -> Self {
        Self {
            config: MapperConfig::default(),
            strategy: None,
            observer: None,
        }
    }
    
    pub fn config(mut self, config: MapperConfig) -> Self {
        self.config = config;
        self
    }
    
    pub fn erase_headers(mut self, erase: bool) -> Self {
        self.config.erase_headers = erase;
        self
    }
    
    pub fn hide_from_peb(mut self, hide: bool) -> Self {
        self.config.hide_from_peb = hide;
        self
    }
    
    pub fn execute_tls(mut self, execute: bool) -> Self {
        self.config.execute_tls = execute;
        self
    }
    
    pub fn strategy<S: InjectionStrategy + 'static>(mut self, strategy: S) -> Self {
        self.strategy = Some(Arc::new(strategy));
        self
    }
    
    pub fn observer<O: MappingObserver + 'static>(mut self, observer: O) -> Self {
        self.observer = Some(Arc::new(observer));
        self
    }
    
    pub fn build(self) -> ManualMapper {
        ManualMapper {
            config: self.config,
            strategy: self.strategy.unwrap_or_else(|| Arc::new(RemoteThreadStrategy::new(true))),
            observer: self.observer.unwrap_or_else(|| Arc::new(NullObserver)),
        }
    }
}

impl Default for MapperBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_protection_from_characteristics() {
        let rwx = MemoryProtection::from_section_characteristics(0xE0000000);
        assert_eq!(rwx, MemoryProtection::ExecuteReadWrite);
        
        let rx = MemoryProtection::from_section_characteristics(0x60000000);
        assert_eq!(rx, MemoryProtection::ExecuteRead);
        
        let rw = MemoryProtection::from_section_characteristics(0xC0000000);
        assert_eq!(rw, MemoryProtection::ReadWrite);
    }
    
    #[test]
    fn test_mapper_builder() {
        let mapper = MapperBuilder::new()
            .erase_headers(false)
            .hide_from_peb(true)
            .strategy(RemoteThreadStrategy::new(false))
            .observer(LoggingObserver::new("test"))
            .build();
        
        assert!(!mapper.config.erase_headers);
        assert!(mapper.config.hide_from_peb);
    }
    
    #[test]
    fn test_default_config() {
        let config = MapperConfig::default();
        assert!(config.erase_headers);
        assert!(config.hide_from_peb);
        assert!(config.execute_tls);
        assert!(config.custom_entry.is_none());
    }
}
```

```rust
// src/manualmapper/injector.rs
//! Core manual mapper implementation

use super::*;
use std::sync::Arc;

/// Manual mapper for injecting PE images into processes
pub struct ManualMapper {
    pub(crate) config: MapperConfig,
    pub(crate) strategy: Arc<dyn InjectionStrategy>,
    pub(crate) observer: Arc<dyn MappingObserver>,
}

impl ManualMapper {
    /// Create a new mapper with default settings
    pub fn new() -> Self {
        MapperBuilder::new().build()
    }
    
    /// Create a builder for customized mapper configuration
    pub fn builder() -> MapperBuilder {
        MapperBuilder::new()
    }
    
    /// Map a PE image into the target process
    pub fn map_image(
        &self,
        process: &mut ProcessContext,
        image_data: &[u8],
    ) -> Result<MappedImage, MapperError> {
        // Parse the PE image
        let pe = PeImage::parse(image_data)?;
        
        // Validate architecture compatibility
        if pe.is_64bit() != !process.is_wow64() {
            return Err(MapperError::ArchitectureMismatch);
        }
        
        // Allocate memory in target process
        let allocation = process.allocate(
            pe.image_size(),
            MemoryProtection::ExecuteReadWrite,
            self.config.allocation_flags,
        )?;
        
        self.observer.on_allocation(allocation.base(), allocation.size());
        
        // Map sections
        let sections_mapped = self.map_sections(process, &pe, &allocation)?;
        self.observer.on_sections_mapped(sections_mapped);
        
        // Apply relocations
        let delta = allocation.base() as isize - pe.preferred_base() as isize;
        if delta != 0 {
            let relocs_applied = self.apply_relocations(process, &pe, &allocation, delta)?;
            self.observer.on_relocations_applied(relocs_applied);
        }
        
        // Resolve imports
        let imports_resolved = self.resolve_imports(process, &pe, &allocation)?;
        self.observer.on_imports_resolved(imports_resolved);
        
        // Execute TLS callbacks if configured
        if self.config.execute_tls {
            let tls_count = self.execute_tls_callbacks(process, &pe, &allocation)?;
            self.observer.on_tls_executed(tls_count);
        }
        
        // Set proper section protections
        self.apply_section_protections(process, &pe, &allocation)?;
        
        // Erase headers if configured
        if self.config.erase_headers {
            self.erase_pe_headers(process, &allocation, pe.headers_size())?;
        }
        
        // Call entry point
        let entry_point = unsafe {
            allocation.base().add(pe.entry_point_rva())
        };
        
        self.observer.on_entry_called(entry_point);
        
        let exit_code = self.strategy.execute(
            process,
            entry_point,
            allocation.base(),
        )?;
        
        self.observer.on_complete(allocation.base());
        
        Ok(MappedImage {
            base_address: allocation.base(),
            size: allocation.size(),
            entry_point,
            exit_code,
        })
    }
    
    fn map_sections(
        &self,
        process: &ProcessContext,
        pe: &PeImage,
        allocation: &RemoteAllocation,
    ) -> Result<usize, MapperError> {
        // First, write headers
        process.write_memory(
            allocation.base(),
            pe.headers_data(),
        )?;
        
        let mut count = 0;
        for section in pe.sections() {
            if section.raw_size == 0 {
                continue;
            }
            
            let dest = unsafe {
                allocation.base().add(section.virtual_address as usize)
            };
            
            let data = pe.section_data(&section)?;
            process.write_memory(dest, data)?;
            count += 1;
        }
        
        Ok(count)
    }
    
    fn apply_relocations(
        &self,
        process: &ProcessContext,
        pe: &PeImage,
        allocation: &RemoteAllocation,
        delta: isize,
    ) -> Result<usize, MapperError> {
        let mut count = 0;
        
        for reloc_block in pe.relocations() {
            for entry in &reloc_block.entries {
                let target_rva = reloc_block.page_rva + entry.offset as u32;
                let target_addr = unsafe {
                    allocation.base().add(target_rva as usize)
                };
                
                match entry.reloc_type {
                    RelocationType::HighLow | RelocationType::Dir64 => {
                        // Read current value
                        let mut buffer = [0u8; 8];
                        let size = if entry.reloc_type == RelocationType::Dir64 { 8 } else { 4 };
                        process.read_memory(target_addr, &mut buffer[..size])?;
                        
                        // Apply delta
                        if size == 8 {
                            let value = i64::from_le_bytes(buffer);
                            let new_value = value.wrapping_add(delta as i64);
                            process.write_memory(target_addr as *mut _, &new_value.to_le_bytes())?;
                        } else {
                            let value = i32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                            let new_value = value.wrapping_add(delta as i32);
                            process.write_memory(target_addr as *mut _, &new_value.to_le_bytes())?;
                        }
                        
                        count += 1;
                    }
                    RelocationType::Absolute => {
                        // No-op, used for padding
                    }
                    _ => {
                        // TODO: Handle other relocation types
                    }
                }
            }
        }
        
        Ok(count)
    }
    
    fn resolve_imports(
        &self,
        process: &mut ProcessContext,
        pe: &PeImage,
        allocation: &RemoteAllocation,
    ) -> Result<usize, MapperError> {
        let mut count = 0;
        
        for import_desc in pe.imports() {
            // Find or load the required module
            let module = process.find_module(&import_desc.module_name)?
                .ok_or(MapperError::ModuleNotFound(import_desc.module_name.clone()))?
                .clone();
            
            for thunk in &import_desc.thunks {
                let func_addr = self.resolve_export(process, &module, &thunk.name)?;
                
                let iat_entry = unsafe {
                    allocation.base().add(thunk.iat_rva as usize)
                };
                
                let addr_bytes = (func_addr as usize).to_le_bytes();
                process.write_memory(iat_entry as *mut _, &addr_bytes)?;
                
                count += 1;
            }
        }
        
        Ok(count)
    }
    
    fn resolve_export(
        &self,
        process: &ProcessContext,
        module: &ModuleInfo,
        name: &str,
    ) -> Result<*const c_void, MapperError> {
        // TODO: Parse remote module's export table
        // For now, return a placeholder
        Err(MapperError::ExportNotFound(name.to_string()))
    }
    
    fn execute_tls_callbacks(
        &self,
        process: &ProcessContext,
        pe: &PeImage,
        allocation: &RemoteAllocation,
    ) -> Result<usize, MapperError> {
        let callbacks = pe.tls_callbacks();
        
        for (i, &callback_rva) in callbacks.iter().enumerate() {
            if callback_rva == 0 {
                break;
            }
            
            let callback_addr = unsafe {
                allocation.base().add(callback_rva as usize)
            };
            
            // Execute TLS callback with DLL_PROCESS_ATTACH
            self.strategy.execute(process, callback_addr, allocation.base())?;
        }
        
        Ok(callbacks.len())
    }
    
    fn apply_section_protections(
        &self,
        process: &ProcessContext,
        pe: &PeImage,
        allocation: &RemoteAllocation,
    ) -> Result<(), MapperError> {
        for section in pe.sections() {
            let protection = MemoryProtection::from_section_characteristics(section.characteristics);
            let section_addr = unsafe {
                allocation.base().add(section.virtual_address as usize)
            };
            
            process.protect(
                section_addr as *mut _,
                section.virtual_size as usize,
                protection,
            )?;
        }
        
        Ok(())
    }
    
    fn erase_pe_headers(
        &self,
        process: &ProcessContext,
        allocation: &RemoteAllocation,
        headers_size: usize,
    ) -> Result<(), MapperError> {
        let zeros = vec![0u8; headers_size];
        process.write_memory(allocation.base(), &zeros)?;
        Ok(())
    }
}

impl Default for ManualMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a successful mapping operation
#[derive(Debug)]
pub struct MappedImage {
    pub base_address: *mut c_void,
    pub size: usize,
    pub entry_point: *const c_void,
    pub exit_code: u32,
}

unsafe impl Send for MappedImage {}
unsafe impl Sync for MappedImage {}
```

```rust
// src/manualmapper/pe_parser.rs
//! PE image parsing functionality

use crate::error::MapperError;
use std::ffi::c_void;

/// Parsed PE image
pub struct PeImage<'a> {
    data: &'a [u8],
    dos_header: DosHeader,
    nt_headers: NtHeaders,
    sections: Vec<SectionHeader>,
    is_64bit: bool,
}

impl<'a> PeImage<'a> {
    /// Parse a PE image from raw bytes
    pub fn parse(data: &'a [u8]) -> Result<Self, MapperError> {
        if data.len() < 64 {
            return Err(MapperError::InvalidPeFormat("File too small".into()));
        }
        
        // Parse DOS header
        let dos_header = DosHeader::parse(data)?;
        
        if dos_header.e_magic != 0x5A4D {
            return Err(MapperError::InvalidPeFormat("Invalid DOS signature".into()));
        }
        
        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > data.len() {
            return Err(MapperError::InvalidPeFormat("Invalid PE offset".into()));
        }
        
        // Check PE signature
        let pe_sig = u32::from_le_bytes([
            data[pe_offset],
            data[pe_offset + 1],
            data[pe_offset + 2],
            data[pe_offset + 3],
        ]);
        
        if pe_sig != 0x00004550 {
            return Err(MapperError::InvalidPeFormat("Invalid PE signature".into()));
        }
        
        // Parse NT headers
        let nt_headers = NtHeaders::parse(&data[pe_offset..])?;
        let is_64bit = nt_headers.optional_header.magic == 0x20B;
        
        // Parse sections
        let sections_offset = pe_offset + 24 + nt_headers.file_header.size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(nt_headers.file_header.number_of_sections as usize);
        
        for i in 0..nt_headers.file_header.number_of_sections as usize {
            let section_offset = sections_offset + i * 40;
            let section = SectionHeader::parse(&data[section_offset..])?;
            sections.push(section);
        }
        
        Ok(Self {
            data,
            dos_header,
            nt_headers,
            sections,
            is_64bit,
        })
    }
    
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }
    
    pub fn image_size(&self) -> usize {
        self.nt_headers.optional_header.size_of_image as usize
    }
    
    pub fn preferred_base(&self) -> *const c_void {
        self.nt_headers.optional_header.image_base as *const c_void
    }
    
    pub fn entry_point_rva(&self) -> usize {
        self.nt_headers.optional_header.address_of_entry_point as usize
    }
    
    pub fn headers_size(&self) -> usize {
        self.nt_headers.optional_header.size_of_headers as usize
    }
    
    pub fn headers_data(&self) -> &[u8] {
        &self