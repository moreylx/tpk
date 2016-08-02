//! Map Context Module
//! 
//! Provides PE parsing, memory mapping, and code injection capabilities
//! for process manipulation and DLL injection scenarios.

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::ptr;
use std::sync::{Arc, RwLock};

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

/// DOS header magic number
const DOS_MAGIC: u16 = 0x5A4D;
/// PE signature
const PE_SIGNATURE: u32 = 0x00004550;
/// PE32 magic
const PE32_MAGIC: u16 = 0x10B;
/// PE32+ magic
const PE64_MAGIC: u16 = 0x20B;

/// Section characteristics flags
pub mod section_flags {
    pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
    pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
    pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
}

/// Memory protection constants
pub mod memory_protection {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
}

/// DOS Header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

/// File Header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Data Directory entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Optional Header for PE32
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// Optional Header for PE64
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// Section Header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Get section name as string
    pub fn name_str(&self) -> String {
        let name_bytes: Vec<u8> = self.name.iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect();
        String::from_utf8_lossy(&name_bytes).to_string()
    }

    /// Check if section is executable
    pub fn is_executable(&self) -> bool {
        self.characteristics & section_flags::IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Check if section is writable
    pub fn is_writable(&self) -> bool {
        self.characteristics & section_flags::IMAGE_SCN_MEM_WRITE != 0
    }

    /// Check if section is readable
    pub fn is_readable(&self) -> bool {
        self.characteristics & section_flags::IMAGE_SCN_MEM_READ != 0
    }

    /// Get memory protection flags for this section
    pub fn get_protection(&self) -> u32 {
        let exec = self.is_executable();
        let write = self.is_writable();
        let read = self.is_readable();

        match (exec, write, read) {
            (true, true, _) => memory_protection::PAGE_EXECUTE_READWRITE,
            (true, false, true) => memory_protection::PAGE_EXECUTE_READ,
            (true, false, false) => memory_protection::PAGE_EXECUTE,
            (false, true, _) => memory_protection::PAGE_READWRITE,
            (false, false, true) => memory_protection::PAGE_READONLY,
            (false, false, false) => memory_protection::PAGE_NOACCESS,
        }
    }
}

/// Import Directory entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

/// Export Directory structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// Base Relocation block
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

/// PE Architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArchitecture {
    X86,
    X64,
}

/// Parsed PE information
#[derive(Debug, Clone)]
pub struct ParsedPe {
    pub architecture: PeArchitecture,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub sections: Vec<SectionHeader>,
    pub data_directories: Vec<DataDirectory>,
    pub raw_data: Vec<u8>,
}

impl ParsedPe {
    /// Get the entry point address
    pub fn entry_point(&self) -> u64 {
        self.image_base + self.entry_point_rva as u64
    }

    /// Find section containing RVA
    pub fn rva_to_section(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| {
            rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size
        })
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.rva_to_section(rva).map(|section| {
            rva - section.virtual_address + section.pointer_to_raw_data
        })
    }

    /// Get data at RVA
    pub fn get_data_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let offset = self.rva_to_offset(rva)? as usize;
        if offset + size <= self.raw_data.len() {
            Some(&self.raw_data[offset..offset + size])
        } else {
            None
        }
    }
}

/// PE Parser for analyzing executable files
pub struct PeParser {
    data: Vec<u8>,
}

impl PeParser {
    /// Create a new PE parser from raw bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a PE parser from a file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, MapperError> {
        let data = std::fs::read(path).map_err(|e| {
            MapperError::IoError(format!("Failed to read PE file: {}", e))
        })?;
        Ok(Self::new(data))
    }

    /// Parse the PE file
    pub fn parse(&self) -> Result<ParsedPe, MapperError> {
        if self.data.len() < mem::size_of::<DosHeader>() {
            return Err(MapperError::InvalidPe("File too small for DOS header".into()));
        }

        // Parse DOS header
        let dos_header: DosHeader = unsafe {
            ptr::read_unaligned(self.data.as_ptr() as *const DosHeader)
        };

        if dos_header.e_magic != DOS_MAGIC {
            return Err(MapperError::InvalidPe("Invalid DOS magic".into()));
        }

        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > self.data.len() {
            return Err(MapperError::InvalidPe("Invalid PE offset".into()));
        }

        // Verify PE signature
        let pe_sig: u32 = unsafe {
            ptr::read_unaligned(self.data.as_ptr().add(pe_offset) as *const u32)
        };

        if pe_sig != PE_SIGNATURE {
            return Err(MapperError::InvalidPe("Invalid PE signature".into()));
        }

        // Parse file header
        let file_header_offset = pe_offset + 4;
        if file_header_offset + mem::size_of::<FileHeader>() > self.data.len() {
            return Err(MapperError::InvalidPe("File too small for file header".into()));
        }

        let file_header: FileHeader = unsafe {
            ptr::read_unaligned(self.data.as_ptr().add(file_header_offset) as *const FileHeader)
        };

        // Parse optional header
        let optional_header_offset = file_header_offset + mem::size_of::<FileHeader>();
        if optional_header_offset + 2 > self.data.len() {
            return Err(MapperError::InvalidPe("File too small for optional header".into()));
        }

        let magic: u16 = unsafe {
            ptr::read_unaligned(self.data.as_ptr().add(optional_header_offset) as *const u16)
        };

        let (architecture, image_base, entry_point_rva, size_of_image, size_of_headers, 
             section_alignment, file_alignment, num_data_dirs, data_dir_offset) = match magic {
            PE32_MAGIC => {
                let opt: OptionalHeader32 = unsafe {
                    ptr::read_unaligned(self.data.as_ptr().add(optional_header_offset) as *const OptionalHeader32)
                };
                (
                    PeArchitecture::X86,
                    opt.image_base as u64,
                    opt.address_of_entry_point,
                    opt.size_of_image,
                    opt.size_of_headers,
                    opt.section_alignment,
                    opt.file_alignment,
                    opt.number_of_rva_and_sizes as usize,
                    optional_header_offset + mem::size_of::<OptionalHeader32>(),
                )
            }
            PE64_MAGIC => {
                let opt: OptionalHeader64 = unsafe {
                    ptr::read_unaligned(self.data.as_ptr().add(optional_header_offset) as *const OptionalHeader64)
                };
                (
                    PeArchitecture::X64,
                    opt.image_base,
                    opt.address_of_entry_point,
                    opt.size_of_image,
                    opt.size_of_headers,
                    opt.section_alignment,
                    opt.file_alignment,
                    opt.number_of_rva_and_sizes as usize,
                    optional_header_offset + mem::size_of::<OptionalHeader64>(),
                )
            }
            _ => return Err(MapperError::InvalidPe(format!("Unknown PE magic: 0x{:04X}", magic))),
        };

        // Parse data directories
        let mut data_directories = Vec::with_capacity(num_data_dirs);
        for i in 0..num_data_dirs {
            let dir_offset = data_dir_offset + i * mem::size_of::<DataDirectory>();
            if dir_offset + mem::size_of::<DataDirectory>() > self.data.len() {
                break;
            }
            let dir: DataDirectory = unsafe {
                ptr::read_unaligned(self.data.as_ptr().add(dir_offset) as *const DataDirectory)
            };
            data_directories.push(dir);
        }

        // Parse section headers
        let section_offset = optional_header_offset + file_header.size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(file_header.number_of_sections as usize);

        for i in 0..file_header.number_of_sections as usize {
            let sec_offset = section_offset + i * mem::size_of::<SectionHeader>();
            if sec_offset + mem::size_of::<SectionHeader>() > self.data.len() {
                return Err(MapperError::InvalidPe("Invalid section header offset".into()));
            }
            let section: SectionHeader = unsafe {
                ptr::read_unaligned(self.data.as_ptr().add(sec_offset) as *const SectionHeader)
            };
            sections.push(section);
        }

        Ok(ParsedPe {
            architecture,
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            section_alignment,
            file_alignment,
            sections,
            data_directories,
            raw_data: self.data.clone(),
        })
    }
}

/// Import information
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub module_name: String,
    pub functions: Vec<ImportedFunction>,
}

/// Imported function details
#[derive(Debug, Clone)]
pub struct ImportedFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: u16,
    pub thunk_rva: u32,
}

/// Export information
#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub forwarded_to: Option<String>,
}

/// Import/Export resolver
pub struct ImportExportResolver<'a> {
    pe: &'a ParsedPe,
}

impl<'a> ImportExportResolver<'a> {
    pub fn new(pe: &'a ParsedPe) -> Self {
        Self { pe }
    }

    /// Resolve all imports
    pub fn resolve_imports(&self) -> Result<Vec<ImportInfo>, MapperError> {
        const IMPORT_DIR_INDEX: usize = 1;
        
        if self.pe.data_directories.len() <= IMPORT_DIR_INDEX {
            return Ok(Vec::new());
        }

        let import_dir = &self.pe.data_directories[IMPORT_DIR_INDEX];
        if import_dir.virtual_address == 0 || import_dir.size == 0 {
            return Ok(Vec::new());
        }

        let mut imports = Vec::new();
        let mut desc_rva = import_dir.virtual_address;

        loop {
            let desc_data = self.pe.get_data_at_rva(desc_rva, mem::size_of::<ImportDescriptor>())
                .ok_or_else(|| MapperError::InvalidPe("Invalid import descriptor".into()))?;

            let desc: ImportDescriptor = unsafe {
                ptr::read_unaligned(desc_data.as_ptr() as *const ImportDescriptor)
            };

            // Check for null terminator
            if desc.name == 0 {
                break;
            }

            // Read module name
            let module_name = self.read_string_at_rva(desc.name)?;

            // Read imported functions
            let functions = self.read_import_thunks(
                if desc.original_first_thunk != 0 { desc.original_first_thunk } else { desc.first_thunk },
                desc.first_thunk,
            )?;

            imports.push(ImportInfo {
                module_name,
                functions,
            });

            desc_rva += mem::size_of::<ImportDescriptor>() as u32;
        }

        Ok(imports)
    }

    fn read_import_thunks(&self, lookup_rva: u32, thunk_rva: u32) -> Result<Vec<ImportedFunction>, MapperError> {
        let mut functions = Vec::new();
        let mut current_lookup = lookup_rva;
        let mut current_thunk = thunk_rva;

        let thunk_size = match self.pe.architecture {
            PeArchitecture::X86 => 4usize,
            PeArchitecture::X64 => 8usize,
        };

        let ordinal_flag: u64 = match self.pe.architecture {
            PeArchitecture::X86 => 0x80000000,
            PeArchitecture::X64 => 0x8000000000000000,
        };

        loop {
            let thunk_data = self.pe.get_data_at_rva(current_lookup, thunk_size)
                .ok_or_else(|| MapperError::InvalidPe("Invalid import thunk".into()))?;

            let thunk_value: u64 = match self.pe.architecture {
                PeArchitecture::X86 => unsafe {
                    ptr::read_unaligned(thunk_data.as_ptr() as *const u32) as u64
                },
                PeArchitecture::X64 => unsafe {
                    ptr::read_unaligned(thunk_data.as_ptr() as *const u64)
                },
            };

            if thunk_value == 0 {
                break;
            }

            let (name, ordinal, hint) = if thunk_value & ordinal_flag != 0 {
                (None, Some((thunk_value & 0xFFFF) as u16), 0)
            } else {
                let hint_name_rva = thunk_value as u32;
                let hint_data = self.pe.get_data_at_rva(hint_name_rva, 2)
                    .ok_or_else(|| MapperError::InvalidPe("Invalid hint/name".into()))?;
                let hint: u16 = unsafe { ptr::read_unaligned(hint_data.as_ptr() as *const u16) };
                let name = self.read_string_at_rva(hint_name_rva + 2)?;
                (Some(name), None, hint)
            };

            functions.push(ImportedFunction {
                name,
                ordinal,
                hint,
                thunk_rva: current_thunk,
            });

            current_lookup += thunk_size as u32;
            current_thunk += thunk_size as u32;
        }

        Ok(functions)
    }

    /// Resolve all exports
    pub fn resolve_exports(&self) -> Result<Vec<ExportInfo>, MapperError> {
        const EXPORT_DIR_INDEX: usize = 0;

        if self.pe.data_directories.is_empty() {
            return Ok(Vec::new());
        }

        let export_dir = &self.pe.data_directories[EXPORT_DIR_INDEX];
        if export_dir.virtual_address == 0 || export_dir.size == 0 {
            return Ok(Vec::new());
        }

        let dir_data = self.pe.get_data_at_rva(export_dir.virtual_address, mem::size_of::<ExportDirectory>())
            .ok_or_else(|| MapperError::InvalidPe("Invalid export directory".into()))?;

        let dir: ExportDirectory = unsafe {
            ptr::read_unaligned(dir_data.as_ptr() as *const ExportDirectory)
        };

        let mut exports = Vec::new();

        // Read function addresses
        let func_count = dir.number_of_functions as usize;
        let name_count = dir.number_of_names as usize;

        // Build name-to-ordinal mapping
        let mut name_ordinals: HashMap<u32, String> = HashMap::new();
        
        for i in 0..name_count {
            let name_ptr_rva = dir.address_of_names + (i as u32 * 4);
            let name_ptr_data = self.pe.get_data_at_rva(name_ptr_rva, 4)
                .ok_or_else(|| MapperError::InvalidPe("Invalid export name pointer".into()))?;
            let name_rva: u32 = unsafe { ptr::read_unaligned(name_ptr_data.as_ptr() as *const u32) };
            
            let ordinal_rva = dir.address_of_name_ordinals + (i as u32 * 2);
            let ordinal_data = self.pe.get_data_at_rva(ordinal_rva, 2)
                .ok_or_else(|| MapperError::InvalidPe("Invalid export ordinal".into()))?;
            let ordinal: u16 = unsafe { ptr::read_unaligned(ordinal_data.as_ptr() as *const u16) };

            let name = self.read_string_at_rva(name_rva)?;
            name_ordinals.insert(ordinal as u32, name);
        }

        // Read all exports
        for i in 0..func_count {
            let func_rva_offset = dir.address_of_functions + (i as u32 * 4);
            let func_data = self.pe.get_data_at_rva(func_rva_offset, 4)
                .ok_or_else(|| MapperError::InvalidPe("Invalid export function address".into()))?;
            let func_rva: u32 = unsafe { ptr::read_unaligned(func_data.as_ptr() as *const u32) };

            if func_rva == 0 {
                continue;
            }

            let ordinal = dir.base + i as u32;
            let name = name_ordinals.get(&(i as u32)).cloned();

            // Check for forwarded export
            let forwarded_to = if func_rva >= export_dir.virtual_address 
                && func_rva < export_dir.virtual_address + export_dir.size {
                Some(self.read_string_at_rva(func_rva)?)
            } else {
                None
            };

            exports.push(ExportInfo {
                name,
                ordinal,
                rva: func_rva,
                forwarded_to,
            });
        }

        Ok(exports)
    }

    fn read_string_at_rva(&self, rva: u32) -> Result<String, MapperError> {
        let offset = self.pe.rva_to_offset(rva)
            .ok_or_else(|| MapperError::InvalidPe("Invalid string RVA".into()))? as usize;

        let mut end = offset;
        while end < self.pe.raw_data.len() && self.pe.raw_data[end] != 0 {
            end += 1;
        }

        String::from_utf8(self.pe.raw_data[offset..end].to_vec())
            .map_err(|_| MapperError::InvalidPe("Invalid UTF-8 string".into()))
    }
}

/// Relocation entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    Absolute,
    High,
    Low,
    HighLow,
    HighAdj,
    Dir64,
    Unknown(u8),
}

impl From<u8> for RelocationType {
    fn from(value: u8) -> Self {
        match value {
            0 => RelocationType::Absolute,
            1 => RelocationType::High,
            2 => RelocationType::Low,
            3 => RelocationType::HighLow,
            4 => RelocationType::HighAdj,
            10 => RelocationType::Dir64,
            v => RelocationType::Unknown(v),
        }
    }
}

/// Relocation entry
#[derive(Debug, Clone)]
pub struct RelocationEntry {
    pub rva: u32,
    pub reloc_type: RelocationType,
}

/// Relocation processor
pub struct RelocationProcessor<'a> {
    pe: &'a ParsedPe,
}

impl<'a> RelocationProcessor<'a> {
    pub fn new(pe: &'a ParsedPe) -> Self {
        Self { pe }
    }

    /// Parse all relocations
    pub fn parse_relocations(&self) -> Result<Vec<RelocationEntry>, MapperError> {
        const RELOC_DIR_INDEX: usize = 5;

        if self.pe.data_directories.len() <= RELOC_DIR_INDEX {
            return Ok(Vec::new());
        }

        let reloc_dir = &self.pe.data_directories[RELOC_DIR_INDEX];
        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
            return Ok(Vec::new());
        }

        let mut relocations = Vec::new();
        let mut current_rva = reloc_dir.virtual_address;
        let end_rva = reloc_dir.virtual_address + reloc_dir.size;

        while current_rva < end_rva {
            let block_data = self.pe.get_data_at_rva(current_rva, mem::size_of::<BaseRelocation>())
                .ok_or_else(|| MapperError::InvalidPe("Invalid relocation block".into()))?;

            let block: BaseRelocation = unsafe {
                ptr::read_unaligned(block_data.as_ptr() as *const BaseRelocation)
            };

            if block.size_of_block == 0 {
                break;
            }

            let entry_count = (block.size_of_block as usize - mem::size_of::<BaseRelocation>()) / 2;
            let entries_rva = current_rva + mem::size_of::<BaseRelocation>() as u32;

            for i in 0..entry_count {
                let entry_data = self.pe.get_data_at_rva(entries_rva + (i as u32 * 2), 2)
                    .ok_or_else(|| MapperError::InvalidPe("Invalid relocation entry".into()))?;

                let entry: u16 = unsafe { ptr::read_unaligned(entry_data.as_ptr() as *const u16) };
                let reloc_type = RelocationType::from((entry >> 12) as u8);