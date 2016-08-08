//! PE (Portable Executable) parsing module for Windows executables
//!
//! This module provides safe abstractions for parsing PE files,
//! including headers, sections, imports, and exports.

use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::slice;
use std::ffi::CStr;

use crate::error::MapperError;

/// DOS header magic number "MZ"
pub const DOS_SIGNATURE: u16 = 0x5A4D;

/// PE signature "PE\0\0"
pub const PE_SIGNATURE: u32 = 0x00004550;

/// PE32 magic number
pub const PE32_MAGIC: u16 = 0x10B;

/// PE32+ magic number
pub const PE64_MAGIC: u16 = 0x20B;

/// Machine type for AMD64
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// Machine type for i386
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x14C;

/// Section characteristic: executable
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

/// Section characteristic: readable
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;

/// Section characteristic: writable
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

/// Section contains code
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;

/// Section contains initialized data
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;

/// Section contains uninitialized data
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;

/// Maximum number of data directories
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// Section name length
pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

/// Data directory indices
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirectoryIndex {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Security = 4,
    BaseReloc = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    Iat = 12,
    DelayImport = 13,
    ComDescriptor = 14,
    Reserved = 15,
}

/// DOS header structure
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

impl DosHeader {
    /// Validates the DOS header magic signature
    pub fn is_valid(&self) -> bool {
        self.e_magic == DOS_SIGNATURE
    }

    /// Returns the offset to the PE header
    pub fn pe_offset(&self) -> u32 {
        self.e_lfanew as u32
    }
}

/// COFF file header
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

impl FileHeader {
    /// Check if this is a 64-bit executable
    pub fn is_64bit(&self) -> bool {
        self.machine == IMAGE_FILE_MACHINE_AMD64
    }

    /// Check if this is a 32-bit executable
    pub fn is_32bit(&self) -> bool {
        self.machine == IMAGE_FILE_MACHINE_I386
    }
}

/// Data directory entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    /// Check if this directory entry is present
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// Optional header for PE32 (32-bit)
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
    pub data_directory: [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

/// Optional header for PE32+ (64-bit)
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
    pub data_directory: [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

/// Section header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; IMAGE_SIZEOF_SHORT_NAME],
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
    /// Get the section name as a string
    pub fn name_str(&self) -> &str {
        let name_bytes = &self.name;
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(IMAGE_SIZEOF_SHORT_NAME);
        std::str::from_utf8(&name_bytes[..end]).unwrap_or("")
    }

    /// Check if section is executable
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Check if section is readable
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// Check if section is writable
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// Check if section contains code
    pub fn contains_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }
}

/// Export directory table
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

/// Import descriptor
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// Check if this is the null terminator
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0 && self.name == 0 && self.first_thunk == 0
    }
}

/// Base relocation block header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

/// Relocation types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    HighAdj = 4,
    Dir64 = 10,
}

impl TryFrom<u16> for RelocationType {
    type Error = MapperError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RelocationType::Absolute),
            1 => Ok(RelocationType::High),
            2 => Ok(RelocationType::Low),
            3 => Ok(RelocationType::HighLow),
            4 => Ok(RelocationType::HighAdj),
            10 => Ok(RelocationType::Dir64),
            _ => Err(MapperError::InvalidFormat(format!("Unknown relocation type: {}", value))),
        }
    }
}

/// Parsed export entry
#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub ordinal: u16,
    pub name: Option<String>,
    pub rva: u32,
    pub forwarded_to: Option<String>,
}

/// Parsed import entry
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<ImportFunction>,
}

/// Imported function
#[derive(Debug, Clone)]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: u16,
}

/// Relocation entry
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry {
    pub rva: u32,
    pub reloc_type: RelocationType,
}

/// Architecture-independent optional header representation
#[derive(Debug, Clone)]
pub enum OptionalHeader {
    Pe32(OptionalHeader32),
    Pe64(OptionalHeader64),
}

impl OptionalHeader {
    /// Get the image base address
    pub fn image_base(&self) -> u64 {
        match self {
            OptionalHeader::Pe32(h) => h.image_base as u64,
            OptionalHeader::Pe64(h) => h.image_base,
        }
    }

    /// Get the entry point RVA
    pub fn entry_point(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.address_of_entry_point,
            OptionalHeader::Pe64(h) => h.address_of_entry_point,
        }
    }

    /// Get the size of the image when loaded
    pub fn size_of_image(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_image,
            OptionalHeader::Pe64(h) => h.size_of_image,
        }
    }

    /// Get the size of headers
    pub fn size_of_headers(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_headers,
            OptionalHeader::Pe64(h) => h.size_of_headers,
        }
    }

    /// Get section alignment
    pub fn section_alignment(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.section_alignment,
            OptionalHeader::Pe64(h) => h.section_alignment,
        }
    }

    /// Get file alignment
    pub fn file_alignment(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.file_alignment,
            OptionalHeader::Pe64(h) => h.file_alignment,
        }
    }

    /// Get a data directory entry
    pub fn data_directory(&self, index: DataDirectoryIndex) -> Option<&DataDirectory> {
        let idx = index as usize;
        match self {
            OptionalHeader::Pe32(h) if idx < h.number_of_rva_and_sizes as usize => {
                Some(&h.data_directory[idx])
            }
            OptionalHeader::Pe64(h) if idx < h.number_of_rva_and_sizes as usize => {
                Some(&h.data_directory[idx])
            }
            _ => None,
        }
    }

    /// Check if this is a 64-bit PE
    pub fn is_64bit(&self) -> bool {
        matches!(self, OptionalHeader::Pe64(_))
    }
}

/// Complete parsed PE file representation
#[derive(Debug)]
pub struct PeFile {
    data: Vec<u8>,
    dos_header: DosHeader,
    file_header: FileHeader,
    optional_header: OptionalHeader,
    sections: Vec<SectionHeader>,
}

impl PeFile {
    /// Parse a PE file from a byte slice
    pub fn parse(data: &[u8]) -> Result<Self, MapperError> {
        if data.len() < mem::size_of::<DosHeader>() {
            return Err(MapperError::InvalidFormat("File too small for DOS header".into()));
        }

        // Parse DOS header
        let dos_header: DosHeader = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const DosHeader)
        };

        if !dos_header.is_valid() {
            return Err(MapperError::InvalidFormat("Invalid DOS signature".into()));
        }

        let pe_offset = dos_header.pe_offset() as usize;
        
        // Validate PE offset
        if pe_offset + 4 > data.len() {
            return Err(MapperError::InvalidFormat("PE offset out of bounds".into()));
        }

        // Check PE signature
        let pe_sig = u32::from_le_bytes([
            data[pe_offset],
            data[pe_offset + 1],
            data[pe_offset + 2],
            data[pe_offset + 3],
        ]);

        if pe_sig != PE_SIGNATURE {
            return Err(MapperError::InvalidFormat("Invalid PE signature".into()));
        }

        // Parse file header
        let file_header_offset = pe_offset + 4;
        if file_header_offset + mem::size_of::<FileHeader>() > data.len() {
            return Err(MapperError::InvalidFormat("File too small for file header".into()));
        }

        let file_header: FileHeader = unsafe {
            std::ptr::read_unaligned(data[file_header_offset..].as_ptr() as *const FileHeader)
        };

        // Parse optional header
        let optional_header_offset = file_header_offset + mem::size_of::<FileHeader>();
        
        if optional_header_offset + 2 > data.len() {
            return Err(MapperError::InvalidFormat("File too small for optional header magic".into()));
        }

        let magic = u16::from_le_bytes([data[optional_header_offset], data[optional_header_offset + 1]]);

        let optional_header = match magic {
            PE32_MAGIC => {
                if optional_header_offset + mem::size_of::<OptionalHeader32>() > data.len() {
                    return Err(MapperError::InvalidFormat("File too small for PE32 optional header".into()));
                }
                let header: OptionalHeader32 = unsafe {
                    std::ptr::read_unaligned(data[optional_header_offset..].as_ptr() as *const OptionalHeader32)
                };
                OptionalHeader::Pe32(header)
            }
            PE64_MAGIC => {
                if optional_header_offset + mem::size_of::<OptionalHeader64>() > data.len() {
                    return Err(MapperError::InvalidFormat("File too small for PE64 optional header".into()));
                }
                let header: OptionalHeader64 = unsafe {
                    std::ptr::read_unaligned(data[optional_header_offset..].as_ptr() as *const OptionalHeader64)
                };
                OptionalHeader::Pe64(header)
            }
            _ => return Err(MapperError::InvalidFormat(format!("Unknown PE magic: 0x{:04X}", magic))),
        };

        // Parse section headers
        let sections_offset = optional_header_offset + file_header.size_of_optional_header as usize;
        let num_sections = file_header.number_of_sections as usize;
        
        let sections_size = num_sections * mem::size_of::<SectionHeader>();
        if sections_offset + sections_size > data.len() {
            return Err(MapperError::InvalidFormat("File too small for section headers".into()));
        }

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let section_offset = sections_offset + i * mem::size_of::<SectionHeader>();
            let section: SectionHeader = unsafe {
                std::ptr::read_unaligned(data[section_offset..].as_ptr() as *const SectionHeader)
            };
            sections.push(section);
        }

        Ok(PeFile {
            data: data.to_vec(),
            dos_header,
            file_header,
            optional_header,
            sections,
        })
    }

    /// Parse from a reader
    pub fn parse_from_reader<R: Read>(reader: &mut R) -> Result<Self, MapperError> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        Self::parse(&data)
    }

    /// Get the DOS header
    pub fn dos_header(&self) -> &DosHeader {
        &self.dos_header
    }

    /// Get the file header
    pub fn file_header(&self) -> &FileHeader {
        &self.file_header
    }

    /// Get the optional header
    pub fn optional_header(&self) -> &OptionalHeader {
        &self.optional_header
    }

    /// Get all section headers
    pub fn sections(&self) -> &[SectionHeader] {
        &self.sections
    }

    /// Find a section by name
    pub fn find_section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name_str() == name)
    }

    /// Get the raw file data
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size;
            
            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some((section.pointer_to_raw_data + offset_in_section) as usize);
            }
        }
        
        // RVA might be in headers
        if rva < self.optional_header.size_of_headers() {
            return Some(rva as usize);
        }
        
        None
    }

    /// Read bytes at an RVA
    pub fn read_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let offset = self.rva_to_offset(rva)?;
        if offset + size <= self.data.len() {
            Some(&self.data[offset..offset + size])
        } else {
            None
        }
    }

    /// Read a null-terminated string at an RVA
    pub fn read_string_at_rva(&self, rva: u32) -> Option<String> {
        let offset = self.rva_to_offset(rva)?;
        if offset >= self.data.len() {
            return None;
        }
        
        let bytes = &self.data[offset..];
        let end = bytes.iter().position(|&b| b == 0)?;
        String::from_utf8(bytes[..end].to_vec()).ok()
    }

    /// Get section data by section header
    pub fn section_data(&self, section: &SectionHeader) -> Option<&[u8]> {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        
        if start + size <= self.data.len() {
            Some(&self.data[start..start + size])
        } else {
            None
        }
    }

    /// Parse export directory
    pub fn parse_exports(&self) -> Result<Vec<ExportEntry>, MapperError> {
        let export_dir = match self.optional_header.data_directory(DataDirectoryIndex::Export) {
            Some(dir) if dir.is_present() => dir,
            _ => return Ok(Vec::new()),
        };

        let export_data = self.read_at_rva(export_dir.virtual_address, mem::size_of::<ExportDirectory>())
            .ok_or_else(|| MapperError::InvalidFormat("Cannot read export directory".into()))?;

        let export_table: ExportDirectory = unsafe {
            std::ptr::read_unaligned(export_data.as_ptr() as *const ExportDirectory)
        };

        let mut exports = Vec::new();
        let num_functions = export_table.number_of_functions as usize;
        let num_names = export_table.number_of_names as usize;

        // Read function addresses
        let func_rvas = self.read_at_rva(export_table.address_of_functions, num_functions * 4)
            .ok_or_else(|| MapperError::InvalidFormat("Cannot read export function addresses".into()))?;

        // Read name pointers
        let name_rvas = if num_names > 0 {
            self.read_at_rva(export_table.address_of_names, num_names * 4)
                .ok_or_else(|| MapperError::InvalidFormat("Cannot read export name pointers".into()))?
        } else {
            &[]
        };

        // Read ordinals
        let ordinals = if num_names > 0 {
            self.read_at_rva(export_table.address_of_name_ordinals, num_names * 2)
                .ok_or_else(|| MapperError::InvalidFormat("Cannot read export ordinals".into()))?
        } else {
            &[]
        };

        // Build ordinal to name mapping
        let mut ordinal_to_name: std::collections::HashMap<u16, String> = std::collections::HashMap::new();
        for i in 0..num_names {
            let ordinal = u16::from_le_bytes([ordinals[i * 2], ordinals[i * 2 + 1]]);
            let name_rva = u32::from_le_bytes([
                name_rvas[i * 4],
                name_rvas[i * 4 + 1],
                name_rvas[i * 4 + 2],
                name_rvas[i * 4 + 3],
            ]);
            
            if let Some(name) = self.read_string_at_rva(name_rva) {
                ordinal_to_name.insert(ordinal, name);
            }
        }

        // Build export entries
        let export_dir_start = export_dir.virtual_address;
        let export_dir_end = export_dir_start + export_dir.size;

        for i in 0..num_functions {
            let func_rva = u32::from_le_bytes([
                func_rvas[i * 4],
                func_rvas[i * 4 + 1],
                func_rvas[i * 4 + 2],
                func_rvas[i * 4 + 3],
            ]);

            if func_rva == 0 {
                continue;
            }

            let ordinal = (i as u32 + export_table.base) as u16;
            let name = ordinal_to_name.get(&(i as u16)).cloned();

            // Check if this is a forwarder
            let forwarded_to = if func_rva >= export_dir_start && func_rva < export_dir_end {
                self.read_string_at_rva(func_rva)
            } else {
                None
            };

            exports.push(ExportEntry {
                ordinal,
                name,
                rva: func_rva,
                forwarded_to,
            });
        }

        Ok(exports)
    }

    /// Parse import directory
    pub fn parse_imports(&self) -> Result<Vec<ImportEntry>, MapperError> {
        let import_dir = match self.optional_header.data_directory(DataDirectoryIndex::Import) {
            Some(dir) if dir.is_present() => dir,
            _ => return Ok(Vec::new()),
        };

        let mut imports = Vec::new();
        let mut offset = 0;

        loop {
            let desc_data = self.read_at_rva(
                import_dir.virtual_address + offset,
                mem::size_of::<ImportDescriptor>()
            ).ok_or_else(|| MapperError::InvalidFormat("Cannot read import descriptor".into()))?;

            let descriptor: ImportDescriptor = unsafe {
                std::ptr::read_unaligned(desc_data.as_ptr() as *const ImportDescriptor)
            };

            if descriptor.is_null() {
                break;
            }

            let dll_name = self.read_string_at_rva(descriptor.name)
                .ok_or_else(|| MapperError::InvalidFormat("Cannot read import DLL name".into()))?;

            let functions = self.parse_import_thunks(
                if descriptor.original_first_thunk != 0 {
                    descriptor.original_first_thunk
                } else {
                    descriptor.first_thunk
                }
            )?;

            imports.push(ImportEntry {
                dll_name,
                functions,
            });

            offset += mem::size_of::<ImportDescriptor>() as u32;
        }

        Ok(imports)
    }

    /// Parse import thunks (lookup table)
    fn parse_import_thunks(&self, thunk_rva: u32) -> Result<Vec<ImportFunction>, MapperError> {
        let mut functions = Vec::new();
        let is_64bit = self.optional_header.is_64bit();
        let thunk_size = if is_64bit { 8 } else { 4 };
        let ordinal_flag: u64 = if is_64bit { 0x8000000000000000 } else { 0x80000000 };

        let mut offset = 0u32;

        loop {
            let thunk_data = self.read_at_rva(thunk_rva + offset, thunk_size)
                .ok_or_else(|| MapperError::InvalidFormat("Cannot read import thunk".into()))?;

            let thunk_value: u64 = if is_64bit {
                u64::from_le_bytes([
                    thunk_data[0], thunk_data[1], thunk_data[2], thunk_data[3],
                    thunk_data[4], thunk_data[5], thunk_data[6], thunk_data[7],
                ])
            } else {
                u32::from_le_bytes([
                    thunk_data[0], thunk_data[1], thunk_data[2], thunk_data[3],
                ]) as u64
            };

            if thunk_value == 0 {
                break;
            }

            let function = if thunk_value & ordinal_flag != 0 {
                // Import by ordinal
                ImportFunction {
                    name: None,
                    ordinal: Some((thunk_value & 0xFFFF) as u16),
                    hint: 0,
                }
            } else {
                // Import by name
                let hint_name_rva = (thunk_value & 0x7FFFFFFF) as u