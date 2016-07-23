//! Portable Executable (PE) parsing and manipulation module.
//!
//! This module provides comprehensive PE file format parsing capabilities,
//! supporting both PE32 and PE32+ (64-bit) executables. It implements
//! safe abstractions over raw PE structures with proper validation.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::slice;

use crate::error::{MapperError, NtStatus};

/// DOS header magic number ("MZ")
pub const DOS_SIGNATURE: u16 = 0x5A4D;

/// PE signature ("PE\0\0")
pub const PE_SIGNATURE: u32 = 0x00004550;

/// PE32 magic number
pub const PE32_MAGIC: u16 = 0x10B;

/// PE32+ (64-bit) magic number
pub const PE64_MAGIC: u16 = 0x20B;

/// Maximum number of sections allowed
pub const MAX_SECTIONS: usize = 96;

/// Section characteristics flags
pub mod section_flags {
    pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
    pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
    pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
    pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;
    pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x08000000;
    pub const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
}

/// Data directory indices
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    ClrRuntime = 14,
    Reserved = 15,
}

impl DataDirectoryIndex {
    pub const COUNT: usize = 16;
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
    pub fn is_valid(&self) -> bool {
        self.e_magic == DOS_SIGNATURE && self.e_lfanew > 0
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

/// Data directory entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
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
    pub data_directory: [DataDirectory; DataDirectoryIndex::COUNT],
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
    pub data_directory: [DataDirectory; DataDirectoryIndex::COUNT],
}

/// Section header
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    /// Get section name as string, handling null termination
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    /// Check if section contains code
    pub fn is_code(&self) -> bool {
        self.characteristics & section_flags::IMAGE_SCN_CNT_CODE != 0
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

    /// Check if RVA falls within this section
    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.virtual_address && rva < self.virtual_address + self.virtual_size
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        if self.contains_rva(rva) {
            Some(rva - self.virtual_address + self.pointer_to_raw_data)
        } else {
            None
        }
    }
}

impl fmt::Debug for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SectionHeader")
            .field("name", &self.name_str())
            .field("virtual_size", &format_args!("0x{:X}", self.virtual_size))
            .field("virtual_address", &format_args!("0x{:X}", self.virtual_address))
            .field("size_of_raw_data", &format_args!("0x{:X}", self.size_of_raw_data))
            .field("pointer_to_raw_data", &format_args!("0x{:X}", self.pointer_to_raw_data))
            .field("characteristics", &format_args!("0x{:X}", self.characteristics))
            .finish()
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
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0 && self.first_thunk == 0
    }
}

/// Base relocation block header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BaseRelocationBlock {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

/// Relocation types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    HighAdj = 4,
    Dir64 = 10,
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
            other => RelocationType::Unknown(other),
        }
    }
}

/// Parsed relocation entry
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry {
    pub rva: u32,
    pub reloc_type: RelocationType,
}

/// PE architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArchitecture {
    X86,
    X64,
}

/// Unified optional header abstraction
#[derive(Debug, Clone)]
pub enum OptionalHeader {
    Pe32(OptionalHeader32),
    Pe64(OptionalHeader64),
}

impl OptionalHeader {
    pub fn architecture(&self) -> PeArchitecture {
        match self {
            OptionalHeader::Pe32(_) => PeArchitecture::X86,
            OptionalHeader::Pe64(_) => PeArchitecture::X64,
        }
    }

    pub fn image_base(&self) -> u64 {
        match self {
            OptionalHeader::Pe32(h) => h.image_base as u64,
            OptionalHeader::Pe64(h) => h.image_base,
        }
    }

    pub fn entry_point(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.address_of_entry_point,
            OptionalHeader::Pe64(h) => h.address_of_entry_point,
        }
    }

    pub fn size_of_image(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_image,
            OptionalHeader::Pe64(h) => h.size_of_image,
        }
    }

    pub fn size_of_headers(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_headers,
            OptionalHeader::Pe64(h) => h.size_of_headers,
        }
    }

    pub fn section_alignment(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.section_alignment,
            OptionalHeader::Pe64(h) => h.section_alignment,
        }
    }

    pub fn file_alignment(&self) -> u32 {
        match self {
            OptionalHeader::Pe32(h) => h.file_alignment,
            OptionalHeader::Pe64(h) => h.file_alignment,
        }
    }

    pub fn data_directory(&self, index: DataDirectoryIndex) -> DataDirectory {
        match self {
            OptionalHeader::Pe32(h) => h.data_directory[index as usize],
            OptionalHeader::Pe64(h) => h.data_directory[index as usize],
        }
    }

    pub fn subsystem(&self) -> u16 {
        match self {
            OptionalHeader::Pe32(h) => h.subsystem,
            OptionalHeader::Pe64(h) => h.subsystem,
        }
    }

    pub fn dll_characteristics(&self) -> u16 {
        match self {
            OptionalHeader::Pe32(h) => h.dll_characteristics,
            OptionalHeader::Pe64(h) => h.dll_characteristics,
        }
    }
}

/// Parsed export information
#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub ordinal: u16,
    pub rva: u32,
    pub forwarded_to: Option<String>,
}

/// Parsed import information
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub dll_name: String,
    pub functions: Vec<ImportFunction>,
}

/// Individual import function
#[derive(Debug, Clone)]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: u16,
    pub thunk_rva: u32,
}

/// Main PE parser structure
pub struct PortableExecutable {
    data: Vec<u8>,
    dos_header: DosHeader,
    file_header: FileHeader,
    optional_header: OptionalHeader,
    sections: Vec<SectionHeader>,
}

impl PortableExecutable {
    /// Parse PE from byte slice
    pub fn parse(data: &[u8]) -> Result<Self, MapperError> {
        if data.len() < mem::size_of::<DosHeader>() {
            return Err(MapperError::InvalidData("Data too small for DOS header".into()));
        }

        // Parse DOS header
        let dos_header: DosHeader = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const DosHeader)
        };

        if !dos_header.is_valid() {
            return Err(MapperError::InvalidData("Invalid DOS signature".into()));
        }

        let pe_offset = dos_header.e_lfanew as usize;
        
        if pe_offset + 4 > data.len() {
            return Err(MapperError::InvalidData("PE offset out of bounds".into()));
        }

        // Verify PE signature
        let pe_sig = u32::from_le_bytes([
            data[pe_offset],
            data[pe_offset + 1],
            data[pe_offset + 2],
            data[pe_offset + 3],
        ]);

        if pe_sig != PE_SIGNATURE {
            return Err(MapperError::InvalidData("Invalid PE signature".into()));
        }

        let file_header_offset = pe_offset + 4;
        
        if file_header_offset + mem::size_of::<FileHeader>() > data.len() {
            return Err(MapperError::InvalidData("File header out of bounds".into()));
        }

        // Parse file header
        let file_header: FileHeader = unsafe {
            std::ptr::read_unaligned(data[file_header_offset..].as_ptr() as *const FileHeader)
        };

        let optional_header_offset = file_header_offset + mem::size_of::<FileHeader>();
        
        if optional_header_offset + 2 > data.len() {
            return Err(MapperError::InvalidData("Optional header magic out of bounds".into()));
        }

        // Determine PE type and parse optional header
        let magic = u16::from_le_bytes([
            data[optional_header_offset],
            data[optional_header_offset + 1],
        ]);

        let optional_header = match magic {
            PE32_MAGIC => {
                if optional_header_offset + mem::size_of::<OptionalHeader32>() > data.len() {
                    return Err(MapperError::InvalidData("PE32 optional header out of bounds".into()));
                }
                let header: OptionalHeader32 = unsafe {
                    std::ptr::read_unaligned(data[optional_header_offset..].as_ptr() as *const OptionalHeader32)
                };
                OptionalHeader::Pe32(header)
            }
            PE64_MAGIC => {
                if optional_header_offset + mem::size_of::<OptionalHeader64>() > data.len() {
                    return Err(MapperError::InvalidData("PE64 optional header out of bounds".into()));
                }
                let header: OptionalHeader64 = unsafe {
                    std::ptr::read_unaligned(data[optional_header_offset..].as_ptr() as *const OptionalHeader64)
                };
                OptionalHeader::Pe64(header)
            }
            _ => {
                return Err(MapperError::InvalidData(format!("Unknown PE magic: 0x{:X}", magic)));
            }
        };

        // Parse section headers
        let sections_offset = optional_header_offset + file_header.size_of_optional_header as usize;
        let num_sections = file_header.number_of_sections as usize;

        if num_sections > MAX_SECTIONS {
            return Err(MapperError::InvalidData("Too many sections".into()));
        }

        let sections_size = num_sections * mem::size_of::<SectionHeader>();
        
        if sections_offset + sections_size > data.len() {
            return Err(MapperError::InvalidData("Section headers out of bounds".into()));
        }

        let mut sections = Vec::with_capacity(num_sections);
        
        for i in 0..num_sections {
            let section_offset = sections_offset + i * mem::size_of::<SectionHeader>();
            let section: SectionHeader = unsafe {
                std::ptr::read_unaligned(data[section_offset..].as_ptr() as *const SectionHeader)
            };
            sections.push(section);
        }

        Ok(Self {
            data: data.to_vec(),
            dos_header,
            file_header,
            optional_header,
            sections,
        })
    }

    /// Parse PE from a reader
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self, MapperError> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        Self::parse(&data)
    }

    /// Get raw PE data
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Get DOS header
    pub fn dos_header(&self) -> &DosHeader {
        &self.dos_header
    }

    /// Get file header
    pub fn file_header(&self) -> &FileHeader {
        &self.file_header
    }

    /// Get optional header
    pub fn optional_header(&self) -> &OptionalHeader {
        &self.optional_header
    }

    /// Get section headers
    pub fn sections(&self) -> &[SectionHeader] {
        &self.sections
    }

    /// Get architecture
    pub fn architecture(&self) -> PeArchitecture {
        self.optional_header.architecture()
    }

    /// Check if PE is 64-bit
    pub fn is_64bit(&self) -> bool {
        matches!(self.optional_header, OptionalHeader::Pe64(_))
    }

    /// Get image base address
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base()
    }

    /// Get entry point RVA
    pub fn entry_point_rva(&self) -> u32 {
        self.optional_header.entry_point()
    }

    /// Get size of image when loaded
    pub fn size_of_image(&self) -> u32 {
        self.optional_header.size_of_image()
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        // Check if RVA is in headers
        if rva < self.optional_header.size_of_headers() {
            return Some(rva);
        }

        // Find containing section
        for section in &self.sections {
            if let Some(offset) = section.rva_to_offset(rva) {
                return Some(offset);
            }
        }

        None
    }

    /// Get data at RVA
    pub fn data_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let offset = self.rva_to_offset(rva)? as usize;
        
        if offset + size <= self.data.len() {
            Some(&self.data[offset..offset + size])
        } else {
            None
        }
    }

    /// Read null-terminated string at RVA
    pub fn string_at_rva(&self, rva: u32) -> Option<String> {
        let offset = self.rva_to_offset(rva)? as usize;
        
        if offset >= self.data.len() {
            return None;
        }

        let end = self.data[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| offset + pos)
            .unwrap_or(self.data.len());

        String::from_utf8(self.data[offset..end].to_vec()).ok()
    }

    /// Get section by name
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name_str() == name)
    }

    /// Get section containing RVA
    pub fn section_containing_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// Get data directory
    pub fn data_directory(&self, index: DataDirectoryIndex) -> DataDirectory {
        self.optional_header.data_directory(index)
    }

    /// Parse export directory
    pub fn parse_exports(&self) -> Result<Vec<ExportInfo>, MapperError> {
        let export_dir = self.data_directory(DataDirectoryIndex::Export);
        
        if !export_dir.is_present() {
            return Ok(Vec::new());
        }

        let export_data = self.data_at_rva(export_dir.virtual_address, mem::size_of::<ExportDirectory>())
            .ok_or_else(|| MapperError::InvalidData("Export directory out of bounds".into()))?;

        let export_table: ExportDirectory = unsafe {
            std::ptr::read_unaligned(export_data.as_ptr() as *const ExportDirectory)
        };

        let mut exports = Vec::new();
        let num_functions = export_table.number_of_functions as usize;
        let num_names = export_table.number_of_names as usize;

        // Read function addresses
        let functions_data = self.data_at_rva(export_table.address_of_functions, num_functions * 4)
            .ok_or_else(|| MapperError::InvalidData("Export functions array out of bounds".into()))?;

        // Read name pointers
        let names_data = self.data_at_rva(export_table.address_of_names, num_names * 4)
            .ok_or_else(|| MapperError::InvalidData("Export names array out of bounds".into()))?;

        // Read ordinals
        let ordinals_data = self.data_at_rva(export_table.address_of_name_ordinals, num_names * 2)
            .ok_or_else(|| MapperError::InvalidData("Export ordinals array out of bounds".into()))?;

        // Build name-to-ordinal mapping
        let mut name_map: HashMap<u16, String> = HashMap::new();
        
        for i in 0..num_names {
            let name_rva = u32::from_le_bytes([
                names_data[i * 4],
                names_data[i * 4 + 1],
                names_data[i * 4 + 2],
                names_data[i * 4 + 3],
            ]);

            let ordinal_index = u16::from_le_bytes([
                ordinals_data[i * 2],
                ordinals_data[i * 2 + 1],
            ]);

            if let Some(name) = self.string_at_rva(name_rva) {
                name_map.insert(ordinal_index, name);
            }
        }

        // Process all exports
        for i in 0..num_functions {
            let func_rva = u32::from_le_bytes([
                functions_data[i * 4],
                functions_data[i * 4 + 1],
                functions_data[i * 4 + 2],
                functions_data[i * 4 + 3],
            ]);

            if func_rva == 0 {
                continue;
            }

            let ordinal = (export_table.base as usize + i) as u16;
            let name = name_map.get(&(i as u16)).cloned().unwrap_or_default();

            // Check for forwarded export
            let forwarded_to = if func_rva >= export_dir.virtual_address 
                && func_rva < export_dir.virtual_address + export_dir.size 
            {
                self.string_at_rva(func_rva)
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

    /// Parse import directory
    pub fn parse_imports(&self) -> Result<Vec<ImportInfo>, MapperError> {
        let import_dir = self.data_directory(DataDirectoryIndex::Import);
        
        if !import_dir.is_present() {
            return Ok(Vec::new());
        }

        let mut imports = Vec::new();
        let mut offset = 0;

        loop {
            let desc_rva = import_dir.virtual_address + offset;
            let desc_data = self.data_at_rva(desc_rva, mem::size_of::<ImportDescriptor>())
                .ok_or_else(|| MapperError::InvalidData("Import descriptor out of bounds".into()))?;

            let descriptor: ImportDescriptor = unsafe {
                std::ptr::read_unaligned(desc_data.as_ptr() as *const ImportDescriptor)
            };

            if descriptor.is_null() {
                break;
            }

            let dll_name = self.string_at_rva(descriptor.name)
                .ok_or_else(|| MapperError::InvalidData("Import DLL name out of bounds".into()))?;

            let functions = self.parse_import_thunks(&descriptor)?;

            imports.push(ImportInfo {
                dll_name,
                functions,
            });

            offset += mem::size_of::<ImportDescriptor>() as u32;
        }

        Ok(imports)
    }

    fn parse_import_thunks(&self, descriptor: &ImportDescriptor) -> Result<Vec<ImportFunction>, MapperError> {
        let mut functions = Vec::new();
        let thunk_rva = if descriptor.original_first_thunk != 0 {
            descriptor.original_first_thunk
        } else {
            descriptor.first_thunk
        };

        let is_64bit = self.is_64bit();
        let thunk_size = if is_64bit { 8 } else { 4 };
        let ordinal_flag: u64 = if is_