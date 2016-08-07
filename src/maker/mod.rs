//! PE (Portable Executable) parsing implementation for Windows binaries.
//! 
//! This module provides functionality to parse PE files, extract headers,
//! sections, imports, exports, and relocations needed for manual mapping.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::mem;

use crate::error::MapperError;

/// DOS header magic number ("MZ")
const DOS_MAGIC: u16 = 0x5A4D;

/// PE signature ("PE\0\0")
const PE_SIGNATURE: u32 = 0x00004550;

/// PE32 magic number
const PE32_MAGIC: u16 = 0x10B;

/// PE32+ magic number
const PE32_PLUS_MAGIC: u16 = 0x20B;

/// Maximum number of sections allowed
const MAX_SECTIONS: usize = 96;

/// Image directory entry indices
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryEntry {
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
}

/// Section characteristics flags
#[derive(Debug, Clone, Copy)]
pub struct SectionFlags(pub u32);

impl SectionFlags {
    pub const CODE: u32 = 0x00000020;
    pub const INITIALIZED_DATA: u32 = 0x00000040;
    pub const UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const DISCARDABLE: u32 = 0x02000000;
    pub const NOT_CACHED: u32 = 0x04000000;
    pub const NOT_PAGED: u32 = 0x08000000;
    pub const SHARED: u32 = 0x10000000;
    pub const EXECUTE: u32 = 0x20000000;
    pub const READ: u32 = 0x40000000;
    pub const WRITE: u32 = 0x80000000;

    pub fn contains(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub fn is_executable(&self) -> bool {
        self.contains(Self::EXECUTE)
    }

    pub fn is_readable(&self) -> bool {
        self.contains(Self::READ)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(Self::WRITE)
    }
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

/// Optional header for PE32
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

/// Optional header for PE32+
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

/// Section header
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

    /// Get section flags
    pub fn flags(&self) -> SectionFlags {
        SectionFlags(self.characteristics)
    }
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

/// Base relocation block
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

/// Relocation types
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
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry {
    pub rva: u32,
    pub reloc_type: RelocationType,
}

/// Import entry
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub thunk_rva: u32,
}

/// Import module with its functions
#[derive(Debug, Clone)]
pub struct ImportModule {
    pub name: String,
    pub entries: Vec<ImportEntry>,
}

/// Export entry
#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: u16,
    pub rva: u32,
    pub forwarded_to: Option<String>,
}

/// PE architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArchitecture {
    X86,
    X64,
}

/// Parsed PE image
#[derive(Debug)]
pub struct PeImage {
    raw_data: Vec<u8>,
    architecture: PeArchitecture,
    dos_header: DosHeader,
    file_header: FileHeader,
    image_base: u64,
    entry_point: u32,
    size_of_image: u32,
    size_of_headers: u32,
    section_alignment: u32,
    file_alignment: u32,
    data_directories: Vec<DataDirectory>,
    sections: Vec<SectionHeader>,
}

impl PeImage {
    /// Parse PE from raw bytes
    pub fn parse(data: Vec<u8>) -> Result<Self, MapperError> {
        if data.len() < mem::size_of::<DosHeader>() {
            return Err(MapperError::InvalidPe("File too small for DOS header".into()));
        }

        // Parse DOS header
        let dos_header: DosHeader = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const DosHeader)
        };

        if dos_header.e_magic != DOS_MAGIC {
            return Err(MapperError::InvalidPe("Invalid DOS magic".into()));
        }

        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > data.len() {
            return Err(MapperError::InvalidPe("Invalid PE offset".into()));
        }

        // Verify PE signature
        let pe_sig: u32 = unsafe {
            std::ptr::read_unaligned(data.as_ptr().add(pe_offset) as *const u32)
        };

        if pe_sig != PE_SIGNATURE {
            return Err(MapperError::InvalidPe("Invalid PE signature".into()));
        }

        // Parse file header
        let file_header_offset = pe_offset + 4;
        if file_header_offset + mem::size_of::<FileHeader>() > data.len() {
            return Err(MapperError::InvalidPe("File too small for file header".into()));
        }

        let file_header: FileHeader = unsafe {
            std::ptr::read_unaligned(data.as_ptr().add(file_header_offset) as *const FileHeader)
        };

        // Parse optional header
        let optional_header_offset = file_header_offset + mem::size_of::<FileHeader>();
        if optional_header_offset + 2 > data.len() {
            return Err(MapperError::InvalidPe("File too small for optional header".into()));
        }

        let magic: u16 = unsafe {
            std::ptr::read_unaligned(data.as_ptr().add(optional_header_offset) as *const u16)
        };

        let (architecture, image_base, entry_point, size_of_image, size_of_headers,
             section_alignment, file_alignment, num_data_dirs, data_dir_offset) = match magic {
            PE32_MAGIC => {
                if optional_header_offset + mem::size_of::<OptionalHeader32>() > data.len() {
                    return Err(MapperError::InvalidPe("File too small for PE32 optional header".into()));
                }
                let opt: OptionalHeader32 = unsafe {
                    std::ptr::read_unaligned(data.as_ptr().add(optional_header_offset) as *const OptionalHeader32)
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
            PE32_PLUS_MAGIC => {
                if optional_header_offset + mem::size_of::<OptionalHeader64>() > data.len() {
                    return Err(MapperError::InvalidPe("File too small for PE32+ optional header".into()));
                }
                let opt: OptionalHeader64 = unsafe {
                    std::ptr::read_unaligned(data.as_ptr().add(optional_header_offset) as *const OptionalHeader64)
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
        let mut data_directories = Vec::with_capacity(num_data_dirs.min(16));
        for i in 0..num_data_dirs.min(16) {
            let dir_offset = data_dir_offset + i * mem::size_of::<DataDirectory>();
            if dir_offset + mem::size_of::<DataDirectory>() > data.len() {
                break;
            }
            let dir: DataDirectory = unsafe {
                std::ptr::read_unaligned(data.as_ptr().add(dir_offset) as *const DataDirectory)
            };
            data_directories.push(dir);
        }

        // Parse section headers
        let sections_offset = optional_header_offset + file_header.size_of_optional_header as usize;
        let num_sections = (file_header.number_of_sections as usize).min(MAX_SECTIONS);
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let section_offset = sections_offset + i * mem::size_of::<SectionHeader>();
            if section_offset + mem::size_of::<SectionHeader>() > data.len() {
                return Err(MapperError::InvalidPe("File too small for section headers".into()));
            }
            let section: SectionHeader = unsafe {
                std::ptr::read_unaligned(data.as_ptr().add(section_offset) as *const SectionHeader)
            };
            sections.push(section);
        }

        Ok(Self {
            raw_data: data,
            architecture,
            dos_header,
            file_header,
            image_base,
            entry_point,
            size_of_image,
            size_of_headers,
            section_alignment,
            file_alignment,
            data_directories,
            sections,
        })
    }

    /// Parse PE from a reader
    pub fn from_reader<R: Read + Seek>(mut reader: R) -> Result<Self, MapperError> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        Self::parse(data)
    }

    /// Get the PE architecture
    pub fn architecture(&self) -> PeArchitecture {
        self.architecture
    }

    /// Check if this is a 64-bit PE
    pub fn is_64bit(&self) -> bool {
        self.architecture == PeArchitecture::X64
    }

    /// Get the preferred image base
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get the entry point RVA
    pub fn entry_point(&self) -> u32 {
        self.entry_point
    }

    /// Get the size of the image when loaded
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// Get the size of headers
    pub fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }

    /// Get section alignment
    pub fn section_alignment(&self) -> u32 {
        self.section_alignment
    }

    /// Get file alignment
    pub fn file_alignment(&self) -> u32 {
        self.file_alignment
    }

    /// Get all sections
    pub fn sections(&self) -> &[SectionHeader] {
        &self.sections
    }

    /// Get raw PE data
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    /// Get a data directory entry
    pub fn data_directory(&self, entry: DirectoryEntry) -> Option<&DataDirectory> {
        self.data_directories.get(entry as usize)
            .filter(|d| d.virtual_address != 0 && d.size != 0)
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        // Check if RVA is in headers
        if rva < self.size_of_headers {
            return Some(rva as usize);
        }

        // Find containing section
        for section in &self.sections {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size.max(section.size_of_raw_data);
            
            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                if offset_in_section < section.size_of_raw_data {
                    return Some((section.pointer_to_raw_data + offset_in_section) as usize);
                }
            }
        }
        None
    }

    /// Read a null-terminated string at an RVA
    pub fn read_string_at_rva(&self, rva: u32) -> Option<String> {
        let offset = self.rva_to_offset(rva)?;
        let mut result = Vec::new();
        
        for &byte in self.raw_data.get(offset..)? {
            if byte == 0 {
                break;
            }
            result.push(byte);
        }
        
        String::from_utf8(result).ok()
    }

    /// Parse import table
    pub fn parse_imports(&self) -> Result<Vec<ImportModule>, MapperError> {
        let import_dir = match self.data_directory(DirectoryEntry::Import) {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        let mut modules = Vec::new();
        let mut descriptor_rva = import_dir.virtual_address;

        loop {
            let offset = self.rva_to_offset(descriptor_rva)
                .ok_or_else(|| MapperError::InvalidPe("Invalid import descriptor RVA".into()))?;

            if offset + mem::size_of::<ImportDescriptor>() > self.raw_data.len() {
                break;
            }

            let descriptor: ImportDescriptor = unsafe {
                std::ptr::read_unaligned(self.raw_data.as_ptr().add(offset) as *const ImportDescriptor)
            };

            // Check for terminating null descriptor
            if descriptor.name == 0 {
                break;
            }

            let module_name = self.read_string_at_rva(descriptor.name)
                .ok_or_else(|| MapperError::InvalidPe("Invalid import module name".into()))?;

            let entries = self.parse_import_entries(&descriptor)?;

            modules.push(ImportModule {
                name: module_name,
                entries,
            });

            descriptor_rva += mem::size_of::<ImportDescriptor>() as u32;
        }

        Ok(modules)
    }

    fn parse_import_entries(&self, descriptor: &ImportDescriptor) -> Result<Vec<ImportEntry>, MapperError> {
        let mut entries = Vec::new();
        let thunk_rva = if descriptor.original_first_thunk != 0 {
            descriptor.original_first_thunk
        } else {
            descriptor.first_thunk
        };

        let thunk_size = if self.is_64bit() { 8usize } else { 4usize };
        let ordinal_flag: u64 = if self.is_64bit() { 0x8000000000000000 } else { 0x80000000 };

        let mut current_thunk_rva = thunk_rva;
        let mut iat_rva = descriptor.first_thunk;

        loop {
            let offset = self.rva_to_offset(current_thunk_rva)
                .ok_or_else(|| MapperError::InvalidPe("Invalid thunk RVA".into()))?;

            if offset + thunk_size > self.raw_data.len() {
                break;
            }

            let thunk_value: u64 = if self.is_64bit() {
                unsafe { std::ptr::read_unaligned(self.raw_data.as_ptr().add(offset) as *const u64) }
            } else {
                unsafe { std::ptr::read_unaligned(self.raw_data.as_ptr().add(offset) as *const u32) as u64 }
            };

            if thunk_value == 0 {
                break;
            }

            let entry = if thunk_value & ordinal_flag != 0 {
                ImportEntry {
                    name: None,
                    ordinal: Some((thunk_value & 0xFFFF) as u16),
                    thunk_rva: iat_rva,
                }
            } else {
                let hint_name_rva = thunk_value as u32;
                let name = self.read_string_at_rva(hint_name_rva + 2);
                ImportEntry {
                    name,
                    ordinal: None,
                    thunk_rva: iat_rva,
                }
            };

            entries.push(entry);
            current_thunk_rva += thunk_size as u32;
            iat_rva += thunk_size as u32;
        }

        Ok(entries)
    }

    /// Parse relocation table
    pub fn parse_relocations(&self) -> Result<Vec<RelocationEntry>, MapperError> {
        let reloc_dir = match self.data_directory(DirectoryEntry::BaseReloc) {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        let mut relocations = Vec::new();
        let mut current_rva = reloc_dir.virtual_address;
        let end_rva = current_rva + reloc_dir.size;

        while current_rva < end_rva {
            let offset = self.rva_to_offset(current_rva)
                .ok_or_else(|| MapperError::InvalidPe("Invalid relocation block RVA".into()))?;

            if offset + mem::size_of::<BaseRelocation>() > self.raw_data.len() {
                break;
            }

            let block: BaseRelocation = unsafe {
                std::ptr::read_unaligned(self.raw_data.as_ptr().add(offset) as *const BaseRelocation)
            };

            if block.size_of_block == 0 {
                break;
            }

            let num_entries = (block.size_of_block as usize - mem::size_of::<BaseRelocation>()) / 2;
            let entries_offset = offset + mem::size_of::<BaseRelocation>();

            for i in 0..num_entries {
                let entry_offset = entries_offset + i * 2;
                if entry_offset + 2 > self.raw_data.len() {
                    break;
                }

                let entry: u16 = unsafe {
                    std::ptr::read_unaligned(self.raw_data.as_ptr().add(entry_offset) as *const u16)
                };

                let reloc_type = RelocationType::from((entry >> 12) as u8);
                let reloc_offset = entry & 0x0FFF;

                if reloc_type != RelocationType::Absolute {
                    relocations.push(RelocationEntry {
                        rva: block.virtual_address + reloc_offset as u32,
                        reloc_type,
                    });
                }
            }

            current_rva += block.size_of_block;
        }

        Ok(relocations)
    }

    /// Get section data by name
    pub fn section_data(&self, name: &str) -> Option<&[u8]> {
        self.sections.iter()
            .find(|s| s.name_str() == name)
            .and_then(|s| {
                let start = s.pointer_to_raw_data as usize;
                let end = start + s.size_of_raw_data as usize;
                self.raw_data.get(start..end)
            })
    }

    /// Find section containing an RVA
    pub fn section_from_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| {
            let start = s.virtual_address;
            let end = start + s.virtual_size.max(s.size_of_raw_data);
            rva >= start && rva < end
        })
    }
}

/// Builder for creating PE images programmatically
pub struct PeBuilder {
    architecture: PeArchitecture,
    image_base: u64,
    entry_point: u32,
    sections: Vec<(String, Vec<u8>, SectionFlags)>,
}

impl PeBuilder {
    pub fn new(architecture: PeArchitecture) -> Self {
        Self {
            architecture,
            image_base: if architecture == PeArchitecture::X64 { 0x140000000 } else { 0x10000000 },
            entry_point: 0,
            sections: Vec::new(),
        }
    }

    pub fn image_base(mut self, base: u64) -> Self {
        self.image_base = base;
        self
    }

    pub fn entry_point(mut self, rva: u32) -> Self {
        self.entry_point = rva;
        self
    }

    pub fn add_section(mut self, name: &str, data: Vec<u8>, flags: SectionFlags) -> Self {
        self.sections.push((name.to_string(), data, flags));
        self
    }

    /// Build the PE image (TODO: implement full PE generation)
    pub fn build(self) -> Result<Vec<u8>, MapperError> {
        // TODO: Implement full PE generation
        Err(MapperError::NotImplemented("PE building not yet implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_flags() {
        let flags = SectionFlags(SectionFlags::READ | SectionFlags::EXECUTE);
        assert!(flags.is_readable());
        assert!(flags.is_executable());
        assert!(!flags.is_writable());
    }

    #[test]
    fn test_relocation_type_conversion() {
        assert_eq!(RelocationType::from(0), RelocationType::Absolute);
        assert_eq!(RelocationType::from(3), RelocationType::HighLow);
        assert_eq!(RelocationType::from(10), RelocationType::Dir64);
        assert!(matches!(RelocationType::from(99), RelocationType::Unknown(99)));
    }
}