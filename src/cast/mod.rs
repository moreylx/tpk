//! PE (Portable Executable) parsing module for Windows executables
//!
//! This module provides safe abstractions for parsing PE files,
//! including headers, sections, imports, and exports.

use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::slice;

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
    pub data_directory: [DataDirectory; 16],
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
    pub data_directory: [DataDirectory; 16],
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
    /// Get the section name as a string
    pub fn name_str(&self) -> &str {
        let name_bytes = &self.name;
        let len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&name_bytes[..len]).unwrap_or("")
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
}

/// Import directory entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

/// Export directory
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
            _ => Err(MapperError::InvalidData(format!(
                "Unknown relocation type: {}",
                value
            ))),
        }
    }
}

/// PE architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArchitecture {
    X86,
    X64,
}

/// Parsed PE image representation
pub struct PeImage {
    data: Vec<u8>,
    architecture: PeArchitecture,
    dos_header_offset: usize,
    nt_headers_offset: usize,
    file_header_offset: usize,
    optional_header_offset: usize,
    sections_offset: usize,
    number_of_sections: u16,
}

impl PeImage {
    /// Parse a PE image from raw bytes
    pub fn parse(data: Vec<u8>) -> Result<Self, MapperError> {
        if data.len() < mem::size_of::<DosHeader>() {
            return Err(MapperError::InvalidData(
                "Data too small for DOS header".into(),
            ));
        }

        // Validate DOS header
        let dos_header = unsafe { &*(data.as_ptr() as *const DosHeader) };
        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(MapperError::InvalidData("Invalid DOS signature".into()));
        }

        let nt_headers_offset = dos_header.e_lfanew as usize;
        if nt_headers_offset + 4 > data.len() {
            return Err(MapperError::InvalidData(
                "Invalid PE header offset".into(),
            ));
        }

        // Validate PE signature
        let pe_signature = unsafe { *(data.as_ptr().add(nt_headers_offset) as *const u32) };
        if pe_signature != PE_SIGNATURE {
            return Err(MapperError::InvalidData("Invalid PE signature".into()));
        }

        let file_header_offset = nt_headers_offset + 4;
        if file_header_offset + mem::size_of::<FileHeader>() > data.len() {
            return Err(MapperError::InvalidData(
                "Data too small for file header".into(),
            ));
        }

        let file_header = unsafe { &*(data.as_ptr().add(file_header_offset) as *const FileHeader) };
        let optional_header_offset = file_header_offset + mem::size_of::<FileHeader>();

        // Determine architecture from optional header magic
        if optional_header_offset + 2 > data.len() {
            return Err(MapperError::InvalidData(
                "Data too small for optional header".into(),
            ));
        }

        let magic = unsafe { *(data.as_ptr().add(optional_header_offset) as *const u16) };
        let architecture = match magic {
            PE32_MAGIC => PeArchitecture::X86,
            PE64_MAGIC => PeArchitecture::X64,
            _ => {
                return Err(MapperError::InvalidData(format!(
                    "Unknown PE magic: 0x{:04X}",
                    magic
                )))
            }
        };

        let optional_header_size = file_header.size_of_optional_header as usize;
        let sections_offset = optional_header_offset + optional_header_size;

        if sections_offset > data.len() {
            return Err(MapperError::InvalidData(
                "Invalid sections offset".into(),
            ));
        }

        Ok(Self {
            data,
            architecture,
            dos_header_offset: 0,
            nt_headers_offset,
            file_header_offset,
            optional_header_offset,
            sections_offset,
            number_of_sections: file_header.number_of_sections,
        })
    }

    /// Parse a PE image from a reader
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self, MapperError> {
        let mut data = Vec::new();
        reader
            .read_to_end(&mut data)
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

    /// Get the DOS header
    pub fn dos_header(&self) -> &DosHeader {
        unsafe { &*(self.data.as_ptr().add(self.dos_header_offset) as *const DosHeader) }
    }

    /// Get the file header
    pub fn file_header(&self) -> &FileHeader {
        unsafe { &*(self.data.as_ptr().add(self.file_header_offset) as *const FileHeader) }
    }

    /// Get the optional header for PE32
    pub fn optional_header_32(&self) -> Option<&OptionalHeader32> {
        if self.architecture == PeArchitecture::X86 {
            Some(unsafe {
                &*(self.data.as_ptr().add(self.optional_header_offset) as *const OptionalHeader32)
            })
        } else {
            None
        }
    }

    /// Get the optional header for PE64
    pub fn optional_header_64(&self) -> Option<&OptionalHeader64> {
        if self.architecture == PeArchitecture::X64 {
            Some(unsafe {
                &*(self.data.as_ptr().add(self.optional_header_offset) as *const OptionalHeader64)
            })
        } else {
            None
        }
    }

    /// Get the image base address
    pub fn image_base(&self) -> u64 {
        match self.architecture {
            PeArchitecture::X86 => self.optional_header_32().unwrap().image_base as u64,
            PeArchitecture::X64 => self.optional_header_64().unwrap().image_base,
        }
    }

    /// Get the entry point RVA
    pub fn entry_point_rva(&self) -> u32 {
        match self.architecture {
            PeArchitecture::X86 => self.optional_header_32().unwrap().address_of_entry_point,
            PeArchitecture::X64 => self.optional_header_64().unwrap().address_of_entry_point,
        }
    }

    /// Get the size of the image when loaded
    pub fn size_of_image(&self) -> u32 {
        match self.architecture {
            PeArchitecture::X86 => self.optional_header_32().unwrap().size_of_image,
            PeArchitecture::X64 => self.optional_header_64().unwrap().size_of_image,
        }
    }

    /// Get the section alignment
    pub fn section_alignment(&self) -> u32 {
        match self.architecture {
            PeArchitecture::X86 => self.optional_header_32().unwrap().section_alignment,
            PeArchitecture::X64 => self.optional_header_64().unwrap().section_alignment,
        }
    }

    /// Get the file alignment
    pub fn file_alignment(&self) -> u32 {
        match self.architecture {
            PeArchitecture::X86 => self.optional_header_32().unwrap().file_alignment,
            PeArchitecture::X64 => self.optional_header_64().unwrap().file_alignment,
        }
    }

    /// Get a data directory entry
    pub fn data_directory(&self, index: DataDirectoryIndex) -> DataDirectory {
        let idx = index as usize;
        match self.architecture {
            PeArchitecture::X86 => {
                let opt = self.optional_header_32().unwrap();
                if idx < opt.number_of_rva_and_sizes as usize {
                    opt.data_directory[idx]
                } else {
                    DataDirectory::default()
                }
            }
            PeArchitecture::X64 => {
                let opt = self.optional_header_64().unwrap();
                if idx < opt.number_of_rva_and_sizes as usize {
                    opt.data_directory[idx]
                } else {
                    DataDirectory::default()
                }
            }
        }
    }

    /// Get all section headers
    pub fn sections(&self) -> &[SectionHeader] {
        let count = self.number_of_sections as usize;
        unsafe {
            slice::from_raw_parts(
                self.data.as_ptr().add(self.sections_offset) as *const SectionHeader,
                count,
            )
        }
    }

    /// Find a section by name
    pub fn find_section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections().iter().find(|s| s.name_str() == name)
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in self.sections() {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some((section.pointer_to_raw_data + offset_in_section) as usize);
            }
        }
        None
    }

    /// Get raw data at an RVA
    pub fn data_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let offset = self.rva_to_offset(rva)?;
        if offset + size <= self.data.len() {
            Some(&self.data[offset..offset + size])
        } else {
            None
        }
    }

    /// Read a null-terminated string at an RVA
    pub fn string_at_rva(&self, rva: u32) -> Option<&str> {
        let offset = self.rva_to_offset(rva)?;
        let remaining = &self.data[offset..];
        let len = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&remaining[..len]).ok()
    }

    /// Get the raw PE data
    pub fn raw_data(&self) -> &[u8] {
        &self.data
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
}

/// Iterator over import descriptors
pub struct ImportIterator<'a> {
    pe: &'a PeImage,
    current_rva: u32,
    end_rva: u32,
}

impl<'a> ImportIterator<'a> {
    /// Create a new import iterator
    pub fn new(pe: &'a PeImage) -> Self {
        let import_dir = pe.data_directory(DataDirectoryIndex::Import);
        Self {
            pe,
            current_rva: import_dir.virtual_address,
            end_rva: import_dir.virtual_address + import_dir.size,
        }
    }
}

impl<'a> Iterator for ImportIterator<'a> {
    type Item = ImportEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_rva >= self.end_rva {
            return None;
        }

        let desc_size = mem::size_of::<ImportDescriptor>() as u32;
        let data = self.pe.data_at_rva(self.current_rva, desc_size as usize)?;
        let descriptor = unsafe { &*(data.as_ptr() as *const ImportDescriptor) };

        // Check for null terminator
        if descriptor.name == 0 {
            return None;
        }

        self.current_rva += desc_size;

        let dll_name = self.pe.string_at_rva(descriptor.name)?;

        Some(ImportEntry {
            pe: self.pe,
            descriptor: *descriptor,
            dll_name,
        })
    }
}

/// A single import entry (DLL)
pub struct ImportEntry<'a> {
    pe: &'a PeImage,
    descriptor: ImportDescriptor,
    dll_name: &'a str,
}

impl<'a> ImportEntry<'a> {
    /// Get the DLL name
    pub fn dll_name(&self) -> &str {
        self.dll_name
    }

    /// Get the import descriptor
    pub fn descriptor(&self) -> &ImportDescriptor {
        &self.descriptor
    }

    // TODO: Add iterator over imported functions
}

/// Iterator over exports
pub struct ExportIterator<'a> {
    pe: &'a PeImage,
    export_dir: Option<ExportDirectory>,
    current_index: u32,
}

impl<'a> ExportIterator<'a> {
    /// Create a new export iterator
    pub fn new(pe: &'a PeImage) -> Self {
        let export_data = pe.data_directory(DataDirectoryIndex::Export);
        let export_dir = if export_data.virtual_address != 0 {
            pe.data_at_rva(export_data.virtual_address, mem::size_of::<ExportDirectory>())
                .map(|data| unsafe { *(data.as_ptr() as *const ExportDirectory) })
        } else {
            None
        };

        Self {
            pe,
            export_dir,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for ExportIterator<'a> {
    type Item = ExportEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let export_dir = self.export_dir.as_ref()?;

        if self.current_index >= export_dir.number_of_functions {
            return None;
        }

        let func_rva_offset = export_dir.address_of_functions + self.current_index * 4;
        let func_rva_data = self.pe.data_at_rva(func_rva_offset, 4)?;
        let func_rva = unsafe { *(func_rva_data.as_ptr() as *const u32) };

        let ordinal = export_dir.base + self.current_index;

        // Try to find the name for this export
        let name = self.find_name_for_ordinal(self.current_index as u16);

        self.current_index += 1;

        Some(ExportEntry {
            rva: func_rva,
            ordinal: ordinal as u16,
            name,
        })
    }
}

impl<'a> ExportIterator<'a> {
    fn find_name_for_ordinal(&self, ordinal_index: u16) -> Option<&'a str> {
        let export_dir = self.export_dir.as_ref()?;

        for i in 0..export_dir.number_of_names {
            let name_ordinal_offset = export_dir.address_of_name_ordinals + i * 2;
            let name_ordinal_data = self.pe.data_at_rva(name_ordinal_offset, 2)?;
            let name_ordinal = unsafe { *(name_ordinal_data.as_ptr() as *const u16) };

            if name_ordinal == ordinal_index {
                let name_rva_offset = export_dir.address_of_names + i * 4;
                let name_rva_data = self.pe.data_at_rva(name_rva_offset, 4)?;
                let name_rva = unsafe { *(name_rva_data.as_ptr() as *const u32) };
                return self.pe.string_at_rva(name_rva);
            }
        }

        None
    }
}

/// A single export entry
#[derive(Debug)]
pub struct ExportEntry<'a> {
    pub rva: u32,
    pub ordinal: u16,
    pub name: Option<&'a str>,
}

/// Iterator over base relocations
pub struct RelocationIterator<'a> {
    pe: &'a PeImage,
    current_offset: usize,
    end_offset: usize,
}

impl<'a> RelocationIterator<'a> {
    /// Create a new relocation iterator
    pub fn new(pe: &'a PeImage) -> Self {
        let reloc_dir = pe.data_directory(DataDirectoryIndex::BaseReloc);
        let start_offset = pe.rva_to_offset(reloc_dir.virtual_address).unwrap_or(0);
        let end_offset = start_offset + reloc_dir.size as usize;

        Self {
            pe,
            current_offset: start_offset,
            end_offset,
        }
    }
}

impl<'a> Iterator for RelocationIterator<'a> {
    type Item = RelocationBlock<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset >= self.end_offset {
            return None;
        }

        let header_size = mem::size_of::<BaseRelocation>();
        if self.current_offset + header_size > self.pe.data.len() {
            return None;
        }

        let header = unsafe {
            &*(self.pe.data.as_ptr().add(self.current_offset) as *const BaseRelocation)
        };

        if header.size_of_block == 0 {
            return None;
        }

        let entries_offset = self.current_offset + header_size;
        let entries_size = header.size_of_block as usize - header_size;
        let entry_count = entries_size / 2;

        let block = RelocationBlock {
            virtual_address: header.virtual_address,
            entries: unsafe {
                slice::from_raw_parts(
                    self.pe.data.as_ptr().add(entries_offset) as *const u16,
                    entry_count,
                )
            },
        };

        self.current_offset += header.size_of_block as usize;

        Some(block)
    }
}

/// A relocation block
pub struct RelocationBlock<'a> {
    pub virtual_address: u32,
    pub entries: &'a [u16],
}

impl<'a> RelocationBlock<'a> {
    /// Iterate over relocation entries in this block
    pub fn iter(&self) -> impl Iterator<Item = (u32, RelocationType)> + '_ {
        self.entries.iter().filter_map(move |&entry| {
            let reloc_type = (entry >> 12) as u16;
            let offset = (entry & 0x0FFF) as u32;

            if reloc_type == 0 {
                return None; // Padding entry
            }

            let rva = self.virtual_address + offset;
            RelocationType::try_from(reloc_type)
                .ok()
                .map(|t| (rva, t))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_signature() {
        assert_eq!(DOS_SIGNATURE, 0x5A4D);
    }

    #[test]
    fn test_pe_signature() {
        assert_eq!(PE_SIGNATURE, 0x00004550);
    }

    #[test]
    fn test_section_header_name() {
        let mut header = SectionHeader {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };

        header.name[0] = b'.';
        header.name[1] = b't';
        header.name[2] = b'e';
        header.name[3] = b'x';
        header.name[4] = b't';

        assert_eq!(header.name_str(), ".text");
    }

    #[test]
    fn test_relocation_type_conversion() {
        assert_eq!(
            RelocationType::try_from(0).unwrap(),
            RelocationType::Absolute
        );
        assert_eq!(
            RelocationType::try_from(3).unwrap(),
            RelocationType::HighLow
        );
        assert_eq!(RelocationType::try_from(10).unwrap(), RelocationType::Dir64);
        assert!(RelocationType::try_from(99).is_err());
    }
}