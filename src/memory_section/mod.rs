//! Memory section management and PE parsing implementation
//!
//! This module provides functionality for:
//! - Memory section creation and manipulation
//! - PE (Portable Executable) file parsing
//! - Section mapping operations for process injection

use std::ffi::c_void;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::slice;

use crate::error::{MapperError, NtStatus};

/// DOS header magic number "MZ"
const DOS_SIGNATURE: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// PE32+ magic number
const PE32_PLUS_MAGIC: u16 = 0x20B;

/// PE32 magic number
const PE32_MAGIC: u16 = 0x10B;

/// Section characteristic flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionCharacteristics {
    ContainsCode = 0x00000020,
    ContainsInitializedData = 0x00000040,
    ContainsUninitializedData = 0x00000080,
    MemoryDiscardable = 0x02000000,
    MemoryNotCached = 0x04000000,
    MemoryNotPaged = 0x08000000,
    MemoryShared = 0x10000000,
    MemoryExecute = 0x20000000,
    MemoryRead = 0x40000000,
    MemoryWrite = 0x80000000,
}

/// Memory protection constants
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// File header structure
#[repr(C)]
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
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Optional header for PE32+
#[repr(C)]
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

/// Optional header for PE32
#[repr(C)]
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

/// Section header structure
#[repr(C)]
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
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        std::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    /// Check if section is executable
    pub fn is_executable(&self) -> bool {
        self.characteristics & SectionCharacteristics::MemoryExecute as u32 != 0
    }

    /// Check if section is writable
    pub fn is_writable(&self) -> bool {
        self.characteristics & SectionCharacteristics::MemoryWrite as u32 != 0
    }

    /// Check if section is readable
    pub fn is_readable(&self) -> bool {
        self.characteristics & SectionCharacteristics::MemoryRead as u32 != 0
    }

    /// Convert section characteristics to memory protection
    pub fn to_protection(&self) -> MemoryProtection {
        let exec = self.is_executable();
        let write = self.is_writable();
        let read = self.is_readable();

        match (exec, write, read) {
            (true, true, _) => MemoryProtection::ExecuteReadWrite,
            (true, false, true) => MemoryProtection::ExecuteRead,
            (true, false, false) => MemoryProtection::Execute,
            (false, true, _) => MemoryProtection::ReadWrite,
            (false, false, true) => MemoryProtection::ReadOnly,
            (false, false, false) => MemoryProtection::NoAccess,
        }
    }
}

/// Export directory structure
#[repr(C)]
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

/// Import descriptor structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

/// Base relocation block
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

/// PE architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArchitecture {
    X86,
    X64,
}

/// Parsed PE information
#[derive(Debug)]
pub struct ParsedPe<'a> {
    raw_data: &'a [u8],
    dos_header: &'a DosHeader,
    file_header: &'a FileHeader,
    architecture: PeArchitecture,
    image_base: u64,
    entry_point_rva: u32,
    size_of_image: u32,
    size_of_headers: u32,
    section_alignment: u32,
    file_alignment: u32,
    data_directories: Vec<DataDirectory>,
    sections: Vec<&'a SectionHeader>,
}

impl<'a> ParsedPe<'a> {
    /// Parse PE from raw bytes
    pub fn parse(data: &'a [u8]) -> Result<Self, MapperError> {
        if data.len() < mem::size_of::<DosHeader>() {
            return Err(MapperError::InvalidParameter);
        }

        // Parse DOS header
        let dos_header = unsafe { &*(data.as_ptr() as *const DosHeader) };

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(MapperError::InvalidImage);
        }

        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > data.len() {
            return Err(MapperError::InvalidImage);
        }

        // Verify PE signature
        let pe_sig = unsafe { *(data.as_ptr().add(pe_offset) as *const u32) };
        if pe_sig != PE_SIGNATURE {
            return Err(MapperError::InvalidImage);
        }

        // Parse file header
        let file_header_offset = pe_offset + 4;
        if file_header_offset + mem::size_of::<FileHeader>() > data.len() {
            return Err(MapperError::InvalidImage);
        }

        let file_header =
            unsafe { &*(data.as_ptr().add(file_header_offset) as *const FileHeader) };

        // Parse optional header
        let optional_header_offset = file_header_offset + mem::size_of::<FileHeader>();
        if optional_header_offset + 2 > data.len() {
            return Err(MapperError::InvalidImage);
        }

        let magic = unsafe { *(data.as_ptr().add(optional_header_offset) as *const u16) };

        let (architecture, image_base, entry_point_rva, size_of_image, size_of_headers, section_alignment, file_alignment, data_directories) =
            match magic {
                PE32_PLUS_MAGIC => {
                    if optional_header_offset + mem::size_of::<OptionalHeader64>() > data.len() {
                        return Err(MapperError::InvalidImage);
                    }
                    let opt = unsafe {
                        &*(data.as_ptr().add(optional_header_offset) as *const OptionalHeader64)
                    };
                    (
                        PeArchitecture::X64,
                        opt.image_base,
                        opt.address_of_entry_point,
                        opt.size_of_image,
                        opt.size_of_headers,
                        opt.section_alignment,
                        opt.file_alignment,
                        opt.data_directory.to_vec(),
                    )
                }
                PE32_MAGIC => {
                    if optional_header_offset + mem::size_of::<OptionalHeader32>() > data.len() {
                        return Err(MapperError::InvalidImage);
                    }
                    let opt = unsafe {
                        &*(data.as_ptr().add(optional_header_offset) as *const OptionalHeader32)
                    };
                    (
                        PeArchitecture::X86,
                        opt.image_base as u64,
                        opt.address_of_entry_point,
                        opt.size_of_image,
                        opt.size_of_headers,
                        opt.section_alignment,
                        opt.file_alignment,
                        opt.data_directory.to_vec(),
                    )
                }
                _ => return Err(MapperError::InvalidImage),
            };

        // Parse section headers
        let section_headers_offset =
            optional_header_offset + file_header.size_of_optional_header as usize;
        let num_sections = file_header.number_of_sections as usize;

        if section_headers_offset + num_sections * mem::size_of::<SectionHeader>() > data.len() {
            return Err(MapperError::InvalidImage);
        }

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let section_offset = section_headers_offset + i * mem::size_of::<SectionHeader>();
            let section =
                unsafe { &*(data.as_ptr().add(section_offset) as *const SectionHeader) };
            sections.push(section);
        }

        Ok(Self {
            raw_data: data,
            dos_header,
            file_header,
            architecture,
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            section_alignment,
            file_alignment,
            data_directories,
            sections,
        })
    }

    /// Get the PE architecture
    pub fn architecture(&self) -> PeArchitecture {
        self.architecture
    }

    /// Get the preferred image base
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get the entry point RVA
    pub fn entry_point_rva(&self) -> u32 {
        self.entry_point_rva
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

    /// Get all section headers
    pub fn sections(&self) -> &[&SectionHeader] {
        &self.sections
    }

    /// Get a data directory by index
    pub fn data_directory(&self, index: usize) -> Option<&DataDirectory> {
        self.data_directories.get(index)
    }

    /// Get export directory
    pub fn export_directory(&self) -> Option<&ExportDirectory> {
        let dir = self.data_directory(0)?;
        if dir.virtual_address == 0 || dir.size == 0 {
            return None;
        }

        let offset = self.rva_to_offset(dir.virtual_address)?;
        if offset + mem::size_of::<ExportDirectory>() > self.raw_data.len() {
            return None;
        }

        Some(unsafe { &*(self.raw_data.as_ptr().add(offset) as *const ExportDirectory) })
    }

    /// Get import descriptors
    pub fn import_descriptors(&self) -> Option<Vec<&ImportDescriptor>> {
        let dir = self.data_directory(1)?;
        if dir.virtual_address == 0 || dir.size == 0 {
            return None;
        }

        let offset = self.rva_to_offset(dir.virtual_address)?;
        let mut descriptors = Vec::new();
        let mut current_offset = offset;

        loop {
            if current_offset + mem::size_of::<ImportDescriptor>() > self.raw_data.len() {
                break;
            }

            let desc = unsafe {
                &*(self.raw_data.as_ptr().add(current_offset) as *const ImportDescriptor)
            };

            // Check for null terminator
            if desc.original_first_thunk == 0 && desc.first_thunk == 0 {
                break;
            }

            descriptors.push(desc);
            current_offset += mem::size_of::<ImportDescriptor>();
        }

        Some(descriptors)
    }

    /// Get base relocations
    pub fn base_relocations(&self) -> Option<Vec<(u32, Vec<u16>)>> {
        let dir = self.data_directory(5)?;
        if dir.virtual_address == 0 || dir.size == 0 {
            return None;
        }

        let offset = self.rva_to_offset(dir.virtual_address)?;
        let mut relocations = Vec::new();
        let mut current_offset = offset;
        let end_offset = offset + dir.size as usize;

        while current_offset < end_offset {
            if current_offset + mem::size_of::<BaseRelocation>() > self.raw_data.len() {
                break;
            }

            let block =
                unsafe { &*(self.raw_data.as_ptr().add(current_offset) as *const BaseRelocation) };

            if block.size_of_block == 0 {
                break;
            }

            let entry_count =
                (block.size_of_block as usize - mem::size_of::<BaseRelocation>()) / 2;
            let entries_offset = current_offset + mem::size_of::<BaseRelocation>();

            let mut entries = Vec::with_capacity(entry_count);
            for i in 0..entry_count {
                if entries_offset + i * 2 + 2 > self.raw_data.len() {
                    break;
                }
                let entry =
                    unsafe { *(self.raw_data.as_ptr().add(entries_offset + i * 2) as *const u16) };
                entries.push(entry);
            }

            relocations.push((block.virtual_address, entries));
            current_offset += block.size_of_block as usize;
        }

        Some(relocations)
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
            let section_end = section_start + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some((section.pointer_to_raw_data + offset_in_section) as usize);
            }
        }

        None
    }

    /// Get raw section data
    pub fn section_data(&self, section: &SectionHeader) -> Option<&[u8]> {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;

        if start + size > self.raw_data.len() {
            return None;
        }

        Some(&self.raw_data[start..start + size])
    }

    /// Get string at RVA
    pub fn string_at_rva(&self, rva: u32) -> Option<&str> {
        let offset = self.rva_to_offset(rva)?;
        if offset >= self.raw_data.len() {
            return None;
        }

        let bytes = &self.raw_data[offset..];
        let end = bytes.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&bytes[..end]).ok()
    }

    /// Get the raw PE data
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }
}

/// Memory section for mapping PE images
pub struct MemorySection {
    base_address: *mut c_void,
    size: usize,
    protection: MemoryProtection,
    is_committed: bool,
}

impl MemorySection {
    /// Create a new memory section (placeholder - actual allocation requires OS calls)
    pub fn new(size: usize, protection: MemoryProtection) -> Result<Self, MapperError> {
        if size == 0 {
            return Err(MapperError::InvalidParameter);
        }

        // TODO: Implement actual memory allocation via NtAllocateVirtualMemory
        Ok(Self {
            base_address: ptr::null_mut(),
            size,
            protection,
            is_committed: false,
        })
    }

    /// Get the base address
    pub fn base_address(&self) -> *mut c_void {
        self.base_address
    }

    /// Get the section size
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the protection flags
    pub fn protection(&self) -> MemoryProtection {
        self.protection
    }

    /// Check if memory is committed
    pub fn is_committed(&self) -> bool {
        self.is_committed
    }

    /// Write data to the section at offset
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), MapperError> {
        if !self.is_committed {
            return Err(MapperError::InvalidState);
        }

        if offset + data.len() > self.size {
            return Err(MapperError::BufferTooSmall);
        }

        // TODO: Implement actual memory write
        Ok(())
    }

    /// Change protection of the section
    pub fn set_protection(&mut self, protection: MemoryProtection) -> Result<(), MapperError> {
        if !self.is_committed {
            return Err(MapperError::InvalidState);
        }

        // TODO: Implement via NtProtectVirtualMemory
        self.protection = protection;
        Ok(())
    }
}

impl Drop for MemorySection {
    fn drop(&mut self) {
        if !self.base_address.is_null() {
            // TODO: Free memory via NtFreeVirtualMemory
        }
    }
}

/// Align value up to alignment boundary
#[inline]
pub fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Align value down to alignment boundary
#[inline]
pub fn align_down(value: usize, alignment: usize) -> usize {
    value & !(alignment - 1)
}

/// Calculate required size for mapped image
pub fn calculate_mapped_size(pe: &ParsedPe) -> usize {
    let alignment = pe.section_alignment() as usize;
    let mut max_end = pe.size_of_headers() as usize;

    for section in pe.sections() {
        let section_end = section.virtual_address as usize + section.virtual_size as usize;
        if section_end > max_end {
            max_end = section_end;
        }
    }

    align_up(max_end, alignment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0, 4096), 0);
        assert_eq!(align_down(1, 4096), 0);
        assert_eq!(align_down(4096, 4096), 4096);
        assert_eq!(align_down(4097, 4096), 4096);
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

        header.name[..5].copy_from_slice(b".text");
        assert_eq!(header.name_str(), ".text");
    }

    #[test]
    fn test_section_protection() {
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
            characteristics: SectionCharacteristics::MemoryExecute as u32
                | SectionCharacteristics::MemoryRead as u32,
        };

        assert!(header.is_executable());
        assert!(header.is_readable());
        assert!(!header.is_writable());
        assert_eq!(header.to_protection(), MemoryProtection::ExecuteRead);
    }
}