//! PE Section parsing and memory operations module
//!
//! Provides functionality for parsing Portable Executable (PE) format files,
//! extracting section information, and performing memory-mapped operations.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::slice;

use crate::error::{MapperError, NtStatus};

/// DOS header magic number "MZ"
const DOS_MAGIC: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// PE32 optional header magic
const PE32_MAGIC: u16 = 0x10B;

/// PE32+ optional header magic
const PE32_PLUS_MAGIC: u16 = 0x20B;

/// Maximum number of sections allowed
const MAX_SECTIONS: usize = 96;

/// Section characteristic flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SectionCharacteristics {
    /// Section contains executable code
    ContainsCode = 0x00000020,
    /// Section contains initialized data
    ContainsInitializedData = 0x00000040,
    /// Section contains uninitialized data
    ContainsUninitializedData = 0x00000080,
    /// Section can be discarded
    MemDiscardable = 0x02000000,
    /// Section is not cacheable
    MemNotCached = 0x04000000,
    /// Section is not pageable
    MemNotPaged = 0x08000000,
    /// Section can be shared
    MemShared = 0x10000000,
    /// Section is executable
    MemExecute = 0x20000000,
    /// Section is readable
    MemRead = 0x40000000,
    /// Section is writable
    MemWrite = 0x80000000,
}

impl SectionCharacteristics {
    /// Check if a characteristics value contains this flag
    pub fn is_set(self, value: u32) -> bool {
        (value & self as u32) != 0
    }
}

/// DOS Header structure
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
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
    /// Validate the DOS header
    pub fn validate(&self) -> Result<(), MapperError> {
        if self.e_magic != DOS_MAGIC {
            return Err(MapperError::InvalidFormat("Invalid DOS magic number".into()));
        }
        if self.e_lfanew < 0 || self.e_lfanew > 0x10000000 {
            return Err(MapperError::InvalidFormat("Invalid PE header offset".into()));
        }
        Ok(())
    }
}

/// COFF File Header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
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
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Optional Header for PE32
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
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

/// Optional Header for PE32+
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
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

/// Section Header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
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
    pub fn name_str(&self) -> String {
        let name_bytes = &self.name;
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&name_bytes[..end]).into_owned()
    }

    /// Check if section has specific characteristic
    pub fn has_characteristic(&self, char: SectionCharacteristics) -> bool {
        char.is_set(self.characteristics)
    }

    /// Check if section is executable
    pub fn is_executable(&self) -> bool {
        self.has_characteristic(SectionCharacteristics::MemExecute)
    }

    /// Check if section is writable
    pub fn is_writable(&self) -> bool {
        self.has_characteristic(SectionCharacteristics::MemWrite)
    }

    /// Check if section is readable
    pub fn is_readable(&self) -> bool {
        self.has_characteristic(SectionCharacteristics::MemRead)
    }
}

/// PE Architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArchitecture {
    X86,
    X64,
}

impl fmt::Display for PeArchitecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeArchitecture::X86 => write!(f, "x86 (32-bit)"),
            PeArchitecture::X64 => write!(f, "x64 (64-bit)"),
        }
    }
}

/// Data directory indices
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
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

/// Parsed section information
#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
    pub data: Vec<u8>,
}

impl ParsedSection {
    /// Create from section header and data
    fn from_header(header: &SectionHeader, data: Vec<u8>) -> Self {
        Self {
            name: header.name_str(),
            virtual_address: header.virtual_address,
            virtual_size: header.virtual_size,
            raw_data_offset: header.pointer_to_raw_data,
            raw_data_size: header.size_of_raw_data,
            characteristics: header.characteristics,
            data,
        }
    }

    /// Get memory protection flags for this section
    pub fn memory_protection(&self) -> MemoryProtection {
        let mut prot = MemoryProtection::empty();
        
        if SectionCharacteristics::MemRead.is_set(self.characteristics) {
            prot |= MemoryProtection::READ;
        }
        if SectionCharacteristics::MemWrite.is_set(self.characteristics) {
            prot |= MemoryProtection::WRITE;
        }
        if SectionCharacteristics::MemExecute.is_set(self.characteristics) {
            prot |= MemoryProtection::EXECUTE;
        }
        
        prot
    }
}

bitflags::bitflags! {
    /// Memory protection flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryProtection: u32 {
        const READ = 0x01;
        const WRITE = 0x02;
        const EXECUTE = 0x04;
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        const READ_EXECUTE = Self::READ.bits() | Self::EXECUTE.bits();
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

/// Parsed PE file information
#[derive(Debug)]
pub struct ParsedPe {
    pub architecture: PeArchitecture,
    pub image_base: u64,
    pub entry_point: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<ParsedSection>,
    pub headers_data: Vec<u8>,
}

impl ParsedPe {
    /// Get a section by name
    pub fn section_by_name(&self, name: &str) -> Option<&ParsedSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Get a mutable section by name
    pub fn section_by_name_mut(&mut self, name: &str) -> Option<&mut ParsedSection> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    /// Get data directory by index
    pub fn data_directory(&self, index: DataDirectoryIndex) -> Option<&DataDirectory> {
        self.data_directories.get(index as usize)
    }

    /// Convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.sections {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size;
            
            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some(section.raw_data_offset + offset_in_section);
            }
        }
        None
    }

    /// Get section containing RVA
    pub fn section_from_rva(&self, rva: u32) -> Option<&ParsedSection> {
        self.sections.iter().find(|s| {
            rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size
        })
    }

    /// Check if PE is a DLL
    pub fn is_dll(&self) -> bool {
        (self.dll_characteristics & 0x2000) != 0
    }

    /// Check if ASLR is enabled
    pub fn has_aslr(&self) -> bool {
        (self.dll_characteristics & 0x0040) != 0
    }

    /// Check if DEP is enabled
    pub fn has_dep(&self) -> bool {
        (self.dll_characteristics & 0x0100) != 0
    }
}

/// PE Parser implementation
pub struct PeParser<R: Read + Seek> {
    reader: R,
    file_size: u64,
}

impl<R: Read + Seek> PeParser<R> {
    /// Create a new PE parser
    pub fn new(mut reader: R) -> io::Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        
        Ok(Self { reader, file_size })
    }

    /// Parse the PE file
    pub fn parse(&mut self) -> Result<ParsedPe, MapperError> {
        // Read and validate DOS header
        let dos_header = self.read_dos_header()?;
        dos_header.validate()?;

        // Seek to PE signature
        let pe_offset = dos_header.e_lfanew as u64;
        self.reader.seek(SeekFrom::Start(pe_offset))
            .map_err(|e| MapperError::IoError(e.to_string()))?;

        // Read and validate PE signature
        let signature = self.read_u32()?;
        if signature != PE_SIGNATURE {
            return Err(MapperError::InvalidFormat("Invalid PE signature".into()));
        }

        // Read file header
        let file_header = self.read_file_header()?;
        
        if file_header.number_of_sections as usize > MAX_SECTIONS {
            return Err(MapperError::InvalidFormat("Too many sections".into()));
        }

        // Read optional header magic to determine architecture
        let optional_magic = self.read_u16()?;
        self.reader.seek(SeekFrom::Current(-2))
            .map_err(|e| MapperError::IoError(e.to_string()))?;

        let (architecture, image_base, entry_point, section_alignment, 
             file_alignment, size_of_image, size_of_headers, subsystem,
             dll_characteristics, num_data_dirs) = match optional_magic {
            PE32_MAGIC => {
                let opt = self.read_optional_header_32()?;
                (
                    PeArchitecture::X86,
                    opt.image_base as u64,
                    opt.address_of_entry_point,
                    opt.section_alignment,
                    opt.file_alignment,
                    opt.size_of_image,
                    opt.size_of_headers,
                    opt.subsystem,
                    opt.dll_characteristics,
                    opt.number_of_rva_and_sizes,
                )
            }
            PE32_PLUS_MAGIC => {
                let opt = self.read_optional_header_64()?;
                (
                    PeArchitecture::X64,
                    opt.image_base,
                    opt.address_of_entry_point,
                    opt.section_alignment,
                    opt.file_alignment,
                    opt.size_of_image,
                    opt.size_of_headers,
                    opt.subsystem,
                    opt.dll_characteristics,
                    opt.number_of_rva_and_sizes,
                )
            }
            _ => return Err(MapperError::InvalidFormat("Unknown PE format".into())),
        };

        // Read data directories
        let mut data_directories = Vec::with_capacity(num_data_dirs as usize);
        for _ in 0..num_data_dirs {
            data_directories.push(self.read_data_directory()?);
        }

        // Read section headers
        let mut section_headers = Vec::with_capacity(file_header.number_of_sections as usize);
        for _ in 0..file_header.number_of_sections {
            section_headers.push(self.read_section_header()?);
        }

        // Read headers data
        self.reader.seek(SeekFrom::Start(0))
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        let mut headers_data = vec![0u8; size_of_headers as usize];
        self.reader.read_exact(&mut headers_data)
            .map_err(|e| MapperError::IoError(e.to_string()))?;

        // Read section data
        let mut sections = Vec::with_capacity(section_headers.len());
        for header in &section_headers {
            let data = self.read_section_data(header)?;
            sections.push(ParsedSection::from_header(header, data));
        }

        Ok(ParsedPe {
            architecture,
            image_base,
            entry_point,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem,
            dll_characteristics,
            data_directories,
            sections,
            headers_data,
        })
    }

    fn read_dos_header(&mut self) -> Result<DosHeader, MapperError> {
        let mut buffer = [0u8; mem::size_of::<DosHeader>()];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        
        // Safety: DosHeader is repr(C, packed) and all fields are primitive types
        Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const DosHeader) })
    }

    fn read_file_header(&mut self) -> Result<FileHeader, MapperError> {
        let mut buffer = [0u8; mem::size_of::<FileHeader>()];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        
        Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const FileHeader) })
    }

    fn read_optional_header_32(&mut self) -> Result<OptionalHeader32, MapperError> {
        let mut buffer = [0u8; mem::size_of::<OptionalHeader32>()];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        
        Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const OptionalHeader32) })
    }

    fn read_optional_header_64(&mut self) -> Result<OptionalHeader64, MapperError> {
        let mut buffer = [0u8; mem::size_of::<OptionalHeader64>()];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        
        Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const OptionalHeader64) })
    }

    fn read_data_directory(&mut self) -> Result<DataDirectory, MapperError> {
        let mut buffer = [0u8; mem::size_of::<DataDirectory>()];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        
        Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const DataDirectory) })
    }

    fn read_section_header(&mut self) -> Result<SectionHeader, MapperError> {
        let mut buffer = [0u8; mem::size_of::<SectionHeader>()];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        
        Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const SectionHeader) })
    }

    fn read_section_data(&mut self, header: &SectionHeader) -> Result<Vec<u8>, MapperError> {
        if header.size_of_raw_data == 0 {
            return Ok(Vec::new());
        }

        let offset = header.pointer_to_raw_data as u64;
        let size = header.size_of_raw_data as usize;

        if offset + size as u64 > self.file_size {
            return Err(MapperError::InvalidFormat("Section data exceeds file size".into()));
        }

        self.reader.seek(SeekFrom::Start(offset))
            .map_err(|e| MapperError::IoError(e.to_string()))?;

        let mut data = vec![0u8; size];
        self.reader.read_exact(&mut data)
            .map_err(|e| MapperError::IoError(e.to_string()))?;

        Ok(data)
    }

    fn read_u16(&mut self) -> Result<u16, MapperError> {
        let mut buffer = [0u8; 2];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        Ok(u16::from_le_bytes(buffer))
    }

    fn read_u32(&mut self) -> Result<u32, MapperError> {
        let mut buffer = [0u8; 4];
        self.reader.read_exact(&mut buffer)
            .map_err(|e| MapperError::IoError(e.to_string()))?;
        Ok(u32::from_le_bytes(buffer))
    }
}

/// Memory region descriptor for mapping operations
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: MemoryProtection,
    pub section_name: Option<String>,
}

/// Memory mapper for PE images
pub struct PeMemoryMapper {
    regions: Vec<MemoryRegion>,
    image_base: usize,
    image_size: usize,
}

impl PeMemoryMapper {
    /// Create a new memory mapper from parsed PE
    pub fn new(pe: &ParsedPe, target_base: Option<usize>) -> Self {
        let image_base = target_base.unwrap_or(pe.image_base as usize);
        let image_size = pe.size_of_image as usize;
        
        let mut regions = Vec::with_capacity(pe.sections.len() + 1);
        
        // Headers region
        regions.push(MemoryRegion {
            base_address: image_base,
            size: pe.size_of_headers as usize,
            protection: MemoryProtection::READ,
            section_name: None,
        });

        // Section regions
        for section in &pe.sections {
            let region_base = image_base + section.virtual_address as usize;
            let region_size = Self::align_up(
                section.virtual_size as usize,
                pe.section_alignment as usize,
            );
            
            regions.push(MemoryRegion {
                base_address: region_base,
                size: region_size,
                protection: section.memory_protection(),
                section_name: Some(section.name.clone()),
            });
        }

        Self {
            regions,
            image_base,
            image_size,
        }
    }

    /// Get all memory regions
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Get image base address
    pub fn image_base(&self) -> usize {
        self.image_base
    }

    /// Get total image size
    pub fn image_size(&self) -> usize {
        self.image_size
    }

    /// Find region containing address
    pub fn region_at(&self, address: usize) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| {
            address >= r.base_address && address < r.base_address + r.size
        })
    }

    fn align_up(value: usize, alignment: usize) -> usize {
        if alignment == 0 {
            return value;
        }
        (value + alignment - 1) & !(alignment - 1)
    }
}

/// Parse PE from byte slice
pub fn parse_pe_bytes(data: &[u8]) -> Result<ParsedPe, MapperError> {
    let cursor = io::Cursor::new(data);
    let mut parser = PeParser::new(cursor)
        .map_err(|e| MapperError::IoError(e.to_string()))?;
    parser.parse()
}

/// Parse PE from file path
pub fn parse_pe_file(path: &std::path::Path) -> Result<ParsedPe, MapperError> {
    let file = std::fs::File::open(path)
        .map_err(|e| MapperError::IoError(e.to_string()))?;
    let reader = io::BufReader::new(file);
    let mut parser = PeParser::new(reader)
        .map_err(|e| MapperError::IoError(e.to_string()))?;
    parser.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_characteristics() {
        let chars = 0x60000020u32; // CODE | MEM_EXECUTE | MEM_READ
        assert!(SectionCharacteristics::ContainsCode.is_set(chars));
        assert!(SectionCharacteristics::MemExecute.is_set(chars));
        assert!(SectionCharacteristics::MemRead.is_set(chars));
        assert!(!SectionCharacteristics::MemWrite.is_set(chars));
    }

    #[test]
    fn test_memory_protection_flags() {
        let prot = MemoryProtection::READ | MemoryProtection::EXECUTE;
        assert!(prot.contains(MemoryProtection::READ));
        assert!(prot.contains(MemoryProtection::EXECUTE));
        assert!(!prot.contains(MemoryProtection::WRITE));
    }

    #[test]
    fn test_align_up() {
        assert_eq!(PeMemoryMapper::align_up(100, 0x1000), 0x1000);
        assert_eq!(PeMemoryMapper::align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(PeMemoryMapper::align_up(0x1001, 0x1000), 0x2000);
    }
}