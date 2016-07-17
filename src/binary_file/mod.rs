//! Binary file parsing and manipulation utilities for PE/COFF format analysis.
//!
//! This module provides functionality for reading, parsing, and manipulating
//! binary executable files, with a focus on Windows PE format structures.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::MapperError;

pub mod pe_parser;
pub mod section;

/// Magic numbers for identifying file formats
pub mod magic {
    pub const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
    pub const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
    pub const PE32_MAGIC: u16 = 0x10B;
    pub const PE32PLUS_MAGIC: u16 = 0x20B;
}

/// Represents the architecture of a binary file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
    Arm,
    Arm64,
    Unknown(u16),
}

impl Architecture {
    pub fn from_machine_type(machine: u16) -> Self {
        match machine {
            0x014C => Architecture::X86,
            0x8664 => Architecture::X64,
            0x01C0 => Architecture::Arm,
            0xAA64 => Architecture::Arm64,
            other => Architecture::Unknown(other),
        }
    }

    pub fn pointer_size(&self) -> usize {
        match self {
            Architecture::X86 | Architecture::Arm => 4,
            Architecture::X64 | Architecture::Arm64 => 8,
            Architecture::Unknown(_) => 0,
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(self, Architecture::X64 | Architecture::Arm64)
    }
}

/// Binary file characteristics flags
#[derive(Debug, Clone, Copy, Default)]
pub struct FileCharacteristics(u16);

impl FileCharacteristics {
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const DLL: u16 = 0x2000;

    pub fn new(value: u16) -> Self {
        Self(value)
    }

    pub fn is_executable(&self) -> bool {
        self.0 & Self::EXECUTABLE_IMAGE != 0
    }

    pub fn is_dll(&self) -> bool {
        self.0 & Self::DLL != 0
    }

    pub fn is_large_address_aware(&self) -> bool {
        self.0 & Self::LARGE_ADDRESS_AWARE != 0
    }

    pub fn has_relocations(&self) -> bool {
        self.0 & Self::RELOCS_STRIPPED == 0
    }

    pub fn raw(&self) -> u16 {
        self.0
    }
}

/// A memory-mapped or buffered view of a binary file
pub struct BinaryFile {
    path: PathBuf,
    data: Vec<u8>,
    architecture: Option<Architecture>,
    characteristics: FileCharacteristics,
}

impl BinaryFile {
    /// Opens and reads a binary file from the specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MapperError> {
        let path = path.as_ref().to_path_buf();
        
        let file = File::open(&path).map_err(|e| {
            MapperError::IoError(format!("Failed to open file '{}': {}", path.display(), e))
        })?;

        let metadata = file.metadata().map_err(|e| {
            MapperError::IoError(format!("Failed to read file metadata: {}", e))
        })?;

        let file_size = metadata.len() as usize;
        if file_size < 64 {
            return Err(MapperError::InvalidFormat("File too small to be a valid binary".into()));
        }

        let mut reader = BufReader::new(file);
        let mut data = Vec::with_capacity(file_size);
        reader.read_to_end(&mut data).map_err(|e| {
            MapperError::IoError(format!("Failed to read file contents: {}", e))
        })?;

        let mut binary = Self {
            path,
            data,
            architecture: None,
            characteristics: FileCharacteristics::default(),
        };

        binary.detect_format()?;
        Ok(binary)
    }

    /// Creates a BinaryFile from raw bytes
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, MapperError> {
        if data.len() < 64 {
            return Err(MapperError::InvalidFormat("Data too small to be a valid binary".into()));
        }

        let mut binary = Self {
            path: PathBuf::new(),
            data,
            architecture: None,
            characteristics: FileCharacteristics::default(),
        };

        binary.detect_format()?;
        Ok(binary)
    }

    /// Detects the binary format and extracts basic metadata
    fn detect_format(&mut self) -> Result<(), MapperError> {
        let dos_sig = self.read_u16(0)?;
        if dos_sig != magic::DOS_SIGNATURE {
            return Err(MapperError::InvalidFormat("Invalid DOS signature".into()));
        }

        let pe_offset = self.read_u32(0x3C)? as usize;
        if pe_offset + 4 > self.data.len() {
            return Err(MapperError::InvalidFormat("Invalid PE header offset".into()));
        }

        let pe_sig = self.read_u32(pe_offset)?;
        if pe_sig != magic::PE_SIGNATURE {
            return Err(MapperError::InvalidFormat("Invalid PE signature".into()));
        }

        let machine = self.read_u16(pe_offset + 4)?;
        self.architecture = Some(Architecture::from_machine_type(machine));

        let characteristics = self.read_u16(pe_offset + 22)?;
        self.characteristics = FileCharacteristics::new(characteristics);

        Ok(())
    }

    /// Returns the file path if available
    pub fn path(&self) -> Option<&Path> {
        if self.path.as_os_str().is_empty() {
            None
        } else {
            Some(&self.path)
        }
    }

    /// Returns the raw binary data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the size of the binary data
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns the detected architecture
    pub fn architecture(&self) -> Option<Architecture> {
        self.architecture
    }

    /// Returns the file characteristics
    pub fn characteristics(&self) -> FileCharacteristics {
        self.characteristics
    }

    /// Reads a byte at the specified offset
    pub fn read_u8(&self, offset: usize) -> Result<u8, MapperError> {
        self.data.get(offset).copied().ok_or_else(|| {
            MapperError::InvalidOffset(format!("Offset {} out of bounds (size: {})", offset, self.data.len()))
        })
    }

    /// Reads a little-endian u16 at the specified offset
    pub fn read_u16(&self, offset: usize) -> Result<u16, MapperError> {
        if offset + 2 > self.data.len() {
            return Err(MapperError::InvalidOffset(format!(
                "Cannot read u16 at offset {} (size: {})", offset, self.data.len()
            )));
        }
        Ok(u16::from_le_bytes([self.data[offset], self.data[offset + 1]]))
    }

    /// Reads a little-endian u32 at the specified offset
    pub fn read_u32(&self, offset: usize) -> Result<u32, MapperError> {
        if offset + 4 > self.data.len() {
            return Err(MapperError::InvalidOffset(format!(
                "Cannot read u32 at offset {} (size: {})", offset, self.data.len()
            )));
        }
        Ok(u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ]))
    }

    /// Reads a little-endian u64 at the specified offset
    pub fn read_u64(&self, offset: usize) -> Result<u64, MapperError> {
        if offset + 8 > self.data.len() {
            return Err(MapperError::InvalidOffset(format!(
                "Cannot read u64 at offset {} (size: {})", offset, self.data.len()
            )));
        }
        Ok(u64::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
            self.data[offset + 4],
            self.data[offset + 5],
            self.data[offset + 6],
            self.data[offset + 7],
        ]))
    }

    /// Reads a slice of bytes at the specified offset
    pub fn read_bytes(&self, offset: usize, length: usize) -> Result<&[u8], MapperError> {
        if offset + length > self.data.len() {
            return Err(MapperError::InvalidOffset(format!(
                "Cannot read {} bytes at offset {} (size: {})", length, offset, self.data.len()
            )));
        }
        Ok(&self.data[offset..offset + length])
    }

    /// Reads a null-terminated string at the specified offset
    pub fn read_cstring(&self, offset: usize, max_length: usize) -> Result<String, MapperError> {
        let end = (offset + max_length).min(self.data.len());
        let slice = &self.data[offset..end];
        
        let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        
        String::from_utf8(slice[..null_pos].to_vec()).map_err(|e| {
            MapperError::InvalidFormat(format!("Invalid UTF-8 string at offset {}: {}", offset, e))
        })
    }

    /// Searches for a byte pattern in the binary data
    pub fn find_pattern(&self, pattern: &[u8], start_offset: usize) -> Option<usize> {
        if pattern.is_empty() || start_offset >= self.data.len() {
            return None;
        }

        self.data[start_offset..]
            .windows(pattern.len())
            .position(|window| window == pattern)
            .map(|pos| pos + start_offset)
    }

    /// Searches for a byte pattern with wildcards (0xFF = wildcard)
    pub fn find_pattern_masked(&self, pattern: &[u8], mask: &[u8], start_offset: usize) -> Option<usize> {
        if pattern.len() != mask.len() || pattern.is_empty() || start_offset >= self.data.len() {
            return None;
        }

        self.data[start_offset..]
            .windows(pattern.len())
            .position(|window| {
                window.iter()
                    .zip(pattern.iter())
                    .zip(mask.iter())
                    .all(|((data, pat), m)| *m == 0 || data == pat)
            })
            .map(|pos| pos + start_offset)
    }
}

impl std::fmt::Debug for BinaryFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryFile")
            .field("path", &self.path)
            .field("size", &self.data.len())
            .field("architecture", &self.architecture)
            .field("characteristics", &self.characteristics)
            .finish()
    }
}

/// Builder for constructing binary data programmatically
pub struct BinaryBuilder {
    data: Vec<u8>,
    cursor: usize,
}

impl BinaryBuilder {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            cursor: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            cursor: 0,
        }
    }

    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.ensure_capacity(1);
        self.data[self.cursor] = value;
        self.cursor += 1;
        self
    }

    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.ensure_capacity(2);
        let bytes = value.to_le_bytes();
        self.data[self.cursor..self.cursor + 2].copy_from_slice(&bytes);
        self.cursor += 2;
        self
    }

    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.ensure_capacity(4);
        let bytes = value.to_le_bytes();
        self.data[self.cursor..self.cursor + 4].copy_from_slice(&bytes);
        self.cursor += 4;
        self
    }

    pub fn write_u64(&mut self, value: u64) -> &mut Self {
        self.ensure_capacity(8);
        let bytes = value.to_le_bytes();
        self.data[self.cursor..self.cursor + 8].copy_from_slice(&bytes);
        self.cursor += 8;
        self
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.ensure_capacity(bytes.len());
        self.data[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        self
    }

    pub fn align(&mut self, alignment: usize) -> &mut Self {
        let padding = (alignment - (self.cursor % alignment)) % alignment;
        self.ensure_capacity(padding);
        for i in 0..padding {
            self.data[self.cursor + i] = 0;
        }
        self.cursor += padding;
        self
    }

    pub fn seek(&mut self, position: usize) -> &mut Self {
        self.cursor = position;
        self
    }

    pub fn position(&self) -> usize {
        self.cursor
    }

    pub fn build(mut self) -> Vec<u8> {
        self.data.truncate(self.cursor.max(self.data.len()));
        self.data
    }

    fn ensure_capacity(&mut self, additional: usize) {
        let required = self.cursor + additional;
        if required > self.data.len() {
            self.data.resize(required, 0);
        }
    }
}

impl Default for BinaryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_detection() {
        assert_eq!(Architecture::from_machine_type(0x014C), Architecture::X86);
        assert_eq!(Architecture::from_machine_type(0x8664), Architecture::X64);
        assert!(Architecture::X64.is_64bit());
        assert!(!Architecture::X86.is_64bit());
    }

    #[test]
    fn test_binary_builder() {
        let mut builder = BinaryBuilder::new();
        builder.write_u32(0x12345678).write_u16(0xABCD);
        
        let data = builder.build();
        assert_eq!(data.len(), 6);
        assert_eq!(data[0], 0x78);
        assert_eq!(data[4], 0xCD);
    }

    #[test]
    fn test_file_characteristics() {
        let chars = FileCharacteristics::new(0x2022);
        assert!(chars.is_executable());
        assert!(chars.is_dll());
        assert!(chars.is_large_address_aware());
    }
}