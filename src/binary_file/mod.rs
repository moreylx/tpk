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

    /// Validates that the architecture is known and supported
    pub fn validate(&self) -> Result<(), MapperError> {
        match self {
            Architecture::Unknown(code) => Err(MapperError::InvalidData(
                format!("Unsupported architecture: 0x{:04X}", code),
            )),
            _ => Ok(()),
        }
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

    pub fn has_relocations(&self) -> bool {
        self.0 & Self::RELOCS_STRIPPED == 0
    }

    pub fn is_large_address_aware(&self) -> bool {
        self.0 & Self::LARGE_ADDRESS_AWARE != 0
    }

    pub fn raw_value(&self) -> u16 {
        self.0
    }
}

/// Validated path wrapper ensuring non-null and valid path references
#[derive(Debug, Clone)]
pub struct ValidatedPath {
    inner: PathBuf,
}

impl ValidatedPath {
    /// Creates a new validated path, ensuring it's not empty
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, MapperError> {
        let path_ref = path.as_ref();
        
        if path_ref.as_os_str().is_empty() {
            return Err(MapperError::InvalidData(
                "Path cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            inner: path_ref.to_path_buf(),
        })
    }

    /// Creates a validated path that must exist on the filesystem
    pub fn existing<P: AsRef<Path>>(path: P) -> Result<Self, MapperError> {
        let validated = Self::new(path)?;
        
        if !validated.inner.exists() {
            return Err(MapperError::FileNotFound(
                validated.inner.display().to_string(),
            ));
        }

        Ok(validated)
    }

    pub fn as_path(&self) -> &Path {
        &self.inner
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.inner
    }
}

impl AsRef<Path> for ValidatedPath {
    fn as_ref(&self) -> &Path {
        &self.inner
    }
}

/// Non-null buffer wrapper with validation
#[derive(Debug, Clone)]
pub struct ValidatedBuffer {
    data: Vec<u8>,
    min_size: usize,
}

impl ValidatedBuffer {
    /// Creates a new validated buffer with minimum size requirement
    pub fn new(data: Vec<u8>, min_size: usize) -> Result<Self, MapperError> {
        if data.is_empty() {
            return Err(MapperError::InvalidData(
                "Buffer cannot be empty".to_string(),
            ));
        }

        if data.len() < min_size {
            return Err(MapperError::InvalidData(
                format!(
                    "Buffer too small: expected at least {} bytes, got {}",
                    min_size,
                    data.len()
                ),
            ));
        }

        Ok(Self { data, min_size })
    }

    /// Creates a buffer without minimum size validation (but still non-empty)
    pub fn from_vec(data: Vec<u8>) -> Result<Self, MapperError> {
        Self::new(data, 1)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Reads a value at the specified offset with bounds checking
    pub fn read_u16_at(&self, offset: usize) -> Result<u16, MapperError> {
        self.validate_range(offset, 2)?;
        Ok(u16::from_le_bytes([self.data[offset], self.data[offset + 1]]))
    }

    pub fn read_u32_at(&self, offset: usize) -> Result<u32, MapperError> {
        self.validate_range(offset, 4)?;
        Ok(u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ]))
    }

    pub fn read_u64_at(&self, offset: usize) -> Result<u64, MapperError> {
        self.validate_range(offset, 8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[offset..offset + 8]);
        Ok(u64::from_le_bytes(bytes))
    }

    fn validate_range(&self, offset: usize, size: usize) -> Result<(), MapperError> {
        let end = offset.checked_add(size).ok_or_else(|| {
            MapperError::InvalidData("Offset overflow".to_string())
        })?;

        if end > self.data.len() {
            return Err(MapperError::InvalidData(
                format!(
                    "Read out of bounds: offset {} + size {} exceeds buffer length {}",
                    offset, size, self.data.len()
                ),
            ));
        }

        Ok(())
    }

    /// Extracts a slice with bounds validation
    pub fn slice(&self, start: usize, len: usize) -> Result<&[u8], MapperError> {
        self.validate_range(start, len)?;
        Ok(&self.data[start..start + len])
    }
}

/// Optional value wrapper with explicit null checking
#[derive(Debug, Clone)]
pub struct Validated<T> {
    inner: Option<T>,
    context: &'static str,
}

impl<T> Validated<T> {
    /// Creates a validated wrapper from an Option
    pub fn from_option(value: Option<T>, context: &'static str) -> Self {
        Self {
            inner: value,
            context,
        }
    }

    /// Creates a validated wrapper that must contain a value
    pub fn required(value: Option<T>, context: &'static str) -> Result<Self, MapperError> {
        if value.is_none() {
            return Err(MapperError::InvalidData(
                format!("{} cannot be null", context),
            ));
        }
        Ok(Self {
            inner: value,
            context,
        })
    }

    /// Unwraps the value, returning an error if None
    pub fn unwrap_validated(self) -> Result<T, MapperError> {
        self.inner.ok_or_else(|| {
            MapperError::InvalidData(format!("{} is null", self.context))
        })
    }

    /// Returns a reference to the inner value if present
    pub fn as_ref(&self) -> Option<&T> {
        self.inner.as_ref()
    }

    /// Checks if the value is present
    pub fn is_some(&self) -> bool {
        self.inner.is_some()
    }

    /// Checks if the value is absent
    pub fn is_none(&self) -> bool {
        self.inner.is_none()
    }

    /// Maps the inner value if present
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Validated<U> {
        Validated {
            inner: self.inner.map(f),
            context: self.context,
        }
    }
}

/// Binary file reader with comprehensive validation
pub struct BinaryFileReader {
    path: ValidatedPath,
    reader: BufReader<File>,
    file_size: u64,
}

impl BinaryFileReader {
    /// Opens a binary file with path validation
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MapperError> {
        let validated_path = ValidatedPath::existing(path)?;
        
        let file = File::open(validated_path.as_path()).map_err(|e| {
            MapperError::IoError(format!(
                "Failed to open file '{}': {}",
                validated_path.as_path().display(),
                e
            ))
        })?;

        let metadata = file.metadata().map_err(|e| {
            MapperError::IoError(format!("Failed to read file metadata: {}", e))
        })?;

        let file_size = metadata.len();
        
        if file_size == 0 {
            return Err(MapperError::InvalidData(
                "File is empty".to_string(),
            ));
        }

        Ok(Self {
            path: validated_path,
            reader: BufReader::new(file),
            file_size,
        })
    }

    /// Returns the file size
    pub fn size(&self) -> u64 {
        self.file_size
    }

    /// Returns the file path
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Reads bytes at a specific offset with validation
    pub fn read_at(&mut self, offset: u64, size: usize) -> Result<ValidatedBuffer, MapperError> {
        if size == 0 {
            return Err(MapperError::InvalidData(
                "Cannot read zero bytes".to_string(),
            ));
        }

        let end_offset = offset.checked_add(size as u64).ok_or_else(|| {
            MapperError::InvalidData("Offset overflow".to_string())
        })?;

        if end_offset > self.file_size {
            return Err(MapperError::InvalidData(
                format!(
                    "Read beyond file end: offset {} + size {} exceeds file size {}",
                    offset, size, self.file_size
                ),
            ));
        }

        self.reader.seek(SeekFrom::Start(offset)).map_err(|e| {
            MapperError::IoError(format!("Seek failed: {}", e))
        })?;

        let mut buffer = vec![0u8; size];
        self.reader.read_exact(&mut buffer).map_err(|e| {
            MapperError::IoError(format!("Read failed: {}", e))
        })?;

        ValidatedBuffer::new(buffer, size)
    }

    /// Reads the entire file into a validated buffer
    pub fn read_all(&mut self) -> Result<ValidatedBuffer, MapperError> {
        if self.file_size > usize::MAX as u64 {
            return Err(MapperError::InvalidData(
                "File too large to read into memory".to_string(),
            ));
        }

        self.read_at(0, self.file_size as usize)
    }

    /// Validates DOS header signature
    pub fn validate_dos_header(&mut self) -> Result<u32, MapperError> {
        let header = self.read_at(0, 64)?;
        
        let signature = header.read_u16_at(0)?;
        if signature != magic::DOS_SIGNATURE {
            return Err(MapperError::InvalidData(
                format!("Invalid DOS signature: expected 0x{:04X}, got 0x{:04X}",
                    magic::DOS_SIGNATURE, signature),
            ));
        }

        // e_lfanew is at offset 0x3C
        let pe_offset = header.read_u32_at(0x3C)?;
        
        if pe_offset == 0 {
            return Err(MapperError::InvalidData(
                "PE header offset is null".to_string(),
            ));
        }

        if pe_offset as u64 >= self.file_size {
            return Err(MapperError::InvalidData(
                format!("PE header offset 0x{:X} exceeds file size", pe_offset),
            ));
        }

        Ok(pe_offset)
    }

    /// Validates PE signature at the given offset
    pub fn validate_pe_signature(&mut self, offset: u32) -> Result<(), MapperError> {
        let sig_buffer = self.read_at(offset as u64, 4)?;
        let signature = sig_buffer.read_u32_at(0)?;

        if signature != magic::PE_SIGNATURE {
            return Err(MapperError::InvalidData(
                format!("Invalid PE signature: expected 0x{:08X}, got 0x{:08X}",
                    magic::PE_SIGNATURE, signature),
            ));
        }

        Ok(())
    }
}

/// RVA (Relative Virtual Address) with validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rva(u32);

impl Rva {
    pub const NULL: Rva = Rva(0);

    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Creates an RVA that must be non-null
    pub fn non_null(value: u32) -> Result<Self, MapperError> {
        if value == 0 {
            return Err(MapperError::InvalidData(
                "RVA cannot be null".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    pub fn value(&self) -> u32 {
        self.0
    }

    /// Adds an offset with overflow checking
    pub fn offset(&self, delta: u32) -> Result<Rva, MapperError> {
        self.0.checked_add(delta)
            .map(Rva)
            .ok_or_else(|| MapperError::InvalidData("RVA overflow".to_string()))
    }

    /// Converts to file offset using section mapping
    pub fn to_file_offset(&self, sections: &[section::SectionInfo]) -> Result<u64, MapperError> {
        if self.is_null() {
            return Err(MapperError::InvalidData(
                "Cannot convert null RVA to file offset".to_string(),
            ));
        }

        for section in sections {
            if section.contains_rva(self.0) {
                let offset = self.0 - section.virtual_address();
                return Ok(section.raw_data_offset() as u64 + offset as u64);
            }
        }

        Err(MapperError::InvalidData(
            format!("RVA 0x{:08X} not found in any section", self.0),
        ))
    }
}

/// VA (Virtual Address) with validation for both 32 and 64-bit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Va {
    Va32(u32),
    Va64(u64),
}

impl Va {
    pub fn new_32(value: u32) -> Self {
        Va::Va32(value)
    }

    pub fn new_64(value: u64) -> Self {
        Va::Va64(value)
    }

    pub fn is_null(&self) -> bool {
        match self {
            Va::Va32(v) => *v == 0,
            Va::Va64(v) => *v == 0,
        }
    }

    /// Creates a VA that must be non-null
    pub fn non_null_32(value: u32) -> Result<Self, MapperError> {
        if value == 0 {
            return Err(MapperError::InvalidData(
                "Virtual address cannot be null".to_string(),
            ));
        }
        Ok(Va::Va32(value))
    }

    pub fn non_null_64(value: u64) -> Result<Self, MapperError> {
        if value == 0 {
            return Err(MapperError::InvalidData(
                "Virtual address cannot be null".to_string(),
            ));
        }
        Ok(Va::Va64(value))
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            Va::Va32(v) => *v as u64,
            Va::Va64(v) => *v,
        }
    }

    /// Converts to RVA by subtracting image base
    pub fn to_rva(&self, image_base: u64) -> Result<Rva, MapperError> {
        let va = self.as_u64();
        
        if va < image_base {
            return Err(MapperError::InvalidData(
                format!("VA 0x{:X} is below image base 0x{:X}", va, image_base),
            ));
        }

        let rva = va - image_base;
        
        if rva > u32::MAX as u64 {
            return Err(MapperError::InvalidData(
                format!("RVA 0x{:X} exceeds 32-bit range", rva),
            ));
        }

        Ok(Rva::new(rva as u32))
    }
}

/// Data directory entry with validation
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    rva: Rva,
    size: u32,
}

impl DataDirectory {
    pub fn new(rva: u32, size: u32) -> Self {
        Self {
            rva: Rva::new(rva),
            size,
        }
    }

    pub fn is_present(&self) -> bool {
        !self.rva.is_null() && self.size > 0
    }

    pub fn rva(&self) -> Rva {
        self.rva
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Validates that the directory is present and has valid size
    pub fn validate_present(&self, name: &str) -> Result<(), MapperError> {
        if self.rva.is_null() {
            return Err(MapperError::InvalidData(
                format!("{} directory RVA is null", name),
            ));
        }

        if self.size == 0 {
            return Err(MapperError::InvalidData(
                format!("{} directory size is zero", name),
            ));
        }

        Ok(())
    }

    /// Validates that the directory fits within the given image size
    pub fn validate_bounds(&self, image_size: u64, name: &str) -> Result<(), MapperError> {
        if !self.is_present() {
            return Ok(());
        }

        let end = (self.rva.value() as u64)
            .checked_add(self.size as u64)
            .ok_or_else(|| {
                MapperError::InvalidData(format!("{} directory bounds overflow", name))
            })?;

        if end > image_size {
            return Err(MapperError::InvalidData(
                format!(
                    "{} directory exceeds image bounds: end 0x{:X} > size 0x{:X}",
                    name, end, image_size
                ),
            ));
        }

        Ok(())
    }
}

/// String table entry with null-termination validation
#[derive(Debug, Clone)]
pub struct ValidatedString {
    inner: String,
    max_length: usize,
}

impl ValidatedString {
    /// Creates a validated string from bytes, ensuring proper null termination
    pub fn from_null_terminated(bytes: &[u8], max_length: usize) -> Result<Self, MapperError> {
        if bytes.is_empty() {
            return Err(MapperError::InvalidData(
                "String buffer is empty".to_string(),
            ));
        }

        let null_pos = bytes.iter()
            .take(max_length)
            .position(|&b| b == 0)
            .unwrap_or(bytes.len().min(max_length));

        let string_bytes = &bytes[..null_pos];
        
        let inner = String::from_utf8_lossy(string_bytes).into_owned();

        Ok(Self { inner, max_length })
    }

    /// Creates a validated string that must not be empty
    pub fn non_empty(bytes: &[u8], max_length: usize) -> Result<Self, MapperError> {
        let validated = Self::from_null_terminated(bytes, max_length)?;
        
        if validated.inner.is_empty() {
            return Err(MapperError::InvalidData(
                "String cannot be empty".to_string(),
            ));
        }

        Ok(validated)
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<str> for ValidatedString {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Display for ValidatedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_validation() {
        assert!(Architecture::X64.validate().is_ok());
        assert!(Architecture::Unknown(0xFFFF).validate().is_err());
    }

    #[test]
    fn test_validated_buffer_bounds() {
        let buffer = ValidatedBuffer::new(vec![1, 2, 3, 4], 4).unwrap();
        assert!(buffer.read_u16_at(0).is_ok());
        assert!(buffer.read_u16_at(3).is_err());
        assert!(buffer.read_u32_at(0).is_ok());
        assert!(buffer.read_u32_at(1).is_err());
    }

    #[test]
    fn test_rva_null_check() {
        assert!(Rva::NULL.is_null());
        assert!(Rva::non_null(0).is_err());
        assert!(Rva::non_null(0x1000).is_ok());
    }

    #[test]
    fn test_validated_string() {
        let bytes = b"test\0extra";
        let s = ValidatedString::from_null_terminated(bytes, 100).unwrap();
        assert_eq!(s.as_str(), "test");

        let empty = b"\0";
        assert!(ValidatedString::non_empty(empty, 100).is_err());
    }

    #[test]
    fn test_data_directory_validation() {
        let empty = DataDirectory::new(0, 0);
        assert!(!empty.is_present());

        let valid = DataDirectory::new(0x1000, 0x100);
        assert!(valid.is_present());
        assert!(valid.validate_present("Test").is_ok());
        assert!(valid.validate_bounds(0x2000, "Test").is_ok());
        assert!(valid.validate_bounds(0x1000, "Test").is_err());
    }
}