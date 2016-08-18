//! Shellcode execution and management module
//!
//! Provides safe abstractions for shellcode injection, execution, and memory management
//! with support for various execution strategies and encoding schemes.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::{MapperError, NtStatus};

/// Memory protection flags for shellcode regions
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
}

impl MemoryProtection {
    pub fn as_raw(&self) -> u32 {
        *self as u32
    }

    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            Self::Execute | Self::ExecuteRead | Self::ExecuteReadWrite | Self::ExecuteWriteCopy
        )
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self,
            Self::ReadWrite | Self::WriteCopy | Self::ExecuteReadWrite | Self::ExecuteWriteCopy
        )
    }
}

/// Allocation type for virtual memory operations
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

/// Shellcode encoding schemes for obfuscation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingScheme {
    None,
    Xor { key: u8 },
    XorMultiByte { key: [u8; 4] },
    RotateLeft { bits: u8 },
    RotateRight { bits: u8 },
    AddSub { delta: u8 },
    Custom,
}

/// Execution strategy for shellcode
pub trait ExecutionStrategy: Send + Sync {
    fn execute(&self, shellcode: &ExecutableShellcode) -> Result<u64, MapperError>;
    fn name(&self) -> &'static str;
    fn supports_parameters(&self) -> bool;
}

/// Direct execution via function pointer cast
pub struct DirectExecution;

impl ExecutionStrategy for DirectExecution {
    fn execute(&self, shellcode: &ExecutableShellcode) -> Result<u64, MapperError> {
        if !shellcode.is_executable() {
            return Err(MapperError::InvalidState(
                "Shellcode region is not executable".into(),
            ));
        }

        let func: extern "system" fn() -> u64 =
            unsafe { std::mem::transmute(shellcode.base_address()) };

        Ok(func())
    }

    fn name(&self) -> &'static str {
        "DirectExecution"
    }

    fn supports_parameters(&self) -> bool {
        false
    }
}

/// Execution via CreateThread
pub struct ThreadExecution {
    wait_timeout_ms: u32,
}

impl ThreadExecution {
    pub fn new(wait_timeout_ms: u32) -> Self {
        Self { wait_timeout_ms }
    }

    pub fn infinite_wait() -> Self {
        Self {
            wait_timeout_ms: u32::MAX,
        }
    }
}

impl Default for ThreadExecution {
    fn default() -> Self {
        Self {
            wait_timeout_ms: 30000,
        }
    }
}

impl ExecutionStrategy for ThreadExecution {
    fn execute(&self, shellcode: &ExecutableShellcode) -> Result<u64, MapperError> {
        if !shellcode.is_executable() {
            return Err(MapperError::InvalidState(
                "Shellcode region is not executable".into(),
            ));
        }

        // Simulated thread execution - in real implementation would use Windows API
        let base = shellcode.base_address();
        
        // For demonstration, we simulate thread creation and execution
        let result = std::thread::spawn(move || {
            let func: extern "system" fn() -> u64 = unsafe { std::mem::transmute(base) };
            func()
        });

        match result.join() {
            Ok(ret) => Ok(ret),
            Err(_) => Err(MapperError::ExecutionFailed("Thread panicked".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ThreadExecution"
    }

    fn supports_parameters(&self) -> bool {
        true
    }
}

/// APC-based execution strategy
pub struct ApcExecution {
    target_thread_id: Option<u32>,
}

impl ApcExecution {
    pub fn new(target_thread_id: Option<u32>) -> Self {
        Self { target_thread_id }
    }
}

impl ExecutionStrategy for ApcExecution {
    fn execute(&self, shellcode: &ExecutableShellcode) -> Result<u64, MapperError> {
        if !shellcode.is_executable() {
            return Err(MapperError::InvalidState(
                "Shellcode region is not executable".into(),
            ));
        }

        // APC execution would queue the shellcode to run in the context of a target thread
        // This is a simplified simulation
        Err(MapperError::NotImplemented("APC execution requires target thread".into()))
    }

    fn name(&self) -> &'static str {
        "ApcExecution"
    }

    fn supports_parameters(&self) -> bool {
        true
    }
}

/// Observer trait for shellcode lifecycle events
pub trait ShellcodeObserver: Send + Sync {
    fn on_allocation(&self, address: *mut c_void, size: usize);
    fn on_protection_change(&self, address: *mut c_void, old: MemoryProtection, new: MemoryProtection);
    fn on_execution_start(&self, address: *mut c_void);
    fn on_execution_complete(&self, address: *mut c_void, result: Result<u64, &MapperError>);
    fn on_deallocation(&self, address: *mut c_void);
}

/// Default observer that logs events
pub struct LoggingObserver {
    verbose: bool,
}

impl LoggingObserver {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
}

impl ShellcodeObserver for LoggingObserver {
    fn on_allocation(&self, address: *mut c_void, size: usize) {
        if self.verbose {
            eprintln!("[SHELLCODE] Allocated {} bytes at {:p}", size, address);
        }
    }

    fn on_protection_change(&self, address: *mut c_void, old: MemoryProtection, new: MemoryProtection) {
        if self.verbose {
            eprintln!(
                "[SHELLCODE] Protection changed at {:p}: {:?} -> {:?}",
                address, old, new
            );
        }
    }

    fn on_execution_start(&self, address: *mut c_void) {
        if self.verbose {
            eprintln!("[SHELLCODE] Execution started at {:p}", address);
        }
    }

    fn on_execution_complete(&self, address: *mut c_void, result: Result<u64, &MapperError>) {
        if self.verbose {
            match result {
                Ok(ret) => eprintln!("[SHELLCODE] Execution completed at {:p}, result: {:#x}", address, ret),
                Err(e) => eprintln!("[SHELLCODE] Execution failed at {:p}: {}", address, e),
            }
        }
    }

    fn on_deallocation(&self, address: *mut c_void) {
        if self.verbose {
            eprintln!("[SHELLCODE] Deallocated memory at {:p}", address);
        }
    }
}

/// RAII wrapper for allocated shellcode memory
pub struct ShellcodeRegion {
    base: NonNull<c_void>,
    size: usize,
    protection: MemoryProtection,
    observers: Vec<Arc<dyn ShellcodeObserver>>,
    is_freed: AtomicBool,
}

// Safety: ShellcodeRegion manages its own memory and synchronization
unsafe impl Send for ShellcodeRegion {}
unsafe impl Sync for ShellcodeRegion {}

impl ShellcodeRegion {
    /// Allocate a new shellcode region with the specified size and protection
    pub fn allocate(size: usize, protection: MemoryProtection) -> Result<Self, MapperError> {
        if size == 0 {
            return Err(MapperError::InvalidParameter("Size cannot be zero".into()));
        }

        // Align size to page boundary (4KB)
        let aligned_size = (size + 0xFFF) & !0xFFF;

        // Use system allocator for demonstration - real implementation would use VirtualAlloc
        let layout = std::alloc::Layout::from_size_align(aligned_size, 0x1000)
            .map_err(|_| MapperError::AllocationFailed("Invalid layout".into()))?;

        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };

        if ptr.is_null() {
            return Err(MapperError::AllocationFailed(
                "Failed to allocate shellcode region".into(),
            ));
        }

        let base = NonNull::new(ptr as *mut c_void)
            .ok_or_else(|| MapperError::AllocationFailed("Null pointer returned".into()))?;

        Ok(Self {
            base,
            size: aligned_size,
            protection,
            observers: Vec::new(),
            is_freed: AtomicBool::new(false),
        })
    }

    /// Add an observer for lifecycle events
    pub fn add_observer(&mut self, observer: Arc<dyn ShellcodeObserver>) {
        self.observers.push(observer);
    }

    /// Get the base address of the region
    pub fn base_address(&self) -> *mut c_void {
        self.base.as_ptr()
    }

    /// Get the size of the region
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get current protection
    pub fn protection(&self) -> MemoryProtection {
        self.protection
    }

    /// Write data to the region at the specified offset
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), MapperError> {
        if self.is_freed.load(Ordering::Acquire) {
            return Err(MapperError::InvalidState("Region has been freed".into()));
        }

        if !self.protection.is_writable() {
            return Err(MapperError::AccessDenied(
                "Region is not writable".into(),
            ));
        }

        if offset + data.len() > self.size {
            return Err(MapperError::BufferOverflow(
                "Write would exceed region bounds".into(),
            ));
        }

        unsafe {
            let dest = (self.base.as_ptr() as *mut u8).add(offset);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
        }

        Ok(())
    }

    /// Read data from the region at the specified offset
    pub fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, MapperError> {
        if self.is_freed.load(Ordering::Acquire) {
            return Err(MapperError::InvalidState("Region has been freed".into()));
        }

        if offset + length > self.size {
            return Err(MapperError::BufferOverflow(
                "Read would exceed region bounds".into(),
            ));
        }

        let mut buffer = vec![0u8; length];
        unsafe {
            let src = (self.base.as_ptr() as *const u8).add(offset);
            std::ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), length);
        }

        Ok(buffer)
    }

    /// Change the protection of the region
    pub fn set_protection(&mut self, new_protection: MemoryProtection) -> Result<MemoryProtection, MapperError> {
        if self.is_freed.load(Ordering::Acquire) {
            return Err(MapperError::InvalidState("Region has been freed".into()));
        }

        let old_protection = self.protection;

        // Notify observers
        for observer in &self.observers {
            observer.on_protection_change(self.base.as_ptr(), old_protection, new_protection);
        }

        // In real implementation, would call VirtualProtect
        self.protection = new_protection;

        Ok(old_protection)
    }

    /// Check if the region is executable
    pub fn is_executable(&self) -> bool {
        self.protection.is_executable()
    }

    /// Notify observers of allocation
    fn notify_allocation(&self) {
        for observer in &self.observers {
            observer.on_allocation(self.base.as_ptr(), self.size);
        }
    }
}

impl Drop for ShellcodeRegion {
    fn drop(&mut self) {
        if !self.is_freed.swap(true, Ordering::AcqRel) {
            // Notify observers
            for observer in &self.observers {
                observer.on_deallocation(self.base.as_ptr());
            }

            // Zero out memory before freeing for security
            unsafe {
                std::ptr::write_bytes(self.base.as_ptr() as *mut u8, 0, self.size);
            }

            // Free the memory
            let layout = std::alloc::Layout::from_size_align(self.size, 0x1000)
                .expect("Layout should be valid");
            unsafe {
                std::alloc::dealloc(self.base.as_ptr() as *mut u8, layout);
            }
        }
    }
}

/// Encoder for shellcode obfuscation
pub struct ShellcodeEncoder {
    scheme: EncodingScheme,
}

impl ShellcodeEncoder {
    pub fn new(scheme: EncodingScheme) -> Self {
        Self { scheme }
    }

    /// Encode shellcode bytes
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        match self.scheme {
            EncodingScheme::None => data.to_vec(),
            EncodingScheme::Xor { key } => data.iter().map(|b| b ^ key).collect(),
            EncodingScheme::XorMultiByte { key } => {
                data.iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % key.len()])
                    .collect()
            }
            EncodingScheme::RotateLeft { bits } => {
                data.iter().map(|b| b.rotate_left(bits as u32)).collect()
            }
            EncodingScheme::RotateRight { bits } => {
                data.iter().map(|b| b.rotate_right(bits as u32)).collect()
            }
            EncodingScheme::AddSub { delta } => {
                data.iter().map(|b| b.wrapping_add(delta)).collect()
            }
            EncodingScheme::Custom => data.to_vec(),
        }
    }

    /// Decode shellcode bytes
    pub fn decode(&self, data: &[u8]) -> Vec<u8> {
        match self.scheme {
            EncodingScheme::None => data.to_vec(),
            EncodingScheme::Xor { key } => data.iter().map(|b| b ^ key).collect(),
            EncodingScheme::XorMultiByte { key } => {
                data.iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % key.len()])
                    .collect()
            }
            EncodingScheme::RotateLeft { bits } => {
                data.iter().map(|b| b.rotate_right(bits as u32)).collect()
            }
            EncodingScheme::RotateRight { bits } => {
                data.iter().map(|b| b.rotate_left(bits as u32)).collect()
            }
            EncodingScheme::AddSub { delta } => {
                data.iter().map(|b| b.wrapping_sub(delta)).collect()
            }
            EncodingScheme::Custom => data.to_vec(),
        }
    }

    /// Get the encoding scheme
    pub fn scheme(&self) -> EncodingScheme {
        self.scheme
    }
}

/// Executable shellcode wrapper with execution capabilities
pub struct ExecutableShellcode {
    region: ShellcodeRegion,
    code_size: usize,
    entry_offset: usize,
    execution_count: AtomicUsize,
}

impl ExecutableShellcode {
    /// Create executable shellcode from raw bytes
    pub fn from_bytes(shellcode: &[u8]) -> Result<Self, MapperError> {
        Self::from_bytes_with_offset(shellcode, 0)
    }

    /// Create executable shellcode with a custom entry point offset
    pub fn from_bytes_with_offset(shellcode: &[u8], entry_offset: usize) -> Result<Self, MapperError> {
        if shellcode.is_empty() {
            return Err(MapperError::InvalidParameter("Shellcode cannot be empty".into()));
        }

        if entry_offset >= shellcode.len() {
            return Err(MapperError::InvalidParameter(
                "Entry offset exceeds shellcode size".into(),
            ));
        }

        // Allocate with RW protection initially
        let mut region = ShellcodeRegion::allocate(shellcode.len(), MemoryProtection::ReadWrite)?;

        // Write shellcode
        region.write(0, shellcode)?;

        // Change to RX protection
        region.set_protection(MemoryProtection::ExecuteRead)?;

        Ok(Self {
            region,
            code_size: shellcode.len(),
            entry_offset,
            execution_count: AtomicUsize::new(0),
        })
    }

    /// Create from encoded shellcode
    pub fn from_encoded(
        encoded_shellcode: &[u8],
        encoder: &ShellcodeEncoder,
    ) -> Result<Self, MapperError> {
        let decoded = encoder.decode(encoded_shellcode);
        Self::from_bytes(&decoded)
    }

    /// Get the base address
    pub fn base_address(&self) -> *mut c_void {
        self.region.base_address()
    }

    /// Get the entry point address
    pub fn entry_point(&self) -> *mut c_void {
        unsafe { (self.region.base_address() as *mut u8).add(self.entry_offset) as *mut c_void }
    }

    /// Get the code size
    pub fn code_size(&self) -> usize {
        self.code_size
    }

    /// Check if executable
    pub fn is_executable(&self) -> bool {
        self.region.is_executable()
    }

    /// Get execution count
    pub fn execution_count(&self) -> usize {
        self.execution_count.load(Ordering::Relaxed)
    }

    /// Execute using the specified strategy
    pub fn execute_with<S: ExecutionStrategy>(&self, strategy: &S) -> Result<u64, MapperError> {
        self.execution_count.fetch_add(1, Ordering::Relaxed);
        strategy.execute(self)
    }

    /// Execute directly (convenience method)
    pub fn execute(&self) -> Result<u64, MapperError> {
        self.execute_with(&DirectExecution)
    }

    /// Add an observer
    pub fn add_observer(&mut self, observer: Arc<dyn ShellcodeObserver>) {
        self.region.add_observer(observer);
    }
}

/// Factory for creating shellcode instances
pub struct ShellcodeFactory {
    default_encoder: Option<ShellcodeEncoder>,
    observers: Vec<Arc<dyn ShellcodeObserver>>,
}

impl ShellcodeFactory {
    pub fn new() -> Self {
        Self {
            default_encoder: None,
            observers: Vec::new(),
        }
    }

    pub fn with_encoder(mut self, encoder: ShellcodeEncoder) -> Self {
        self.default_encoder = Some(encoder);
        self
    }

    pub fn with_observer(mut self, observer: Arc<dyn ShellcodeObserver>) -> Self {
        self.observers.push(observer);
        self
    }

    /// Create shellcode from raw bytes
    pub fn create(&self, shellcode: &[u8]) -> Result<ExecutableShellcode, MapperError> {
        let data = if let Some(ref encoder) = self.default_encoder {
            encoder.decode(shellcode)
        } else {
            shellcode.to_vec()
        };

        let mut exec = ExecutableShellcode::from_bytes(&data)?;

        for observer in &self.observers {
            exec.add_observer(Arc::clone(observer));
        }

        Ok(exec)
    }

    /// Create shellcode with custom entry offset
    pub fn create_with_offset(
        &self,
        shellcode: &[u8],
        entry_offset: usize,
    ) -> Result<ExecutableShellcode, MapperError> {
        let data = if let Some(ref encoder) = self.default_encoder {
            encoder.decode(shellcode)
        } else {
            shellcode.to_vec()
        };

        let mut exec = ExecutableShellcode::from_bytes_with_offset(&data, entry_offset)?;

        for observer in &self.observers {
            exec.add_observer(Arc::clone(observer));
        }

        Ok(exec)
    }
}

impl Default for ShellcodeFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Shellcode builder for fluent API
pub struct ShellcodeBuilder {
    shellcode: Vec<u8>,
    entry_offset: usize,
    encoder: Option<ShellcodeEncoder>,
    observers: Vec<Arc<dyn ShellcodeObserver>>,
}

impl ShellcodeBuilder {
    pub fn new() -> Self {
        Self {
            shellcode: Vec::new(),
            entry_offset: 0,
            encoder: None,
            observers: Vec::new(),
        }
    }

    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.shellcode.extend_from_slice(bytes);
        self
    }

    pub fn with_entry_offset(mut self, offset: usize) -> Self {
        self.entry_offset = offset;
        self
    }

    pub fn with_encoder(mut self, encoder: ShellcodeEncoder) -> Self {
        self.encoder = Some(encoder);
        self
    }

    pub fn with_observer(mut self, observer: Arc<dyn ShellcodeObserver>) -> Self {
        self.observers.push(observer);
        self
    }

    /// Append NOP sled
    pub fn with_nop_sled(mut self, count: usize) -> Self {
        self.shellcode.extend(std::iter::repeat(0x90).take(count));
        self
    }

    /// Build the executable shellcode
    pub fn build(self) -> Result<ExecutableShellcode, MapperError> {
        let data = if let Some(encoder) = &self.encoder {
            encoder.decode(&self.shellcode)
        } else {
            self.shellcode
        };

        let mut exec = ExecutableShellcode::from_bytes_with_offset(&data, self.entry_offset)?;

        for observer in self.observers {
            exec.add_observer(observer);
        }

        Ok(exec)
    }
}

impl Default for ShellcodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for shellcode execution
#[derive(Debug, Default)]
pub struct ShellcodeStats {
    pub total_allocations: AtomicUsize,
    pub total_executions: AtomicUsize,
    pub total_bytes_allocated: AtomicUsize,
    pub failed_executions: AtomicUsize,
}

impl ShellcodeStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_allocation(&self, size: usize) {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_allocated.fetch_add(size, Ordering::Relaxed);
    }

    pub fn record_execution(&self, success: bool) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.failed_executions.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> ShellcodeStatsSnapshot {
        ShellcodeStatsSnapshot {
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            total_executions: self.total_executions.load(Ordering::Relaxed),
            total_bytes_allocated: self.total_bytes_allocated.load(Ordering::Relaxed),
            failed_executions: self.failed_executions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShellcodeStatsSnapshot {
    pub total_allocations: usize,
    pub total_executions: usize,
    pub total_bytes_allocated: usize,
    pub failed_executions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_protection_flags() {
        assert!(MemoryProtection::ExecuteRead.is_executable());
        assert!(!MemoryProtection::ReadOnly.is_executable());
        assert!(MemoryProtection::ReadWrite.is_writable());
        assert!(!MemoryProtection::ReadOnly.is_writable());
    }

    #[test]
    fn test_encoder_xor() {
        let encoder = ShellcodeEncoder::new(EncodingScheme::Xor { key: 0x41 });
        let original = vec![0x90, 0x90, 0xCC];
        let encoded = encoder.encode(&original);
        let decoded = encoder.decode(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encoder_rotate() {
        let encoder = ShellcodeEncoder::new(EncodingScheme::RotateLeft { bits: 3 });
        let original = vec![0x90, 0x90, 0xCC];
        let encoded = encoder.encode(&original);
        let decoded = encoder.decode(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_shellcode_region_allocation() {
        let region = ShellcodeRegion::allocate(4096, MemoryProtection::ReadWrite);
        assert!(region.is_ok());
        let region = region.unwrap();
        assert_eq!(region.size(), 4096);
        assert_eq!(region.protection(), MemoryProtection::ReadWrite);
    }

    #[test]
    fn test_shellcode_region_write_read() {
        let mut region = ShellcodeRegion::allocate(4096, MemoryProtection::ReadWrite).unwrap();
        let data = vec![0x90, 0x90, 0xCC, 0xC3];
        region.write(0, &data).unwrap();
        let read_data = region.read(0, data.len()).unwrap();
        assert_eq!(data, read_data);
    }

    #[test]
    fn test_shellcode_builder() {
        let builder = ShellcodeBuilder::new()
            .with_nop_sled(10)
            .with_bytes(&[0xCC, 0xC3])
            .with_entry_offset(10);

        // Note: actual execution would require valid shellcode
        // This test just verifies the builder pattern works
        assert!(builder.shellcode.len() == 12);
    }

    #[test]
    fn test_shellcode_stats() {
        let stats = ShellcodeStats::new();
        stats.record_allocation(4096);
        stats.record_execution(true);
        stats.record_execution(false);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_allocations, 1);
        assert_eq!(snapshot.total_executions, 2);
        assert_eq!(snapshot.failed_executions, 1);
        assert_eq!(snapshot.total_bytes_allocated, 4096);
    }

    #[test]
    fn test_factory_creation() {
        let factory = ShellcodeFactory::new()
            .with_encoder(ShellcodeEncoder::new(EncodingScheme::None));

        // Simple test shellcode (just a return)
        let shellcode = vec![0xC3];
        let result = factory.create(&shellcode);
        assert!(result.is_ok());
    }
}