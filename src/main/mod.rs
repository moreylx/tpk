//! Main module for NT Mapper - Process management and memory operations
//! 
//! This module provides the core functionality for process enumeration,
//! memory manipulation, and system-level operations using Windows NT APIs.

mod process;
mod memory;
mod system;

pub use process::*;
pub use memory::*;
pub use system::*;

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Once};
use std::ffi::CString;

/// Global initialization guard
static INIT: Once = Once::new();
static mut GLOBAL_CONTEXT: Option<Arc<RwLock<MapperContext>>> = None;

/// Process identifier type alias for clarity
pub type ProcessId = u32;
pub type ThreadId = u32;

/// Memory protection flags
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
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400,
}

impl MemoryProtection {
    pub fn from_raw(value: u32) -> Option<Self> {
        match value {
            0x01 => Some(Self::NoAccess),
            0x02 => Some(Self::ReadOnly),
            0x04 => Some(Self::ReadWrite),
            0x08 => Some(Self::WriteCopy),
            0x10 => Some(Self::Execute),
            0x20 => Some(Self::ExecuteRead),
            0x40 => Some(Self::ExecuteReadWrite),
            0x80 => Some(Self::ExecuteWriteCopy),
            0x100 => Some(Self::Guard),
            0x200 => Some(Self::NoCache),
            0x400 => Some(Self::WriteCombine),
            _ => None,
        }
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

/// Memory allocation type flags
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

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: MemoryState,
    pub protect: u32,
    pub region_type: MemoryType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Private,
    Mapped,
    Image,
}

/// Process information structure
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: ProcessId,
    pub parent_pid: ProcessId,
    pub name: String,
    pub path: Option<String>,
    pub thread_count: u32,
    pub base_priority: i32,
    pub handle_count: u32,
    pub session_id: u32,
}

/// Thread information structure
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub tid: ThreadId,
    pub owner_pid: ProcessId,
    pub base_priority: i32,
    pub priority: i32,
    pub start_address: usize,
    pub state: ThreadState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    Unknown,
}

/// Module information structure
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
    pub entry_point: usize,
    pub name: String,
    pub path: String,
}

/// Global mapper context for managing state
pub struct MapperContext {
    process_cache: HashMap<ProcessId, ProcessInfo>,
    module_cache: HashMap<ProcessId, Vec<ModuleInfo>>,
    observers: Vec<Box<dyn ProcessObserver + Send + Sync>>,
    active_handles: Vec<SafeHandle>,
}

impl MapperContext {
    fn new() -> Self {
        Self {
            process_cache: HashMap::new(),
            module_cache: HashMap::new(),
            observers: Vec::new(),
            active_handles: Vec::new(),
        }
    }

    pub fn register_observer(&mut self, observer: Box<dyn ProcessObserver + Send + Sync>) {
        self.observers.push(observer);
    }

    pub fn notify_process_event(&self, event: ProcessEvent) {
        for observer in &self.observers {
            observer.on_process_event(&event);
        }
    }

    pub fn cache_process(&mut self, info: ProcessInfo) {
        self.process_cache.insert(info.pid, info);
    }

    pub fn get_cached_process(&self, pid: ProcessId) -> Option<&ProcessInfo> {
        self.process_cache.get(&pid)
    }

    pub fn invalidate_cache(&mut self) {
        self.process_cache.clear();
        self.module_cache.clear();
    }
}

/// Observer pattern trait for process events
pub trait ProcessObserver {
    fn on_process_event(&self, event: &ProcessEvent);
}

/// Process events for observer notification
#[derive(Debug, Clone)]
pub enum ProcessEvent {
    Created { pid: ProcessId, name: String },
    Terminated { pid: ProcessId, exit_code: i32 },
    ModuleLoaded { pid: ProcessId, module: ModuleInfo },
    ModuleUnloaded { pid: ProcessId, base_address: usize },
    MemoryAllocated { pid: ProcessId, address: usize, size: usize },
    MemoryFreed { pid: ProcessId, address: usize },
}

/// Strategy pattern for memory scanning
pub trait MemoryScanStrategy {
    fn scan(&self, buffer: &[u8], pattern: &[u8], mask: Option<&[u8]>) -> Vec<usize>;
}

/// Boyer-Moore-Horspool scanning strategy
pub struct BoyerMooreScanner;

impl MemoryScanStrategy for BoyerMooreScanner {
    fn scan(&self, buffer: &[u8], pattern: &[u8], mask: Option<&[u8]>) -> Vec<usize> {
        if pattern.is_empty() || buffer.len() < pattern.len() {
            return Vec::new();
        }

        let mut results = Vec::new();
        let pattern_len = pattern.len();
        
        // Build bad character table
        let mut bad_char = [pattern_len; 256];
        for (i, &byte) in pattern.iter().enumerate().take(pattern_len - 1) {
            bad_char[byte as usize] = pattern_len - 1 - i;
        }

        let mut i = pattern_len - 1;
        while i < buffer.len() {
            let mut j = pattern_len - 1;
            let mut k = i;
            
            loop {
                let matches = match mask {
                    Some(m) => m[j] == b'?' || buffer[k] == pattern[j],
                    None => buffer[k] == pattern[j],
                };

                if !matches {
                    break;
                }

                if j == 0 {
                    results.push(k);
                    break;
                }

                j -= 1;
                k -= 1;
            }

            i += bad_char[buffer[i] as usize];
        }

        results
    }
}

/// Simple linear scanning strategy
pub struct LinearScanner;

impl MemoryScanStrategy for LinearScanner {
    fn scan(&self, buffer: &[u8], pattern: &[u8], mask: Option<&[u8]>) -> Vec<usize> {
        if pattern.is_empty() || buffer.len() < pattern.len() {
            return Vec::new();
        }

        let mut results = Vec::new();
        
        'outer: for i in 0..=(buffer.len() - pattern.len()) {
            for (j, &p) in pattern.iter().enumerate() {
                let matches = match mask {
                    Some(m) => m[j] == b'?' || buffer[i + j] == p,
                    None => buffer[i + j] == p,
                };
                
                if !matches {
                    continue 'outer;
                }
            }
            results.push(i);
        }

        results
    }
}

/// Factory for creating process handles with appropriate access rights
pub struct ProcessHandleFactory;

impl ProcessHandleFactory {
    pub const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
    pub const PROCESS_VM_READ: u32 = 0x0010;
    pub const PROCESS_VM_WRITE: u32 = 0x0020;
    pub const PROCESS_VM_OPERATION: u32 = 0x0008;
    pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    pub fn create_read_handle(_pid: ProcessId) -> Result<SafeHandle, MapperError> {
        // TODO: Implement actual handle creation via NtOpenProcess
        Err(MapperError::NotImplemented("ProcessHandleFactory::create_read_handle"))
    }

    pub fn create_write_handle(_pid: ProcessId) -> Result<SafeHandle, MapperError> {
        // TODO: Implement actual handle creation via NtOpenProcess
        Err(MapperError::NotImplemented("ProcessHandleFactory::create_write_handle"))
    }

    pub fn create_full_access_handle(_pid: ProcessId) -> Result<SafeHandle, MapperError> {
        // TODO: Implement actual handle creation via NtOpenProcess
        Err(MapperError::NotImplemented("ProcessHandleFactory::create_full_access_handle"))
    }
}

/// Memory scanner with configurable strategy
pub struct MemoryScanner<S: MemoryScanStrategy> {
    strategy: S,
}

impl<S: MemoryScanStrategy> MemoryScanner<S> {
    pub fn new(strategy: S) -> Self {
        Self { strategy }
    }

    pub fn find_pattern(&self, buffer: &[u8], pattern: &[u8]) -> Vec<usize> {
        self.strategy.scan(buffer, pattern, None)
    }

    pub fn find_pattern_masked(&self, buffer: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
        self.strategy.scan(buffer, pattern, Some(mask))
    }

    /// Parse IDA-style pattern string (e.g., "48 8B ? ? 90")
    pub fn parse_ida_pattern(pattern_str: &str) -> (Vec<u8>, Vec<u8>) {
        let mut pattern = Vec::new();
        let mut mask = Vec::new();

        for part in pattern_str.split_whitespace() {
            if part == "?" || part == "??" {
                pattern.push(0);
                mask.push(b'?');
            } else if let Ok(byte) = u8::from_str_radix(part, 16) {
                pattern.push(byte);
                mask.push(b'x');
            }
        }

        (pattern, mask)
    }
}

/// Initialize the mapper subsystem
pub fn initialize_mapper() -> Result<(), MapperError> {
    let mut result = Ok(());
    
    INIT.call_once(|| {
        if !crate::is_initialized() {
            if let Err(e) = crate::initialize() {
                result = Err(MapperError::InitializationFailed(format!("{:?}", e)));
                return;
            }
        }

        unsafe {
            GLOBAL_CONTEXT = Some(Arc::new(RwLock::new(MapperContext::new())));
        }
    });

    result
}

/// Get the global mapper context
pub fn get_context() -> Option<Arc<RwLock<MapperContext>>> {
    unsafe { GLOBAL_CONTEXT.clone() }
}

/// Shutdown the mapper subsystem
pub fn shutdown_mapper() -> Result<(), MapperError> {
    unsafe {
        if let Some(ctx) = GLOBAL_CONTEXT.take() {
            if let Ok(mut guard) = ctx.write() {
                guard.invalidate_cache();
                guard.active_handles.clear();
            }
        }
    }
    
    crate::shutdown();
    Ok(())
}

/// Read memory from a process
pub fn read_process_memory<T: Copy>(
    _handle: &SafeHandle,
    _address: usize,
) -> Result<T, MapperError> {
    // TODO: Implement via NtReadVirtualMemory
    Err(MapperError::NotImplemented("read_process_memory"))
}

/// Read a buffer from process memory
pub fn read_process_memory_buffer(
    _handle: &SafeHandle,
    _address: usize,
    _size: usize,
) -> Result<Vec<u8>, MapperError> {
    // TODO: Implement via NtReadVirtualMemory
    Err(MapperError::NotImplemented("read_process_memory_buffer"))
}

/// Write memory to a process
pub fn write_process_memory<T: Copy>(
    _handle: &SafeHandle,
    _address: usize,
    _value: &T,
) -> Result<usize, MapperError> {
    // TODO: Implement via NtWriteVirtualMemory
    Err(MapperError::NotImplemented("write_process_memory"))
}

/// Write a buffer to process memory
pub fn write_process_memory_buffer(
    _handle: &SafeHandle,
    _address: usize,
    _buffer: &[u8],
) -> Result<usize, MapperError> {
    // TODO: Implement via NtWriteVirtualMemory
    Err(MapperError::NotImplemented("write_process_memory_buffer"))
}

/// Allocate memory in a remote process
pub fn allocate_remote_memory(
    _handle: &SafeHandle,
    _size: usize,
    _protection: MemoryProtection,
    _allocation_type: AllocationType,
) -> Result<usize, MapperError> {
    // TODO: Implement via NtAllocateVirtualMemory
    Err(MapperError::NotImplemented("allocate_remote_memory"))
}

/// Free memory in a remote process
pub fn free_remote_memory(
    _handle: &SafeHandle,
    _address: usize,
) -> Result<(), MapperError> {
    // TODO: Implement via NtFreeVirtualMemory
    Err(MapperError::NotImplemented("free_remote_memory"))
}

/// Query memory region information
pub fn query_memory_region(
    _handle: &SafeHandle,
    _address: usize,
) -> Result<MemoryRegion, MapperError> {
    // TODO: Implement via NtQueryVirtualMemory
    Err(MapperError::NotImplemented("query_memory_region"))
}

/// Enumerate all memory regions in a process
pub fn enumerate_memory_regions(
    handle: &SafeHandle,
) -> Result<Vec<MemoryRegion>, MapperError> {
    let mut regions = Vec::new();
    let mut address: usize = 0;
    
    loop {
        match query_memory_region(handle, address) {
            Ok(region) => {
                let next_address = region.base_address.saturating_add(region.region_size);
                if next_address <= address {
                    break;
                }
                address = next_address;
                regions.push(region);
            }
            Err(MapperError::NotImplemented(_)) => {
                return Err(MapperError::NotImplemented("enumerate_memory_regions"));
            }
            Err(_) => break,
        }
    }

    Ok(regions)
}

/// Enumerate all processes on the system
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>, MapperError> {
    // TODO: Implement via NtQuerySystemInformation
    Err(MapperError::NotImplemented("enumerate_processes"))
}

/// Find a process by name
pub fn find_process_by_name(name: &str) -> Result<Option<ProcessInfo>, MapperError> {
    let processes = enumerate_processes()?;
    Ok(processes.into_iter().find(|p| p.name.eq_ignore_ascii_case(name)))
}

/// Enumerate modules in a process
pub fn enumerate_modules(_handle: &SafeHandle) -> Result<Vec<ModuleInfo>, MapperError> {
    // TODO: Implement via NtQueryInformationProcess + walking PEB
    Err(MapperError::NotImplemented("enumerate_modules"))
}

/// Find a module by name in a process
pub fn find_module_by_name(
    handle: &SafeHandle,
    name: &str,
) -> Result<Option<ModuleInfo>, MapperError> {
    let modules = enumerate_modules(handle)?;
    Ok(modules.into_iter().find(|m| m.name.eq_ignore_ascii_case(name)))
}

/// Enumerate threads in a process
pub fn enumerate_threads(_pid: ProcessId) -> Result<Vec<ThreadInfo>, MapperError> {
    // TODO: Implement via NtQuerySystemInformation
    Err(MapperError::NotImplemented("enumerate_threads"))
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
    fn test_linear_scanner() {
        let scanner = MemoryScanner::new(LinearScanner);
        let buffer = vec![0x48, 0x8B, 0x05, 0x12, 0x34, 0x48, 0x8B, 0x05, 0x56, 0x78];
        let pattern = vec![0x48, 0x8B, 0x05];
        
        let results = scanner.find_pattern(&buffer, &pattern);
        assert_eq!(results, vec![0, 5]);
    }

    #[test]
    fn test_masked_scan() {
        let scanner = MemoryScanner::new(LinearScanner);
        let buffer = vec![0x48, 0x8B, 0x05, 0x12, 0x34, 0x48, 0x8B, 0x0D, 0x56, 0x78];
        let pattern = vec![0x48, 0x8B, 0x00];
        let mask = vec![b'x', b'x', b'?'];
        
        let results = scanner.find_pattern_masked(&buffer, &pattern, &mask);
        assert_eq!(results, vec![0, 5]);
    }

    #[test]
    fn test_ida_pattern_parsing() {
        let (pattern, mask) = MemoryScanner::<LinearScanner>::parse_ida_pattern("48 8B ? 12 34");
        assert_eq!(pattern, vec![0x48, 0x8B, 0x00, 0x12, 0x34]);
        assert_eq!(mask, vec![b'x', b'x', b'?', b'x', b'x']);
    }

    #[test]
    fn test_boyer_moore_scanner() {
        let scanner = MemoryScanner::new(BoyerMooreScanner);
        let buffer = vec![0x90, 0x90, 0x48, 0x8B, 0x05, 0x90, 0x90];
        let pattern = vec![0x48, 0x8B, 0x05];
        
        let results = scanner.find_pattern(&buffer, &pattern);
        assert_eq!(results, vec![2]);
    }
}