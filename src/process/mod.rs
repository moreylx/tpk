//! Process management module for NT Mapper
//! 
//! Provides safe abstractions for Windows process and thread operations,
//! including process enumeration, memory operations, and thread management.

mod thread;
mod memory;

pub use thread::*;
pub use memory::*;

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::mem;
use std::sync::Arc;
use std::collections::HashMap;

use windows_sys::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, CloseHandle, BOOL, GetLastError,
    ERROR_NO_MORE_FILES, STILL_ACTIVE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, GetCurrentProcessId, GetCurrentProcess,
    GetExitCodeProcess, TerminateProcess, GetProcessId,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_TERMINATE,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32EnumProcessModules, K32GetModuleBaseNameW, K32GetModuleInformation,
    MODULEINFO,
};

use crate::error::{MapperError, NtStatus};

/// Process access rights for opening processes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessAccess(u32);

impl ProcessAccess {
    pub const ALL: Self = Self(PROCESS_ALL_ACCESS);
    pub const QUERY_INFO: Self = Self(PROCESS_QUERY_INFORMATION);
    pub const QUERY_LIMITED: Self = Self(PROCESS_QUERY_LIMITED_INFORMATION);
    pub const VM_READ: Self = Self(PROCESS_VM_READ);
    pub const VM_WRITE: Self = Self(PROCESS_VM_WRITE);
    pub const VM_OPERATION: Self = Self(PROCESS_VM_OPERATION);
    pub const TERMINATE: Self = Self(PROCESS_TERMINATE);
    pub const CREATE_THREAD: Self = Self(PROCESS_CREATE_THREAD);
    
    /// Combine multiple access rights
    pub fn combine(rights: &[ProcessAccess]) -> Self {
        let combined = rights.iter().fold(0u32, |acc, r| acc | r.0);
        Self(combined)
    }
    
    /// Get the raw access value
    pub fn raw(&self) -> u32 {
        self.0
    }
    
    /// Check if this access includes another
    pub fn includes(&self, other: ProcessAccess) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for ProcessAccess {
    type Output = Self;
    
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ProcessAccess {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// RAII wrapper for process handles
#[derive(Debug)]
pub struct ProcessHandle {
    handle: HANDLE,
    pid: u32,
    owned: bool,
}

impl ProcessHandle {
    /// Open a process by its ID with specified access rights
    pub fn open(pid: u32, access: ProcessAccess) -> Result<Self, MapperError> {
        let handle = unsafe { OpenProcess(access.raw(), 0, pid) };
        
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return Err(MapperError::ProcessOpenFailed {
                pid,
                error_code: unsafe { GetLastError() },
            });
        }
        
        Ok(Self {
            handle,
            pid,
            owned: true,
        })
    }
    
    /// Get a handle to the current process (not owned, won't be closed)
    pub fn current() -> Self {
        Self {
            handle: unsafe { GetCurrentProcess() },
            pid: unsafe { GetCurrentProcessId() },
            owned: false,
        }
    }
    
    /// Create from a raw handle (takes ownership)
    /// 
    /// # Safety
    /// The caller must ensure the handle is valid and can be owned
    pub unsafe fn from_raw_owned(handle: HANDLE, pid: u32) -> Self {
        Self {
            handle,
            pid,
            owned: true,
        }
    }
    
    /// Create from a raw handle without taking ownership
    /// 
    /// # Safety
    /// The caller must ensure the handle remains valid for the lifetime of this wrapper
    pub unsafe fn from_raw_borrowed(handle: HANDLE, pid: u32) -> Self {
        Self {
            handle,
            pid,
            owned: false,
        }
    }
    
    /// Get the raw handle value
    pub fn raw(&self) -> HANDLE {
        self.handle
    }
    
    /// Get the process ID
    pub fn pid(&self) -> u32 {
        self.pid
    }
    
    /// Check if the process is still running
    pub fn is_running(&self) -> Result<bool, MapperError> {
        let mut exit_code: u32 = 0;
        let result = unsafe { GetExitCodeProcess(self.handle, &mut exit_code) };
        
        if result == 0 {
            return Err(MapperError::SystemCallFailed {
                function: "GetExitCodeProcess",
                error_code: unsafe { GetLastError() },
            });
        }
        
        Ok(exit_code == STILL_ACTIVE)
    }
    
    /// Get the exit code if the process has terminated
    pub fn exit_code(&self) -> Result<Option<u32>, MapperError> {
        let mut exit_code: u32 = 0;
        let result = unsafe { GetExitCodeProcess(self.handle, &mut exit_code) };
        
        if result == 0 {
            return Err(MapperError::SystemCallFailed {
                function: "GetExitCodeProcess",
                error_code: unsafe { GetLastError() },
            });
        }
        
        if exit_code == STILL_ACTIVE {
            Ok(None)
        } else {
            Ok(Some(exit_code))
        }
    }
    
    /// Terminate the process with the specified exit code
    pub fn terminate(&self, exit_code: u32) -> Result<(), MapperError> {
        let result = unsafe { TerminateProcess(self.handle, exit_code) };
        
        if result == 0 {
            return Err(MapperError::SystemCallFailed {
                function: "TerminateProcess",
                error_code: unsafe { GetLastError() },
            });
        }
        
        Ok(())
    }
    
    /// Duplicate this handle (creates a new owned handle)
    pub fn duplicate(&self) -> Result<Self, MapperError> {
        use windows_sys::Win32::Foundation::DuplicateHandle;
        use windows_sys::Win32::System::Threading::DUPLICATE_SAME_ACCESS;
        
        let current = unsafe { GetCurrentProcess() };
        let mut new_handle: HANDLE = 0;
        
        let result = unsafe {
            DuplicateHandle(
                current,
                self.handle,
                current,
                &mut new_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        
        if result == 0 {
            return Err(MapperError::SystemCallFailed {
                function: "DuplicateHandle",
                error_code: unsafe { GetLastError() },
            });
        }
        
        Ok(Self {
            handle: new_handle,
            pid: self.pid,
            owned: true,
        })
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.owned && self.handle != 0 && self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

// ProcessHandle is Send but not Sync (handle operations aren't thread-safe)
unsafe impl Send for ProcessHandle {}

/// Information about a running process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub base_priority: i32,
    pub name: String,
}

impl ProcessInfo {
    fn from_entry(entry: &PROCESSENTRY32W) -> Self {
        let name_len = entry.szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        
        let name = OsString::from_wide(&entry.szExeFile[..name_len])
            .to_string_lossy()
            .into_owned();
        
        Self {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            thread_count: entry.cntThreads,
            base_priority: entry.pcPriClassBase as i32,
            name,
        }
    }
}

/// Information about a loaded module
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
    pub entry_point: usize,
    pub name: String,
}

/// Strategy trait for process filtering during enumeration
pub trait ProcessFilter: Send + Sync {
    fn matches(&self, info: &ProcessInfo) -> bool;
}

/// Filter that matches all processes
pub struct AllProcessesFilter;

impl ProcessFilter for AllProcessesFilter {
    fn matches(&self, _info: &ProcessInfo) -> bool {
        true
    }
}

/// Filter by process name (case-insensitive)
pub struct NameFilter {
    name: String,
    exact: bool,
}

impl NameFilter {
    pub fn exact(name: impl Into<String>) -> Self {
        Self {
            name: name.into().to_lowercase(),
            exact: true,
        }
    }
    
    pub fn contains(name: impl Into<String>) -> Self {
        Self {
            name: name.into().to_lowercase(),
            exact: false,
        }
    }
}

impl ProcessFilter for NameFilter {
    fn matches(&self, info: &ProcessInfo) -> bool {
        let process_name = info.name.to_lowercase();
        if self.exact {
            process_name == self.name
        } else {
            process_name.contains(&self.name)
        }
    }
}

/// Filter by process ID
pub struct PidFilter {
    pids: Vec<u32>,
}

impl PidFilter {
    pub fn new(pids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            pids: pids.into_iter().collect(),
        }
    }
    
    pub fn single(pid: u32) -> Self {
        Self { pids: vec![pid] }
    }
}

impl ProcessFilter for PidFilter {
    fn matches(&self, info: &ProcessInfo) -> bool {
        self.pids.contains(&info.pid)
    }
}

/// Composite filter combining multiple filters with AND logic
pub struct CompositeFilter {
    filters: Vec<Box<dyn ProcessFilter>>,
}

impl CompositeFilter {
    pub fn new() -> Self {
        Self { filters: Vec::new() }
    }
    
    pub fn add<F: ProcessFilter + 'static>(mut self, filter: F) -> Self {
        self.filters.push(Box::new(filter));
        self
    }
}

impl Default for CompositeFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessFilter for CompositeFilter {
    fn matches(&self, info: &ProcessInfo) -> bool {
        self.filters.iter().all(|f| f.matches(info))
    }
}

/// Observer trait for process enumeration events
pub trait ProcessObserver: Send + Sync {
    fn on_process_found(&self, info: &ProcessInfo);
    fn on_enumeration_complete(&self, count: usize);
    fn on_enumeration_error(&self, error: &MapperError);
}

/// Default observer that does nothing
pub struct NullObserver;

impl ProcessObserver for NullObserver {
    fn on_process_found(&self, _info: &ProcessInfo) {}
    fn on_enumeration_complete(&self, _count: usize) {}
    fn on_enumeration_error(&self, _error: &MapperError) {}
}

/// Logging observer for debugging
pub struct LoggingObserver {
    prefix: String,
}

impl LoggingObserver {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefix: prefix.into() }
    }
}

impl ProcessObserver for LoggingObserver {
    fn on_process_found(&self, info: &ProcessInfo) {
        eprintln!("{} Found process: {} (PID: {})", self.prefix, info.name, info.pid);
    }
    
    fn on_enumeration_complete(&self, count: usize) {
        eprintln!("{} Enumeration complete: {} processes found", self.prefix, count);
    }
    
    fn on_enumeration_error(&self, error: &MapperError) {
        eprintln!("{} Enumeration error: {:?}", self.prefix, error);
    }
}

/// Process enumerator with configurable filtering and observation
pub struct ProcessEnumerator {
    filter: Box<dyn ProcessFilter>,
    observers: Vec<Arc<dyn ProcessObserver>>,
}

impl ProcessEnumerator {
    /// Create a new enumerator with default settings (all processes, no observers)
    pub fn new() -> Self {
        Self {
            filter: Box::new(AllProcessesFilter),
            observers: Vec::new(),
        }
    }
    
    /// Set the filter for process enumeration
    pub fn with_filter<F: ProcessFilter + 'static>(mut self, filter: F) -> Self {
        self.filter = Box::new(filter);
        self
    }
    
    /// Add an observer for enumeration events
    pub fn with_observer<O: ProcessObserver + 'static>(mut self, observer: Arc<O>) -> Self {
        self.observers.push(observer);
        self
    }
    
    /// Enumerate all matching processes
    pub fn enumerate(&self) -> Result<Vec<ProcessInfo>, MapperError> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        
        if snapshot == INVALID_HANDLE_VALUE {
            let error = MapperError::SystemCallFailed {
                function: "CreateToolhelp32Snapshot",
                error_code: unsafe { GetLastError() },
            };
            self.notify_error(&error);
            return Err(error);
        }
        
        // RAII cleanup for snapshot handle
        struct SnapshotGuard(HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let _guard = SnapshotGuard(snapshot);
        
        let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        
        let mut processes = Vec::new();
        
        // Get first process
        if unsafe { Process32FirstW(snapshot, &mut entry) } == 0 {
            let error_code = unsafe { GetLastError() };
            if error_code != ERROR_NO_MORE_FILES {
                let error = MapperError::SystemCallFailed {
                    function: "Process32FirstW",
                    error_code,
                };
                self.notify_error(&error);
                return Err(error);
            }
            self.notify_complete(0);
            return Ok(processes);
        }
        
        loop {
            let info = ProcessInfo::from_entry(&entry);
            
            if self.filter.matches(&info) {
                self.notify_found(&info);
                processes.push(info);
            }
            
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                let error_code = unsafe { GetLastError() };
                if error_code != ERROR_NO_MORE_FILES {
                    let error = MapperError::SystemCallFailed {
                        function: "Process32NextW",
                        error_code,
                    };
                    self.notify_error(&error);
                    return Err(error);
                }
                break;
            }
        }
        
        self.notify_complete(processes.len());
        Ok(processes)
    }
    
    fn notify_found(&self, info: &ProcessInfo) {
        for observer in &self.observers {
            observer.on_process_found(info);
        }
    }
    
    fn notify_complete(&self, count: usize) {
        for observer in &self.observers {
            observer.on_enumeration_complete(count);
        }
    }
    
    fn notify_error(&self, error: &MapperError) {
        for observer in &self.observers {
            observer.on_enumeration_error(error);
        }
    }
}

impl Default for ProcessEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating process handles with common configurations
pub struct ProcessHandleFactory;

impl ProcessHandleFactory {
    /// Open a process for reading memory
    pub fn for_memory_read(pid: u32) -> Result<ProcessHandle, MapperError> {
        ProcessHandle::open(pid, ProcessAccess::VM_READ | ProcessAccess::QUERY_INFO)
    }
    
    /// Open a process for writing memory
    pub fn for_memory_write(pid: u32) -> Result<ProcessHandle, MapperError> {
        ProcessHandle::open(
            pid,
            ProcessAccess::VM_READ | ProcessAccess::VM_WRITE | ProcessAccess::VM_OPERATION,
        )
    }
    
    /// Open a process for injection operations
    pub fn for_injection(pid: u32) -> Result<ProcessHandle, MapperError> {
        ProcessHandle::open(
            pid,
            ProcessAccess::VM_READ 
                | ProcessAccess::VM_WRITE 
                | ProcessAccess::VM_OPERATION
                | ProcessAccess::CREATE_THREAD
                | ProcessAccess::QUERY_INFO,
        )
    }
    
    /// Open a process with full access
    pub fn with_full_access(pid: u32) -> Result<ProcessHandle, MapperError> {
        ProcessHandle::open(pid, ProcessAccess::ALL)
    }
    
    /// Open a process for termination
    pub fn for_termination(pid: u32) -> Result<ProcessHandle, MapperError> {
        ProcessHandle::open(pid, ProcessAccess::TERMINATE)
    }
}

/// Get the current process ID
pub fn current_process_id() -> u32 {
    unsafe { GetCurrentProcessId() }
}

/// Find a process by name (returns first match)
pub fn find_process_by_name(name: &str) -> Result<Option<ProcessInfo>, MapperError> {
    let enumerator = ProcessEnumerator::new()
        .with_filter(NameFilter::exact(name));
    
    let processes = enumerator.enumerate()?;
    Ok(processes.into_iter().next())
}

/// Find all processes matching a name pattern
pub fn find_processes_by_name(name: &str) -> Result<Vec<ProcessInfo>, MapperError> {
    let enumerator = ProcessEnumerator::new()
        .with_filter(NameFilter::contains(name));
    
    enumerator.enumerate()
}

/// Get information about a specific process by PID
pub fn get_process_info(pid: u32) -> Result<Option<ProcessInfo>, MapperError> {
    let enumerator = ProcessEnumerator::new()
        .with_filter(PidFilter::single(pid));
    
    let processes = enumerator.enumerate()?;
    Ok(processes.into_iter().next())
}

/// Enumerate modules loaded in a process
pub fn enumerate_modules(handle: &ProcessHandle) -> Result<Vec<ModuleInfo>, MapperError> {
    const MAX_MODULES: usize = 1024;
    let mut module_handles: [HANDLE; MAX_MODULES] = [0; MAX_MODULES];
    let mut bytes_needed: u32 = 0;
    
    let result = unsafe {
        K32EnumProcessModules(
            handle.raw(),
            module_handles.as_mut_ptr() as *mut _,
            (MAX_MODULES * mem::size_of::<HANDLE>()) as u32,
            &mut bytes_needed,
        )
    };
    
    if result == 0 {
        return Err(MapperError::SystemCallFailed {
            function: "K32EnumProcessModules",
            error_code: unsafe { GetLastError() },
        });
    }
    
    let module_count = (bytes_needed as usize) / mem::size_of::<HANDLE>();
    let mut modules = Vec::with_capacity(module_count);
    
    for i in 0..module_count {
        let module_handle = module_handles[i];
        
        // Get module name
        let mut name_buffer: [u16; 260] = [0; 260];
        let name_len = unsafe {
            K32GetModuleBaseNameW(
                handle.raw(),
                module_handle,
                name_buffer.as_mut_ptr(),
                name_buffer.len() as u32,
            )
        };
        
        let name = if name_len > 0 {
            OsString::from_wide(&name_buffer[..name_len as usize])
                .to_string_lossy()
                .into_owned()
        } else {
            String::from("<unknown>")
        };
        
        // Get module info
        let mut mod_info: MODULEINFO = unsafe { mem::zeroed() };
        let info_result = unsafe {
            K32GetModuleInformation(
                handle.raw(),
                module_handle,
                &mut mod_info,
                mem::size_of::<MODULEINFO>() as u32,
            )
        };
        
        if info_result != 0 {
            modules.push(ModuleInfo {
                base_address: mod_info.lpBaseOfDll as usize,
                size: mod_info.SizeOfImage as usize,
                entry_point: mod_info.EntryPoint as usize,
                name,
            });
        }
    }
    
    Ok(modules)
}

/// Find a module by name in a process
pub fn find_module(handle: &ProcessHandle, module_name: &str) -> Result<Option<ModuleInfo>, MapperError> {
    let modules = enumerate_modules(handle)?;
    let target = module_name.to_lowercase();
    
    Ok(modules.into_iter().find(|m| m.name.to_lowercase() == target))
}

/// Process cache for frequently accessed process information
pub struct ProcessCache {
    cache: HashMap<u32, ProcessInfo>,
    max_age_ms: u64,
    last_refresh: std::time::Instant,
}

impl ProcessCache {
    pub fn new(max_age_ms: u64) -> Self {
        Self {
            cache: HashMap::new(),
            max_age_ms,
            last_refresh: std::time::Instant::now(),
        }
    }
    
    /// Refresh the cache if it's stale
    pub fn refresh_if_needed(&mut self) -> Result<(), MapperError> {
        let elapsed = self.last_refresh.elapsed().as_millis() as u64;
        if elapsed >= self.max_age_ms {
            self.refresh()?;
        }
        Ok(())
    }
    
    /// Force a cache refresh
    pub fn refresh(&mut self) -> Result<(), MapperError> {
        let enumerator = ProcessEnumerator::new();
        let processes = enumerator.enumerate()?;
        
        self.cache.clear();
        for process in processes {
            self.cache.insert(process.pid, process);
        }
        
        self.last_refresh = std::time::Instant::now();
        Ok(())
    }
    
    /// Get a process by PID from cache
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.cache.get(&pid)
    }
    
    /// Find processes by name in cache
    pub fn find_by_name(&self, name: &str) -> Vec<&ProcessInfo> {
        let target = name.to_lowercase();
        self.cache
            .values()
            .filter(|p| p.name.to_lowercase().contains(&target))
            .collect()
    }
    
    /// Get all cached processes
    pub fn all(&self) -> impl Iterator<Item = &ProcessInfo> {
        self.cache.values()
    }
    
    /// Check if cache is stale
    pub fn is_stale(&self) -> bool {
        self.last_refresh.elapsed().as_millis() as u64 >= self.max_age_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_process_access_combine() {
        let combined = ProcessAccess::combine(&[
            ProcessAccess::VM_READ,
            ProcessAccess::VM_WRITE,
        ]);
        
        assert!(combined.includes(ProcessAccess::VM_READ));
        assert!(combined.includes(ProcessAccess::VM_WRITE));
        assert!(!combined.includes(ProcessAccess::TERMINATE));
    }
    
    #[test]
    fn test_process_access_bitor() {
        let access = ProcessAccess::VM_READ | ProcessAccess::QUERY_INFO;
        assert!(access.includes(ProcessAccess::VM_READ));
        assert!(access.includes(ProcessAccess::QUERY_INFO));
    }
    
    #[test]
    fn test_current_process() {
        let handle = ProcessHandle::current();
        assert_eq!(handle.pid(), current_process_id());
        assert!(handle.is_running().unwrap());
    }
    
    #[test]
    fn test_name_filter_exact() {
        let filter = NameFilter::exact("test.exe");
        
        let info = ProcessInfo {
            pid: 1,
            parent_pid: 0,
            thread_count: 1,
            base_priority: 0,
            name: "test.exe".to_string(),
        };
        
        assert!(filter.matches(&info));
        
        let info2 = ProcessInfo {
            pid: 2,
            parent_pid: 0,
            thread_count: 1,
            base_priority: 0,
            name: "other.exe".to_string(),
        };
        
        assert!(!filter.matches(&info2));
    }
    
    #[test]
    fn test_name_filter_contains() {
        let filter = NameFilter::contains("test");
        
        let info = ProcessInfo {
            pid: 1,
            parent_pid: 0,
            thread_count: 1,
            base_priority: 0,
            name: "mytest.exe".to_string(),
        };
        
        assert!(filter.matches(&info));
    }
    
    #[test]
    fn test_composite_filter() {
        let filter = CompositeFilter::new()
            .add(NameFilter::contains("test"))
            .add(PidFilter::new([1, 2, 3]));
        
        let info = ProcessInfo {
            pid: 1,
            parent_pid: 0,
            thread_count: 1,
            base_priority: 0,
            name: "test.exe".to_string(),
        };
        
        assert!(filter.matches(&info));
        
        let info2 = ProcessInfo {
            pid: 999,
            parent_pid: 0,
            thread_count: 1,
            base_priority: 0,
            name: "test.exe".to_string(),
        };
        
        assert!(!filter.matches(&info2));
    }
    
    #[test]
    fn test_process_enumeration() {
        let enumerator = ProcessEnumerator::new();
        let processes = enumerator.enumerate().unwrap();
        
        // Should find at least the current process
        assert!(!processes.is_empty());
        
        let current_pid = current_process_id();
        assert!(processes.iter().any(|p| p.pid == current_pid));
    }
}