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
        Self(rights.iter().fold(0, |acc, r| acc | r.0))
    }
    
    pub fn raw(&self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for ProcessAccess {
    type Output = Self;
    
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Information about a running process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub thread_count: u32,
    pub priority_base: i32,
}

/// Information about a loaded module
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
    pub entry_point: usize,
    pub name: String,
}

/// Safe wrapper around a process handle with RAII cleanup
pub struct ProcessHandle {
    handle: HANDLE,
    pid: u32,
    owns_handle: bool,
}

impl ProcessHandle {
    /// Open a process by PID with specified access rights
    pub fn open(pid: u32, access: ProcessAccess) -> Result<Self, MapperError> {
        let handle = unsafe { OpenProcess(access.raw(), 0, pid) };
        
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return Err(MapperError::from_raw(unsafe { GetLastError() } as i32));
        }
        
        Ok(Self {
            handle,
            pid,
            owns_handle: true,
        })
    }
    
    /// Get a handle to the current process (does not need to be closed)
    pub fn current() -> Self {
        Self {
            handle: unsafe { GetCurrentProcess() },
            pid: unsafe { GetCurrentProcessId() },
            owns_handle: false,
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
            return Err(MapperError::from_raw(unsafe { GetLastError() } as i32));
        }
        
        Ok(exit_code == STILL_ACTIVE)
    }
    
    /// Get the exit code if the process has terminated
    pub fn exit_code(&self) -> Result<Option<u32>, MapperError> {
        let mut exit_code: u32 = 0;
        let result = unsafe { GetExitCodeProcess(self.handle, &mut exit_code) };
        
        if result == 0 {
            return Err(MapperError::from_raw(unsafe { GetLastError() } as i32));
        }
        
        if exit_code == STILL_ACTIVE {
            Ok(None)
        } else {
            Ok(Some(exit_code))
        }
    }
    
    /// Terminate the process with the given exit code
    pub fn terminate(&self, exit_code: u32) -> Result<(), MapperError> {
        let result = unsafe { TerminateProcess(self.handle, exit_code) };
        
        if result == 0 {
            return Err(MapperError::from_raw(unsafe { GetLastError() } as i32));
        }
        
        Ok(())
    }
    
    /// Enumerate loaded modules in the process
    pub fn modules(&self) -> Result<Vec<ModuleInfo>, MapperError> {
        let mut modules: [HANDLE; 1024] = [0; 1024];
        let mut bytes_needed: u32 = 0;
        
        let result = unsafe {
            K32EnumProcessModules(
                self.handle,
                modules.as_mut_ptr() as *mut _,
                (modules.len() * mem::size_of::<HANDLE>()) as u32,
                &mut bytes_needed,
            )
        };
        
        if result == 0 {
            return Err(MapperError::from_raw(unsafe { GetLastError() } as i32));
        }
        
        let module_count = bytes_needed as usize / mem::size_of::<HANDLE>();
        let mut module_infos = Vec::with_capacity(module_count);
        
        for i in 0..module_count {
            let module_handle = modules[i];
            
            // Get module name
            let mut name_buf: [u16; 260] = [0; 260];
            let name_len = unsafe {
                K32GetModuleBaseNameW(
                    self.handle,
                    module_handle,
                    name_buf.as_mut_ptr(),
                    name_buf.len() as u32,
                )
            };
            
            let name = if name_len > 0 {
                OsString::from_wide(&name_buf[..name_len as usize])
                    .to_string_lossy()
                    .into_owned()
            } else {
                String::from("<unknown>")
            };
            
            // Get module info
            let mut mod_info: MODULEINFO = unsafe { mem::zeroed() };
            let info_result = unsafe {
                K32GetModuleInformation(
                    self.handle,
                    module_handle,
                    &mut mod_info,
                    mem::size_of::<MODULEINFO>() as u32,
                )
            };
            
            if info_result != 0 {
                module_infos.push(ModuleInfo {
                    base_address: mod_info.lpBaseOfDll as usize,
                    size: mod_info.SizeOfImage as usize,
                    entry_point: mod_info.EntryPoint as usize,
                    name,
                });
            }
        }
        
        Ok(module_infos)
    }
    
    /// Find a module by name (case-insensitive)
    pub fn find_module(&self, name: &str) -> Result<Option<ModuleInfo>, MapperError> {
        let modules = self.modules()?;
        let name_lower = name.to_lowercase();
        
        Ok(modules.into_iter().find(|m| m.name.to_lowercase() == name_lower))
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.owns_handle && self.handle != 0 && self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

// Safety: ProcessHandle can be sent between threads
unsafe impl Send for ProcessHandle {}

/// Process enumerator using toolhelp snapshots
pub struct ProcessEnumerator {
    snapshot: HANDLE,
    first_call: bool,
}

impl ProcessEnumerator {
    /// Create a new process enumerator
    pub fn new() -> Result<Self, MapperError> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(MapperError::from_raw(unsafe { GetLastError() } as i32));
        }
        
        Ok(Self {
            snapshot,
            first_call: true,
        })
    }
    
    /// Collect all processes into a vector
    pub fn collect_all(self) -> Result<Vec<ProcessInfo>, MapperError> {
        self.collect()
    }
    
    /// Find a process by name (case-insensitive)
    pub fn find_by_name(name: &str) -> Result<Option<ProcessInfo>, MapperError> {
        let name_lower = name.to_lowercase();
        let enumerator = Self::new()?;
        
        for result in enumerator {
            let info = result?;
            if info.name.to_lowercase() == name_lower {
                return Ok(Some(info));
            }
        }
        
        Ok(None)
    }
    
    /// Find all processes matching a name (case-insensitive)
    pub fn find_all_by_name(name: &str) -> Result<Vec<ProcessInfo>, MapperError> {
        let name_lower = name.to_lowercase();
        let enumerator = Self::new()?;
        let mut results = Vec::new();
        
        for result in enumerator {
            let info = result?;
            if info.name.to_lowercase() == name_lower {
                results.push(info);
            }
        }
        
        Ok(results)
    }
}

impl Iterator for ProcessEnumerator {
    type Item = Result<ProcessInfo, MapperError>;
    
    fn next(&mut self) -> Option<Self::Item> {
        let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        
        let result = if self.first_call {
            self.first_call = false;
            unsafe { Process32FirstW(self.snapshot, &mut entry) }
        } else {
            unsafe { Process32NextW(self.snapshot, &mut entry) }
        };
        
        if result == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                return None;
            }
            return Some(Err(MapperError::from_raw(error as i32)));
        }
        
        // Find the null terminator in the name
        let name_len = entry.szExeFile.iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        
        let name = OsString::from_wide(&entry.szExeFile[..name_len])
            .to_string_lossy()
            .into_owned();
        
        Some(Ok(ProcessInfo {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            name,
            thread_count: entry.cntThreads,
            priority_base: entry.pcPriClassBase as i32,
        }))
    }
}

impl Drop for ProcessEnumerator {
    fn drop(&mut self) {
        if self.snapshot != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.snapshot) };
        }
    }
}

/// Observer pattern for process events
pub trait ProcessObserver: Send + Sync {
    fn on_process_start(&self, info: &ProcessInfo);
    fn on_process_exit(&self, pid: u32, exit_code: u32);
    fn on_module_load(&self, pid: u32, module: &ModuleInfo);
}

/// Process watcher that monitors process lifecycle events
pub struct ProcessWatcher {
    observers: Vec<Arc<dyn ProcessObserver>>,
    watched_processes: HashMap<u32, ProcessHandle>,
    // TODO: Implement background monitoring thread
}

impl ProcessWatcher {
    pub fn new() -> Self {
        Self {
            observers: Vec::new(),
            watched_processes: HashMap::new(),
        }
    }
    
    pub fn add_observer(&mut self, observer: Arc<dyn ProcessObserver>) {
        self.observers.push(observer);
    }
    
    pub fn remove_observer(&mut self, observer: &Arc<dyn ProcessObserver>) {
        self.observers.retain(|o| !Arc::ptr_eq(o, observer));
    }
    
    pub fn watch(&mut self, pid: u32) -> Result<(), MapperError> {
        let handle = ProcessHandle::open(pid, ProcessAccess::QUERY_INFO)?;
        self.watched_processes.insert(pid, handle);
        Ok(())
    }
    
    pub fn unwatch(&mut self, pid: u32) {
        self.watched_processes.remove(&pid);
    }
    
    /// Poll for process state changes
    /// TODO: Implement proper event-based monitoring
    pub fn poll(&mut self) -> Result<(), MapperError> {
        let mut exited = Vec::new();
        
        for (&pid, handle) in &self.watched_processes {
            if let Ok(Some(exit_code)) = handle.exit_code() {
                for observer in &self.observers {
                    observer.on_process_exit(pid, exit_code);
                }
                exited.push(pid);
            }
        }
        
        for pid in exited {
            self.watched_processes.remove(&pid);
        }
        
        Ok(())
    }
}

impl Default for ProcessWatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the current process ID
pub fn current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

/// Get process ID from a handle
pub fn pid_from_handle(handle: HANDLE) -> u32 {
    unsafe { GetProcessId(handle) }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_current_process() {
        let handle = ProcessHandle::current();
        assert!(handle.is_running().unwrap());
        assert_eq!(handle.pid(), current_pid());
    }
    
    #[test]
    fn test_process_enumeration() {
        let enumerator = ProcessEnumerator::new().unwrap();
        let processes: Vec<_> = enumerator.filter_map(|r| r.ok()).collect();
        assert!(!processes.is_empty());
        
        // Current process should be in the list
        let current = current_pid();
        assert!(processes.iter().any(|p| p.pid == current));
    }
    
    #[test]
    fn test_process_access_combine() {
        let combined = ProcessAccess::VM_READ | ProcessAccess::VM_WRITE;
        assert_eq!(combined.raw(), PROCESS_VM_READ | PROCESS_VM_WRITE);
    }
}