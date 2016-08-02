//! Load Library Module
//!
//! Provides functionality for dynamic library loading, process management,
//! and thread operations with proper RAII semantics and Windows API integration.

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

/// Windows API constants
mod constants {
    pub const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
    pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
    pub const PROCESS_VM_OPERATION: u32 = 0x0008;
    pub const PROCESS_VM_READ: u32 = 0x0010;
    pub const PROCESS_VM_WRITE: u32 = 0x0020;
    pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    
    pub const THREAD_ALL_ACCESS: u32 = 0x1F03FF;
    pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    pub const THREAD_GET_CONTEXT: u32 = 0x0008;
    pub const THREAD_SET_CONTEXT: u32 = 0x0010;
    pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
    
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_RELEASE: u32 = 0x8000;
    
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    
    pub const INFINITE: u32 = 0xFFFFFFFF;
    pub const WAIT_OBJECT_0: u32 = 0x00000000;
    pub const WAIT_TIMEOUT: u32 = 0x00000102;
    pub const WAIT_FAILED: u32 = 0xFFFFFFFF;
}

/// Module handle wrapper with automatic cleanup
#[derive(Debug)]
pub struct ModuleHandle {
    handle: *mut std::ffi::c_void,
    path: String,
    ref_count: Arc<AtomicUsize>,
}

unsafe impl Send for ModuleHandle {}
unsafe impl Sync for ModuleHandle {}

impl ModuleHandle {
    /// Creates a new module handle from a raw pointer
    ///
    /// # Safety
    /// The caller must ensure the handle is valid and was obtained from LoadLibrary
    pub unsafe fn from_raw(handle: *mut std::ffi::c_void, path: impl Into<String>) -> Self {
        Self {
            handle,
            path: path.into(),
            ref_count: Arc::new(AtomicUsize::new(1)),
        }
    }

    /// Returns the raw handle value
    pub fn as_raw(&self) -> *mut std::ffi::c_void {
        self.handle
    }

    /// Returns the module path
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Checks if the handle is valid (non-null)
    pub fn is_valid(&self) -> bool {
        !self.handle.is_null()
    }

    /// Increments the reference count
    pub fn add_ref(&self) -> usize {
        self.ref_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Gets the current reference count
    pub fn ref_count(&self) -> usize {
        self.ref_count.load(Ordering::SeqCst)
    }

    /// Retrieves a function pointer from the loaded module
    ///
    /// # Safety
    /// The caller must ensure the function signature matches the actual export
    pub unsafe fn get_proc_address<F>(&self, name: &str) -> Result<F, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        let c_name = CString::new(name)
            .map_err(|_| MapperError::InvalidParameter("Invalid function name".into()))?;

        #[cfg(windows)]
        {
            extern "system" {
                fn GetProcAddress(
                    hModule: *mut std::ffi::c_void,
                    lpProcName: *const i8,
                ) -> *mut std::ffi::c_void;
            }

            let proc = GetProcAddress(self.handle, c_name.as_ptr());
            if proc.is_null() {
                return Err(MapperError::ProcNotFound(name.to_string()));
            }

            Ok(std::mem::transmute_copy(&proc))
        }

        #[cfg(not(windows))]
        {
            Err(MapperError::UnsupportedPlatform)
        }
    }
}

impl Clone for ModuleHandle {
    fn clone(&self) -> Self {
        self.add_ref();
        Self {
            handle: self.handle,
            path: self.path.clone(),
            ref_count: Arc::clone(&self.ref_count),
        }
    }
}

impl Drop for ModuleHandle {
    fn drop(&mut self) {
        let prev = self.ref_count.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 && !self.handle.is_null() {
            #[cfg(windows)]
            unsafe {
                extern "system" {
                    fn FreeLibrary(hLibModule: *mut std::ffi::c_void) -> i32;
                }
                FreeLibrary(self.handle);
            }
        }
    }
}

/// Process access rights configuration
#[derive(Debug, Clone, Copy)]
pub struct ProcessAccess {
    rights: u32,
}

impl ProcessAccess {
    pub const fn all() -> Self {
        Self { rights: constants::PROCESS_ALL_ACCESS }
    }

    pub const fn read_write() -> Self {
        Self {
            rights: constants::PROCESS_VM_READ 
                | constants::PROCESS_VM_WRITE 
                | constants::PROCESS_VM_OPERATION
                | constants::PROCESS_QUERY_INFORMATION,
        }
    }

    pub const fn inject() -> Self {
        Self {
            rights: constants::PROCESS_CREATE_THREAD
                | constants::PROCESS_VM_OPERATION
                | constants::PROCESS_VM_READ
                | constants::PROCESS_VM_WRITE
                | constants::PROCESS_QUERY_INFORMATION,
        }
    }

    pub fn with_rights(rights: u32) -> Self {
        Self { rights }
    }

    pub fn rights(&self) -> u32 {
        self.rights
    }
}

impl Default for ProcessAccess {
    fn default() -> Self {
        Self::read_write()
    }
}

/// Thread state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Running,
    Suspended,
    Waiting,
    Terminated,
    Unknown,
}

/// Thread context flags
#[derive(Debug, Clone, Copy)]
pub struct ContextFlags(u32);

impl ContextFlags {
    pub const CONTROL: Self = Self(0x00010001);
    pub const INTEGER: Self = Self(0x00010002);
    pub const SEGMENTS: Self = Self(0x00010004);
    pub const FLOATING_POINT: Self = Self(0x00010008);
    pub const DEBUG_REGISTERS: Self = Self(0x00010010);
    pub const FULL: Self = Self(0x0001001F);
    pub const ALL: Self = Self(0x0010003F);

    pub fn value(&self) -> u32 {
        self.0
    }
}

/// Thread handle wrapper with RAII cleanup
#[derive(Debug)]
pub struct ThreadHandle {
    handle: *mut std::ffi::c_void,
    thread_id: u32,
    owning_process: u32,
}

unsafe impl Send for ThreadHandle {}
unsafe impl Sync for ThreadHandle {}

impl ThreadHandle {
    /// Creates a thread handle from raw values
    ///
    /// # Safety
    /// The handle must be valid and obtained from proper Windows API calls
    pub unsafe fn from_raw(
        handle: *mut std::ffi::c_void,
        thread_id: u32,
        owning_process: u32,
    ) -> Self {
        Self {
            handle,
            thread_id,
            owning_process,
        }
    }

    pub fn as_raw(&self) -> *mut std::ffi::c_void {
        self.handle
    }

    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    pub fn owning_process(&self) -> u32 {
        self.owning_process
    }

    pub fn is_valid(&self) -> bool {
        !self.handle.is_null()
    }

    /// Suspends the thread
    pub fn suspend(&self) -> Result<u32, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn SuspendThread(hThread: *mut std::ffi::c_void) -> u32;
            }

            let result = SuspendThread(self.handle);
            if result == u32::MAX {
                return Err(MapperError::ThreadOperationFailed("SuspendThread failed".into()));
            }
            Ok(result)
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Resumes the thread
    pub fn resume(&self) -> Result<u32, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn ResumeThread(hThread: *mut std::ffi::c_void) -> u32;
            }

            let result = ResumeThread(self.handle);
            if result == u32::MAX {
                return Err(MapperError::ThreadOperationFailed("ResumeThread failed".into()));
            }
            Ok(result)
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Waits for the thread to complete
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<WaitResult, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn WaitForSingleObject(hHandle: *mut std::ffi::c_void, dwMilliseconds: u32) -> u32;
            }

            let timeout = timeout_ms.unwrap_or(constants::INFINITE);
            let result = WaitForSingleObject(self.handle, timeout);

            match result {
                constants::WAIT_OBJECT_0 => Ok(WaitResult::Signaled),
                constants::WAIT_TIMEOUT => Ok(WaitResult::Timeout),
                constants::WAIT_FAILED => Err(MapperError::WaitFailed),
                _ => Ok(WaitResult::Abandoned),
            }
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Gets the thread exit code
    pub fn exit_code(&self) -> Result<u32, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn GetExitCodeThread(hThread: *mut std::ffi::c_void, lpExitCode: *mut u32) -> i32;
            }

            let mut exit_code: u32 = 0;
            if GetExitCodeThread(self.handle, &mut exit_code) == 0 {
                return Err(MapperError::ThreadOperationFailed("GetExitCodeThread failed".into()));
            }
            Ok(exit_code)
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Terminates the thread (use with caution)
    pub fn terminate(&self, exit_code: u32) -> Result<(), MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn TerminateThread(hThread: *mut std::ffi::c_void, dwExitCode: u32) -> i32;
            }

            if TerminateThread(self.handle, exit_code) == 0 {
                return Err(MapperError::ThreadOperationFailed("TerminateThread failed".into()));
            }
            Ok(())
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            #[cfg(windows)]
            unsafe {
                extern "system" {
                    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
                }
                CloseHandle(self.handle);
            }
        }
    }
}

/// Wait operation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    Signaled,
    Timeout,
    Abandoned,
}

/// Process handle wrapper with comprehensive process management
#[derive(Debug)]
pub struct ProcessHandle {
    handle: *mut std::ffi::c_void,
    process_id: u32,
    access: ProcessAccess,
    is_owned: bool,
}

unsafe impl Send for ProcessHandle {}
unsafe impl Sync for ProcessHandle {}

impl ProcessHandle {
    /// Opens a process by its ID
    pub fn open(process_id: u32, access: ProcessAccess) -> Result<Self, MapperError> {
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn OpenProcess(
                    dwDesiredAccess: u32,
                    bInheritHandle: i32,
                    dwProcessId: u32,
                ) -> *mut std::ffi::c_void;
            }

            let handle = OpenProcess(access.rights(), 0, process_id);
            if handle.is_null() {
                return Err(MapperError::ProcessOpenFailed(process_id));
            }

            Ok(Self {
                handle,
                process_id,
                access,
                is_owned: true,
            })
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Creates a process handle from a raw handle
    ///
    /// # Safety
    /// The handle must be valid
    pub unsafe fn from_raw(
        handle: *mut std::ffi::c_void,
        process_id: u32,
        access: ProcessAccess,
        is_owned: bool,
    ) -> Self {
        Self {
            handle,
            process_id,
            access,
            is_owned,
        }
    }

    pub fn as_raw(&self) -> *mut std::ffi::c_void {
        self.handle
    }

    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    pub fn is_valid(&self) -> bool {
        !self.handle.is_null()
    }

    /// Allocates memory in the target process
    pub fn allocate_memory(
        &self,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<RemoteMemory, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn VirtualAllocEx(
                    hProcess: *mut std::ffi::c_void,
                    lpAddress: *mut std::ffi::c_void,
                    dwSize: usize,
                    flAllocationType: u32,
                    flProtect: u32,
                ) -> *mut std::ffi::c_void;
            }

            let address = VirtualAllocEx(
                self.handle,
                ptr::null_mut(),
                size,
                constants::MEM_COMMIT | constants::MEM_RESERVE,
                protection.to_windows(),
            );

            if address.is_null() {
                return Err(MapperError::MemoryAllocationFailed(size));
            }

            Ok(RemoteMemory {
                process_handle: self.handle,
                address: address as usize,
                size,
                protection,
            })
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Writes data to the target process memory
    pub fn write_memory(&self, address: usize, data: &[u8]) -> Result<usize, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn WriteProcessMemory(
                    hProcess: *mut std::ffi::c_void,
                    lpBaseAddress: *mut std::ffi::c_void,
                    lpBuffer: *const std::ffi::c_void,
                    nSize: usize,
                    lpNumberOfBytesWritten: *mut usize,
                ) -> i32;
            }

            let mut bytes_written: usize = 0;
            let result = WriteProcessMemory(
                self.handle,
                address as *mut std::ffi::c_void,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                &mut bytes_written,
            );

            if result == 0 {
                return Err(MapperError::MemoryWriteFailed(address));
            }

            Ok(bytes_written)
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Reads data from the target process memory
    pub fn read_memory(&self, address: usize, size: usize) -> Result<Vec<u8>, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn ReadProcessMemory(
                    hProcess: *mut std::ffi::c_void,
                    lpBaseAddress: *const std::ffi::c_void,
                    lpBuffer: *mut std::ffi::c_void,
                    nSize: usize,
                    lpNumberOfBytesRead: *mut usize,
                ) -> i32;
            }

            let mut buffer = vec![0u8; size];
            let mut bytes_read: usize = 0;

            let result = ReadProcessMemory(
                self.handle,
                address as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                &mut bytes_read,
            );

            if result == 0 {
                return Err(MapperError::MemoryReadFailed(address));
            }

            buffer.truncate(bytes_read);
            Ok(buffer)
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Creates a remote thread in the target process
    pub fn create_remote_thread(
        &self,
        start_address: usize,
        parameter: usize,
    ) -> Result<ThreadHandle, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn CreateRemoteThread(
                    hProcess: *mut std::ffi::c_void,
                    lpThreadAttributes: *mut std::ffi::c_void,
                    dwStackSize: usize,
                    lpStartAddress: *mut std::ffi::c_void,
                    lpParameter: *mut std::ffi::c_void,
                    dwCreationFlags: u32,
                    lpThreadId: *mut u32,
                ) -> *mut std::ffi::c_void;
            }

            let mut thread_id: u32 = 0;
            let handle = CreateRemoteThread(
                self.handle,
                ptr::null_mut(),
                0,
                start_address as *mut std::ffi::c_void,
                parameter as *mut std::ffi::c_void,
                0,
                &mut thread_id,
            );

            if handle.is_null() {
                return Err(MapperError::ThreadCreationFailed);
            }

            Ok(ThreadHandle::from_raw(handle, thread_id, self.process_id))
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Gets the exit code of the process
    pub fn exit_code(&self) -> Result<u32, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn GetExitCodeProcess(hProcess: *mut std::ffi::c_void, lpExitCode: *mut u32) -> i32;
            }

            let mut exit_code: u32 = 0;
            if GetExitCodeProcess(self.handle, &mut exit_code) == 0 {
                return Err(MapperError::ProcessQueryFailed);
            }
            Ok(exit_code)
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Waits for the process to exit
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<WaitResult, MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn WaitForSingleObject(hHandle: *mut std::ffi::c_void, dwMilliseconds: u32) -> u32;
            }

            let timeout = timeout_ms.unwrap_or(constants::INFINITE);
            let result = WaitForSingleObject(self.handle, timeout);

            match result {
                constants::WAIT_OBJECT_0 => Ok(WaitResult::Signaled),
                constants::WAIT_TIMEOUT => Ok(WaitResult::Timeout),
                constants::WAIT_FAILED => Err(MapperError::WaitFailed),
                _ => Ok(WaitResult::Abandoned),
            }
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Terminates the process
    pub fn terminate(&self, exit_code: u32) -> Result<(), MapperError> {
        if !self.is_valid() {
            return Err(MapperError::InvalidHandle);
        }

        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn TerminateProcess(hProcess: *mut std::ffi::c_void, uExitCode: u32) -> i32;
            }

            if TerminateProcess(self.handle, exit_code) == 0 {
                return Err(MapperError::ProcessTerminationFailed);
            }
            Ok(())
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.is_owned && !self.handle.is_null() {
            #[cfg(windows)]
            unsafe {
                extern "system" {
                    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
                }
                CloseHandle(self.handle);
            }
        }
    }
}

/// Memory protection flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    ReadWrite,
    ExecuteReadWrite,
    ReadOnly,
    Execute,
    NoAccess,
}

impl MemoryProtection {
    fn to_windows(&self) -> u32 {
        match self {
            MemoryProtection::ReadWrite => constants::PAGE_READWRITE,
            MemoryProtection::ExecuteReadWrite => constants::PAGE_EXECUTE_READWRITE,
            MemoryProtection::ReadOnly => 0x02,
            MemoryProtection::Execute => 0x10,
            MemoryProtection::NoAccess => 0x01,
        }
    }
}

/// Remote memory allocation with automatic cleanup
#[derive(Debug)]
pub struct RemoteMemory {
    process_handle: *mut std::ffi::c_void,
    address: usize,
    size: usize,
    protection: MemoryProtection,
}

impl RemoteMemory {
    pub fn address(&self) -> usize {
        self.address
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn protection(&self) -> MemoryProtection {
        self.protection
    }

    /// Prevents automatic deallocation, returning the raw address
    pub fn leak(mut self) -> usize {
        let addr = self.address;
        self.address = 0;
        addr
    }
}

impl Drop for RemoteMemory {
    fn drop(&mut self) {
        if self.address != 0 && !self.process_handle.is_null() {
            #[cfg(windows)]
            unsafe {
                extern "system" {
                    fn VirtualFreeEx(
                        hProcess: *mut std::ffi::c_void,
                        lpAddress: *mut std::ffi::c_void,
                        dwSize: usize,
                        dwFreeType: u32,
                    ) -> i32;
                }
                VirtualFreeEx(
                    self.process_handle,
                    self.address as *mut std::ffi::c_void,
                    0,
                    constants::MEM_RELEASE,
                );
            }
        }
    }
}

/// Library loader with caching and reference counting
pub struct LibraryLoader {
    cache: RwLock<HashMap<String, ModuleHandle>>,
    search_paths: RwLock<Vec<String>>,
}

impl LibraryLoader {
    /// Creates a new library loader instance
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            search_paths: RwLock::new(Vec::new()),
        }
    }

    /// Adds a search path for library resolution
    pub fn add_search_path(&self, path: impl Into<String>) {
        if let Ok(mut paths) = self.search_paths.write() {
            paths.push(path.into());
        }
    }

    /// Loads a library by name or path
    pub fn load(&self, name: &str) -> Result<ModuleHandle, MapperError> {
        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(handle) = cache.get(name) {
                return Ok(handle.clone());
            }
        }

        // Try to load the library
        let handle = self.load_library_internal(name)?;

        // Cache the result
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(name.to_string(), handle.clone());
        }

        Ok(handle)
    }

    fn load_library_internal(&self, name: &str) -> Result<ModuleHandle, MapperError> {
        #[cfg(windows)]
        {
            let wide_name: Vec<u16> = OsStr::new(name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                extern "system" {
                    fn LoadLibraryW(lpLibFileName: *const u16) -> *mut std::ffi::c_void;
                }

                let handle = LoadLibraryW(wide_name.as_ptr());
                if handle.is_null() {
                    // Try search paths
                    if let Ok(paths) = self.search_paths.read() {
                        for search_path in paths.iter() {
                            let full_path = format!("{}\\{}", search_path, name);
                            let wide_path: Vec<u16> = OsStr::new(&full_path)
                                .encode_wide()
                                .chain(std::iter::once(0))
                                .collect();

                            let handle = LoadLibraryW(wide_path.as_ptr());
                            if !handle.is_null() {
                                return Ok(ModuleHandle::from_raw(handle, full_path));
                            }
                        }
                    }
                    return Err(MapperError::LibraryLoadFailed(name.to_string()));
                }

                Ok(ModuleHandle::from_raw(handle, name))
            }
        }

        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Unloads a library from the cache
    pub fn unload(&self, name: &str) -> bool {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(name).is_some()
        } else {
            false
        }
    }

    /// Clears the entire cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Returns the number of cached libraries
    pub fn cached_count(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }
}

impl Default for LibraryLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Process enumeration utilities
pub struct ProcessEnumerator;

impl ProcessEnumerator {
    /// Enumerates all process IDs in the system
    pub fn enumerate_process_ids() -> Result<Vec<u32>, MapperError> {
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn EnumProcesses(
                    lpidProcess: *mut u32,
                    cb: u32,
                    lpcbNeeded: *mut u32,
                ) -> i32;
            }

            let mut process_ids = vec![0u32; 1024];
            let mut bytes_returned: u32 = 0;

            let result = EnumProcesses(
                process_ids.as_mut_ptr(),
                (process_ids.len() * std::mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            );

            if result