//! Load Library Module
//!
//! Provides functionality for dynamic library loading, process management,
//! and thread operations with proper RAII semantics and Windows API integration.

use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

/// Module handle wrapper with automatic cleanup
#[derive(Debug)]
pub struct ModuleHandle {
    handle: *mut std::ffi::c_void,
    path: String,
    ref_count: Arc<std::sync::atomic::AtomicUsize>,
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
            ref_count: Arc::new(std::sync::atomic::AtomicUsize::new(1)),
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
            // Last reference, free the library
            #[cfg(windows)]
            unsafe {
                windows_sys::Win32::System::LibraryLoader::FreeLibrary(
                    self.handle as windows_sys::Win32::Foundation::HMODULE,
                );
            }
        }
    }
}

/// Thread creation flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ThreadCreationFlags {
    /// Thread runs immediately after creation
    RunImmediately = 0,
    /// Thread is created in a suspended state
    CreateSuspended = 0x00000004,
    /// Stack size parameter specifies initial reserve size
    StackSizeParamIsReservation = 0x00010000,
}

/// Thread priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ThreadPriority {
    Idle = -15,
    Lowest = -2,
    BelowNormal = -1,
    Normal = 0,
    AboveNormal = 1,
    Highest = 2,
    TimeCritical = 15,
}

/// Represents a managed thread with RAII cleanup
#[derive(Debug)]
pub struct ManagedThread {
    handle: SafeHandle,
    thread_id: u32,
    is_suspended: AtomicBool,
}

impl ManagedThread {
    /// Creates a new managed thread wrapper
    ///
    /// # Safety
    /// The handle must be a valid thread handle
    pub unsafe fn from_raw(handle: *mut std::ffi::c_void, thread_id: u32) -> Result<Self, MapperError> {
        if handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        Ok(Self {
            handle: SafeHandle::from_raw_handle(handle as isize),
            thread_id,
            is_suspended: AtomicBool::new(false),
        })
    }

    /// Returns the thread ID
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Checks if the thread is currently suspended
    pub fn is_suspended(&self) -> bool {
        self.is_suspended.load(Ordering::SeqCst)
    }

    /// Suspends the thread
    pub fn suspend(&self) -> Result<u32, MapperError> {
        #[cfg(windows)]
        unsafe {
            let result = windows_sys::Win32::System::Threading::SuspendThread(
                self.handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
            );
            if result == u32::MAX {
                return Err(MapperError::ThreadOperationFailed);
            }
            self.is_suspended.store(true, Ordering::SeqCst);
            Ok(result)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Resumes the thread
    pub fn resume(&self) -> Result<u32, MapperError> {
        #[cfg(windows)]
        unsafe {
            let result = windows_sys::Win32::System::Threading::ResumeThread(
                self.handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
            );
            if result == u32::MAX {
                return Err(MapperError::ThreadOperationFailed);
            }
            if result <= 1 {
                self.is_suspended.store(false, Ordering::SeqCst);
            }
            Ok(result)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Sets the thread priority
    pub fn set_priority(&self, priority: ThreadPriority) -> Result<(), MapperError> {
        #[cfg(windows)]
        unsafe {
            let result = windows_sys::Win32::System::Threading::SetThreadPriority(
                self.handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                priority as i32,
            );
            if result == 0 {
                return Err(MapperError::ThreadOperationFailed);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Waits for the thread to complete
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<WaitResult, MapperError> {
        #[cfg(windows)]
        unsafe {
            let timeout = timeout_ms.unwrap_or(windows_sys::Win32::System::Threading::INFINITE);
            let result = windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                timeout,
            );
            match result {
                0 => Ok(WaitResult::Signaled),
                0x00000080 => Ok(WaitResult::Abandoned),
                0x00000102 => Ok(WaitResult::Timeout),
                _ => Err(MapperError::WaitFailed),
            }
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Gets the thread exit code
    pub fn exit_code(&self) -> Result<u32, MapperError> {
        #[cfg(windows)]
        unsafe {
            let mut exit_code: u32 = 0;
            let result = windows_sys::Win32::System::Threading::GetExitCodeThread(
                self.handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                &mut exit_code,
            );
            if result == 0 {
                return Err(MapperError::ThreadOperationFailed);
            }
            Ok(exit_code)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }
}

/// Result of a wait operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// The object was signaled
    Signaled,
    /// The wait was abandoned
    Abandoned,
    /// The wait timed out
    Timeout,
}

/// Library loader with caching and management capabilities
pub struct LibraryLoader {
    loaded_modules: std::sync::RwLock<std::collections::HashMap<String, ModuleHandle>>,
    search_paths: std::sync::RwLock<Vec<String>>,
}

impl LibraryLoader {
    /// Creates a new library loader instance
    pub fn new() -> Self {
        Self {
            loaded_modules: std::sync::RwLock::new(std::collections::HashMap::new()),
            search_paths: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// Adds a search path for library resolution
    pub fn add_search_path(&self, path: impl Into<String>) {
        let mut paths = self.search_paths.write().unwrap();
        paths.push(path.into());
    }

    /// Loads a library by name or path
    pub fn load_library(&self, name: &str) -> Result<ModuleHandle, MapperError> {
        // Check if already loaded
        {
            let modules = self.loaded_modules.read().unwrap();
            if let Some(handle) = modules.get(name) {
                return Ok(handle.clone());
            }
        }

        // Try to load the library
        let handle = self.load_library_internal(name)?;

        // Cache the handle
        {
            let mut modules = self.loaded_modules.write().unwrap();
            modules.insert(name.to_string(), handle.clone());
        }

        Ok(handle)
    }

    fn load_library_internal(&self, name: &str) -> Result<ModuleHandle, MapperError> {
        #[cfg(windows)]
        {
            let wide_name = self.to_wide_string(name);
            unsafe {
                let handle = windows_sys::Win32::System::LibraryLoader::LoadLibraryW(
                    wide_name.as_ptr(),
                );
                if handle.is_null() {
                    return Err(MapperError::LibraryLoadFailed);
                }
                Ok(ModuleHandle::from_raw(handle as *mut std::ffi::c_void, name))
            }
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Gets a procedure address from a loaded module
    pub fn get_proc_address(
        &self,
        module: &ModuleHandle,
        proc_name: &str,
    ) -> Result<*const std::ffi::c_void, MapperError> {
        #[cfg(windows)]
        {
            let c_name = CString::new(proc_name).map_err(|_| MapperError::InvalidParameter)?;
            unsafe {
                let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                    module.as_raw() as windows_sys::Win32::Foundation::HMODULE,
                    c_name.as_ptr() as *const u8,
                );
                if addr.is_none() {
                    return Err(MapperError::ProcNotFound);
                }
                Ok(addr.unwrap() as *const std::ffi::c_void)
            }
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Unloads a library by name
    pub fn unload_library(&self, name: &str) -> Result<(), MapperError> {
        let mut modules = self.loaded_modules.write().unwrap();
        if modules.remove(name).is_some() {
            Ok(())
        } else {
            Err(MapperError::ModuleNotFound)
        }
    }

    /// Returns the number of loaded modules
    pub fn loaded_count(&self) -> usize {
        self.loaded_modules.read().unwrap().len()
    }

    fn to_wide_string(&self, s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

impl Default for LibraryLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread factory for creating and managing threads
pub struct ThreadFactory {
    created_threads: std::sync::Mutex<Vec<Arc<ManagedThread>>>,
}

impl ThreadFactory {
    /// Creates a new thread factory
    pub fn new() -> Self {
        Self {
            created_threads: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new thread with the specified start routine
    ///
    /// # Safety
    /// The start_routine must be a valid function pointer
    pub unsafe fn create_thread(
        &self,
        start_routine: *const std::ffi::c_void,
        parameter: *mut std::ffi::c_void,
        flags: ThreadCreationFlags,
        stack_size: usize,
    ) -> Result<Arc<ManagedThread>, MapperError> {
        #[cfg(windows)]
        {
            let mut thread_id: u32 = 0;
            let handle = windows_sys::Win32::System::Threading::CreateThread(
                ptr::null(),
                stack_size,
                Some(std::mem::transmute(start_routine)),
                parameter,
                flags as u32,
                &mut thread_id,
            );

            if handle.is_null() {
                return Err(MapperError::ThreadCreationFailed);
            }

            let thread = Arc::new(ManagedThread::from_raw(
                handle as *mut std::ffi::c_void,
                thread_id,
            )?);

            if flags == ThreadCreationFlags::CreateSuspended {
                thread.is_suspended.store(true, Ordering::SeqCst);
            }

            let mut threads = self.created_threads.lock().unwrap();
            threads.push(Arc::clone(&thread));

            Ok(thread)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Creates a remote thread in another process
    ///
    /// # Safety
    /// The process handle must be valid and have appropriate access rights
    pub unsafe fn create_remote_thread(
        &self,
        process_handle: *mut std::ffi::c_void,
        start_routine: *const std::ffi::c_void,
        parameter: *mut std::ffi::c_void,
        flags: ThreadCreationFlags,
    ) -> Result<Arc<ManagedThread>, MapperError> {
        #[cfg(windows)]
        {
            let mut thread_id: u32 = 0;
            let handle = windows_sys::Win32::System::Threading::CreateRemoteThread(
                process_handle as windows_sys::Win32::Foundation::HANDLE,
                ptr::null(),
                0,
                Some(std::mem::transmute(start_routine)),
                parameter,
                flags as u32,
                &mut thread_id,
            );

            if handle.is_null() {
                return Err(MapperError::ThreadCreationFailed);
            }

            let thread = Arc::new(ManagedThread::from_raw(
                handle as *mut std::ffi::c_void,
                thread_id,
            )?);

            let mut threads = self.created_threads.lock().unwrap();
            threads.push(Arc::clone(&thread));

            Ok(thread)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Returns the count of threads created by this factory
    pub fn thread_count(&self) -> usize {
        self.created_threads.lock().unwrap().len()
    }

    /// Waits for all created threads to complete
    pub fn wait_all(&self, timeout_ms: Option<u32>) -> Result<(), MapperError> {
        let threads = self.created_threads.lock().unwrap();
        for thread in threads.iter() {
            match thread.wait(timeout_ms)? {
                WaitResult::Timeout => return Err(MapperError::WaitTimeout),
                _ => continue,
            }
        }
        Ok(())
    }
}

impl Default for ThreadFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Process memory operations helper
pub struct ProcessMemory {
    process_handle: SafeHandle,
}

impl ProcessMemory {
    /// Creates a new process memory helper for the specified process
    ///
    /// # Safety
    /// The handle must be a valid process handle with appropriate access rights
    pub unsafe fn from_handle(handle: *mut std::ffi::c_void) -> Result<Self, MapperError> {
        if handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }
        Ok(Self {
            process_handle: SafeHandle::from_raw_handle(handle as isize),
        })
    }

    /// Allocates memory in the target process
    pub fn allocate(
        &self,
        size: usize,
        allocation_type: u32,
        protection: u32,
    ) -> Result<*mut std::ffi::c_void, MapperError> {
        #[cfg(windows)]
        unsafe {
            let addr = windows_sys::Win32::System::Memory::VirtualAllocEx(
                self.process_handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                ptr::null(),
                size,
                allocation_type,
                protection,
            );
            if addr.is_null() {
                return Err(MapperError::AllocationFailed);
            }
            Ok(addr)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Frees memory in the target process
    pub fn free(&self, address: *mut std::ffi::c_void) -> Result<(), MapperError> {
        #[cfg(windows)]
        unsafe {
            let result = windows_sys::Win32::System::Memory::VirtualFreeEx(
                self.process_handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                address,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
            if result == 0 {
                return Err(MapperError::FreeFailed);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Writes data to the target process memory
    pub fn write(&self, address: *mut std::ffi::c_void, data: &[u8]) -> Result<usize, MapperError> {
        #[cfg(windows)]
        unsafe {
            let mut bytes_written: usize = 0;
            let result = windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                self.process_handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                address,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                &mut bytes_written,
            );
            if result == 0 {
                return Err(MapperError::WriteFailed);
            }
            Ok(bytes_written)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Reads data from the target process memory
    pub fn read(
        &self,
        address: *const std::ffi::c_void,
        buffer: &mut [u8],
    ) -> Result<usize, MapperError> {
        #[cfg(windows)]
        unsafe {
            let mut bytes_read: usize = 0;
            let result = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                self.process_handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                address,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer.len(),
                &mut bytes_read,
            );
            if result == 0 {
                return Err(MapperError::ReadFailed);
            }
            Ok(bytes_read)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }

    /// Changes memory protection in the target process
    pub fn protect(
        &self,
        address: *mut std::ffi::c_void,
        size: usize,
        new_protection: u32,
    ) -> Result<u32, MapperError> {
        #[cfg(windows)]
        unsafe {
            let mut old_protection: u32 = 0;
            let result = windows_sys::Win32::System::Memory::VirtualProtectEx(
                self.process_handle.as_raw() as windows_sys::Win32::Foundation::HANDLE,
                address,
                size,
                new_protection,
                &mut old_protection,
            );
            if result == 0 {
                return Err(MapperError::ProtectFailed);
            }
            Ok(old_protection)
        }
        #[cfg(not(windows))]
        Err(MapperError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_loader_creation() {
        let loader = LibraryLoader::new();
        assert_eq!(loader.loaded_count(), 0);
    }

    #[test]
    fn test_thread_factory_creation() {
        let factory = ThreadFactory::new();
        assert_eq!(factory.thread_count(), 0);
    }

    #[test]
    fn test_thread_priority_values() {
        assert_eq!(ThreadPriority::Normal as i32, 0);
        assert_eq!(ThreadPriority::Highest as i32, 2);
        assert_eq!(ThreadPriority::Lowest as i32, -2);
    }

    #[test]
    fn test_thread_creation_flags() {
        assert_eq!(ThreadCreationFlags::RunImmediately as u32, 0);
        assert_eq!(ThreadCreationFlags::CreateSuspended as u32, 0x00000004);
    }
}