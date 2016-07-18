//! Safe handle management with RAII semantics for Windows kernel objects
//! 
//! This module provides type-safe wrappers around raw handles with automatic
//! cleanup and proper error handling following Rust's ownership model.

use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{MapperError, NtStatus};

/// Global handle statistics for debugging and monitoring
static HANDLES_CREATED: AtomicU64 = AtomicU64::new(0);
static HANDLES_CLOSED: AtomicU64 = AtomicU64::new(0);

/// Trait defining handle cleanup behavior
pub trait HandleDrop {
    /// Performs the cleanup operation for this handle type
    fn drop_handle(handle: *mut std::ffi::c_void);
    
    /// Returns a human-readable name for this handle type
    fn type_name() -> &'static str;
}

/// Generic safe handle wrapper with RAII semantics
/// 
/// # Type Parameters
/// * `T` - The handle drop strategy implementing `HandleDrop`
/// 
/// # Example
/// ```ignore
/// let handle = SafeHandle::<ProcessHandleDrop>::new(raw_handle)?;
/// // Handle is automatically closed when dropped
/// ```
pub struct SafeHandle<T: HandleDrop> {
    inner: NonNull<std::ffi::c_void>,
    _marker: PhantomData<T>,
}

impl<T: HandleDrop> SafeHandle<T> {
    /// Invalid handle sentinel value
    pub const INVALID_HANDLE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;
    
    /// Creates a new safe handle from a raw pointer
    /// 
    /// # Safety
    /// The caller must ensure the handle is valid and owned
    pub fn new(handle: *mut std::ffi::c_void) -> Result<Self, MapperError> {
        if handle.is_null() || handle == Self::INVALID_HANDLE {
            return Err(MapperError::InvalidHandle {
                handle_type: T::type_name(),
                reason: "null or invalid handle value",
            });
        }
        
        // SAFETY: We just verified the handle is not null
        let inner = unsafe { NonNull::new_unchecked(handle) };
        
        HANDLES_CREATED.fetch_add(1, Ordering::Relaxed);
        
        Ok(Self {
            inner,
            _marker: PhantomData,
        })
    }
    
    /// Returns the raw handle value without transferring ownership
    #[inline]
    pub fn as_raw(&self) -> *mut std::ffi::c_void {
        self.inner.as_ptr()
    }
    
    /// Consumes the handle and returns the raw value without closing it
    /// 
    /// # Safety
    /// The caller becomes responsible for closing the handle
    #[inline]
    pub fn into_raw(self) -> *mut std::ffi::c_void {
        let ptr = self.inner.as_ptr();
        std::mem::forget(self);
        ptr
    }
    
    /// Duplicates the handle if the underlying type supports it
    pub fn try_clone(&self) -> Result<Self, MapperError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{
                DuplicateHandle, GetCurrentProcess, DUPLICATE_SAME_ACCESS,
            };
            
            let mut new_handle: *mut std::ffi::c_void = std::ptr::null_mut();
            let current_process = unsafe { GetCurrentProcess() };
            
            let result = unsafe {
                DuplicateHandle(
                    current_process,
                    self.inner.as_ptr(),
                    current_process,
                    &mut new_handle as *mut _ as *mut _,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            
            if result == 0 {
                return Err(MapperError::HandleDuplicationFailed {
                    handle_type: T::type_name(),
                });
            }
            
            Self::new(new_handle)
        }
        
        #[cfg(not(windows))]
        {
            Err(MapperError::UnsupportedPlatform)
        }
    }
    
    /// Checks if the handle is still valid
    pub fn is_valid(&self) -> bool {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::GetHandleInformation;
            
            let mut flags: u32 = 0;
            let result = unsafe {
                GetHandleInformation(self.inner.as_ptr(), &mut flags)
            };
            result != 0
        }
        
        #[cfg(not(windows))]
        {
            true
        }
    }
}

impl<T: HandleDrop> Drop for SafeHandle<T> {
    fn drop(&mut self) {
        T::drop_handle(self.inner.as_ptr());
        HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
    }
}

impl<T: HandleDrop> fmt::Debug for SafeHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeHandle")
            .field("type", &T::type_name())
            .field("ptr", &format_args!("{:p}", self.inner.as_ptr()))
            .finish()
    }
}

impl<T: HandleDrop> Deref for SafeHandle<T> {
    type Target = *mut std::ffi::c_void;
    
    fn deref(&self) -> &Self::Target {
        // SAFETY: We maintain a valid pointer throughout the lifetime
        unsafe { &*(&self.inner as *const NonNull<_> as *const *mut _) }
    }
}

// SAFETY: Handles can be sent between threads
unsafe impl<T: HandleDrop> Send for SafeHandle<T> {}

/// Process handle drop strategy
pub struct ProcessHandleDrop;

impl HandleDrop for ProcessHandleDrop {
    fn drop_handle(handle: *mut std::ffi::c_void) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            unsafe { CloseHandle(handle) };
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
        }
    }
    
    fn type_name() -> &'static str {
        "Process"
    }
}

/// File handle drop strategy
pub struct FileHandleDrop;

impl HandleDrop for FileHandleDrop {
    fn drop_handle(handle: *mut std::ffi::c_void) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            unsafe { CloseHandle(handle) };
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
        }
    }
    
    fn type_name() -> &'static str {
        "File"
    }
}

/// Memory mapping handle drop strategy
pub struct MappingHandleDrop;

impl HandleDrop for MappingHandleDrop {
    fn drop_handle(handle: *mut std::ffi::c_void) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            unsafe { CloseHandle(handle) };
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
        }
    }
    
    fn type_name() -> &'static str {
        "FileMapping"
    }
}

/// Thread handle drop strategy
pub struct ThreadHandleDrop;

impl HandleDrop for ThreadHandleDrop {
    fn drop_handle(handle: *mut std::ffi::c_void) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            unsafe { CloseHandle(handle) };
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
        }
    }
    
    fn type_name() -> &'static str {
        "Thread"
    }
}

/// Type aliases for common handle types
pub type ProcessHandle = SafeHandle<ProcessHandleDrop>;
pub type FileHandle = SafeHandle<FileHandleDrop>;
pub type MappingHandle = SafeHandle<MappingHandleDrop>;
pub type ThreadHandle = SafeHandle<ThreadHandleDrop>;

/// Handle statistics for monitoring
#[derive(Debug, Clone, Copy)]
pub struct HandleStats {
    pub created: u64,
    pub closed: u64,
    pub active: u64,
}

impl HandleStats {
    /// Retrieves current handle statistics
    pub fn current() -> Self {
        let created = HANDLES_CREATED.load(Ordering::Relaxed);
        let closed = HANDLES_CLOSED.load(Ordering::Relaxed);
        Self {
            created,
            closed,
            active: created.saturating_sub(closed),
        }
    }
    
    /// Resets the statistics counters
    pub fn reset() {
        HANDLES_CREATED.store(0, Ordering::Relaxed);
        HANDLES_CLOSED.store(0, Ordering::Relaxed);
    }
}

/// Mapped view wrapper for memory-mapped file regions
pub struct MappedView {
    base: NonNull<u8>,
    size: usize,
}

impl MappedView {
    /// Creates a new mapped view from a base address and size
    /// 
    /// # Safety
    /// The caller must ensure the memory region is valid and properly mapped
    pub unsafe fn new(base: *mut u8, size: usize) -> Result<Self, MapperError> {
        let base = NonNull::new(base).ok_or(MapperError::InvalidHandle {
            handle_type: "MappedView",
            reason: "null base address",
        })?;
        
        Ok(Self { base, size })
    }
    
    /// Returns the base address of the mapped region
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.base.as_ptr()
    }
    
    /// Returns a mutable pointer to the mapped region
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.base.as_ptr()
    }
    
    /// Returns the size of the mapped region
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// Returns the mapped region as a byte slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base.as_ptr(), self.size) }
    }
    
    /// Returns the mapped region as a mutable byte slice
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr(), self.size) }
    }
    
    /// Reads a value of type T at the specified offset
    pub fn read_at<T: Copy>(&self, offset: usize) -> Result<T, MapperError> {
        let type_size = std::mem::size_of::<T>();
        
        if offset.checked_add(type_size).map_or(true, |end| end > self.size) {
            return Err(MapperError::BufferOverflow {
                requested: offset + type_size,
                available: self.size,
            });
        }
        
        let ptr = unsafe { self.base.as_ptr().add(offset) as *const T };
        
        if (ptr as usize) % std::mem::align_of::<T>() != 0 {
            // Unaligned read - use read_unaligned
            Ok(unsafe { ptr.read_unaligned() })
        } else {
            Ok(unsafe { ptr.read() })
        }
    }
    
    /// Reads a slice of bytes at the specified offset
    pub fn read_bytes(&self, offset: usize, len: usize) -> Result<&[u8], MapperError> {
        if offset.checked_add(len).map_or(true, |end| end > self.size) {
            return Err(MapperError::BufferOverflow {
                requested: offset + len,
                available: self.size,
            });
        }
        
        Ok(unsafe { std::slice::from_raw_parts(self.base.as_ptr().add(offset), len) })
    }
}

impl Drop for MappedView {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::UnmapViewOfFile;
            unsafe { UnmapViewOfFile(self.base.as_ptr() as _) };
        }
    }
}

impl fmt::Debug for MappedView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappedView")
            .field("base", &format_args!("{:p}", self.base.as_ptr()))
            .field("size", &self.size)
            .finish()
    }
}

// SAFETY: MappedView can be sent between threads
unsafe impl Send for MappedView {}

/// Handle guard for temporary handle borrowing with automatic restoration
pub struct HandleGuard<'a, T: HandleDrop> {
    handle: &'a SafeHandle<T>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, T: HandleDrop> HandleGuard<'a, T> {
    /// Creates a new handle guard
    pub fn new(handle: &'a SafeHandle<T>) -> Self {
        Self {
            handle,
            _phantom: PhantomData,
        }
    }
    
    /// Returns the raw handle value
    #[inline]
    pub fn as_raw(&self) -> *mut std::ffi::c_void {
        self.handle.as_raw()
    }
}

impl<'a, T: HandleDrop> Deref for HandleGuard<'a, T> {
    type Target = SafeHandle<T>;
    
    fn deref(&self) -> &Self::Target {
        self.handle
    }
}

/// Builder for creating handles with specific access rights
pub struct HandleBuilder<T: HandleDrop> {
    access_mask: u32,
    inherit: bool,
    _marker: PhantomData<T>,
}

impl<T: HandleDrop> Default for HandleBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: HandleDrop> HandleBuilder<T> {
    /// Creates a new handle builder with default settings
    pub fn new() -> Self {
        Self {
            access_mask: 0,
            inherit: false,
            _marker: PhantomData,
        }
    }
    
    /// Sets the desired access mask
    pub fn access(mut self, mask: u32) -> Self {
        self.access_mask = mask;
        self
    }
    
    /// Sets whether the handle should be inheritable
    pub fn inheritable(mut self, inherit: bool) -> Self {
        self.inherit = inherit;
        self
    }
    
    /// Returns the configured access mask
    pub fn access_mask(&self) -> u32 {
        self.access_mask
    }
    
    /// Returns whether the handle is inheritable
    pub fn is_inheritable(&self) -> bool {
        self.inherit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_handle_stats() {
        HandleStats::reset();
        let stats = HandleStats::current();
        assert_eq!(stats.created, 0);
        assert_eq!(stats.closed, 0);
        assert_eq!(stats.active, 0);
    }
    
    #[test]
    fn test_invalid_handle_creation() {
        let result = ProcessHandle::new(std::ptr::null_mut());
        assert!(result.is_err());
        
        let result = ProcessHandle::new(SafeHandle::<ProcessHandleDrop>::INVALID_HANDLE);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_handle_builder() {
        let builder = HandleBuilder::<ProcessHandleDrop>::new()
            .access(0x1F0FFF)
            .inheritable(true);
        
        assert_eq!(builder.access_mask(), 0x1F0FFF);
        assert!(builder.is_inheritable());
    }
}