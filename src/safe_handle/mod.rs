//! Safe handle management with RAII semantics for Windows kernel objects
//! 
//! This module provides type-safe wrappers around raw handles with automatic
//! cleanup and proper error handling following Rust's ownership model.

use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ptr::NonNull;

use crate::error::{MapperError, NtStatus};

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
    
    /// Consumes the handle and returns the raw value without cleanup
    #[inline]
    pub fn into_raw(self) -> *mut std::ffi::c_void {
        let ptr = self.inner.as_ptr();
        std::mem::forget(self);
        ptr
    }
    
    /// Attempts to duplicate this handle
    pub fn try_clone(&self) -> Result<Self, MapperError> {
        // Platform-specific duplication would go here
        // For now, return an error indicating duplication is not supported
        Err(MapperError::OperationNotSupported {
            operation: "handle duplication",
        })
    }
}

impl<T: HandleDrop> Drop for SafeHandle<T> {
    fn drop(&mut self) {
        T::drop_handle(self.inner.as_ptr());
    }
}

impl<T: HandleDrop> fmt::Debug for SafeHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeHandle")
            .field("type", &T::type_name())
            .field("value", &format_args!("{:p}", self.inner.as_ptr()))
            .finish()
    }
}

// SafeHandle is Send if the underlying handle can be safely transferred
unsafe impl<T: HandleDrop + Send> Send for SafeHandle<T> {}

// SafeHandle is Sync if the underlying handle can be safely shared
unsafe impl<T: HandleDrop + Sync> Sync for SafeHandle<T> {}

/// Handle drop strategy for process handles
pub struct ProcessHandleDrop;

impl HandleDrop for ProcessHandleDrop {
    fn drop_handle(handle: *mut std::ffi::c_void) {
        #[cfg(windows)]
        unsafe {
            // CloseHandle equivalent
            extern "system" {
                fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
            }
            let _ = CloseHandle(handle);
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

/// Handle drop strategy for file handles
pub struct FileHandleDrop;

impl HandleDrop for FileHandleDrop {
    fn drop_handle(handle: *mut std::ffi::c_void) {
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
            }
            let _ = CloseHandle(handle);
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

/// Handle drop strategy for memory section handles
pub struct SectionHandleDrop;

impl HandleDrop for SectionHandleDrop {
    fn drop_handle(handle: *mut std::ffi::c_void) {
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
            }
            let _ = CloseHandle(handle);
        }
        
        #[cfg(not(windows))]
        {
            let _ = handle;
        }
    }
    
    fn type_name() -> &'static str {
        "Section"
    }
}

/// Type alias for process handles
pub type ProcessHandle = SafeHandle<ProcessHandleDrop>;

/// Type alias for file handles  
pub type FileHandle = SafeHandle<FileHandleDrop>;

/// Type alias for section handles
pub type SectionHandle = SafeHandle<SectionHandleDrop>;

/// Mapped memory view with automatic unmapping
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
        if base.is_null() {
            return Err(MapperError::InvalidHandle {
                handle_type: "MappedView",
                reason: "null base address",
            });
        }
        
        if size == 0 {
            return Err(MapperError::InvalidParameter {
                param: "size",
                reason: "mapped view size cannot be zero",
            });
        }
        
        Ok(Self {
            base: NonNull::new_unchecked(base),
            size,
        })
    }
    
    /// Returns the base address of the mapped view
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.base.as_ptr()
    }
    
    /// Returns a mutable pointer to the base address
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.base.as_ptr()
    }
    
    /// Returns the size of the mapped view
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// Returns the mapped memory as a byte slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: The memory was validated during construction
        unsafe { std::slice::from_raw_parts(self.base.as_ptr(), self.size) }
    }
    
    /// Returns the mapped memory as a mutable byte slice
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: The memory was validated during construction
        unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr(), self.size) }
    }
    
    /// Reads a value of type T at the specified offset
    /// 
    /// # Safety
    /// The offset must be properly aligned and within bounds
    pub unsafe fn read_at<V: Copy>(&self, offset: usize) -> Result<V, MapperError> {
        let type_size = std::mem::size_of::<V>();
        
        if offset.checked_add(type_size).map_or(true, |end| end > self.size) {
            return Err(MapperError::OutOfBounds {
                offset,
                size: type_size,
                limit: self.size,
            });
        }
        
        let ptr = self.base.as_ptr().add(offset) as *const V;
        
        if (ptr as usize) % std::mem::align_of::<V>() != 0 {
            return Err(MapperError::AlignmentError {
                address: ptr as usize,
                required: std::mem::align_of::<V>(),
            });
        }
        
        Ok(ptr.read_unaligned())
    }
    
    /// Writes a value of type T at the specified offset
    /// 
    /// # Safety
    /// The offset must be properly aligned and within bounds
    pub unsafe fn write_at<V: Copy>(&mut self, offset: usize, value: V) -> Result<(), MapperError> {
        let type_size = std::mem::size_of::<V>();
        
        if offset.checked_add(type_size).map_or(true, |end| end > self.size) {
            return Err(MapperError::OutOfBounds {
                offset,
                size: type_size,
                limit: self.size,
            });
        }
        
        let ptr = self.base.as_ptr().add(offset) as *mut V;
        ptr.write_unaligned(value);
        
        Ok(())
    }
}

impl Drop for MappedView {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn UnmapViewOfFile(base: *mut std::ffi::c_void) -> i32;
            }
            let _ = UnmapViewOfFile(self.base.as_ptr() as *mut std::ffi::c_void);
        }
    }
}

impl fmt::Debug for MappedView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappedView")
            .field("base", &format_args!("{:p}", self.base.as_ptr()))
            .field("size", &format_args!("0x{:x}", self.size))
            .finish()
    }
}

/// Handle guard for temporary handle borrowing with automatic restoration
pub struct HandleGuard<'a, T: HandleDrop> {
    handle: &'a SafeHandle<T>,
    original_value: *mut std::ffi::c_void,
}

impl<'a, T: HandleDrop> HandleGuard<'a, T> {
    /// Creates a new handle guard
    pub fn new(handle: &'a SafeHandle<T>) -> Self {
        Self {
            handle,
            original_value: handle.as_raw(),
        }
    }
    
    /// Returns the guarded handle value
    #[inline]
    pub fn value(&self) -> *mut std::ffi::c_void {
        self.original_value
    }
}

impl<'a, T: HandleDrop> Deref for HandleGuard<'a, T> {
    type Target = SafeHandle<T>;
    
    fn deref(&self) -> &Self::Target {
        self.handle
    }
}

/// Builder for creating handles with validation
pub struct HandleBuilder<T: HandleDrop> {
    handle: Option<*mut std::ffi::c_void>,
    _marker: PhantomData<T>,
}

impl<T: HandleDrop> HandleBuilder<T> {
    /// Creates a new handle builder
    pub fn new() -> Self {
        Self {
            handle: None,
            _marker: PhantomData,
        }
    }
    
    /// Sets the raw handle value
    pub fn with_handle(mut self, handle: *mut std::ffi::c_void) -> Self {
        self.handle = Some(handle);
        self
    }
    
    /// Builds the safe handle
    pub fn build(self) -> Result<SafeHandle<T>, MapperError> {
        match self.handle {
            Some(h) => SafeHandle::new(h),
            None => Err(MapperError::InvalidHandle {
                handle_type: T::type_name(),
                reason: "no handle value provided",
            }),
        }
    }
}

impl<T: HandleDrop> Default for HandleBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct MockHandleDrop;
    
    impl HandleDrop for MockHandleDrop {
        fn drop_handle(_handle: *mut std::ffi::c_void) {
            // No-op for testing
        }
        
        fn type_name() -> &'static str {
            "Mock"
        }
    }
    
    #[test]
    fn test_safe_handle_creation() {
        let raw = 0x1234usize as *mut std::ffi::c_void;
        let handle = SafeHandle::<MockHandleDrop>::new(raw);
        assert!(handle.is_ok());
    }
    
    #[test]
    fn test_null_handle_rejected() {
        let handle = SafeHandle::<MockHandleDrop>::new(std::ptr::null_mut());
        assert!(handle.is_err());
    }
    
    #[test]
    fn test_invalid_handle_rejected() {
        let handle = SafeHandle::<MockHandleDrop>::new(SafeHandle::<MockHandleDrop>::INVALID_HANDLE);
        assert!(handle.is_err());
    }
    
    #[test]
    fn test_handle_builder() {
        let raw = 0x5678usize as *mut std::ffi::c_void;
        let handle = HandleBuilder::<MockHandleDrop>::new()
            .with_handle(raw)
            .build();
        assert!(handle.is_ok());
        assert_eq!(handle.unwrap().as_raw(), raw);
    }
}