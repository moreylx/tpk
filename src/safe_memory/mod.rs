//! Safe memory management module for NT Mapper
//! 
//! Provides RAII-based memory management with automatic cleanup,
//! memory protection utilities, and safe abstractions over raw memory operations.

use std::alloc::{alloc, alloc_zeroed, dealloc, realloc, Layout};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::{MapperError, NtStatus};

/// Global memory allocation tracker for debugging and leak detection
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static TOTAL_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

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
    /// Check if protection allows read access
    #[inline]
    pub fn can_read(self) -> bool {
        matches!(
            self,
            Self::ReadOnly
                | Self::ReadWrite
                | Self::WriteCopy
                | Self::ExecuteRead
                | Self::ExecuteReadWrite
                | Self::ExecuteWriteCopy
        )
    }

    /// Check if protection allows write access
    #[inline]
    pub fn can_write(self) -> bool {
        matches!(
            self,
            Self::ReadWrite | Self::WriteCopy | Self::ExecuteReadWrite | Self::ExecuteWriteCopy
        )
    }

    /// Check if protection allows execution
    #[inline]
    pub fn can_execute(self) -> bool {
        matches!(
            self,
            Self::Execute | Self::ExecuteRead | Self::ExecuteReadWrite | Self::ExecuteWriteCopy
        )
    }
}

/// Memory allocation strategy trait for the Strategy pattern
pub trait AllocationStrategy {
    /// Allocate memory with the given layout
    fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, MapperError>;
    
    /// Deallocate memory
    /// 
    /// # Safety
    /// The pointer must have been allocated by this strategy with the same layout
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout);
    
    /// Reallocate memory to a new size
    /// 
    /// # Safety
    /// The pointer must have been allocated by this strategy
    unsafe fn reallocate(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_size: usize,
    ) -> Result<NonNull<u8>, MapperError>;
}

/// Default system allocator strategy
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemAllocator;

impl AllocationStrategy for SystemAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, MapperError> {
        if layout.size() == 0 {
            return Err(MapperError::InvalidParameter);
        }

        let ptr = unsafe { alloc_zeroed(layout) };
        NonNull::new(ptr).ok_or_else(|| {
            MapperError::AllocationFailed {
                size: layout.size(),
            }
        })
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        dealloc(ptr.as_ptr(), layout);
    }

    unsafe fn reallocate(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_size: usize,
    ) -> Result<NonNull<u8>, MapperError> {
        if new_size == 0 {
            self.deallocate(ptr, old_layout);
            return Err(MapperError::InvalidParameter);
        }

        let new_ptr = realloc(ptr.as_ptr(), old_layout, new_size);
        NonNull::new(new_ptr).ok_or_else(|| MapperError::AllocationFailed { size: new_size })
    }
}

/// Aligned allocator for specific alignment requirements
#[derive(Debug, Clone, Copy)]
pub struct AlignedAllocator {
    alignment: usize,
}

impl AlignedAllocator {
    pub fn new(alignment: usize) -> Result<Self, MapperError> {
        if !alignment.is_power_of_two() {
            return Err(MapperError::InvalidParameter);
        }
        Ok(Self { alignment })
    }
}

impl AllocationStrategy for AlignedAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, MapperError> {
        let aligned_layout = layout
            .align_to(self.alignment)
            .map_err(|_| MapperError::InvalidParameter)?
            .pad_to_align();

        let ptr = unsafe { alloc_zeroed(aligned_layout) };
        NonNull::new(ptr).ok_or_else(|| MapperError::AllocationFailed {
            size: aligned_layout.size(),
        })
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let aligned_layout = layout
            .align_to(self.alignment)
            .expect("Layout alignment failed")
            .pad_to_align();
        dealloc(ptr.as_ptr(), aligned_layout);
    }

    unsafe fn reallocate(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_size: usize,
    ) -> Result<NonNull<u8>, MapperError> {
        let old_aligned = old_layout
            .align_to(self.alignment)
            .map_err(|_| MapperError::InvalidParameter)?
            .pad_to_align();

        let new_layout = Layout::from_size_align(new_size, self.alignment)
            .map_err(|_| MapperError::InvalidParameter)?;

        let new_ptr = realloc(ptr.as_ptr(), old_aligned, new_layout.size());
        NonNull::new(new_ptr).ok_or_else(|| MapperError::AllocationFailed { size: new_size })
    }
}

/// RAII-based safe memory buffer with automatic cleanup
pub struct SafeBuffer<T, A: AllocationStrategy = SystemAllocator> {
    ptr: NonNull<T>,
    len: usize,
    capacity: usize,
    layout: Layout,
    allocator: A,
    _marker: PhantomData<T>,
}

impl<T> SafeBuffer<T, SystemAllocator> {
    /// Create a new buffer with the specified capacity
    pub fn with_capacity(capacity: usize) -> Result<Self, MapperError> {
        Self::with_capacity_and_allocator(capacity, SystemAllocator)
    }

    /// Create a new zeroed buffer
    pub fn zeroed(len: usize) -> Result<Self, MapperError> {
        let mut buffer = Self::with_capacity(len)?;
        buffer.len = len;
        Ok(buffer)
    }
}

impl<T, A: AllocationStrategy> SafeBuffer<T, A> {
    /// Create a new buffer with custom allocator
    pub fn with_capacity_and_allocator(capacity: usize, allocator: A) -> Result<Self, MapperError> {
        if capacity == 0 {
            return Err(MapperError::InvalidParameter);
        }

        let layout = Layout::array::<T>(capacity).map_err(|_| MapperError::InvalidParameter)?;

        let ptr = allocator.allocate(layout)?;

        ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);

        Ok(Self {
            ptr: ptr.cast(),
            len: 0,
            capacity,
            layout,
            allocator,
            _marker: PhantomData,
        })
    }

    /// Get the current length
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the capacity
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get raw pointer to the buffer
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    /// Get mutable raw pointer to the buffer
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Get the buffer as a slice
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Get the buffer as a mutable slice
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Set the length of the buffer
    /// 
    /// # Safety
    /// The caller must ensure that `new_len` elements are properly initialized
    #[inline]
    pub unsafe fn set_len(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.capacity);
        self.len = new_len;
    }

    /// Reserve additional capacity
    pub fn reserve(&mut self, additional: usize) -> Result<(), MapperError> {
        let required = self
            .len
            .checked_add(additional)
            .ok_or(MapperError::InvalidParameter)?;

        if required <= self.capacity {
            return Ok(());
        }

        let new_capacity = required.max(self.capacity * 2);
        self.grow_to(new_capacity)
    }

    /// Grow buffer to exact capacity
    fn grow_to(&mut self, new_capacity: usize) -> Result<(), MapperError> {
        let new_layout =
            Layout::array::<T>(new_capacity).map_err(|_| MapperError::InvalidParameter)?;

        let old_size = self.layout.size();
        let new_ptr =
            unsafe { self.allocator.reallocate(self.ptr.cast(), self.layout, new_layout.size())? };

        TOTAL_ALLOCATED_BYTES.fetch_sub(old_size, Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_add(new_layout.size(), Ordering::Relaxed);

        self.ptr = new_ptr.cast();
        self.capacity = new_capacity;
        self.layout = new_layout;

        Ok(())
    }

    /// Clear the buffer without deallocating
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<T: Clone, A: AllocationStrategy> SafeBuffer<T, A> {
    /// Push an element to the buffer
    pub fn push(&mut self, value: T) -> Result<(), MapperError> {
        if self.len >= self.capacity {
            self.reserve(1)?;
        }

        unsafe {
            self.ptr.as_ptr().add(self.len).write(value);
            self.len += 1;
        }

        Ok(())
    }

    /// Pop an element from the buffer
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        self.len -= 1;
        unsafe { Some(self.ptr.as_ptr().add(self.len).read()) }
    }
}

impl<T, A: AllocationStrategy> Drop for SafeBuffer<T, A> {
    fn drop(&mut self) {
        unsafe {
            // Drop all elements
            std::ptr::drop_in_place(std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len));

            // Deallocate memory
            self.allocator.deallocate(self.ptr.cast(), self.layout);
        }

        ALLOCATION_COUNT.fetch_sub(1, Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_sub(self.layout.size(), Ordering::Relaxed);
    }
}

impl<T, A: AllocationStrategy> Deref for SafeBuffer<T, A> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T, A: AllocationStrategy> DerefMut for SafeBuffer<T, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

// Safety: SafeBuffer is Send if T is Send
unsafe impl<T: Send, A: AllocationStrategy + Send> Send for SafeBuffer<T, A> {}

// Safety: SafeBuffer is Sync if T is Sync
unsafe impl<T: Sync, A: AllocationStrategy + Sync> Sync for SafeBuffer<T, A> {}

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: MemoryProtection,
    pub state: MemoryState,
    pub region_type: MemoryType,
}

/// Memory state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

/// Memory type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Private,
    Mapped,
    Image,
}

impl MemoryRegion {
    /// Create a new memory region descriptor
    pub fn new(
        base_address: usize,
        size: usize,
        protection: MemoryProtection,
        state: MemoryState,
        region_type: MemoryType,
    ) -> Self {
        Self {
            base_address,
            size,
            protection,
            state,
            region_type,
        }
    }

    /// Check if an address falls within this region
    #[inline]
    pub fn contains(&self, address: usize) -> bool {
        address >= self.base_address && address < self.base_address + self.size
    }

    /// Get the end address of the region
    #[inline]
    pub fn end_address(&self) -> usize {
        self.base_address + self.size
    }
}

/// Memory observer trait for the Observer pattern
pub trait MemoryObserver: Send + Sync {
    /// Called when memory is allocated
    fn on_allocate(&self, address: usize, size: usize);
    
    /// Called when memory is deallocated
    fn on_deallocate(&self, address: usize, size: usize);
    
    /// Called when memory protection changes
    fn on_protection_change(&self, address: usize, old: MemoryProtection, new: MemoryProtection);
}

/// Memory statistics
#[derive(Debug, Default, Clone)]
pub struct MemoryStats {
    pub allocation_count: usize,
    pub total_allocated: usize,
    pub peak_allocated: usize,
}

impl MemoryStats {
    /// Get current global memory statistics
    pub fn current() -> Self {
        Self {
            allocation_count: ALLOCATION_COUNT.load(Ordering::Relaxed),
            total_allocated: TOTAL_ALLOCATED_BYTES.load(Ordering::Relaxed),
            peak_allocated: 0, // TODO: Track peak allocation
        }
    }
}

/// Safe memory copy with bounds checking
pub fn safe_copy<T: Copy>(src: &[T], dst: &mut [T]) -> Result<usize, MapperError> {
    let copy_len = src.len().min(dst.len());
    dst[..copy_len].copy_from_slice(&src[..copy_len]);
    Ok(copy_len)
}

/// Safe memory fill
pub fn safe_fill<T: Clone>(dst: &mut [T], value: T) {
    dst.fill(value);
}

/// Zero memory securely (prevents compiler optimization)
pub fn secure_zero(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_buffer_creation() {
        let buffer: SafeBuffer<u8> = SafeBuffer::with_capacity(1024).unwrap();
        assert_eq!(buffer.capacity(), 1024);
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_safe_buffer_push_pop() {
        let mut buffer: SafeBuffer<i32> = SafeBuffer::with_capacity(4).unwrap();
        buffer.push(1).unwrap();
        buffer.push(2).unwrap();
        buffer.push(3).unwrap();

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.pop(), Some(3));
        assert_eq!(buffer.pop(), Some(2));
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn test_safe_buffer_grow() {
        let mut buffer: SafeBuffer<u8> = SafeBuffer::with_capacity(2).unwrap();
        for i in 0..10 {
            buffer.push(i).unwrap();
        }
        assert!(buffer.capacity() >= 10);
        assert_eq!(buffer.len(), 10);
    }

    #[test]
    fn test_memory_protection_flags() {
        assert!(MemoryProtection::ReadWrite.can_read());
        assert!(MemoryProtection::ReadWrite.can_write());
        assert!(!MemoryProtection::ReadWrite.can_execute());

        assert!(MemoryProtection::ExecuteReadWrite.can_execute());
        assert!(MemoryProtection::ExecuteReadWrite.can_read());
        assert!(MemoryProtection::ExecuteReadWrite.can_write());
    }

    #[test]
    fn test_memory_region_contains() {
        let region = MemoryRegion::new(
            0x1000,
            0x1000,
            MemoryProtection::ReadWrite,
            MemoryState::Commit,
            MemoryType::Private,
        );

        assert!(region.contains(0x1000));
        assert!(region.contains(0x1500));
        assert!(!region.contains(0x2000));
        assert!(!region.contains(0x0500));
    }

    #[test]
    fn test_secure_zero() {
        let mut buffer = vec![0xFFu8; 256];
        secure_zero(&mut buffer);
        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_aligned_allocator() {
        let allocator = AlignedAllocator::new(64).unwrap();
        let buffer: SafeBuffer<u8, _> =
            SafeBuffer::with_capacity_and_allocator(128, allocator).unwrap();
        
        // Verify alignment
        assert_eq!(buffer.as_ptr() as usize % 64, 0);
    }
}