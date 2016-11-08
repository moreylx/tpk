//! Safe memory management module for NT Mapper
//! 
//! Provides RAII-based memory management with automatic cleanup,
//! memory protection utilities, and safe abstractions over raw memory operations.
//! 
//! # Performance Optimizations
//! - Lock-free allocation tracking using atomic operations
//! - Memory pooling for frequently allocated sizes
//! - Cache-aligned allocations for hot data structures
//! - Batch allocation support for bulk operations

use std::alloc::{alloc, alloc_zeroed, dealloc, realloc, Layout};
use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::fmt;

use crate::error::{MapperError, NtStatus};

/// Global memory allocation tracker for debugging and leak detection
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static TOTAL_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Cache line size for alignment optimization
const CACHE_LINE_SIZE: usize = 64;

/// Small allocation threshold for pool usage
const SMALL_ALLOC_THRESHOLD: usize = 256;

/// Number of size classes in the memory pool
const POOL_SIZE_CLASSES: usize = 8;

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

    /// Convert from raw Windows protection constant
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

    /// Convert to raw Windows protection constant
    #[inline]
    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

/// Memory allocation statistics for performance monitoring
#[derive(Debug, Clone, Copy)]
pub struct AllocationStats {
    pub current_count: usize,
    pub total_bytes: usize,
    pub peak_bytes: usize,
    pub pool_hits: usize,
    pub pool_misses: usize,
}

impl AllocationStats {
    /// Capture current allocation statistics
    pub fn capture() -> Self {
        Self {
            current_count: ALLOCATION_COUNT.load(Ordering::Relaxed),
            total_bytes: TOTAL_ALLOCATED_BYTES.load(Ordering::Relaxed),
            peak_bytes: PEAK_ALLOCATED_BYTES.load(Ordering::Relaxed),
            pool_hits: POOL_STATS.hits.load(Ordering::Relaxed),
            pool_misses: POOL_STATS.misses.load(Ordering::Relaxed),
        }
    }
}

/// Pool statistics tracking
struct PoolStats {
    hits: AtomicUsize,
    misses: AtomicUsize,
}

static POOL_STATS: PoolStats = PoolStats {
    hits: AtomicUsize::new(0),
    misses: AtomicUsize::new(0),
};

/// Lock-free memory pool node
struct PoolNode {
    next: AtomicPtr<PoolNode>,
}

/// Lock-free memory pool for small allocations
struct MemoryPool {
    free_lists: [AtomicPtr<PoolNode>; POOL_SIZE_CLASSES],
    initialized: AtomicBool,
}

impl MemoryPool {
    const fn new() -> Self {
        Self {
            free_lists: [
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
                AtomicPtr::new(ptr::null_mut()),
            ],
        }
    }

    /// Get size class index for a given size
    #[inline]
    fn size_class(size: usize) -> Option<usize> {
        if size == 0 || size > SMALL_ALLOC_THRESHOLD {
            return None;
        }
        // Size classes: 32, 64, 96, 128, 160, 192, 224, 256
        Some(((size + 31) / 32).saturating_sub(1).min(POOL_SIZE_CLASSES - 1))
    }

    /// Get allocation size for a size class
    #[inline]
    fn class_size(class: usize) -> usize {
        (class + 1) * 32
    }

    /// Try to allocate from pool
    fn try_alloc(&self, size: usize) -> Option<NonNull<u8>> {
        let class = Self::size_class(size)?;
        let free_list = &self.free_lists[class];
        
        loop {
            let head = free_list.load(Ordering::Acquire);
            if head.is_null() {
                POOL_STATS.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            
            // SAFETY: head is non-null and was previously allocated by us
            let next = unsafe { (*head).next.load(Ordering::Relaxed) };
            
            if free_list.compare_exchange_weak(
                head,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                POOL_STATS.hits.fetch_add(1, Ordering::Relaxed);
                return NonNull::new(head as *mut u8);
            }
        }
    }

    /// Return memory to pool
    fn return_to_pool(&self, ptr: NonNull<u8>, size: usize) -> bool {
        let Some(class) = Self::size_class(size) else {
            return false;
        };
        
        let node = ptr.as_ptr() as *mut PoolNode;
        let free_list = &self.free_lists[class];
        
        loop {
            let head = free_list.load(Ordering::Relaxed);
            // SAFETY: node points to valid memory we own
            unsafe { (*node).next.store(head, Ordering::Relaxed) };
            
            if free_list.compare_exchange_weak(
                head,
                node,
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }
}

static MEMORY_POOL: MemoryPool = MemoryPool::new();

/// Track allocation in global statistics
#[inline]
fn track_allocation(size: usize) {
    ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
    let new_total = TOTAL_ALLOCATED_BYTES.fetch_add(size, Ordering::Relaxed) + size;
    
    // Update peak if necessary
    let mut peak = PEAK_ALLOCATED_BYTES.load(Ordering::Relaxed);
    while new_total > peak {
        match PEAK_ALLOCATED_BYTES.compare_exchange_weak(
            peak,
            new_total,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(current) => peak = current,
        }
    }
}

/// Track deallocation in global statistics
#[inline]
fn track_deallocation(size: usize) {
    ALLOCATION_COUNT.fetch_sub(1, Ordering::Relaxed);
    TOTAL_ALLOCATED_BYTES.fetch_sub(size, Ordering::Relaxed);
}

/// RAII wrapper for raw memory allocations with automatic cleanup
pub struct SafeBuffer<T> {
    ptr: NonNull<T>,
    len: usize,
    capacity: usize,
    from_pool: bool,
    _marker: PhantomData<T>,
}

impl<T> SafeBuffer<T> {
    /// Create a new buffer with the specified capacity
    pub fn with_capacity(capacity: usize) -> Result<Self, MapperError> {
        if capacity == 0 {
            return Err(MapperError::InvalidParameter("capacity cannot be zero".into()));
        }

        let size = capacity.checked_mul(mem::size_of::<T>())
            .ok_or_else(|| MapperError::InvalidParameter("allocation size overflow".into()))?;

        let (ptr, from_pool) = if size <= SMALL_ALLOC_THRESHOLD && mem::align_of::<T>() <= 32 {
            if let Some(p) = MEMORY_POOL.try_alloc(size) {
                (p.cast(), true)
            } else {
                (Self::alloc_raw(size, mem::align_of::<T>())?, false)
            }
        } else {
            (Self::alloc_raw(size, mem::align_of::<T>())?, false)
        };

        if !from_pool {
            track_allocation(size);
        }

        Ok(Self {
            ptr,
            len: 0,
            capacity,
            from_pool,
            _marker: PhantomData,
        })
    }

    /// Create a zeroed buffer with the specified capacity
    pub fn zeroed(capacity: usize) -> Result<Self, MapperError> {
        if capacity == 0 {
            return Err(MapperError::InvalidParameter("capacity cannot be zero".into()));
        }

        let size = capacity.checked_mul(mem::size_of::<T>())
            .ok_or_else(|| MapperError::InvalidParameter("allocation size overflow".into()))?;

        let layout = Layout::from_size_align(size, mem::align_of::<T>())
            .map_err(|_| MapperError::InvalidParameter("invalid layout".into()))?;

        // SAFETY: layout is valid and non-zero
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr as *mut T)
            .ok_or_else(|| MapperError::AllocationFailed(size))?;

        track_allocation(size);

        Ok(Self {
            ptr,
            len: 0,
            capacity,
            from_pool: false,
            _marker: PhantomData,
        })
    }

    /// Allocate raw memory with specified size and alignment
    fn alloc_raw(size: usize, align: usize) -> Result<NonNull<T>, MapperError> {
        let layout = Layout::from_size_align(size, align)
            .map_err(|_| MapperError::InvalidParameter("invalid layout".into()))?;

        // SAFETY: layout is valid and non-zero
        let ptr = unsafe { alloc(layout) };
        NonNull::new(ptr as *mut T)
            .ok_or_else(|| MapperError::AllocationFailed(size))
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

    /// Get raw pointer
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    /// Get mutable raw pointer
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Set the length (unsafe - caller must ensure elements are initialized)
    /// 
    /// # Safety
    /// Caller must ensure that `new_len` elements are properly initialized
    #[inline]
    pub unsafe fn set_len(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.capacity);
        self.len = new_len;
    }

    /// Resize the buffer, potentially reallocating
    pub fn resize(&mut self, new_capacity: usize) -> Result<(), MapperError> {
        if new_capacity == self.capacity {
            return Ok(());
        }

        let old_size = self.capacity * mem::size_of::<T>();
        let new_size = new_capacity.checked_mul(mem::size_of::<T>())
            .ok_or_else(|| MapperError::InvalidParameter("allocation size overflow".into()))?;

        // If from pool, we need to allocate new memory and copy
        if self.from_pool {
            let new_ptr = Self::alloc_raw(new_size, mem::align_of::<T>())?;
            
            // SAFETY: both pointers are valid, non-overlapping
            unsafe {
                ptr::copy_nonoverlapping(
                    self.ptr.as_ptr(),
                    new_ptr.as_ptr(),
                    self.len.min(new_capacity),
                );
            }
            
            // Return old memory to pool
            let pool_size = MemoryPool::size_class(old_size)
                .map(MemoryPool::class_size)
                .unwrap_or(old_size);
            MEMORY_POOL.return_to_pool(self.ptr.cast(), pool_size);
            
            self.ptr = new_ptr;
            self.from_pool = false;
            track_allocation(new_size);
        } else {
            let old_layout = Layout::from_size_align(old_size, mem::align_of::<T>())
                .map_err(|_| MapperError::InvalidParameter("invalid layout".into()))?;

            // SAFETY: ptr was allocated with old_layout, new_size is valid
            let new_ptr = unsafe {
                realloc(self.ptr.as_ptr() as *mut u8, old_layout, new_size)
            };

            self.ptr = NonNull::new(new_ptr as *mut T)
                .ok_or_else(|| MapperError::AllocationFailed(new_size))?;

            // Update tracking
            if new_size > old_size {
                track_allocation(new_size - old_size);
            } else {
                track_deallocation(old_size - new_size);
            }
        }

        self.capacity = new_capacity;
        self.len = self.len.min(new_capacity);
        Ok(())
    }

    /// Get a slice of the initialized portion
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: ptr is valid and len elements are initialized
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Get a mutable slice of the initialized portion
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: ptr is valid and len elements are initialized
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T> Drop for SafeBuffer<T> {
    fn drop(&mut self) {
        let size = self.capacity * mem::size_of::<T>();
        
        if self.from_pool {
            let pool_size = MemoryPool::size_class(size)
                .map(MemoryPool::class_size)
                .unwrap_or(size);
            MEMORY_POOL.return_to_pool(self.ptr.cast(), pool_size);
        } else {
            if let Ok(layout) = Layout::from_size_align(size, mem::align_of::<T>()) {
                // SAFETY: ptr was allocated with this layout
                unsafe { dealloc(self.ptr.as_ptr() as *mut u8, layout) };
                track_deallocation(size);
            }
        }
    }
}

impl<T> Deref for SafeBuffer<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T> DerefMut for SafeBuffer<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<T: fmt::Debug> fmt::Debug for SafeBuffer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeBuffer")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("from_pool", &self.from_pool)
            .field("data", &self.as_slice())
            .finish()
    }
}

// SAFETY: SafeBuffer owns its data and T is Send
unsafe impl<T: Send> Send for SafeBuffer<T> {}
// SAFETY: SafeBuffer provides &T access and T is Sync
unsafe impl<T: Sync> Sync for SafeBuffer<T> {}

/// Cache-aligned allocation wrapper for hot data structures
#[repr(C, align(64))]
pub struct CacheAligned<T> {
    value: T,
}

impl<T> CacheAligned<T> {
    /// Create a new cache-aligned value
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Get reference to inner value
    #[inline]
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Get mutable reference to inner value
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Consume and return inner value
    #[inline]
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T> Deref for CacheAligned<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> DerefMut for CacheAligned<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T: Default> Default for CacheAligned<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for CacheAligned<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Batch allocator for bulk memory operations
pub struct BatchAllocator {
    chunk_size: usize,
    chunks: Vec<NonNull<u8>>,
    current_offset: usize,
    total_allocated: usize,
}

impl BatchAllocator {
    /// Create a new batch allocator with specified chunk size
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size: chunk_size.max(4096),
            chunks: Vec::new(),
            current_offset: 0,
            total_allocated: 0,
        }
    }

    /// Allocate memory from the batch allocator
    pub fn alloc<T>(&mut self) -> Result<NonNull<T>, MapperError> {
        self.alloc_aligned(mem::size_of::<T>(), mem::align_of::<T>())
            .map(|p| p.cast())
    }

    /// Allocate memory with specific alignment
    pub fn alloc_aligned(&mut self, size: usize, align: usize) -> Result<NonNull<u8>, MapperError> {
        if size == 0 {
            return Err(MapperError::InvalidParameter("size cannot be zero".into()));
        }

        // Align current offset
        let aligned_offset = (self.current_offset + align - 1) & !(align - 1);
        
        // Check if we have space in current chunk
        if self.chunks.is_empty() || aligned_offset + size > self.chunk_size {
            self.allocate_chunk()?;
            self.current_offset = 0;
        }

        let aligned_offset = (self.current_offset + align - 1) & !(align - 1);
        let chunk = *self.chunks.last().unwrap();
        
        // SAFETY: offset is within bounds of chunk
        let ptr = unsafe { chunk.as_ptr().add(aligned_offset) };
        self.current_offset = aligned_offset + size;
        
        NonNull::new(ptr).ok_or_else(|| MapperError::AllocationFailed(size))
    }

    /// Allocate a new chunk
    fn allocate_chunk(&mut self) -> Result<(), MapperError> {
        let layout = Layout::from_size_align(self.chunk_size, CACHE_LINE_SIZE)
            .map_err(|_| MapperError::InvalidParameter("invalid layout".into()))?;

        // SAFETY: layout is valid
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr)
            .ok_or_else(|| MapperError::AllocationFailed(self.chunk_size))?;

        self.chunks.push(ptr);
        self.total_allocated += self.chunk_size;
        track_allocation(self.chunk_size);
        
        Ok(())
    }

    /// Get total bytes allocated
    #[inline]
    pub fn total_allocated(&self) -> usize {
        self.total_allocated
    }

    /// Reset allocator, keeping allocated chunks for reuse
    pub fn reset(&mut self) {
        self.current_offset = 0;
        // Keep only first chunk if we have multiple
        if self.chunks.len() > 1 {
            let layout = Layout::from_size_align(self.chunk_size, CACHE_LINE_SIZE).unwrap();
            for chunk in self.chunks.drain(1..) {
                // SAFETY: chunk was allocated with this layout
                unsafe { dealloc(chunk.as_ptr(), layout) };
                track_deallocation(self.chunk_size);
            }
            self.total_allocated = self.chunk_size;
        }
    }
}

impl Drop for BatchAllocator {
    fn drop(&mut self) {
        if let Ok(layout) = Layout::from_size_align(self.chunk_size, CACHE_LINE_SIZE) {
            for chunk in &self.chunks {
                // SAFETY: chunk was allocated with this layout
                unsafe { dealloc(chunk.as_ptr(), layout) };
                track_deallocation(self.chunk_size);
            }
        }
    }
}

/// Memory region descriptor for process memory operations
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: MemoryProtection,
    pub state: MemoryState,
    pub region_type: MemoryType,
}

/// Memory state flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

/// Memory type flags
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

    /// Get the end address of this region
    #[inline]
    pub fn end_address(&self) -> usize {
        self.base_address + self.size
    }
}

/// Safe wrapper for reading memory with bounds checking
pub struct MemoryReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> MemoryReader<'a> {
    /// Create a new memory reader
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Get current position
    #[inline]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get remaining bytes
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Seek to a position
    pub fn seek(&mut self, position: usize) -> Result<(), MapperError> {
        if position > self.data.len() {
            return Err(MapperError::InvalidParameter("seek position out of bounds".into()));
        }
        self.position = position;
        Ok(())
    }

    /// Read a value of type T
    pub fn read<T: Copy>(&mut self) -> Result<T, MapperError> {
        let size = mem::size_of::<T>();
        if self.position + size > self.data.len() {
            return Err(MapperError::BufferTooSmall {
                required: size,
                available: self.remaining(),
            });
        }

        // SAFETY: we've verified bounds and alignment requirements
        let value = unsafe {
            let ptr = self.data.as_ptr().add(self.position) as *const T;
            ptr.read_unaligned()
        };

        self.position += size;
        Ok(value)
    }

    /// Read a slice of bytes
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], MapperError> {
        if self.position + len > self.data.len() {
            return Err(MapperError::BufferTooSmall {
                required: len,
                available: self.remaining(),
            });
        }

        let slice = &self.data[self.position..self.position + len];
        self.position += len;
        Ok(slice)
    }

    /// Peek at a value without advancing position
    pub fn peek<T: Copy>(&self) -> Result<T, MapperError> {
        let size = mem::size_of::<T>();
        if self.position + size > self.data.len() {
            return Err(MapperError::BufferTooSmall {
                required: size,
                available: self.remaining(),
            });
        }

        // SAFETY: we've verified bounds
        let value = unsafe {
            let ptr = self.data.as_ptr().add(self.position) as *const T;
            ptr.read_unaligned()
        };

        Ok(value)
    }
}

/// Get current allocation statistics
pub fn get_allocation_stats() -> AllocationStats {
    AllocationStats::capture()
}

/// Reset allocation statistics (for testing)
pub fn reset_allocation_stats() {
    ALLOCATION_COUNT.store(0, Ordering::Relaxed);
    TOTAL_ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    PEAK_ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    POOL_STATS.hits.store(0, Ordering::Relaxed);
    POOL_STATS.misses.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_buffer_creation() {
        let buffer: SafeBuffer<u32> = SafeBuffer::with_capacity(100).unwrap();
        assert_eq!(buffer.capacity(), 100);
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_safe_buffer_zeroed() {
        let buffer: SafeBuffer<u8> = SafeBuffer::zeroed(64).unwrap();
        assert_eq!(buffer.capacity(), 64);
        // Verify memory is zeroed by checking raw bytes
        let ptr = buffer.as_ptr();
        for i in 0..64 {
            unsafe {
                assert_eq!(*ptr.add(i), 0);
            }
        }
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
    fn test_cache_aligned() {
        let aligned = CacheAligned::new(42u64);
        assert_eq!(*aligned, 42);
        
        let ptr = &aligned as *const _ as usize;
        assert_eq!(ptr % CACHE_LINE_SIZE, 0);
    }

    #[test]
    fn test_batch_allocator() {
        let mut allocator = BatchAllocator::new(4096);
        
        let ptr1: NonNull<u32> = allocator.alloc().unwrap();
        let ptr2: NonNull<u64> = allocator.alloc().unwrap();