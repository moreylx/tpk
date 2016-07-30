//! Safe memory management module for NT Mapper
//! 
//! Provides RAII-based memory management with automatic cleanup,
//! memory protection utilities, and safe abstractions over raw memory operations.

use std::alloc::{alloc, alloc_zeroed, dealloc, realloc, Layout};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::fmt;

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
}

/// Memory allocation strategy trait for the Strategy pattern
pub trait AllocationStrategy {
    /// Allocate memory with the given layout
    fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, MapperError>;
    
    /// Deallocate memory previously allocated
    fn deallocate(&self, ptr: NonNull<u8>, layout: Layout);
    
    /// Reallocate memory to a new size
    fn reallocate(&self, ptr: NonNull<u8>, old_layout: Layout, new_size: usize) -> Result<NonNull<u8>, MapperError>;
    
    /// Returns true if this strategy zero-initializes memory
    fn zeroes_memory(&self) -> bool;
}

/// Standard heap allocation strategy
#[derive(Debug, Default, Clone, Copy)]
pub struct HeapStrategy;

impl AllocationStrategy for HeapStrategy {
    fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, MapperError> {
        if layout.size() == 0 {
            return Err(MapperError::InvalidParameter("Cannot allocate zero-sized memory".into()));
        }
        
        let ptr = unsafe { alloc(layout) };
        NonNull::new(ptr).ok_or_else(|| {
            MapperError::AllocationFailed {
                size: layout.size(),
                reason: "System allocator returned null".into(),
            }
        })
    }
    
    fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        unsafe { dealloc(ptr.as_ptr(), layout) }
    }
    
    fn reallocate(&self, ptr: NonNull<u8>, old_layout: Layout, new_size: usize) -> Result<NonNull<u8>, MapperError> {
        if new_size == 0 {
            self.deallocate(ptr, old_layout);
            return Err(MapperError::InvalidParameter("Cannot reallocate to zero size".into()));
        }
        
        let new_ptr = unsafe { realloc(ptr.as_ptr(), old_layout, new_size) };
        NonNull::new(new_ptr).ok_or_else(|| {
            MapperError::AllocationFailed {
                size: new_size,
                reason: "Reallocation failed".into(),
            }
        })
    }
    
    fn zeroes_memory(&self) -> bool {
        false
    }
}

/// Zero-initialized heap allocation strategy
#[derive(Debug, Default, Clone, Copy)]
pub struct ZeroedHeapStrategy;

impl AllocationStrategy for ZeroedHeapStrategy {
    fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, MapperError> {
        if layout.size() == 0 {
            return Err(MapperError::InvalidParameter("Cannot allocate zero-sized memory".into()));
        }
        
        let ptr = unsafe { alloc_zeroed(layout) };
        NonNull::new(ptr).ok_or_else(|| {
            MapperError::AllocationFailed {
                size: layout.size(),
                reason: "System allocator returned null".into(),
            }
        })
    }
    
    fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        unsafe { dealloc(ptr.as_ptr(), layout) }
    }
    
    fn reallocate(&self, ptr: NonNull<u8>, old_layout: Layout, new_size: usize) -> Result<NonNull<u8>, MapperError> {
        if new_size == 0 {
            self.deallocate(ptr, old_layout);
            return Err(MapperError::InvalidParameter("Cannot reallocate to zero size".into()));
        }
        
        let new_ptr = unsafe { realloc(ptr.as_ptr(), old_layout, new_size) };
        if let Some(valid_ptr) = NonNull::new(new_ptr) {
            // Zero out the new portion if we grew
            if new_size > old_layout.size() {
                unsafe {
                    std::ptr::write_bytes(
                        valid_ptr.as_ptr().add(old_layout.size()),
                        0,
                        new_size - old_layout.size(),
                    );
                }
            }
            Ok(valid_ptr)
        } else {
            Err(MapperError::AllocationFailed {
                size: new_size,
                reason: "Reallocation failed".into(),
            })
        }
    }
    
    fn zeroes_memory(&self) -> bool {
        true
    }
}

/// RAII-based safe memory buffer with automatic cleanup
pub struct SafeBuffer<T, S: AllocationStrategy = HeapStrategy> {
    ptr: NonNull<T>,
    len: usize,
    capacity: usize,
    layout: Layout,
    strategy: S,
    _marker: PhantomData<T>,
}

impl<T> SafeBuffer<T, HeapStrategy> {
    /// Create a new buffer with the specified capacity using default heap strategy
    pub fn with_capacity(capacity: usize) -> Result<Self, MapperError> {
        Self::with_capacity_and_strategy(capacity, HeapStrategy)
    }
    
    /// Create a new zeroed buffer with the specified capacity
    pub fn zeroed(capacity: usize) -> Result<SafeBuffer<T, ZeroedHeapStrategy>, MapperError> {
        SafeBuffer::with_capacity_and_strategy(capacity, ZeroedHeapStrategy)
    }
}

impl<T, S: AllocationStrategy> SafeBuffer<T, S> {
    /// Create a new buffer with custom allocation strategy
    pub fn with_capacity_and_strategy(capacity: usize, strategy: S) -> Result<Self, MapperError> {
        if capacity == 0 {
            return Err(MapperError::InvalidParameter("Capacity must be greater than zero".into()));
        }
        
        let layout = Layout::array::<T>(capacity)
            .map_err(|_| MapperError::InvalidParameter("Layout calculation overflow".into()))?;
        
        let ptr = strategy.allocate(layout)?;
        
        ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        
        Ok(Self {
            ptr: ptr.cast(),
            len: 0,
            capacity,
            layout,
            strategy,
            _marker: PhantomData,
        })
    }
    
    /// Returns the number of elements in the buffer
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    
    /// Returns true if the buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    
    /// Returns the capacity of the buffer
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    
    /// Returns a raw pointer to the buffer
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
    
    /// Returns a mutable raw pointer to the buffer
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }
    
    /// Push an element to the buffer
    pub fn push(&mut self, value: T) -> Result<(), MapperError> {
        if self.len >= self.capacity {
            self.grow()?;
        }
        
        unsafe {
            std::ptr::write(self.ptr.as_ptr().add(self.len), value);
        }
        self.len += 1;
        Ok(())
    }
    
    /// Pop an element from the buffer
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        
        self.len -= 1;
        unsafe { Some(std::ptr::read(self.ptr.as_ptr().add(self.len))) }
    }
    
    /// Clear all elements from the buffer
    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }
    
    /// Grow the buffer capacity
    fn grow(&mut self) -> Result<(), MapperError> {
        let new_capacity = self.capacity.checked_mul(2)
            .ok_or_else(|| MapperError::InvalidParameter("Capacity overflow".into()))?;
        
        let new_layout = Layout::array::<T>(new_capacity)
            .map_err(|_| MapperError::InvalidParameter("Layout calculation overflow".into()))?;
        
        let new_ptr = self.strategy.reallocate(
            self.ptr.cast(),
            self.layout,
            new_layout.size(),
        )?;
        
        TOTAL_ALLOCATED_BYTES.fetch_sub(self.layout.size(), Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_add(new_layout.size(), Ordering::Relaxed);
        
        self.ptr = new_ptr.cast();
        self.capacity = new_capacity;
        self.layout = new_layout;
        
        Ok(())
    }
    
    /// Get a slice view of the buffer contents
    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
    
    /// Get a mutable slice view of the buffer contents
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T, S: AllocationStrategy> Drop for SafeBuffer<T, S> {
    fn drop(&mut self) {
        // Drop all elements
        for i in 0..self.len {
            unsafe {
                std::ptr::drop_in_place(self.ptr.as_ptr().add(i));
            }
        }
        
        // Deallocate memory
        self.strategy.deallocate(self.ptr.cast(), self.layout);
        
        ALLOCATION_COUNT.fetch_sub(1, Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_sub(self.layout.size(), Ordering::Relaxed);
    }
}

impl<T, S: AllocationStrategy> Deref for SafeBuffer<T, S> {
    type Target = [T];
    
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T, S: AllocationStrategy> DerefMut for SafeBuffer<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

unsafe impl<T: Send, S: AllocationStrategy + Send> Send for SafeBuffer<T, S> {}
unsafe impl<T: Sync, S: AllocationStrategy + Sync> Sync for SafeBuffer<T, S> {}

/// Memory region descriptor for virtual memory operations
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
    
    /// Get the end address of this region
    #[inline]
    pub fn end_address(&self) -> usize {
        self.base_address + self.size
    }
}

/// Observer trait for memory events
pub trait MemoryObserver: Send + Sync {
    /// Called when memory is allocated
    fn on_allocate(&self, address: usize, size: usize, protection: MemoryProtection);
    
    /// Called when memory is freed
    fn on_free(&self, address: usize, size: usize);
    
    /// Called when memory protection changes
    fn on_protect(&self, address: usize, size: usize, old_protection: MemoryProtection, new_protection: MemoryProtection);
}

/// Memory manager with observer support
pub struct MemoryManager {
    regions: Vec<MemoryRegion>,
    observers: Vec<Box<dyn MemoryObserver>>,
}

impl MemoryManager {
    /// Create a new memory manager
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            observers: Vec::new(),
        }
    }
    
    /// Register an observer for memory events
    pub fn register_observer(&mut self, observer: Box<dyn MemoryObserver>) {
        self.observers.push(observer);
    }
    
    /// Track a memory allocation
    pub fn track_allocation(&mut self, region: MemoryRegion) {
        for observer in &self.observers {
            observer.on_allocate(region.base_address, region.size, region.protection);
        }
        self.regions.push(region);
    }
    
    /// Track memory being freed
    pub fn track_free(&mut self, base_address: usize) -> Option<MemoryRegion> {
        if let Some(pos) = self.regions.iter().position(|r| r.base_address == base_address) {
            let region = self.regions.remove(pos);
            for observer in &self.observers {
                observer.on_free(region.base_address, region.size);
            }
            Some(region)
        } else {
            None
        }
    }
    
    /// Find a region containing the given address
    pub fn find_region(&self, address: usize) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(address))
    }
    
    /// Get all tracked regions
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }
    
    /// Calculate total committed memory
    pub fn total_committed(&self) -> usize {
        self.regions
            .iter()
            .filter(|r| r.state == MemoryState::Commit)
            .map(|r| r.size)
            .sum()
    }
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Safe wrapper for reading memory from a process
pub struct ProcessMemoryReader {
    process_id: u32,
    base_address: usize,
}

impl ProcessMemoryReader {
    /// Create a new process memory reader
    pub fn new(process_id: u32, base_address: usize) -> Self {
        Self {
            process_id,
            base_address,
        }
    }
    
    /// Read a value of type T from the specified offset
    /// 
    /// # Safety
    /// The caller must ensure the memory at the offset is valid and properly aligned for type T
    pub unsafe fn read_at<T: Copy>(&self, offset: usize) -> Result<T, MapperError> {
        let address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        // TODO: Implement actual process memory reading via system calls
        // This is a placeholder that would need platform-specific implementation
        Err(MapperError::NotImplemented("Process memory reading requires platform-specific implementation".into()))
    }
    
    /// Read bytes into a buffer from the specified offset
    pub fn read_bytes(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, MapperError> {
        let _address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        // TODO: Implement actual process memory reading
        Err(MapperError::NotImplemented("Process memory reading requires platform-specific implementation".into()))
    }
    
    /// Get the process ID
    #[inline]
    pub fn process_id(&self) -> u32 {
        self.process_id
    }
    
    /// Get the base address
    #[inline]
    pub fn base_address(&self) -> usize {
        self.base_address
    }
}

/// Safe wrapper for writing memory to a process
pub struct ProcessMemoryWriter {
    process_id: u32,
    base_address: usize,
}

impl ProcessMemoryWriter {
    /// Create a new process memory writer
    pub fn new(process_id: u32, base_address: usize) -> Self {
        Self {
            process_id,
            base_address,
        }
    }
    
    /// Write a value of type T at the specified offset
    /// 
    /// # Safety
    /// The caller must ensure the memory at the offset is valid, writable, and properly aligned for type T
    pub unsafe fn write_at<T: Copy>(&self, offset: usize, value: &T) -> Result<(), MapperError> {
        let _address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        // TODO: Implement actual process memory writing via system calls
        Err(MapperError::NotImplemented("Process memory writing requires platform-specific implementation".into()))
    }
    
    /// Write bytes from a buffer at the specified offset
    pub fn write_bytes(&self, offset: usize, buffer: &[u8]) -> Result<usize, MapperError> {
        let _address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        // TODO: Implement actual process memory writing
        Err(MapperError::NotImplemented("Process memory writing requires platform-specific implementation".into()))
    }
}

/// Memory pattern scanner for finding byte sequences
pub struct PatternScanner<'a> {
    data: &'a [u8],
}

impl<'a> PatternScanner<'a> {
    /// Create a new pattern scanner for the given data
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    
    /// Find the first occurrence of a pattern with optional wildcards
    /// Wildcards are represented as None in the pattern
    pub fn find_pattern(&self, pattern: &[Option<u8>]) -> Option<usize> {
        if pattern.is_empty() || pattern.len() > self.data.len() {
            return None;
        }
        
        'outer: for i in 0..=(self.data.len() - pattern.len()) {
            for (j, &pat_byte) in pattern.iter().enumerate() {
                if let Some(expected) = pat_byte {
                    if self.data[i + j] != expected {
                        continue 'outer;
                    }
                }
            }
            return Some(i);
        }
        
        None
    }
    
    /// Find all occurrences of a pattern
    pub fn find_all_patterns(&self, pattern: &[Option<u8>]) -> Vec<usize> {
        let mut results = Vec::new();
        
        if pattern.is_empty() || pattern.len() > self.data.len() {
            return results;
        }
        
        'outer: for i in 0..=(self.data.len() - pattern.len()) {
            for (j, &pat_byte) in pattern.iter().enumerate() {
                if let Some(expected) = pat_byte {
                    if self.data[i + j] != expected {
                        continue 'outer;
                    }
                }
            }
            results.push(i);
        }
        
        results
    }
    
    /// Parse a pattern string like "48 8B ?? 90" into a pattern vector
    pub fn parse_pattern_string(pattern_str: &str) -> Result<Vec<Option<u8>>, MapperError> {
        let mut pattern = Vec::new();
        
        for part in pattern_str.split_whitespace() {
            if part == "??" || part == "?" {
                pattern.push(None);
            } else {
                let byte = u8::from_str_radix(part, 16)
                    .map_err(|_| MapperError::InvalidParameter(format!("Invalid hex byte: {}", part)))?;
                pattern.push(Some(byte));
            }
        }
        
        Ok(pattern)
    }
}

/// Get current allocation statistics
pub fn allocation_stats() -> (usize, usize) {
    (
        ALLOCATION_COUNT.load(Ordering::Relaxed),
        TOTAL_ALLOCATED_BYTES.load(Ordering::Relaxed),
    )
}

/// Reset allocation statistics (for testing)
pub fn reset_allocation_stats() {
    ALLOCATION_COUNT.store(0, Ordering::Relaxed);
    TOTAL_ALLOCATED_BYTES.store(0, Ordering::Relaxed);
}

impl<T: fmt::Debug, S: AllocationStrategy> fmt::Debug for SafeBuffer<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeBuffer")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("contents", &self.as_slice())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_safe_buffer_basic_operations() {
        let mut buffer: SafeBuffer<i32> = SafeBuffer::with_capacity(4).unwrap();
        
        assert!(buffer.is_empty());
        assert_eq!(buffer.capacity(), 4);
        
        buffer.push(1).unwrap();
        buffer.push(2).unwrap();
        buffer.push(3).unwrap();
        
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.as_slice(), &[1, 2, 3]);
        
        assert_eq!(buffer.pop(), Some(3));
        assert_eq!(buffer.len(), 2);
    }
    
    #[test]
    fn test_safe_buffer_growth() {
        let mut buffer: SafeBuffer<i32> = SafeBuffer::with_capacity(2).unwrap();
        
        for i in 0..10 {
            buffer.push(i).unwrap();
        }
        
        assert_eq!(buffer.len(), 10);
        assert!(buffer.capacity() >= 10);
    }
    
    #[test]
    fn test_memory_protection_flags() {
        assert!(MemoryProtection::ReadWrite.can_read());
        assert!(MemoryProtection::ReadWrite.can_write());
        assert!(!MemoryProtection::ReadWrite.can_execute());
        
        assert!(MemoryProtection::ExecuteReadWrite.can_read());
        assert!(MemoryProtection::ExecuteReadWrite.can_write());
        assert!(MemoryProtection::ExecuteReadWrite.can_execute());
        
        assert!(!MemoryProtection::NoAccess.can_read());
        assert!(!MemoryProtection::NoAccess.can_write());
        assert!(!MemoryProtection::NoAccess.can_execute());
    }
    
    #[test]
    fn test_memory_region() {
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
        assert_eq!(region.end_address(), 0x2000);
    }
    
    #[test]
    fn test_pattern_scanner() {
        let data = [0x48, 0x8B, 0x05, 0x90, 0x90, 0x48, 0x8B, 0x0D];
        let scanner = PatternScanner::new(&data);
        
        let pattern = vec![Some(0x48), Some(0x8B), None];
        assert_eq!(scanner.find_pattern(&pattern), Some(0));
        
        let all_matches = scanner.find_all_patterns(&pattern);
        assert_eq!(all_matches, vec![0, 5]);
    }
    
    #[test]
    fn test_pattern_string_parsing() {
        let pattern = PatternScanner::parse_pattern_string("48 8B ?? 90").unwrap();
        assert_eq!(pattern, vec![Some(0x48), Some(0x8B), None, Some(0x90)]);
    }
}