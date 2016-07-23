//! Thread operations and memory management module
//!
//! Provides safe abstractions for thread manipulation, memory operations,
//! and cross-process memory access with proper RAII semantics.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::{MapperError, NtStatus};

/// Thread access rights flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ThreadAccess {
    Terminate = 0x0001,
    SuspendResume = 0x0002,
    GetContext = 0x0008,
    SetContext = 0x0010,
    QueryInformation = 0x0040,
    SetInformation = 0x0020,
    SetThreadToken = 0x0080,
    Impersonate = 0x0100,
    DirectImpersonation = 0x0200,
    SetLimitedInformation = 0x0400,
    QueryLimitedInformation = 0x0800,
    AllAccess = 0x1FFFFF,
}

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

/// Memory free type flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FreeType {
    Decommit = 0x4000,
    Release = 0x8000,
    CoalescePlaceholders = 0x1,
    PreservePlaceholder = 0x2,
}

/// Thread state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    Unknown(u32),
}

impl From<u32> for ThreadState {
    fn from(value: u32) -> Self {
        match value {
            0 => ThreadState::Initialized,
            1 => ThreadState::Ready,
            2 => ThreadState::Running,
            3 => ThreadState::Standby,
            4 => ThreadState::Terminated,
            5 => ThreadState::Waiting,
            6 => ThreadState::Transition,
            7 => ThreadState::DeferredReady,
            8 => ThreadState::GateWaitObsolete,
            9 => ThreadState::WaitingForProcessInSwap,
            n => ThreadState::Unknown(n),
        }
    }
}

/// Thread context structure for x64
#[repr(C, align(16))]
#[derive(Debug, Clone)]
pub struct ThreadContext {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    _xmm_reserved: [u8; 512],
    _vector_reserved: [u8; 256],
}

impl Default for ThreadContext {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: MemoryProtection,
    pub region_size: usize,
    pub state: u32,
    pub protect: MemoryProtection,
    pub region_type: u32,
}

/// Observer trait for thread events
pub trait ThreadObserver: Send + Sync {
    fn on_thread_created(&self, thread_id: u32);
    fn on_thread_terminated(&self, thread_id: u32, exit_code: u32);
    fn on_thread_suspended(&self, thread_id: u32);
    fn on_thread_resumed(&self, thread_id: u32);
}

/// Strategy trait for memory allocation
pub trait AllocationStrategy: Send + Sync {
    fn allocate(&self, size: usize, protection: MemoryProtection) -> Result<NonNull<c_void>, MapperError>;
    fn deallocate(&self, ptr: NonNull<c_void>, size: usize) -> Result<(), MapperError>;
    fn protect(&self, ptr: NonNull<c_void>, size: usize, protection: MemoryProtection) -> Result<MemoryProtection, MapperError>;
}

/// Default allocation strategy using virtual memory
pub struct VirtualAllocationStrategy {
    process_handle: usize,
}

impl VirtualAllocationStrategy {
    pub fn new(process_handle: usize) -> Self {
        Self { process_handle }
    }
    
    pub fn for_current_process() -> Self {
        Self { process_handle: usize::MAX }
    }
}

impl AllocationStrategy for VirtualAllocationStrategy {
    fn allocate(&self, size: usize, protection: MemoryProtection) -> Result<NonNull<c_void>, MapperError> {
        // TODO: Implement actual VirtualAllocEx call
        let aligned_size = (size + 0xFFF) & !0xFFF;
        
        if aligned_size == 0 {
            return Err(MapperError::InvalidParameter("Size cannot be zero".into()));
        }
        
        // Placeholder - would call NtAllocateVirtualMemory
        Err(MapperError::NotImplemented("VirtualAlloc not yet implemented".into()))
    }
    
    fn deallocate(&self, ptr: NonNull<c_void>, size: usize) -> Result<(), MapperError> {
        // TODO: Implement actual VirtualFreeEx call
        Err(MapperError::NotImplemented("VirtualFree not yet implemented".into()))
    }
    
    fn protect(&self, ptr: NonNull<c_void>, size: usize, protection: MemoryProtection) -> Result<MemoryProtection, MapperError> {
        // TODO: Implement actual VirtualProtectEx call
        Err(MapperError::NotImplemented("VirtualProtect not yet implemented".into()))
    }
}

/// RAII wrapper for allocated memory regions
pub struct AllocatedRegion<S: AllocationStrategy> {
    ptr: NonNull<c_void>,
    size: usize,
    strategy: Arc<S>,
    _marker: PhantomData<*mut c_void>,
}

impl<S: AllocationStrategy> AllocatedRegion<S> {
    pub fn new(strategy: Arc<S>, size: usize, protection: MemoryProtection) -> Result<Self, MapperError> {
        let ptr = strategy.allocate(size, protection)?;
        Ok(Self {
            ptr,
            size,
            strategy,
            _marker: PhantomData,
        })
    }
    
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
    
    pub fn size(&self) -> usize {
        self.size
    }
    
    pub fn protect(&self, protection: MemoryProtection) -> Result<MemoryProtection, MapperError> {
        self.strategy.protect(self.ptr, self.size, protection)
    }
    
    /// Write data to the allocated region
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<(), MapperError> {
        if offset + data.len() > self.size {
            return Err(MapperError::InvalidParameter("Write exceeds region bounds".into()));
        }
        
        unsafe {
            let dest = (self.ptr.as_ptr() as *mut u8).add(offset);
            ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
        }
        
        Ok(())
    }
    
    /// Read data from the allocated region
    pub fn read(&self, offset: usize, len: usize) -> Result<Vec<u8>, MapperError> {
        if offset + len > self.size {
            return Err(MapperError::InvalidParameter("Read exceeds region bounds".into()));
        }
        
        let mut buffer = vec![0u8; len];
        unsafe {
            let src = (self.ptr.as_ptr() as *const u8).add(offset);
            ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), len);
        }
        
        Ok(buffer)
    }
}

impl<S: AllocationStrategy> Drop for AllocatedRegion<S> {
    fn drop(&mut self) {
        let _ = self.strategy.deallocate(self.ptr, self.size);
    }
}

unsafe impl<S: AllocationStrategy> Send for AllocatedRegion<S> {}
unsafe impl<S: AllocationStrategy> Sync for AllocatedRegion<S> {}

/// Thread handle wrapper with RAII semantics
pub struct ThreadHandle {
    handle: usize,
    thread_id: u32,
    owns_handle: bool,
    suspended_count: AtomicUsize,
    observers: Vec<Arc<dyn ThreadObserver>>,
}

impl ThreadHandle {
    /// Open an existing thread by ID
    pub fn open(thread_id: u32, access: ThreadAccess) -> Result<Self, MapperError> {
        // TODO: Implement actual NtOpenThread call
        Err(MapperError::NotImplemented("Thread opening not yet implemented".into()))
    }
    
    /// Get the current thread
    pub fn current() -> Self {
        Self {
            handle: usize::MAX - 1, // Pseudo-handle for current thread
            thread_id: 0, // Would be filled by GetCurrentThreadId
            owns_handle: false,
            suspended_count: AtomicUsize::new(0),
            observers: Vec::new(),
        }
    }
    
    /// Register an observer for thread events
    pub fn register_observer(&mut self, observer: Arc<dyn ThreadObserver>) {
        self.observers.push(observer);
    }
    
    /// Get the thread ID
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }
    
    /// Get the raw handle value
    pub fn raw_handle(&self) -> usize {
        self.handle
    }
    
    /// Suspend the thread
    pub fn suspend(&self) -> Result<u32, MapperError> {
        // TODO: Implement actual NtSuspendThread call
        let prev_count = self.suspended_count.fetch_add(1, Ordering::SeqCst);
        
        for observer in &self.observers {
            observer.on_thread_suspended(self.thread_id);
        }
        
        Ok(prev_count as u32)
    }
    
    /// Resume the thread
    pub fn resume(&self) -> Result<u32, MapperError> {
        // TODO: Implement actual NtResumeThread call
        let prev_count = self.suspended_count.load(Ordering::SeqCst);
        if prev_count > 0 {
            self.suspended_count.fetch_sub(1, Ordering::SeqCst);
        }
        
        for observer in &self.observers {
            observer.on_thread_resumed(self.thread_id);
        }
        
        Ok(prev_count as u32)
    }
    
    /// Get the thread context
    pub fn get_context(&self, flags: u32) -> Result<ThreadContext, MapperError> {
        // TODO: Implement actual NtGetContextThread call
        let mut context = ThreadContext::default();
        context.context_flags = flags;
        
        Err(MapperError::NotImplemented("GetContext not yet implemented".into()))
    }
    
    /// Set the thread context
    pub fn set_context(&self, context: &ThreadContext) -> Result<(), MapperError> {
        // TODO: Implement actual NtSetContextThread call
        Err(MapperError::NotImplemented("SetContext not yet implemented".into()))
    }
    
    /// Terminate the thread
    pub fn terminate(&self, exit_code: u32) -> Result<(), MapperError> {
        // TODO: Implement actual NtTerminateThread call
        for observer in &self.observers {
            observer.on_thread_terminated(self.thread_id, exit_code);
        }
        
        Err(MapperError::NotImplemented("Terminate not yet implemented".into()))
    }
    
    /// Query thread information
    pub fn query_state(&self) -> Result<ThreadState, MapperError> {
        // TODO: Implement actual NtQueryInformationThread call
        Err(MapperError::NotImplemented("QueryState not yet implemented".into()))
    }
    
    /// Wait for the thread to terminate
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<(), MapperError> {
        // TODO: Implement actual NtWaitForSingleObject call
        Err(MapperError::NotImplemented("Wait not yet implemented".into()))
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        if self.owns_handle && self.handle != 0 && self.handle != usize::MAX - 1 {
            // TODO: Close handle via NtClose
        }
    }
}

/// Factory for creating threads
pub struct ThreadFactory {
    default_stack_size: usize,
    create_suspended: bool,
}

impl ThreadFactory {
    pub fn new() -> Self {
        Self {
            default_stack_size: 0, // Use system default
            create_suspended: false,
        }
    }
    
    pub fn with_stack_size(mut self, size: usize) -> Self {
        self.default_stack_size = size;
        self
    }
    
    pub fn create_suspended(mut self, suspended: bool) -> Self {
        self.create_suspended = suspended;
        self
    }
    
    /// Create a new thread in the current process
    pub fn create_local<F>(&self, _entry: F) -> Result<ThreadHandle, MapperError>
    where
        F: FnOnce() + Send + 'static,
    {
        // TODO: Implement actual thread creation
        Err(MapperError::NotImplemented("Local thread creation not yet implemented".into()))
    }
    
    /// Create a remote thread in another process
    pub fn create_remote(
        &self,
        process_handle: usize,
        start_address: usize,
        parameter: usize,
    ) -> Result<ThreadHandle, MapperError> {
        // TODO: Implement actual NtCreateThreadEx call
        Err(MapperError::NotImplemented("Remote thread creation not yet implemented".into()))
    }
}

impl Default for ThreadFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory operations for cross-process memory access
pub struct RemoteMemory {
    process_handle: usize,
    base_address: usize,
}

impl RemoteMemory {
    pub fn new(process_handle: usize, base_address: usize) -> Self {
        Self {
            process_handle,
            base_address,
        }
    }
    
    /// Read memory from the remote process
    pub fn read(&self, offset: usize, size: usize) -> Result<Vec<u8>, MapperError> {
        if size == 0 {
            return Ok(Vec::new());
        }
        
        let mut buffer = vec![0u8; size];
        self.read_into(offset, &mut buffer)?;
        Ok(buffer)
    }
    
    /// Read memory into an existing buffer
    pub fn read_into(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, MapperError> {
        // TODO: Implement actual NtReadVirtualMemory call
        let target_address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        Err(MapperError::NotImplemented("Remote read not yet implemented".into()))
    }
    
    /// Read a typed value from remote memory
    pub fn read_value<T: Copy>(&self, offset: usize) -> Result<T, MapperError> {
        let size = mem::size_of::<T>();
        let data = self.read(offset, size)?;
        
        if data.len() != size {
            return Err(MapperError::InvalidParameter("Incomplete read".into()));
        }
        
        Ok(unsafe { ptr::read_unaligned(data.as_ptr() as *const T) })
    }
    
    /// Write memory to the remote process
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<usize, MapperError> {
        if data.is_empty() {
            return Ok(0);
        }
        
        // TODO: Implement actual NtWriteVirtualMemory call
        let target_address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        Err(MapperError::NotImplemented("Remote write not yet implemented".into()))
    }
    
    /// Write a typed value to remote memory
    pub fn write_value<T: Copy>(&self, offset: usize, value: &T) -> Result<(), MapperError> {
        let data = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>())
        };
        
        let written = self.write(offset, data)?;
        if written != mem::size_of::<T>() {
            return Err(MapperError::InvalidParameter("Incomplete write".into()));
        }
        
        Ok(())
    }
    
    /// Query memory region information
    pub fn query_region(&self, offset: usize) -> Result<MemoryRegionInfo, MapperError> {
        // TODO: Implement actual NtQueryVirtualMemory call
        let target_address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        Err(MapperError::NotImplemented("Query region not yet implemented".into()))
    }
    
    /// Change memory protection
    pub fn protect(&self, offset: usize, size: usize, protection: MemoryProtection) -> Result<MemoryProtection, MapperError> {
        // TODO: Implement actual NtProtectVirtualMemory call
        let target_address = self.base_address.checked_add(offset)
            .ok_or_else(|| MapperError::InvalidParameter("Address overflow".into()))?;
        
        Err(MapperError::NotImplemented("Protect not yet implemented".into()))
    }
}

/// Scoped memory protection change with RAII restoration
pub struct ProtectionGuard<'a> {
    memory: &'a RemoteMemory,
    offset: usize,
    size: usize,
    original_protection: MemoryProtection,
}

impl<'a> ProtectionGuard<'a> {
    pub fn new(
        memory: &'a RemoteMemory,
        offset: usize,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Result<Self, MapperError> {
        let original = memory.protect(offset, size, new_protection)?;
        
        Ok(Self {
            memory,
            offset,
            size,
            original_protection: original,
        })
    }
}

impl<'a> Drop for ProtectionGuard<'a> {
    fn drop(&mut self) {
        let _ = self.memory.protect(self.offset, self.size, self.original_protection);
    }
}

/// Thread-local storage slot manager
pub struct TlsSlot {
    index: u32,
    allocated: AtomicBool,
}

impl TlsSlot {
    /// Allocate a new TLS slot
    pub fn allocate() -> Result<Self, MapperError> {
        // TODO: Implement actual TlsAlloc call
        Err(MapperError::NotImplemented("TLS allocation not yet implemented".into()))
    }
    
    /// Get the slot index
    pub fn index(&self) -> u32 {
        self.index
    }
    
    /// Set the value for the current thread
    pub fn set(&self, value: usize) -> Result<(), MapperError> {
        if !self.allocated.load(Ordering::SeqCst) {
            return Err(MapperError::InvalidParameter("TLS slot not allocated".into()));
        }
        
        // TODO: Implement actual TlsSetValue call
        Err(MapperError::NotImplemented("TLS set not yet implemented".into()))
    }
    
    /// Get the value for the current thread
    pub fn get(&self) -> Result<usize, MapperError> {
        if !self.allocated.load(Ordering::SeqCst) {
            return Err(MapperError::InvalidParameter("TLS slot not allocated".into()));
        }
        
        // TODO: Implement actual TlsGetValue call
        Err(MapperError::NotImplemented("TLS get not yet implemented".into()))
    }
}

impl Drop for TlsSlot {
    fn drop(&mut self) {
        if self.allocated.swap(false, Ordering::SeqCst) {
            // TODO: Implement actual TlsFree call
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_thread_state_conversion() {
        assert_eq!(ThreadState::from(0), ThreadState::Initialized);
        assert_eq!(ThreadState::from(2), ThreadState::Running);
        assert_eq!(ThreadState::from(4), ThreadState::Terminated);
        assert_eq!(ThreadState::from(100), ThreadState::Unknown(100));
    }
    
    #[test]
    fn test_thread_context_default() {
        let ctx = ThreadContext::default();
        assert_eq!(ctx.rax, 0);
        assert_eq!(ctx.rip, 0);
    }
    
    #[test]
    fn test_thread_factory_builder() {
        let factory = ThreadFactory::new()
            .with_stack_size(1024 * 1024)
            .create_suspended(true);
        
        assert_eq!(factory.default_stack_size, 1024 * 1024);
        assert!(factory.create_suspended);
    }
    
    #[test]
    fn test_remote_memory_address_overflow() {
        let mem = RemoteMemory::new(0, usize::MAX);
        let result = mem.read(1, 10);
        assert!(result.is_err());
    }
}