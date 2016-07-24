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

impl MemoryProtection {
    /// Combines multiple protection flags
    pub fn combine(flags: &[MemoryProtection]) -> u32 {
        flags.iter().fold(0u32, |acc, &flag| acc | flag as u32)
    }

    /// Check if protection allows reading
    pub fn is_readable(self) -> bool {
        matches!(
            self,
            MemoryProtection::ReadOnly
                | MemoryProtection::ReadWrite
                | MemoryProtection::WriteCopy
                | MemoryProtection::ExecuteRead
                | MemoryProtection::ExecuteReadWrite
                | MemoryProtection::ExecuteWriteCopy
        )
    }

    /// Check if protection allows writing
    pub fn is_writable(self) -> bool {
        matches!(
            self,
            MemoryProtection::ReadWrite
                | MemoryProtection::WriteCopy
                | MemoryProtection::ExecuteReadWrite
                | MemoryProtection::ExecuteWriteCopy
        )
    }

    /// Check if protection allows execution
    pub fn is_executable(self) -> bool {
        matches!(
            self,
            MemoryProtection::Execute
                | MemoryProtection::ExecuteRead
                | MemoryProtection::ExecuteReadWrite
                | MemoryProtection::ExecuteWriteCopy
        )
    }
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

impl AllocationType {
    /// Combines multiple allocation flags
    pub fn combine(flags: &[AllocationType]) -> u32 {
        flags.iter().fold(0u32, |acc, &flag| acc | flag as u32)
    }
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

/// Thread priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

impl TryFrom<i32> for ThreadPriority {
    type Error = MapperError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -15 => Ok(ThreadPriority::Idle),
            -2 => Ok(ThreadPriority::Lowest),
            -1 => Ok(ThreadPriority::BelowNormal),
            0 => Ok(ThreadPriority::Normal),
            1 => Ok(ThreadPriority::AboveNormal),
            2 => Ok(ThreadPriority::Highest),
            15 => Ok(ThreadPriority::TimeCritical),
            _ => Err(MapperError::InvalidParameter(format!(
                "Invalid thread priority: {}",
                value
            ))),
        }
    }
}

/// CPU context for thread state capture
#[derive(Debug, Clone)]
#[repr(C, align(16))]
pub struct ThreadContext {
    pub context_flags: u32,
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
    pub rflags: u64,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub xmm: [[u8; 16]; 16],
}

impl Default for ThreadContext {
    fn default() -> Self {
        Self {
            context_flags: 0x10001F, // CONTEXT_ALL
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            cs: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            ss: 0,
            mxcsr: 0,
            mxcsr_mask: 0,
            xmm: [[0u8; 16]; 16],
        }
    }
}

/// Thread information structure
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub process_id: u32,
    pub state: ThreadState,
    pub priority: i32,
    pub base_priority: i32,
    pub start_address: usize,
    pub teb_address: usize,
    pub kernel_time: u64,
    pub user_time: u64,
    pub wait_reason: u32,
}

/// Safe handle wrapper for thread handles with RAII semantics
#[derive(Debug)]
pub struct ThreadHandle {
    handle: *mut c_void,
    thread_id: u32,
    owns_handle: bool,
}

impl ThreadHandle {
    /// Creates a new thread handle from a raw handle
    ///
    /// # Safety
    /// The caller must ensure the handle is valid and has appropriate access rights
    pub unsafe fn from_raw(handle: *mut c_void, thread_id: u32, owns: bool) -> Self {
        Self {
            handle,
            thread_id,
            owns_handle: owns,
        }
    }

    /// Opens an existing thread by ID
    pub fn open(thread_id: u32, access: ThreadAccess) -> Result<Self, MapperError> {
        Self::open_with_flags(thread_id, access as u32)
    }

    /// Opens an existing thread with combined access flags
    pub fn open_with_flags(thread_id: u32, access_flags: u32) -> Result<Self, MapperError> {
        // Simulated syscall - in real implementation would call NtOpenThread
        let handle = unsafe { simulate_open_thread(thread_id, access_flags)? };

        Ok(Self {
            handle,
            thread_id,
            owns_handle: true,
        })
    }

    /// Returns the raw handle value
    pub fn as_raw(&self) -> *mut c_void {
        self.handle
    }

    /// Returns the thread ID
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Suspends the thread
    pub fn suspend(&self) -> Result<u32, MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        unsafe { simulate_suspend_thread(self.handle) }
    }

    /// Resumes the thread
    pub fn resume(&self) -> Result<u32, MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        unsafe { simulate_resume_thread(self.handle) }
    }

    /// Gets the thread context
    pub fn get_context(&self, flags: u32) -> Result<ThreadContext, MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        let mut context = ThreadContext::default();
        context.context_flags = flags;

        unsafe { simulate_get_thread_context(self.handle, &mut context)? };

        Ok(context)
    }

    /// Sets the thread context
    pub fn set_context(&self, context: &ThreadContext) -> Result<(), MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        unsafe { simulate_set_thread_context(self.handle, context) }
    }

    /// Terminates the thread
    pub fn terminate(&self, exit_code: u32) -> Result<(), MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        unsafe { simulate_terminate_thread(self.handle, exit_code) }
    }

    /// Queries thread information
    pub fn query_info(&self) -> Result<ThreadInfo, MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        unsafe { simulate_query_thread_info(self.handle, self.thread_id) }
    }

    /// Sets thread priority
    pub fn set_priority(&self, priority: ThreadPriority) -> Result<(), MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        unsafe { simulate_set_thread_priority(self.handle, priority as i32) }
    }

    /// Waits for the thread to terminate
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<bool, MapperError> {
        if self.handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        unsafe { simulate_wait_for_thread(self.handle, timeout_ms) }
    }

    /// Releases ownership of the handle without closing it
    pub fn into_raw(mut self) -> *mut c_void {
        self.owns_handle = false;
        self.handle
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        if self.owns_handle && !self.handle.is_null() {
            unsafe {
                let _ = simulate_close_handle(self.handle);
            }
        }
    }
}

unsafe impl Send for ThreadHandle {}
unsafe impl Sync for ThreadHandle {}

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
}

impl MemoryRegion {
    /// Checks if the region is committed
    pub fn is_committed(&self) -> bool {
        self.state == 0x1000 // MEM_COMMIT
    }

    /// Checks if the region is reserved
    pub fn is_reserved(&self) -> bool {
        self.state == 0x2000 // MEM_RESERVE
    }

    /// Checks if the region is free
    pub fn is_free(&self) -> bool {
        self.state == 0x10000 // MEM_FREE
    }

    /// Gets the protection as enum
    pub fn protection(&self) -> Option<MemoryProtection> {
        match self.protect {
            0x01 => Some(MemoryProtection::NoAccess),
            0x02 => Some(MemoryProtection::ReadOnly),
            0x04 => Some(MemoryProtection::ReadWrite),
            0x08 => Some(MemoryProtection::WriteCopy),
            0x10 => Some(MemoryProtection::Execute),
            0x20 => Some(MemoryProtection::ExecuteRead),
            0x40 => Some(MemoryProtection::ExecuteReadWrite),
            0x80 => Some(MemoryProtection::ExecuteWriteCopy),
            _ => None,
        }
    }
}

/// Virtual memory allocator with RAII semantics
#[derive(Debug)]
pub struct VirtualAllocation {
    base_address: NonNull<c_void>,
    size: usize,
    process_handle: *mut c_void,
    owns_memory: bool,
}

impl VirtualAllocation {
    /// Allocates virtual memory in the current process
    pub fn allocate(
        size: usize,
        allocation_type: AllocationType,
        protection: MemoryProtection,
    ) -> Result<Self, MapperError> {
        Self::allocate_at(None, size, allocation_type, protection)
    }

    /// Allocates virtual memory at a specific address
    pub fn allocate_at(
        preferred_address: Option<usize>,
        size: usize,
        allocation_type: AllocationType,
        protection: MemoryProtection,
    ) -> Result<Self, MapperError> {
        if size == 0 {
            return Err(MapperError::InvalidParameter(
                "Size cannot be zero".to_string(),
            ));
        }

        let base = unsafe {
            simulate_virtual_alloc(
                preferred_address.unwrap_or(0) as *mut c_void,
                size,
                allocation_type as u32,
                protection as u32,
            )?
        };

        let base_nn = NonNull::new(base)
            .ok_or_else(|| MapperError::AllocationFailed("VirtualAlloc returned null".to_string()))?;

        Ok(Self {
            base_address: base_nn,
            size,
            process_handle: std::ptr::null_mut(), // Current process
            owns_memory: true,
        })
    }

    /// Allocates virtual memory in a remote process
    pub fn allocate_remote(
        process_handle: *mut c_void,
        size: usize,
        allocation_type: AllocationType,
        protection: MemoryProtection,
    ) -> Result<Self, MapperError> {
        if process_handle.is_null() {
            return Err(MapperError::InvalidHandle);
        }

        if size == 0 {
            return Err(MapperError::InvalidParameter(
                "Size cannot be zero".to_string(),
            ));
        }

        let base = unsafe {
            simulate_virtual_alloc_ex(
                process_handle,
                std::ptr::null_mut(),
                size,
                allocation_type as u32,
                protection as u32,
            )?
        };

        let base_nn = NonNull::new(base).ok_or_else(|| {
            MapperError::AllocationFailed("VirtualAllocEx returned null".to_string())
        })?;

        Ok(Self {
            base_address: base_nn,
            size,
            process_handle,
            owns_memory: true,
        })
    }

    /// Returns the base address of the allocation
    pub fn base_address(&self) -> *mut c_void {
        self.base_address.as_ptr()
    }

    /// Returns the size of the allocation
    pub fn size(&self) -> usize {
        self.size
    }

    /// Changes the protection of the allocated memory
    pub fn protect(&self, new_protection: MemoryProtection) -> Result<u32, MapperError> {
        unsafe {
            if self.process_handle.is_null() {
                simulate_virtual_protect(
                    self.base_address.as_ptr(),
                    self.size,
                    new_protection as u32,
                )
            } else {
                simulate_virtual_protect_ex(
                    self.process_handle,
                    self.base_address.as_ptr(),
                    self.size,
                    new_protection as u32,
                )
            }
        }
    }

    /// Writes data to the allocation
    pub fn write<T: Copy>(&self, offset: usize, data: &T) -> Result<(), MapperError> {
        let data_size = mem::size_of::<T>();
        if offset + data_size > self.size {
            return Err(MapperError::InvalidParameter(
                "Write would exceed allocation bounds".to_string(),
            ));
        }

        unsafe {
            let dest = (self.base_address.as_ptr() as *mut u8).add(offset) as *mut T;
            if self.process_handle.is_null() {
                ptr::write(dest, *data);
            } else {
                simulate_write_process_memory(
                    self.process_handle,
                    dest as *mut c_void,
                    data as *const T as *const c_void,
                    data_size,
                )?;
            }
        }

        Ok(())
    }

    /// Writes a slice of data to the allocation
    pub fn write_slice<T: Copy>(&self, offset: usize, data: &[T]) -> Result<(), MapperError> {
        let data_size = mem::size_of_val(data);
        if offset + data_size > self.size {
            return Err(MapperError::InvalidParameter(
                "Write would exceed allocation bounds".to_string(),
            ));
        }

        unsafe {
            let dest = (self.base_address.as_ptr() as *mut u8).add(offset);
            if self.process_handle.is_null() {
                ptr::copy_nonoverlapping(data.as_ptr() as *const u8, dest, data_size);
            } else {
                simulate_write_process_memory(
                    self.process_handle,
                    dest as *mut c_void,
                    data.as_ptr() as *const c_void,
                    data_size,
                )?;
            }
        }

        Ok(())
    }

    /// Reads data from the allocation
    pub fn read<T: Copy>(&self, offset: usize) -> Result<T, MapperError> {
        let data_size = mem::size_of::<T>();
        if offset + data_size > self.size {
            return Err(MapperError::InvalidParameter(
                "Read would exceed allocation bounds".to_string(),
            ));
        }

        unsafe {
            let src = (self.base_address.as_ptr() as *const u8).add(offset) as *const T;
            if self.process_handle.is_null() {
                Ok(ptr::read(src))
            } else {
                let mut result = MaybeUninit::<T>::uninit();
                simulate_read_process_memory(
                    self.process_handle,
                    src as *const c_void,
                    result.as_mut_ptr() as *mut c_void,
                    data_size,
                )?;
                Ok(result.assume_init())
            }
        }
    }

    /// Fills the allocation with a byte value
    pub fn fill(&self, value: u8) -> Result<(), MapperError> {
        unsafe {
            if self.process_handle.is_null() {
                ptr::write_bytes(self.base_address.as_ptr() as *mut u8, value, self.size);
                Ok(())
            } else {
                // For remote process, we need to write in chunks
                let chunk = vec![value; self.size.min(4096)];
                let mut offset = 0;
                while offset < self.size {
                    let write_size = (self.size - offset).min(chunk.len());
                    let dest = (self.base_address.as_ptr() as *mut u8).add(offset);
                    simulate_write_process_memory(
                        self.process_handle,
                        dest as *mut c_void,
                        chunk.as_ptr() as *const c_void,
                        write_size,
                    )?;
                    offset += write_size;
                }
                Ok(())
            }
        }
    }

    /// Releases ownership without freeing the memory
    pub fn leak(mut self) -> *mut c_void {
        self.owns_memory = false;
        self.base_address.as_ptr()
    }
}

impl Drop for VirtualAllocation {
    fn drop(&mut self) {
        if self.owns_memory {
            unsafe {
                if self.process_handle.is_null() {
                    let _ = simulate_virtual_free(
                        self.base_address.as_ptr(),
                        0,
                        FreeType::Release as u32,
                    );
                } else {
                    let _ = simulate_virtual_free_ex(
                        self.process_handle,
                        self.base_address.as_ptr(),
                        0,
                        FreeType::Release as u32,
                    );
                }
            }
        }
    }
}

unsafe impl Send for VirtualAllocation {}
unsafe impl Sync for VirtualAllocation {}

/// Memory scanner for pattern matching
pub struct MemoryScanner {
    regions: Vec<MemoryRegion>,
    scan_executable: bool,
    scan_writable: bool,
    scan_readable: bool,
}

impl MemoryScanner {
    /// Creates a new memory scanner
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            scan_executable: true,
            scan_writable: true,
            scan_readable: true,
        }
    }

    /// Sets whether to scan executable regions
    pub fn with_executable(mut self, scan: bool) -> Self {
        self.scan_executable = scan;
        self
    }

    /// Sets whether to scan writable regions
    pub fn with_writable(mut self, scan: bool) -> Self {
        self.scan_writable = scan;
        self
    }

    /// Sets whether to scan readable regions
    pub fn with_readable(mut self, scan: bool) -> Self {
        self.scan_readable = scan;
        self
    }

    /// Enumerates memory regions in the current process
    pub fn enumerate_regions(&mut self) -> Result<&[MemoryRegion], MapperError> {
        self.regions.clear();

        let mut address: usize = 0;
        let max_address: usize = 0x7FFFFFFFFFFF; // User-mode address space limit

        while address < max_address {
            match unsafe { simulate_query_virtual_memory(address) } {
                Ok(region) => {
                    let next_address = region.base_address.saturating_add(region.region_size);
                    if self.should_include_region(&region) {
                        self.regions.push(region);
                    }
                    address = next_address;
                }
                Err(_) => {
                    address = address.saturating_add(0x1000);
                }
            }

            if address == 0 {
                break; // Overflow protection
            }
        }

        Ok(&self.regions)
    }

    /// Scans for a byte pattern with optional wildcards
    pub fn scan_pattern(&self, pattern: &[Option<u8>]) -> Vec<usize> {
        let mut results = Vec::new();

        for region in &self.regions {
            if !region.is_committed() {
                continue;
            }

            // Read region memory
            let data = match self.read_region_safe(region) {
                Some(d) => d,
                None => continue,
            };

            // Search for pattern
            for i in 0..data.len().saturating_sub(pattern.len()) {
                let mut matched = true;
                for (j, &pat_byte) in pattern.iter().enumerate() {
                    if let Some(expected) = pat_byte {
                        if data[i + j] != expected {
                            matched = false;
                            break;
                        }
                    }
                }
                if matched {
                    results.push(region.base_address + i);
                }
            }
        }

        results
    }

    /// Scans for a specific value
    pub fn scan_value<T: Copy + PartialEq>(&self, value: T) -> Vec<usize> {
        let mut results = Vec::new();
        let value_size = mem::size_of::<T>();

        for region in &self.regions {
            if !region.is_committed() || region.region_size < value_size {
                continue;
            }

            let data = match self.read_region_safe(region) {
                Some(d) => d,
                None => continue,
            };

            for i in 0..=data.len().saturating_sub(value_size) {
                let candidate = unsafe { ptr::read_unaligned(data[i..].as_ptr() as *const T) };
                if candidate == value {
                    results.push(region.base_address + i);
                }
            }
        }

        results
    }

    fn should_include_region(&self, region: &MemoryRegion) -> bool {
        if !region.is_committed() {
            return false;
        }

        let prot = match region.protection() {
            Some(p) => p,
            None => return false,
        };

        if self.scan_executable && prot.is_executable() {
            return true;
        }
        if self.scan_writable && prot.is_writable() {
            return true;
        }
        if self.scan_readable && prot.is_readable() {
            return true;
        }

        false
    }

    fn read_region_safe(&self, region: &MemoryRegion) -> Option<Vec<u8>> {
        if region.region_size > 256 * 1024 * 1024 {
            // Skip regions larger than 256MB
            return None;
        }

        let mut buffer = vec![0u8; region.region_size];
        unsafe {
            if ptr::copy_nonoverlapping(
                region.base_address as *const u8,
                buffer.as_mut_ptr(),
                region.region_size,
            )
            .is_err()
            {
                return None;
            }
        }

        Some(buffer)
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread pool for parallel operations
pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<crossbeam_channel::Sender<Job>>,
    active_jobs: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

struct Worker {
    id: usize,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ThreadPool {
    /// Creates a new thread pool with the specified number of workers
    pub fn new(num_workers: usize) -> Self {
        let num_workers = num_workers.max(1);
        let (sender, receiver) = crossbeam_channel::unbounded::<Job>();
        let receiver = Arc::new(receiver);
        let active_jobs = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        let mut workers = Vec::with_capacity(num_workers);

        for id in 0..num_workers {
            let receiver = Arc::clone(&receiver);
            let active_jobs = Arc::clone(&active_jobs);
            let shutdown = Arc::clone(&shutdown);

            let thread = std::thread::spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                        Ok(job) => {
                            active_jobs.fetch_add(1, Ordering::SeqCst);
                            job();
                            active_jobs.fetch_sub(1, Ordering::SeqCst);
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,