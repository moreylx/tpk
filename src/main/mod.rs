//! Main module for NT Mapper - Process management and memory operations
//! 
//! This module provides the core functionality for process enumeration,
//! memory manipulation, and system-level operations using Windows NT APIs.

mod process;
mod memory;
mod system;

pub use process::*;
pub use memory::*;
pub use system::*;

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Once, Mutex};
use std::ffi::CString;
use std::ptr;
use std::mem;

/// Global initialization guard
static INIT: Once = Once::new();
static mut GLOBAL_CONTEXT: Option<Arc<RwLock<MapperContext>>> = None;

/// Process identifier type alias for clarity
pub type ProcessId = u32;
pub type ThreadId = u32;
pub type Address = usize;

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

    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            Self::Execute | Self::ExecuteRead | Self::ExecuteReadWrite | Self::ExecuteWriteCopy
        )
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self,
            Self::ReadWrite | Self::WriteCopy | Self::ExecuteReadWrite | Self::ExecuteWriteCopy
        )
    }

    pub fn is_readable(&self) -> bool {
        !matches!(self, Self::NoAccess)
    }

    pub fn to_raw(&self) -> u32 {
        *self as u32
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
    pub fn combine(flags: &[AllocationType]) -> u32 {
        flags.iter().fold(0u32, |acc, f| acc | (*f as u32))
    }
}

/// Memory region state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryState {
    Commit = 0x1000,
    Reserve = 0x2000,
    Free = 0x10000,
}

impl MemoryState {
    pub fn from_raw(value: u32) -> Option<Self> {
        match value {
            0x1000 => Some(Self::Commit),
            0x2000 => Some(Self::Reserve),
            0x10000 => Some(Self::Free),
            _ => None,
        }
    }
}

/// Memory region type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryType {
    Private = 0x20000,
    Mapped = 0x40000,
    Image = 0x1000000,
}

impl MemoryType {
    pub fn from_raw(value: u32) -> Option<Self> {
        match value {
            0x20000 => Some(Self::Private),
            0x40000 => Some(Self::Mapped),
            0x1000000 => Some(Self::Image),
            _ => None,
        }
    }
}

/// Information about a memory region
#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub base_address: Address,
    pub allocation_base: Address,
    pub allocation_protect: MemoryProtection,
    pub region_size: usize,
    pub state: MemoryState,
    pub protect: MemoryProtection,
    pub memory_type: Option<MemoryType>,
}

impl MemoryRegionInfo {
    pub fn is_committed(&self) -> bool {
        self.state == MemoryState::Commit
    }

    pub fn is_accessible(&self) -> bool {
        self.is_committed() && self.protect.is_readable()
    }
}

/// Process access rights
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProcessAccess {
    Terminate = 0x0001,
    CreateThread = 0x0002,
    VmOperation = 0x0008,
    VmRead = 0x0010,
    VmWrite = 0x0020,
    DupHandle = 0x0040,
    CreateProcess = 0x0080,
    SetQuota = 0x0100,
    SetInformation = 0x0200,
    QueryInformation = 0x0400,
    SuspendResume = 0x0800,
    QueryLimitedInformation = 0x1000,
    Synchronize = 0x00100000,
    AllAccess = 0x001FFFFF,
}

impl ProcessAccess {
    pub fn combine(rights: &[ProcessAccess]) -> u32 {
        rights.iter().fold(0u32, |acc, r| acc | (*r as u32))
    }
}

/// Process information structure
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: ProcessId,
    pub parent_pid: ProcessId,
    pub name: String,
    pub thread_count: u32,
    pub base_priority: i32,
    pub handle_count: u32,
    pub session_id: u32,
}

impl ProcessInfo {
    pub fn new(pid: ProcessId, name: String) -> Self {
        Self {
            pid,
            parent_pid: 0,
            name,
            thread_count: 0,
            base_priority: 0,
            handle_count: 0,
            session_id: 0,
        }
    }
}

/// Thread information structure
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub tid: ThreadId,
    pub owner_pid: ProcessId,
    pub base_priority: i32,
    pub delta_priority: i32,
    pub start_address: Address,
    pub state: ThreadState,
}

/// Thread execution state
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
    GateWait,
    Unknown(u32),
}

impl ThreadState {
    pub fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Initialized,
            1 => Self::Ready,
            2 => Self::Running,
            3 => Self::Standby,
            4 => Self::Terminated,
            5 => Self::Waiting,
            6 => Self::Transition,
            7 => Self::DeferredReady,
            8 => Self::GateWait,
            v => Self::Unknown(v),
        }
    }
}

/// Module information structure
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base_address: Address,
    pub size: usize,
    pub entry_point: Address,
    pub name: String,
    pub path: String,
}

/// Observer trait for process events
pub trait ProcessObserver: Send + Sync {
    fn on_process_created(&self, info: &ProcessInfo);
    fn on_process_terminated(&self, pid: ProcessId);
    fn on_memory_allocated(&self, pid: ProcessId, address: Address, size: usize);
    fn on_memory_freed(&self, pid: ProcessId, address: Address);
}

/// Strategy trait for memory allocation
pub trait AllocationStrategy: Send + Sync {
    fn select_region(&self, size: usize, regions: &[MemoryRegionInfo]) -> Option<Address>;
    fn alignment(&self) -> usize;
}

/// Default allocation strategy - finds first suitable free region
pub struct FirstFitStrategy {
    min_alignment: usize,
}

impl FirstFitStrategy {
    pub fn new(alignment: usize) -> Self {
        Self {
            min_alignment: alignment.max(0x1000),
        }
    }
}

impl AllocationStrategy for FirstFitStrategy {
    fn select_region(&self, size: usize, regions: &[MemoryRegionInfo]) -> Option<Address> {
        for region in regions {
            if region.state == MemoryState::Free && region.region_size >= size {
                let aligned = (region.base_address + self.min_alignment - 1) & !(self.min_alignment - 1);
                if aligned + size <= region.base_address + region.region_size {
                    return Some(aligned);
                }
            }
        }
        None
    }

    fn alignment(&self) -> usize {
        self.min_alignment
    }
}

/// Best-fit allocation strategy - finds smallest suitable region
pub struct BestFitStrategy {
    min_alignment: usize,
}

impl BestFitStrategy {
    pub fn new(alignment: usize) -> Self {
        Self {
            min_alignment: alignment.max(0x1000),
        }
    }
}

impl AllocationStrategy for BestFitStrategy {
    fn select_region(&self, size: usize, regions: &[MemoryRegionInfo]) -> Option<Address> {
        let mut best: Option<(Address, usize)> = None;
        
        for region in regions {
            if region.state == MemoryState::Free && region.region_size >= size {
                let aligned = (region.base_address + self.min_alignment - 1) & !(self.min_alignment - 1);
                let available = region.base_address + region.region_size - aligned;
                
                if available >= size {
                    match best {
                        None => best = Some((aligned, available)),
                        Some((_, best_size)) if available < best_size => {
                            best = Some((aligned, available));
                        }
                        _ => {}
                    }
                }
            }
        }
        
        best.map(|(addr, _)| addr)
    }

    fn alignment(&self) -> usize {
        self.min_alignment
    }
}

/// Factory for creating process handles
pub struct ProcessHandleFactory;

impl ProcessHandleFactory {
    pub fn open(pid: ProcessId, access: &[ProcessAccess]) -> Result<ProcessHandle, MapperError> {
        let access_mask = ProcessAccess::combine(access);
        ProcessHandle::open_with_access(pid, access_mask)
    }

    pub fn open_for_read(pid: ProcessId) -> Result<ProcessHandle, MapperError> {
        Self::open(pid, &[ProcessAccess::VmRead, ProcessAccess::QueryInformation])
    }

    pub fn open_for_write(pid: ProcessId) -> Result<ProcessHandle, MapperError> {
        Self::open(pid, &[
            ProcessAccess::VmRead,
            ProcessAccess::VmWrite,
            ProcessAccess::VmOperation,
            ProcessAccess::QueryInformation,
        ])
    }

    pub fn open_full_access(pid: ProcessId) -> Result<ProcessHandle, MapperError> {
        Self::open(pid, &[ProcessAccess::AllAccess])
    }
}

/// RAII wrapper for process handles
pub struct ProcessHandle {
    handle: SafeHandle,
    pid: ProcessId,
    access_mask: u32,
}

impl ProcessHandle {
    fn open_with_access(pid: ProcessId, access_mask: u32) -> Result<Self, MapperError> {
        // Simulated handle opening - in real implementation would call NtOpenProcess
        let raw_handle = Self::simulate_open_process(pid, access_mask)?;
        
        Ok(Self {
            handle: SafeHandle::new(raw_handle),
            pid,
            access_mask,
        })
    }

    fn simulate_open_process(pid: ProcessId, _access: u32) -> Result<*mut std::ffi::c_void, MapperError> {
        // Placeholder - real implementation would use NT APIs
        if pid == 0 {
            return Err(MapperError::InvalidParameter("Invalid process ID".into()));
        }
        // Return a mock handle value for demonstration
        Ok((pid as usize * 4) as *mut std::ffi::c_void)
    }

    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    pub fn access_mask(&self) -> u32 {
        self.access_mask
    }

    pub fn has_access(&self, required: ProcessAccess) -> bool {
        (self.access_mask & (required as u32)) != 0
    }

    pub fn raw_handle(&self) -> *mut std::ffi::c_void {
        self.handle.as_ptr()
    }
}

/// Memory manager for a specific process
pub struct ProcessMemoryManager {
    handle: Arc<ProcessHandle>,
    allocation_strategy: Box<dyn AllocationStrategy>,
    cached_regions: RwLock<Vec<MemoryRegionInfo>>,
    allocations: Mutex<HashMap<Address, usize>>,
}

impl ProcessMemoryManager {
    pub fn new(handle: ProcessHandle) -> Self {
        Self::with_strategy(handle, Box::new(FirstFitStrategy::new(0x1000)))
    }

    pub fn with_strategy(handle: ProcessHandle, strategy: Box<dyn AllocationStrategy>) -> Self {
        Self {
            handle: Arc::new(handle),
            allocation_strategy: strategy,
            cached_regions: RwLock::new(Vec::new()),
            allocations: Mutex::new(HashMap::new()),
        }
    }

    pub fn refresh_regions(&self) -> Result<(), MapperError> {
        let regions = self.query_all_regions()?;
        let mut cache = self.cached_regions.write()
            .map_err(|_| MapperError::LockPoisoned)?;
        *cache = regions;
        Ok(())
    }

    fn query_all_regions(&self) -> Result<Vec<MemoryRegionInfo>, MapperError> {
        let mut regions = Vec::new();
        let mut address: Address = 0;
        
        // Simulate querying memory regions
        // Real implementation would use NtQueryVirtualMemory
        while address < 0x7FFFFFFFFFFF {
            if let Some(region) = self.query_region_at(address)? {
                let next_addr = region.base_address.saturating_add(region.region_size);
                regions.push(region);
                
                if next_addr <= address {
                    break;
                }
                address = next_addr;
            } else {
                break;
            }
        }
        
        Ok(regions)
    }

    fn query_region_at(&self, address: Address) -> Result<Option<MemoryRegionInfo>, MapperError> {
        // Simulated region query - real implementation would call NtQueryVirtualMemory
        // For demonstration, create mock regions
        if address >= 0x7FFFFFFFFFFF {
            return Ok(None);
        }

        let region_size = 0x10000usize;
        let state = if address % 0x30000 == 0 {
            MemoryState::Commit
        } else if address % 0x20000 == 0 {
            MemoryState::Reserve
        } else {
            MemoryState::Free
        };

        Ok(Some(MemoryRegionInfo {
            base_address: address,
            allocation_base: address & !0xFFFF,
            allocation_protect: MemoryProtection::ReadWrite,
            region_size,
            state,
            protect: MemoryProtection::ReadWrite,
            memory_type: Some(MemoryType::Private),
        }))
    }

    pub fn allocate(&self, size: usize, protection: MemoryProtection) -> Result<Address, MapperError> {
        self.allocate_at(None, size, protection)
    }

    pub fn allocate_at(
        &self,
        preferred_address: Option<Address>,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<Address, MapperError> {
        if !self.handle.has_access(ProcessAccess::VmOperation) {
            return Err(MapperError::AccessDenied);
        }

        let aligned_size = (size + 0xFFF) & !0xFFF;
        
        let target_address = match preferred_address {
            Some(addr) => addr,
            None => {
                let regions = self.cached_regions.read()
                    .map_err(|_| MapperError::LockPoisoned)?;
                self.allocation_strategy.select_region(aligned_size, &regions)
                    .ok_or(MapperError::InsufficientMemory)?
            }
        };

        // Simulate allocation - real implementation would call NtAllocateVirtualMemory
        let allocated_address = self.simulate_allocate(target_address, aligned_size, protection)?;
        
        let mut allocations = self.allocations.lock()
            .map_err(|_| MapperError::LockPoisoned)?;
        allocations.insert(allocated_address, aligned_size);
        
        Ok(allocated_address)
    }

    fn simulate_allocate(
        &self,
        address: Address,
        size: usize,
        _protection: MemoryProtection,
    ) -> Result<Address, MapperError> {
        // Placeholder for actual NT API call
        if size == 0 {
            return Err(MapperError::InvalidParameter("Size cannot be zero".into()));
        }
        Ok(address)
    }

    pub fn free(&self, address: Address) -> Result<(), MapperError> {
        if !self.handle.has_access(ProcessAccess::VmOperation) {
            return Err(MapperError::AccessDenied);
        }

        let mut allocations = self.allocations.lock()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        if allocations.remove(&address).is_none() {
            return Err(MapperError::InvalidParameter("Address not allocated by this manager".into()));
        }

        // Simulate free - real implementation would call NtFreeVirtualMemory
        self.simulate_free(address)?;
        
        Ok(())
    }

    fn simulate_free(&self, _address: Address) -> Result<(), MapperError> {
        // Placeholder for actual NT API call
        Ok(())
    }

    pub fn protect(
        &self,
        address: Address,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Result<MemoryProtection, MapperError> {
        if !self.handle.has_access(ProcessAccess::VmOperation) {
            return Err(MapperError::AccessDenied);
        }

        // Simulate protection change - real implementation would call NtProtectVirtualMemory
        self.simulate_protect(address, size, new_protection)
    }

    fn simulate_protect(
        &self,
        _address: Address,
        _size: usize,
        _protection: MemoryProtection,
    ) -> Result<MemoryProtection, MapperError> {
        // Return previous protection (simulated)
        Ok(MemoryProtection::ReadWrite)
    }

    pub fn read(&self, address: Address, buffer: &mut [u8]) -> Result<usize, MapperError> {
        if !self.handle.has_access(ProcessAccess::VmRead) {
            return Err(MapperError::AccessDenied);
        }

        // Simulate read - real implementation would call NtReadVirtualMemory
        self.simulate_read(address, buffer)
    }

    fn simulate_read(&self, _address: Address, buffer: &mut [u8]) -> Result<usize, MapperError> {
        // Fill with placeholder data for demonstration
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        Ok(buffer.len())
    }

    pub fn read_exact(&self, address: Address, buffer: &mut [u8]) -> Result<(), MapperError> {
        let bytes_read = self.read(address, buffer)?;
        if bytes_read != buffer.len() {
            return Err(MapperError::PartialOperation {
                expected: buffer.len(),
                actual: bytes_read,
            });
        }
        Ok(())
    }

    pub fn read_value<T: Copy>(&self, address: Address) -> Result<T, MapperError> {
        let mut buffer = vec![0u8; mem::size_of::<T>()];
        self.read_exact(address, &mut buffer)?;
        
        // Safety: buffer is properly sized and aligned for T
        Ok(unsafe { ptr::read_unaligned(buffer.as_ptr() as *const T) })
    }

    pub fn write(&self, address: Address, data: &[u8]) -> Result<usize, MapperError> {
        if !self.handle.has_access(ProcessAccess::VmWrite) {
            return Err(MapperError::AccessDenied);
        }

        // Simulate write - real implementation would call NtWriteVirtualMemory
        self.simulate_write(address, data)
    }

    fn simulate_write(&self, _address: Address, data: &[u8]) -> Result<usize, MapperError> {
        Ok(data.len())
    }

    pub fn write_exact(&self, address: Address, data: &[u8]) -> Result<(), MapperError> {
        let bytes_written = self.write(address, data)?;
        if bytes_written != data.len() {
            return Err(MapperError::PartialOperation {
                expected: data.len(),
                actual: bytes_written,
            });
        }
        Ok(())
    }

    pub fn write_value<T: Copy>(&self, address: Address, value: &T) -> Result<(), MapperError> {
        let data = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>())
        };
        self.write_exact(address, data)
    }

    pub fn find_pattern(&self, pattern: &[Option<u8>], range: Option<(Address, Address)>) -> Result<Option<Address>, MapperError> {
        let (start, end) = range.unwrap_or((0x10000, 0x7FFFFFFEFFFF));
        
        let regions = self.cached_regions.read()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        for region in regions.iter() {
            if !region.is_accessible() {
                continue;
            }
            
            if region.base_address >= end || region.base_address + region.region_size <= start {
                continue;
            }

            let scan_start = region.base_address.max(start);
            let scan_end = (region.base_address + region.region_size).min(end);
            let scan_size = scan_end - scan_start;

            if scan_size < pattern.len() {
                continue;
            }

            let mut buffer = vec![0u8; scan_size];
            if self.read(scan_start, &mut buffer).is_err() {
                continue;
            }

            if let Some(offset) = Self::match_pattern(&buffer, pattern) {
                return Ok(Some(scan_start + offset));
            }
        }
        
        Ok(None)
    }

    fn match_pattern(data: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
        if pattern.is_empty() || data.len() < pattern.len() {
            return None;
        }

        'outer: for i in 0..=(data.len() - pattern.len()) {
            for (j, pat_byte) in pattern.iter().enumerate() {
                if let Some(expected) = pat_byte {
                    if data[i + j] != *expected {
                        continue 'outer;
                    }
                }
            }
            return Some(i);
        }
        None
    }
}

/// Global mapper context for managing multiple processes
pub struct MapperContext {
    processes: HashMap<ProcessId, Arc<ProcessMemoryManager>>,
    observers: Vec<Arc<dyn ProcessObserver>>,
    system_info: SystemInfo,
}

/// System information cache
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub page_size: usize,
    pub allocation_granularity: usize,
    pub min_address: Address,
    pub max_address: Address,
    pub processor_count: u32,
    pub os_version: (u32, u32, u32),
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self {
            page_size: 0x1000,
            allocation_granularity: 0x10000,
            min_address: 0x10000,
            max_address: 0x7FFFFFFEFFFF,
            processor_count: 1,
            os_version: (10, 0, 0),
        }
    }
}

impl MapperContext {
    pub fn new() -> Result<Self, MapperError> {
        let system_info = Self::query_system_info()?;
        
        Ok(Self {
            processes: HashMap::new(),
            observers: Vec::new(),
            system_info,
        })
    }

    fn query_system_info() -> Result<SystemInfo, MapperError> {
        // Simulated system info query - real implementation would use NtQuerySystemInformation
        Ok(SystemInfo::default())
    }

    pub fn system_info(&self) -> &SystemInfo {
        &self.system_info
    }

    pub fn register_observer(&mut self, observer: Arc<dyn ProcessObserver>) {
        self.observers.push(observer);
    }

    pub fn unregister_observer(&mut self, observer: &Arc<dyn ProcessObserver>) {
        self.observers.retain(|o| !Arc::ptr_eq(o, observer));
    }

    fn notify_process_created(&self, info: &ProcessInfo) {
        for observer in &self.observers {
            observer.on_process_created(info);
        }
    }

    fn notify_process_terminated(&self, pid: ProcessId) {
        for observer in &self.observers {
            observer.on_process_terminated(pid);
        }
    }

    pub fn attach(&mut self, pid: ProcessId) -> Result<Arc<ProcessMemoryManager>, MapperError> {
        if let Some(manager) = self.processes.get(&pid) {
            return Ok(Arc::clone(manager));
        }

        let handle = ProcessHandleFactory::open_for_write(pid)?;
        let manager = Arc::new(ProcessMemoryManager::new(handle));
        
        self.processes.insert(pid, Arc::clone(&manager));
        
        let info = ProcessInfo::new(pid, format!("Process_{}", pid));
        self.notify_process_created(&info);
        
        Ok(manager)
    }

    pub fn detach(&mut self, pid: ProcessId) -> Result<(), MapperError> {
        if self.processes.remove(&pid).is_some() {
            self.notify_process_terminated(pid);
            Ok(())
        } else {
            Err(MapperError::ProcessNotFound(pid))
        }
    }

    pub fn get_manager(&self, pid: ProcessId) -> Option<Arc<ProcessMemoryManager>> {
        self.processes.get(&pid).cloned()
    }

    pub fn enumerate_processes() -> Result<Vec<ProcessInfo>, MapperError> {
        // Simulated process enumeration - real implementation would use NtQuerySystemInformation
        let mut processes = Vec::new();
        
        // Mock data for demonstration
        processes.push(ProcessInfo {
            pid: 4,
            parent_pid: 0,
            name: "System".to_string(),
            thread_count: 100,
            base_priority: 8,
            handle_count: 1000,
            session_id: 0,
        });
        
        processes.push(ProcessInfo {
            pid: 1234,
            parent_pid: 4,
            name: "example.exe".to_string(),
            thread_count: 5,
            base_priority: 8,
            handle_count: 50,
            session_id: 1,
        });
        
        Ok(processes)
    }

    pub fn find_process_by_name(name: &str) -> Result<Option<ProcessInfo>, MapperError> {
        let processes = Self::enumerate_processes()?;
        let name_lower = name.to_lowercase();
        
        Ok(processes.into_iter().find(|p| p.name.to_lowercase() == name_lower))
    }
}

impl Default for MapperContext {
    fn default() -> Self {
        Self::new().expect("Failed to create default MapperContext")
    }
}

/// Initialize the global mapper context
pub fn initialize_global() -> Result<(), MapperError> {
    let mut init_result = Ok(());
    
    INIT.call_once(|| {
        match MapperContext::new() {
            Ok(ctx) => {
                unsafe {
                    GLOBAL_CONTEXT = Some(Arc::new(RwLock::new(ctx)));
                }
            }
            Err(e) => {
                init_result = Err(e);
            }
        }
    });
    
    init_result
}

/// Get the global mapper context
pub fn global_context() -> Result<Arc<RwLock<MapperContext>>, MapperError> {
    unsafe {
        GLOBAL_CONTEXT.clone().ok_or(MapperError::NotInitialized)
    }
}

/// Convenience function to attach to a process using global context
pub fn attach_process(pid: ProcessId) -> Result<Arc<ProcessMemoryManager>, MapperError> {
    let ctx = global_context()?;
    let mut guard = ctx.write().map_err(|_| MapperError::LockPoisoned)?;
    guard.attach(pid)
}

/// Convenience function to detach from a process using global context
pub fn detach_process(pid: ProcessId) -> Result<(), MapperError> {
    let ctx = global_context()?;
    let mut guard = ctx.write().map_