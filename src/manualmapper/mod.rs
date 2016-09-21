//! Manual Mapper Module
//! 
//! Provides functionality for manual PE mapping and code injection
//! into target processes using low-level Windows NT APIs.

mod injector;
mod pe_parser;
mod relocations;
mod imports;

pub use injector::ManualMapper;
pub use pe_parser::PeImage;

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

/// Memory protection flags for allocated regions
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
    pub fn as_raw(&self) -> u32 {
        *self as u32
    }
    
    pub fn from_section_characteristics(characteristics: u32) -> Self {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
        const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
        
        let executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        let writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        
        match (executable, readable, writable) {
            (true, true, true) => MemoryProtection::ExecuteReadWrite,
            (true, true, false) => MemoryProtection::ExecuteRead,
            (true, false, true) => MemoryProtection::ExecuteWriteCopy,
            (true, false, false) => MemoryProtection::Execute,
            (false, true, true) => MemoryProtection::ReadWrite,
            (false, true, false) => MemoryProtection::ReadOnly,
            (false, false, true) => MemoryProtection::WriteCopy,
            (false, false, false) => MemoryProtection::NoAccess,
        }
    }
}

/// Allocation type flags for memory operations
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
    pub fn as_raw(&self) -> u32 {
        *self as u32
    }
    
    pub fn combine(flags: &[AllocationType]) -> u32 {
        flags.iter().fold(0u32, |acc, f| acc | f.as_raw())
    }
}

/// Represents a mapped memory region within a target process
#[derive(Debug)]
pub struct MappedRegion {
    base_address: NonNull<c_void>,
    size: usize,
    protection: MemoryProtection,
    committed: bool,
}

impl MappedRegion {
    /// Creates a new mapped region descriptor
    pub fn new(
        base: *mut c_void,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<Self, MapperError> {
        let base_address = NonNull::new(base)
            .ok_or(MapperError::InvalidAddress)?;
        
        Ok(Self {
            base_address,
            size,
            protection,
            committed: true,
        })
    }
    
    /// Returns the base address of the region
    pub fn base(&self) -> *mut c_void {
        self.base_address.as_ptr()
    }
    
    /// Returns the size of the region in bytes
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// Returns the memory protection of the region
    pub fn protection(&self) -> MemoryProtection {
        self.protection
    }
    
    /// Checks if the region is committed
    pub fn is_committed(&self) -> bool {
        self.committed
    }
}

/// Runtime state for tracking mapped modules
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    Uninitialized,
    Initializing,
    Running,
    Suspended,
    ShuttingDown,
    Terminated,
}

/// Observer trait for runtime events
pub trait RuntimeObserver: Send + Sync {
    fn on_state_change(&self, old_state: RuntimeState, new_state: RuntimeState);
    fn on_module_mapped(&self, module_name: &str, base_address: usize);
    fn on_module_unmapped(&self, module_name: &str);
    fn on_error(&self, error: &MapperError);
}

/// Strategy trait for memory allocation
pub trait AllocationStrategy: Send + Sync {
    fn allocate(
        &self,
        process_handle: &SafeHandle,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<MappedRegion, MapperError>;
    
    fn deallocate(
        &self,
        process_handle: &SafeHandle,
        region: &MappedRegion,
    ) -> Result<(), MapperError>;
    
    fn change_protection(
        &self,
        process_handle: &SafeHandle,
        region: &MappedRegion,
        new_protection: MemoryProtection,
    ) -> Result<MemoryProtection, MapperError>;
}

/// Default allocation strategy using standard NT APIs
pub struct DefaultAllocationStrategy;

impl AllocationStrategy for DefaultAllocationStrategy {
    fn allocate(
        &self,
        _process_handle: &SafeHandle,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<MappedRegion, MapperError> {
        // Placeholder for actual NT allocation
        let aligned_size = (size + 0xFFF) & !0xFFF;
        
        if aligned_size == 0 {
            return Err(MapperError::InvalidSize);
        }
        
        // In real implementation, this would call NtAllocateVirtualMemory
        Err(MapperError::NotImplemented)
    }
    
    fn deallocate(
        &self,
        _process_handle: &SafeHandle,
        _region: &MappedRegion,
    ) -> Result<(), MapperError> {
        // In real implementation, this would call NtFreeVirtualMemory
        Err(MapperError::NotImplemented)
    }
    
    fn change_protection(
        &self,
        _process_handle: &SafeHandle,
        _region: &MappedRegion,
        _new_protection: MemoryProtection,
    ) -> Result<MemoryProtection, MapperError> {
        // In real implementation, this would call NtProtectVirtualMemory
        Err(MapperError::NotImplemented)
    }
}

/// Tracked module information
#[derive(Debug)]
pub struct TrackedModule {
    name: String,
    base_address: usize,
    size: usize,
    entry_point: Option<usize>,
    regions: Vec<MappedRegion>,
    load_time: std::time::Instant,
}

impl TrackedModule {
    pub fn new(name: String, base_address: usize, size: usize) -> Self {
        Self {
            name,
            base_address,
            size,
            entry_point: None,
            regions: Vec::new(),
            load_time: std::time::Instant::now(),
        }
    }
    
    pub fn name(&self) -> &str {
        &self.name
    }
    
    pub fn base_address(&self) -> usize {
        self.base_address
    }
    
    pub fn size(&self) -> usize {
        self.size
    }
    
    pub fn entry_point(&self) -> Option<usize> {
        self.entry_point
    }
    
    pub fn set_entry_point(&mut self, entry: usize) {
        self.entry_point = Some(entry);
    }
    
    pub fn add_region(&mut self, region: MappedRegion) {
        self.regions.push(region);
    }
    
    pub fn uptime(&self) -> std::time::Duration {
        self.load_time.elapsed()
    }
}

/// Central runtime manager for coordinating mapping operations
pub struct RuntimeManager {
    state: RwLock<RuntimeState>,
    initialized: AtomicBool,
    operation_counter: AtomicU64,
    modules: RwLock<HashMap<String, TrackedModule>>,
    observers: RwLock<Vec<Arc<dyn RuntimeObserver>>>,
    allocation_strategy: RwLock<Arc<dyn AllocationStrategy>>,
    process_handle: RwLock<Option<SafeHandle>>,
}

impl RuntimeManager {
    /// Creates a new RuntimeManager instance
    pub fn new() -> Self {
        Self {
            state: RwLock::new(RuntimeState::Uninitialized),
            initialized: AtomicBool::new(false),
            operation_counter: AtomicU64::new(0),
            modules: RwLock::new(HashMap::new()),
            observers: RwLock::new(Vec::new()),
            allocation_strategy: RwLock::new(Arc::new(DefaultAllocationStrategy)),
            process_handle: RwLock::new(None),
        }
    }
    
    /// Initializes the runtime manager with a target process handle
    pub fn initialize(&self, process_handle: SafeHandle) -> Result<(), MapperError> {
        let mut state = self.state.write().map_err(|_| MapperError::LockPoisoned)?;
        
        if *state != RuntimeState::Uninitialized {
            return Err(MapperError::AlreadyInitialized);
        }
        
        let old_state = *state;
        *state = RuntimeState::Initializing;
        drop(state);
        
        self.notify_state_change(old_state, RuntimeState::Initializing);
        
        // Store the process handle
        {
            let mut handle_guard = self.process_handle.write()
                .map_err(|_| MapperError::LockPoisoned)?;
            *handle_guard = Some(process_handle);
        }
        
        // Transition to running state
        let mut state = self.state.write().map_err(|_| MapperError::LockPoisoned)?;
        *state = RuntimeState::Running;
        self.initialized.store(true, Ordering::SeqCst);
        
        self.notify_state_change(RuntimeState::Initializing, RuntimeState::Running);
        
        Ok(())
    }
    
    /// Checks if the runtime is initialized and running
    pub fn is_running(&self) -> bool {
        self.initialized.load(Ordering::SeqCst) && 
            matches!(
                self.state.read().ok().map(|s| *s),
                Some(RuntimeState::Running)
            )
    }
    
    /// Returns the current runtime state
    pub fn state(&self) -> Result<RuntimeState, MapperError> {
        self.state.read()
            .map(|s| *s)
            .map_err(|_| MapperError::LockPoisoned)
    }
    
    /// Suspends runtime operations
    pub fn suspend(&self) -> Result<(), MapperError> {
        let mut state = self.state.write().map_err(|_| MapperError::LockPoisoned)?;
        
        if *state != RuntimeState::Running {
            return Err(MapperError::InvalidState);
        }
        
        let old_state = *state;
        *state = RuntimeState::Suspended;
        drop(state);
        
        self.notify_state_change(old_state, RuntimeState::Suspended);
        Ok(())
    }
    
    /// Resumes runtime operations
    pub fn resume(&self) -> Result<(), MapperError> {
        let mut state = self.state.write().map_err(|_| MapperError::LockPoisoned)?;
        
        if *state != RuntimeState::Suspended {
            return Err(MapperError::InvalidState);
        }
        
        let old_state = *state;
        *state = RuntimeState::Running;
        drop(state);
        
        self.notify_state_change(old_state, RuntimeState::Running);
        Ok(())
    }
    
    /// Shuts down the runtime manager
    pub fn shutdown(&self) -> Result<(), MapperError> {
        let mut state = self.state.write().map_err(|_| MapperError::LockPoisoned)?;
        
        match *state {
            RuntimeState::Uninitialized | RuntimeState::Terminated => {
                return Ok(());
            }
            RuntimeState::ShuttingDown => {
                return Err(MapperError::ShutdownInProgress);
            }
            _ => {}
        }
        
        let old_state = *state;
        *state = RuntimeState::ShuttingDown;
        drop(state);
        
        self.notify_state_change(old_state, RuntimeState::ShuttingDown);
        
        // Unmap all modules
        self.unmap_all_modules()?;
        
        // Clear process handle
        {
            let mut handle_guard = self.process_handle.write()
                .map_err(|_| MapperError::LockPoisoned)?;
            *handle_guard = None;
        }
        
        // Finalize shutdown
        let mut state = self.state.write().map_err(|_| MapperError::LockPoisoned)?;
        *state = RuntimeState::Terminated;
        self.initialized.store(false, Ordering::SeqCst);
        
        self.notify_state_change(RuntimeState::ShuttingDown, RuntimeState::Terminated);
        
        Ok(())
    }
    
    /// Registers an observer for runtime events
    pub fn register_observer(&self, observer: Arc<dyn RuntimeObserver>) -> Result<(), MapperError> {
        let mut observers = self.observers.write()
            .map_err(|_| MapperError::LockPoisoned)?;
        observers.push(observer);
        Ok(())
    }
    
    /// Sets a custom allocation strategy
    pub fn set_allocation_strategy(
        &self,
        strategy: Arc<dyn AllocationStrategy>,
    ) -> Result<(), MapperError> {
        let mut current = self.allocation_strategy.write()
            .map_err(|_| MapperError::LockPoisoned)?;
        *current = strategy;
        Ok(())
    }
    
    /// Tracks a newly mapped module
    pub fn track_module(&self, module: TrackedModule) -> Result<(), MapperError> {
        if !self.is_running() {
            return Err(MapperError::NotInitialized);
        }
        
        let module_name = module.name().to_string();
        let base_address = module.base_address();
        
        {
            let mut modules = self.modules.write()
                .map_err(|_| MapperError::LockPoisoned)?;
            
            if modules.contains_key(&module_name) {
                return Err(MapperError::ModuleAlreadyLoaded);
            }
            
            modules.insert(module_name.clone(), module);
        }
        
        self.increment_operation_counter();
        self.notify_module_mapped(&module_name, base_address);
        
        Ok(())
    }
    
    /// Untracks and prepares a module for unmapping
    pub fn untrack_module(&self, name: &str) -> Result<TrackedModule, MapperError> {
        if !self.is_running() {
            return Err(MapperError::NotInitialized);
        }
        
        let module = {
            let mut modules = self.modules.write()
                .map_err(|_| MapperError::LockPoisoned)?;
            
            modules.remove(name)
                .ok_or(MapperError::ModuleNotFound)?
        };
        
        self.increment_operation_counter();
        self.notify_module_unmapped(name);
        
        Ok(module)
    }
    
    /// Returns information about a tracked module
    pub fn get_module_info(&self, name: &str) -> Result<(usize, usize, Option<usize>), MapperError> {
        let modules = self.modules.read()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        let module = modules.get(name)
            .ok_or(MapperError::ModuleNotFound)?;
        
        Ok((module.base_address(), module.size(), module.entry_point()))
    }
    
    /// Lists all tracked module names
    pub fn list_modules(&self) -> Result<Vec<String>, MapperError> {
        let modules = self.modules.read()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        Ok(modules.keys().cloned().collect())
    }
    
    /// Returns the total number of operations performed
    pub fn operation_count(&self) -> u64 {
        self.operation_counter.load(Ordering::Relaxed)
    }
    
    /// Allocates memory in the target process
    pub fn allocate_memory(
        &self,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<MappedRegion, MapperError> {
        if !self.is_running() {
            return Err(MapperError::NotInitialized);
        }
        
        let handle_guard = self.process_handle.read()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        let handle = handle_guard.as_ref()
            .ok_or(MapperError::InvalidHandle)?;
        
        let strategy = self.allocation_strategy.read()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        let region = strategy.allocate(handle, size, protection)?;
        self.increment_operation_counter();
        
        Ok(region)
    }
    
    /// Deallocates memory in the target process
    pub fn deallocate_memory(&self, region: &MappedRegion) -> Result<(), MapperError> {
        if !self.is_running() {
            return Err(MapperError::NotInitialized);
        }
        
        let handle_guard = self.process_handle.read()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        let handle = handle_guard.as_ref()
            .ok_or(MapperError::InvalidHandle)?;
        
        let strategy = self.allocation_strategy.read()
            .map_err(|_| MapperError::LockPoisoned)?;
        
        strategy.deallocate(handle, region)?;
        self.increment_operation_counter();
        
        Ok(())
    }
    
    // Private helper methods
    
    fn increment_operation_counter(&self) {
        self.operation_counter.fetch_add(1, Ordering::Relaxed);
    }
    
    fn notify_state_change(&self, old_state: RuntimeState, new_state: RuntimeState) {
        if let Ok(observers) = self.observers.read() {
            for observer in observers.iter() {
                observer.on_state_change(old_state, new_state);
            }
        }
    }
    
    fn notify_module_mapped(&self, name: &str, base_address: usize) {
        if let Ok(observers) = self.observers.read() {
            for observer in observers.iter() {
                observer.on_module_mapped(name, base_address);
            }
        }
    }
    
    fn notify_module_unmapped(&self, name: &str) {
        if let Ok(observers) = self.observers.read() {
            for observer in observers.iter() {
                observer.on_module_unmapped(name);
            }
        }
    }
    
    fn notify_error(&self, error: &MapperError) {
        if let Ok(observers) = self.observers.read() {
            for observer in observers.iter() {
                observer.on_error(error);
            }
        }
    }
    
    fn unmap_all_modules(&self) -> Result<(), MapperError> {
        let module_names: Vec<String> = {
            let modules = self.modules.read()
                .map_err(|_| MapperError::LockPoisoned)?;
            modules.keys().cloned().collect()
        };
        
        for name in module_names {
            if let Err(e) = self.untrack_module(&name) {
                self.notify_error(&e);
            }
        }
        
        Ok(())
    }
}

impl Default for RuntimeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RuntimeManager {
    fn drop(&mut self) {
        // Attempt graceful shutdown on drop
        let _ = self.shutdown();
    }
}

/// Factory for creating RuntimeManager instances with different configurations
pub struct RuntimeManagerFactory;

impl RuntimeManagerFactory {
    /// Creates a default RuntimeManager
    pub fn create_default() -> RuntimeManager {
        RuntimeManager::new()
    }
    
    /// Creates a RuntimeManager with a custom allocation strategy
    pub fn create_with_strategy(strategy: Arc<dyn AllocationStrategy>) -> RuntimeManager {
        let manager = RuntimeManager::new();
        let _ = manager.set_allocation_strategy(strategy);
        manager
    }
    
    /// Creates a RuntimeManager with pre-registered observers
    pub fn create_with_observers(observers: Vec<Arc<dyn RuntimeObserver>>) -> RuntimeManager {
        let manager = RuntimeManager::new();
        for observer in observers {
            let _ = manager.register_observer(observer);
        }
        manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_protection_from_characteristics() {
        let rwx = MemoryProtection::from_section_characteristics(0xE0000000);
        assert_eq!(rwx, MemoryProtection::ExecuteReadWrite);
        
        let rx = MemoryProtection::from_section_characteristics(0x60000000);
        assert_eq!(rx, MemoryProtection::ExecuteRead);
        
        let rw = MemoryProtection::from_section_characteristics(0xC0000000);
        assert_eq!(rw, MemoryProtection::ReadWrite);
    }
    
    #[test]
    fn test_allocation_type_combine() {
        let combined = AllocationType::combine(&[
            AllocationType::Commit,
            AllocationType::Reserve,
        ]);
        assert_eq!(combined, 0x3000);
    }
    
    #[test]
    fn test_runtime_manager_initial_state() {
        let manager = RuntimeManager::new();
        assert_eq!(manager.state().unwrap(), RuntimeState::Uninitialized);
        assert!(!manager.is_running());
    }
    
    #[test]
    fn test_tracked_module_creation() {
        let module = TrackedModule::new(
            "test.dll".to_string(),
            0x10000000,
            0x5000,
        );
        
        assert_eq!(module.name(), "test.dll");
        assert_eq!(module.base_address(), 0x10000000);
        assert_eq!(module.size(), 0x5000);
        assert!(module.entry_point().is_none());
    }
}