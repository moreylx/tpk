//! Main module for NT Mapper - Process management and memory operations
//! 
//! This module provides the core functionality for process enumeration,
//! memory manipulation, and system-level operations using Windows NT APIs.
//! 
//! # RAII and Resource Management
//! 
//! All resources are managed through RAII patterns ensuring proper cleanup
//! even in the presence of panics or early returns.

mod process;
mod memory;
mod system;

pub use process::*;
pub use memory::*;
pub use system::*;

use crate::error::{MapperError, NtStatus};
use crate::TraceManager::SafeHandle;

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Once, Mutex, Weak};
use std::ffi::CString;
use std::ptr;
use std::mem;
use std::ops::{Deref, DerefMut};

/// Global initialization guard
static INIT: Once = Once::new();
static mut GLOBAL_CONTEXT: Option<Arc<RwLock<MapperContext>>> = None;
static CLEANUP_REGISTRY: Mutex<Option<CleanupRegistry>> = Mutex::new(None);

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
}

/// Cleanup callback type for deferred resource cleanup
type CleanupFn = Box<dyn FnOnce() + Send + 'static>;

/// Registry for tracking cleanup callbacks
struct CleanupRegistry {
    callbacks: Vec<(u64, CleanupFn)>,
    next_id: u64,
}

impl CleanupRegistry {
    fn new() -> Self {
        Self {
            callbacks: Vec::new(),
            next_id: 0,
        }
    }

    fn register(&mut self, callback: CleanupFn) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.callbacks.push((id, callback));
        id
    }

    fn unregister(&mut self, id: u64) -> Option<CleanupFn> {
        if let Some(pos) = self.callbacks.iter().position(|(i, _)| *i == id) {
            Some(self.callbacks.remove(pos).1)
        } else {
            None
        }
    }

    fn execute_all(&mut self) {
        // Execute in reverse order (LIFO)
        while let Some((_, callback)) = self.callbacks.pop() {
            callback();
        }
    }
}

/// RAII guard for cleanup registration
pub struct CleanupGuard {
    id: Option<u64>,
}

impl CleanupGuard {
    /// Register a cleanup callback that will be executed on drop
    pub fn new<F>(callback: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let id = {
            let mut registry = CLEANUP_REGISTRY.lock().unwrap();
            if registry.is_none() {
                *registry = Some(CleanupRegistry::new());
            }
            registry.as_mut().unwrap().register(Box::new(callback))
        };
        Self { id: Some(id) }
    }

    /// Disarm the guard, preventing cleanup execution
    pub fn disarm(&mut self) {
        if let Some(id) = self.id.take() {
            let mut registry = CLEANUP_REGISTRY.lock().unwrap();
            if let Some(reg) = registry.as_mut() {
                reg.unregister(id);
            }
        }
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let callback = {
                let mut registry = CLEANUP_REGISTRY.lock().unwrap();
                registry.as_mut().and_then(|r| r.unregister(id))
            };
            if let Some(cb) = callback {
                cb();
            }
        }
    }
}

/// RAII wrapper for memory allocations with automatic deallocation
pub struct ManagedAllocation<T> {
    ptr: *mut T,
    size: usize,
    deallocator: Option<Box<dyn FnOnce(*mut T, usize) + Send>>,
}

impl<T> ManagedAllocation<T> {
    /// Create a new managed allocation with custom deallocator
    pub fn with_deallocator<F>(ptr: *mut T, size: usize, deallocator: F) -> Self
    where
        F: FnOnce(*mut T, usize) + Send + 'static,
    {
        Self {
            ptr,
            size,
            deallocator: Some(Box::new(deallocator)),
        }
    }

    /// Create from raw pointer with default heap deallocation
    pub unsafe fn from_raw(ptr: *mut T, size: usize) -> Self {
        Self {
            ptr,
            size,
            deallocator: Some(Box::new(|p, _| {
                if !p.is_null() {
                    drop(Box::from_raw(p));
                }
            })),
        }
    }

    /// Get the raw pointer
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    /// Get the mutable raw pointer
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }

    /// Get the allocation size
    pub fn size(&self) -> usize {
        self.size
    }

    /// Release ownership without deallocating
    pub fn leak(mut self) -> *mut T {
        self.deallocator = None;
        self.ptr
    }
}

impl<T> Drop for ManagedAllocation<T> {
    fn drop(&mut self) {
        if let Some(deallocator) = self.deallocator.take() {
            deallocator(self.ptr, self.size);
        }
    }
}

unsafe impl<T: Send> Send for ManagedAllocation<T> {}
unsafe impl<T: Sync> Sync for ManagedAllocation<T> {}

/// RAII scope guard for executing code on scope exit
pub struct ScopeGuard<F: FnOnce()> {
    callback: Option<F>,
}

impl<F: FnOnce()> ScopeGuard<F> {
    pub fn new(callback: F) -> Self {
        Self {
            callback: Some(callback),
        }
    }

    /// Disarm the guard, preventing callback execution
    pub fn disarm(mut self) {
        self.callback = None;
    }
}

impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(callback) = self.callback.take() {
            callback();
        }
    }
}

/// Macro for creating scope guards with closure syntax
#[macro_export]
macro_rules! defer {
    ($($body:tt)*) => {
        let _guard = $crate::main::ScopeGuard::new(|| { $($body)* });
    };
}

/// Resource tracker for monitoring active resources
pub struct ResourceTracker {
    active_handles: Arc<Mutex<HashMap<u64, ResourceInfo>>>,
    next_id: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone)]
pub struct ResourceInfo {
    pub resource_type: ResourceType,
    pub created_at: std::time::Instant,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    ProcessHandle,
    ThreadHandle,
    FileHandle,
    MemoryMapping,
    VirtualAllocation,
    Module,
    Custom,
}

impl ResourceTracker {
    pub fn new() -> Self {
        Self {
            active_handles: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Track a new resource and return its tracking ID
    pub fn track(&self, resource_type: ResourceType, description: impl Into<String>) -> u64 {
        let mut id_guard = self.next_id.lock().unwrap();
        let id = *id_guard;
        *id_guard = id_guard.wrapping_add(1);
        drop(id_guard);

        let info = ResourceInfo {
            resource_type,
            created_at: std::time::Instant::now(),
            description: description.into(),
        };

        self.active_handles.lock().unwrap().insert(id, info);
        id
    }

    /// Untrack a resource
    pub fn untrack(&self, id: u64) -> Option<ResourceInfo> {
        self.active_handles.lock().unwrap().remove(&id)
    }

    /// Get count of active resources
    pub fn active_count(&self) -> usize {
        self.active_handles.lock().unwrap().len()
    }

    /// Get all active resources
    pub fn active_resources(&self) -> Vec<(u64, ResourceInfo)> {
        self.active_handles
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Check for resource leaks (resources older than threshold)
    pub fn check_leaks(&self, threshold: std::time::Duration) -> Vec<(u64, ResourceInfo)> {
        let now = std::time::Instant::now();
        self.active_handles
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, info)| now.duration_since(info.created_at) > threshold)
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }
}

impl Default for ResourceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII tracked resource wrapper
pub struct TrackedResource<T> {
    inner: T,
    tracker: Arc<ResourceTracker>,
    tracking_id: u64,
}

impl<T> TrackedResource<T> {
    pub fn new(
        inner: T,
        tracker: Arc<ResourceTracker>,
        resource_type: ResourceType,
        description: impl Into<String>,
    ) -> Self {
        let tracking_id = tracker.track(resource_type, description);
        Self {
            inner,
            tracker,
            tracking_id,
        }
    }

    /// Get the tracking ID
    pub fn tracking_id(&self) -> u64 {
        self.tracking_id
    }

    /// Consume and return inner value, untracking the resource
    pub fn into_inner(self) -> T {
        // Prevent Drop from running
        let inner = unsafe { ptr::read(&self.inner) };
        self.tracker.untrack(self.tracking_id);
        mem::forget(self);
        inner
    }
}

impl<T> Deref for TrackedResource<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for TrackedResource<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Drop for TrackedResource<T> {
    fn drop(&mut self) {
        self.tracker.untrack(self.tracking_id);
    }
}

/// Global mapper context with RAII cleanup
pub struct MapperContext {
    initialized: bool,
    resource_tracker: Arc<ResourceTracker>,
    process_handles: HashMap<ProcessId, SafeHandle>,
    memory_regions: Vec<MappedRegion>,
    observers: Vec<Weak<dyn ContextObserver>>,
}

/// Observer trait for context lifecycle events
pub trait ContextObserver: Send + Sync {
    fn on_process_opened(&self, pid: ProcessId);
    fn on_process_closed(&self, pid: ProcessId);
    fn on_memory_mapped(&self, address: Address, size: usize);
    fn on_memory_unmapped(&self, address: Address);
    fn on_shutdown(&self);
}

#[derive(Debug)]
pub struct MappedRegion {
    pub base_address: Address,
    pub size: usize,
    pub protection: MemoryProtection,
    pub process_id: ProcessId,
}

impl MapperContext {
    /// Create a new mapper context
    pub fn new() -> Self {
        Self {
            initialized: false,
            resource_tracker: Arc::new(ResourceTracker::new()),
            process_handles: HashMap::new(),
            memory_regions: Vec::new(),
            observers: Vec::new(),
        }
    }

    /// Initialize the context
    pub fn initialize(&mut self) -> Result<(), MapperError> {
        if self.initialized {
            return Ok(());
        }

        // Perform initialization logic here
        self.initialized = true;
        Ok(())
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the resource tracker
    pub fn resource_tracker(&self) -> Arc<ResourceTracker> {
        Arc::clone(&self.resource_tracker)
    }

    /// Register an observer
    pub fn register_observer(&mut self, observer: Arc<dyn ContextObserver>) {
        self.observers.push(Arc::downgrade(&observer));
    }

    /// Notify observers of process open
    fn notify_process_opened(&self, pid: ProcessId) {
        for observer in &self.observers {
            if let Some(obs) = observer.upgrade() {
                obs.on_process_opened(pid);
            }
        }
    }

    /// Notify observers of process close
    fn notify_process_closed(&self, pid: ProcessId) {
        for observer in &self.observers {
            if let Some(obs) = observer.upgrade() {
                obs.on_process_closed(pid);
            }
        }
    }

    /// Notify observers of shutdown
    fn notify_shutdown(&self) {
        for observer in &self.observers {
            if let Some(obs) = observer.upgrade() {
                obs.on_shutdown();
            }
        }
    }

    /// Store a process handle
    pub fn store_process_handle(&mut self, pid: ProcessId, handle: SafeHandle) {
        self.process_handles.insert(pid, handle);
        self.notify_process_opened(pid);
    }

    /// Remove and close a process handle
    pub fn close_process_handle(&mut self, pid: ProcessId) -> Option<SafeHandle> {
        let handle = self.process_handles.remove(&pid);
        if handle.is_some() {
            self.notify_process_closed(pid);
        }
        handle
    }

    /// Track a mapped memory region
    pub fn track_memory_region(&mut self, region: MappedRegion) {
        self.memory_regions.push(region);
    }

    /// Untrack a memory region by base address
    pub fn untrack_memory_region(&mut self, base_address: Address) -> Option<MappedRegion> {
        if let Some(pos) = self
            .memory_regions
            .iter()
            .position(|r| r.base_address == base_address)
        {
            Some(self.memory_regions.remove(pos))
        } else {
            None
        }
    }

    /// Perform cleanup of all resources
    pub fn cleanup(&mut self) {
        // Notify observers before cleanup
        self.notify_shutdown();

        // Clear memory regions
        self.memory_regions.clear();

        // Close all process handles (SafeHandle will handle actual closing)
        let pids: Vec<ProcessId> = self.process_handles.keys().copied().collect();
        for pid in pids {
            self.close_process_handle(pid);
        }

        // Clean up stale observers
        self.observers.retain(|w| w.strong_count() > 0);

        self.initialized = false;
    }

    /// Get active resource count
    pub fn active_resource_count(&self) -> usize {
        self.resource_tracker.active_count()
    }
}

impl Default for MapperContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MapperContext {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Initialize the global mapper context
pub fn initialize_global() -> Result<Arc<RwLock<MapperContext>>, MapperError> {
    let mut result: Result<Arc<RwLock<MapperContext>>, MapperError> = Ok(Arc::new(RwLock::new(MapperContext::new())));
    
    INIT.call_once(|| {
        let context = Arc::new(RwLock::new(MapperContext::new()));
        
        match context.write() {
            Ok(mut ctx) => {
                if let Err(e) = ctx.initialize() {
                    result = Err(e);
                    return;
                }
            }
            Err(_) => {
                result = Err(MapperError::LockError("Failed to acquire write lock".into()));
                return;
            }
        }
        
        unsafe {
            GLOBAL_CONTEXT = Some(Arc::clone(&context));
        }
        result = Ok(context);
    });
    
    result
}

/// Get the global context
pub fn global_context() -> Option<Arc<RwLock<MapperContext>>> {
    unsafe { GLOBAL_CONTEXT.as_ref().map(Arc::clone) }
}

/// Shutdown and cleanup global context
pub fn shutdown_global() {
    unsafe {
        if let Some(context) = GLOBAL_CONTEXT.take() {
            if let Ok(mut ctx) = context.write() {
                ctx.cleanup();
            }
        }
    }

    // Execute all registered cleanup callbacks
    let mut registry = CLEANUP_REGISTRY.lock().unwrap();
    if let Some(ref mut reg) = *registry {
        reg.execute_all();
    }
}

/// RAII guard for automatic global shutdown
pub struct GlobalShutdownGuard;

impl GlobalShutdownGuard {
    pub fn new() -> Result<Self, MapperError> {
        initialize_global()?;
        Ok(Self)
    }
}

impl Default for GlobalShutdownGuard {
    fn default() -> Self {
        Self::new().expect("Failed to initialize global context")
    }
}

impl Drop for GlobalShutdownGuard {
    fn drop(&mut self) {
        shutdown_global();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_guard_executes() {
        let executed = Arc::new(Mutex::new(false));
        let executed_clone = Arc::clone(&executed);
        
        {
            let _guard = ScopeGuard::new(move || {
                *executed_clone.lock().unwrap() = true;
            });
        }
        
        assert!(*executed.lock().unwrap());
    }

    #[test]
    fn test_scope_guard_disarm() {
        let executed = Arc::new(Mutex::new(false));
        let executed_clone = Arc::clone(&executed);
        
        {
            let guard = ScopeGuard::new(move || {
                *executed_clone.lock().unwrap() = true;
            });
            guard.disarm();
        }
        
        assert!(!*executed.lock().unwrap());
    }

    #[test]
    fn test_resource_tracker() {
        let tracker = ResourceTracker::new();
        
        let id1 = tracker.track(ResourceType::ProcessHandle, "test process");
        let id2 = tracker.track(ResourceType::MemoryMapping, "test mapping");
        
        assert_eq!(tracker.active_count(), 2);
        
        tracker.untrack(id1);
        assert_eq!(tracker.active_count(), 1);
        
        tracker.untrack(id2);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_memory_protection() {
        assert!(MemoryProtection::ExecuteRead.is_executable());
        assert!(!MemoryProtection::ReadOnly.is_executable());
        assert!(MemoryProtection::ReadWrite.is_writable());
        assert!(!MemoryProtection::ReadOnly.is_writable());
    }

    #[test]
    fn test_mapper_context_lifecycle() {
        let mut context = MapperContext::new();
        assert!(!context.is_initialized());
        
        context.initialize().unwrap();
        assert!(context.is_initialized());
        
        context.cleanup();
        assert!(!context.is_initialized());
    }
}