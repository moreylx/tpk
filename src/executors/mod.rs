//! Process management and thread operations module
//!
//! Provides safe abstractions for process and thread management operations
//! using RAII patterns and idiomatic Rust error handling.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::error::{MapperError, NtStatus};

/// Process identifier type alias for clarity
pub type ProcessId = u32;

/// Thread identifier type alias
pub type ThreadId = u32;

/// Execution priority levels for managed tasks
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionPriority {
    Idle = 0,
    Low = 1,
    BelowNormal = 2,
    Normal = 3,
    AboveNormal = 4,
    High = 5,
    Critical = 6,
}

impl Default for ExecutionPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// State of an executor task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// Configuration for executor behavior
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub max_threads: usize,
    pub default_priority: ExecutionPriority,
    pub task_timeout: Option<Duration>,
    pub enable_metrics: bool,
    pub retry_count: u32,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_threads: num_cpus::get().max(4),
            default_priority: ExecutionPriority::Normal,
            task_timeout: Some(Duration::from_secs(300)),
            enable_metrics: true,
            retry_count: 3,
        }
    }
}

/// Metrics collected during task execution
#[derive(Debug, Clone, Default)]
pub struct ExecutionMetrics {
    pub tasks_submitted: u64,
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    pub total_execution_time: Duration,
    pub average_wait_time: Duration,
}

/// Trait for executable tasks within the executor
pub trait Executable: Send + 'static {
    /// Execute the task and return a result
    fn execute(&mut self) -> Result<(), MapperError>;
    
    /// Get the task's priority
    fn priority(&self) -> ExecutionPriority {
        ExecutionPriority::Normal
    }
    
    /// Called when the task is cancelled
    fn on_cancel(&mut self) {}
    
    /// Get a description of the task
    fn description(&self) -> &str {
        "unnamed task"
    }
}

/// A handle to a submitted task
#[derive(Debug)]
pub struct TaskHandle {
    id: u64,
    state: Arc<RwLock<TaskState>>,
    result: Arc<Mutex<Option<Result<(), MapperError>>>>,
}

impl TaskHandle {
    fn new(id: u64) -> Self {
        Self {
            id,
            state: Arc::new(RwLock::new(TaskState::Pending)),
            result: Arc::new(Mutex::new(None)),
        }
    }
    
    /// Get the task ID
    pub fn id(&self) -> u64 {
        self.id
    }
    
    /// Get the current state of the task
    pub fn state(&self) -> TaskState {
        *self.state.read().unwrap()
    }
    
    /// Check if the task has completed (successfully or not)
    pub fn is_finished(&self) -> bool {
        matches!(
            self.state(),
            TaskState::Completed | TaskState::Failed | TaskState::Cancelled
        )
    }
    
    /// Wait for the task to complete and get the result
    pub fn wait(&self) -> Result<(), MapperError> {
        while !self.is_finished() {
            thread::sleep(Duration::from_millis(10));
        }
        
        self.result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(Err(MapperError::from_status(NtStatus::from_raw(0xC0000001))))
    }
    
    /// Wait for the task with a timeout
    pub fn wait_timeout(&self, timeout: Duration) -> Option<Result<(), MapperError>> {
        let start = Instant::now();
        while !self.is_finished() {
            if start.elapsed() >= timeout {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
        
        self.result.lock().unwrap().clone()
    }
}

/// Internal task wrapper for the executor
struct ManagedTask {
    id: u64,
    executable: Box<dyn Executable>,
    state: Arc<RwLock<TaskState>>,
    result: Arc<Mutex<Option<Result<(), MapperError>>>>,
    submitted_at: Instant,
    priority: ExecutionPriority,
}

impl ManagedTask {
    fn new(
        id: u64,
        executable: Box<dyn Executable>,
        state: Arc<RwLock<TaskState>>,
        result: Arc<Mutex<Option<Result<(), MapperError>>>>,
    ) -> Self {
        let priority = executable.priority();
        Self {
            id,
            executable,
            state,
            result,
            submitted_at: Instant::now(),
            priority,
        }
    }
    
    fn run(&mut self) -> Result<(), MapperError> {
        *self.state.write().unwrap() = TaskState::Running;
        
        let result = self.executable.execute();
        
        *self.state.write().unwrap() = if result.is_ok() {
            TaskState::Completed
        } else {
            TaskState::Failed
        };
        
        *self.result.lock().unwrap() = Some(result.clone());
        result
    }
}

/// Observer trait for executor events
pub trait ExecutorObserver: Send + Sync {
    fn on_task_submitted(&self, task_id: u64);
    fn on_task_started(&self, task_id: u64);
    fn on_task_completed(&self, task_id: u64, success: bool);
    fn on_executor_shutdown(&self);
}

/// Thread-safe task executor with priority scheduling
pub struct TaskExecutor {
    config: ExecutorConfig,
    task_queue: Arc<Mutex<Vec<ManagedTask>>>,
    workers: Vec<JoinHandle<()>>,
    next_task_id: Arc<Mutex<u64>>,
    metrics: Arc<RwLock<ExecutionMetrics>>,
    observers: Arc<RwLock<Vec<Arc<dyn ExecutorObserver>>>>,
    shutdown_flag: Arc<Mutex<bool>>,
    active_tasks: Arc<Mutex<HashMap<u64, TaskState>>>,
}

impl TaskExecutor {
    /// Create a new executor with default configuration
    pub fn new() -> Self {
        Self::with_config(ExecutorConfig::default())
    }
    
    /// Create a new executor with custom configuration
    pub fn with_config(config: ExecutorConfig) -> Self {
        let executor = Self {
            config,
            task_queue: Arc::new(Mutex::new(Vec::new())),
            workers: Vec::new(),
            next_task_id: Arc::new(Mutex::new(1)),
            metrics: Arc::new(RwLock::new(ExecutionMetrics::default())),
            observers: Arc::new(RwLock::new(Vec::new())),
            shutdown_flag: Arc::new(Mutex::new(false)),
            active_tasks: Arc::new(Mutex::new(HashMap::new())),
        };
        executor
    }
    
    /// Start the executor worker threads
    pub fn start(&mut self) -> Result<(), MapperError> {
        if !self.workers.is_empty() {
            return Err(MapperError::from_status(NtStatus::from_raw(0xC0000001)));
        }
        
        *self.shutdown_flag.lock().unwrap() = false;
        
        for worker_id in 0..self.config.max_threads {
            let queue = Arc::clone(&self.task_queue);
            let shutdown = Arc::clone(&self.shutdown_flag);
            let metrics = Arc::clone(&self.metrics);
            let observers = Arc::clone(&self.observers);
            let active = Arc::clone(&self.active_tasks);
            
            let handle = thread::Builder::new()
                .name(format!("executor-worker-{}", worker_id))
                .spawn(move || {
                    Self::worker_loop(queue, shutdown, metrics, observers, active);
                })
                .map_err(|_| MapperError::from_status(NtStatus::from_raw(0xC0000017)))?;
            
            self.workers.push(handle);
        }
        
        Ok(())
    }
    
    fn worker_loop(
        queue: Arc<Mutex<Vec<ManagedTask>>>,
        shutdown: Arc<Mutex<bool>>,
        metrics: Arc<RwLock<ExecutionMetrics>>,
        observers: Arc<RwLock<Vec<Arc<dyn ExecutorObserver>>>>,
        active: Arc<Mutex<HashMap<u64, TaskState>>>,
    ) {
        loop {
            if *shutdown.lock().unwrap() {
                break;
            }
            
            let task = {
                let mut queue_guard = queue.lock().unwrap();
                if queue_guard.is_empty() {
                    None
                } else {
                    // Sort by priority (highest first)
                    queue_guard.sort_by(|a, b| b.priority.cmp(&a.priority));
                    Some(queue_guard.remove(0))
                }
            };
            
            match task {
                Some(mut managed_task) => {
                    let task_id = managed_task.id;
                    let start_time = Instant::now();
                    
                    // Notify observers
                    for observer in observers.read().unwrap().iter() {
                        observer.on_task_started(task_id);
                    }
                    
                    active.lock().unwrap().insert(task_id, TaskState::Running);
                    
                    let result = managed_task.run();
                    let success = result.is_ok();
                    
                    active.lock().unwrap().remove(&task_id);
                    
                    // Update metrics
                    {
                        let mut m = metrics.write().unwrap();
                        if success {
                            m.tasks_completed += 1;
                        } else {
                            m.tasks_failed += 1;
                        }
                        m.total_execution_time += start_time.elapsed();
                    }
                    
                    // Notify observers
                    for observer in observers.read().unwrap().iter() {
                        observer.on_task_completed(task_id, success);
                    }
                }
                None => {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
    
    /// Submit a task for execution
    pub fn submit<T: Executable>(&self, task: T) -> TaskHandle {
        let id = {
            let mut next_id = self.next_task_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            id
        };
        
        let handle = TaskHandle::new(id);
        let managed = ManagedTask::new(
            id,
            Box::new(task),
            Arc::clone(&handle.state),
            Arc::clone(&handle.result),
        );
        
        self.task_queue.lock().unwrap().push(managed);
        
        // Update metrics
        self.metrics.write().unwrap().tasks_submitted += 1;
        
        // Notify observers
        for observer in self.observers.read().unwrap().iter() {
            observer.on_task_submitted(id);
        }
        
        handle
    }
    
    /// Submit a closure as a task
    pub fn submit_fn<F>(&self, f: F, priority: ExecutionPriority) -> TaskHandle
    where
        F: FnOnce() -> Result<(), MapperError> + Send + 'static,
    {
        struct ClosureTask<F> {
            closure: Option<F>,
            priority: ExecutionPriority,
        }
        
        impl<F> Executable for ClosureTask<F>
        where
            F: FnOnce() -> Result<(), MapperError> + Send + 'static,
        {
            fn execute(&mut self) -> Result<(), MapperError> {
                if let Some(f) = self.closure.take() {
                    f()
                } else {
                    Err(MapperError::from_status(NtStatus::from_raw(0xC0000001)))
                }
            }
            
            fn priority(&self) -> ExecutionPriority {
                self.priority
            }
        }
        
        self.submit(ClosureTask {
            closure: Some(f),
            priority,
        })
    }
    
    /// Register an observer for executor events
    pub fn add_observer(&self, observer: Arc<dyn ExecutorObserver>) {
        self.observers.write().unwrap().push(observer);
    }
    
    /// Get current execution metrics
    pub fn metrics(&self) -> ExecutionMetrics {
        self.metrics.read().unwrap().clone()
    }
    
    /// Get the number of pending tasks
    pub fn pending_count(&self) -> usize {
        self.task_queue.lock().unwrap().len()
    }
    
    /// Get the number of active tasks
    pub fn active_count(&self) -> usize {
        self.active_tasks.lock().unwrap().len()
    }
    
    /// Shutdown the executor gracefully
    pub fn shutdown(&mut self) {
        *self.shutdown_flag.lock().unwrap() = true;
        
        // Notify observers
        for observer in self.observers.read().unwrap().iter() {
            observer.on_executor_shutdown();
        }
        
        // Wait for workers to finish
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
    
    /// Shutdown immediately, cancelling pending tasks
    pub fn shutdown_now(&mut self) {
        // Clear pending tasks
        {
            let mut queue = self.task_queue.lock().unwrap();
            for mut task in queue.drain(..) {
                *task.state.write().unwrap() = TaskState::Cancelled;
                task.executable.on_cancel();
            }
        }
        
        self.shutdown();
    }
}

impl Default for TaskExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TaskExecutor {
    fn drop(&mut self) {
        if !self.workers.is_empty() {
            self.shutdown();
        }
    }
}

/// Thread pool for parallel execution of homogeneous tasks
pub struct ThreadPool {
    executor: TaskExecutor,
}

impl ThreadPool {
    /// Create a new thread pool with the specified number of threads
    pub fn new(num_threads: usize) -> Result<Self, MapperError> {
        let config = ExecutorConfig {
            max_threads: num_threads,
            ..Default::default()
        };
        
        let mut executor = TaskExecutor::with_config(config);
        executor.start()?;
        
        Ok(Self { executor })
    }
    
    /// Execute a closure on the thread pool
    pub fn execute<F>(&self, f: F) -> TaskHandle
    where
        F: FnOnce() -> Result<(), MapperError> + Send + 'static,
    {
        self.executor.submit_fn(f, ExecutionPriority::Normal)
    }
    
    /// Execute multiple closures in parallel and wait for all to complete
    pub fn execute_all<F, I>(&self, tasks: I) -> Vec<Result<(), MapperError>>
    where
        F: FnOnce() -> Result<(), MapperError> + Send + 'static,
        I: IntoIterator<Item = F>,
    {
        let handles: Vec<_> = tasks
            .into_iter()
            .map(|f| self.execute(f))
            .collect();
        
        handles.into_iter().map(|h| h.wait()).collect()
    }
    
    /// Get the number of threads in the pool
    pub fn thread_count(&self) -> usize {
        self.executor.config.max_threads
    }
}

/// Scoped thread for RAII-based thread management
pub struct ScopedThread<T> {
    handle: Option<JoinHandle<T>>,
    name: String,
}

impl<T> ScopedThread<T> {
    /// Spawn a new scoped thread
    pub fn spawn<F>(name: &str, f: F) -> Result<Self, MapperError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .spawn(f)
            .map_err(|_| MapperError::from_status(NtStatus::from_raw(0xC0000017)))?;
        
        Ok(Self {
            handle: Some(handle),
            name: name.to_string(),
        })
    }
    
    /// Get the thread name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Check if the thread has finished
    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().map_or(true, |h| h.is_finished())
    }
    
    /// Join the thread and get the result
    pub fn join(mut self) -> Result<T, MapperError> {
        self.handle
            .take()
            .ok_or_else(|| MapperError::from_status(NtStatus::from_raw(0xC0000001)))?
            .join()
            .map_err(|_| MapperError::from_status(NtStatus::from_raw(0xC0000001)))
    }
}

impl<T> Drop for ScopedThread<T> {
    fn drop(&mut self) {
        // Thread will be detached if not joined
        // This is intentional - we don't want to block in drop
    }
}

/// Process information structure
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: ProcessId,
    pub name: String,
    pub parent_pid: Option<ProcessId>,
    pub thread_count: u32,
    pub priority: ExecutionPriority,
}

/// Thread information structure
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub tid: ThreadId,
    pub owner_pid: ProcessId,
    pub priority: ExecutionPriority,
    pub state: ThreadState,
}

/// Thread execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Waiting,
    Suspended,
    Terminated,
}

/// Strategy trait for process enumeration
pub trait ProcessEnumerationStrategy: Send + Sync {
    fn enumerate(&self) -> Result<Vec<ProcessInfo>, MapperError>;
    fn get_process(&self, pid: ProcessId) -> Result<Option<ProcessInfo>, MapperError>;
}

/// Default process enumeration using system calls
pub struct SystemProcessEnumerator;

impl ProcessEnumerationStrategy for SystemProcessEnumerator {
    fn enumerate(&self) -> Result<Vec<ProcessInfo>, MapperError> {
        // TODO: Implement actual system enumeration
        // This would use platform-specific APIs
        Ok(Vec::new())
    }
    
    fn get_process(&self, _pid: ProcessId) -> Result<Option<ProcessInfo>, MapperError> {
        // TODO: Implement actual process lookup
        Ok(None)
    }
}

/// Process manager with pluggable enumeration strategy
pub struct ProcessManager {
    strategy: Box<dyn ProcessEnumerationStrategy>,
    cache: RwLock<HashMap<ProcessId, ProcessInfo>>,
    cache_ttl: Duration,
    last_refresh: Mutex<Instant>,
}

impl ProcessManager {
    /// Create a new process manager with the default strategy
    pub fn new() -> Self {
        Self::with_strategy(Box::new(SystemProcessEnumerator))
    }
    
    /// Create a new process manager with a custom strategy
    pub fn with_strategy(strategy: Box<dyn ProcessEnumerationStrategy>) -> Self {
        Self {
            strategy,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(5),
            last_refresh: Mutex::new(Instant::now() - Duration::from_secs(10)),
        }
    }
    
    /// Refresh the process cache
    pub fn refresh(&self) -> Result<(), MapperError> {
        let processes = self.strategy.enumerate()?;
        
        let mut cache = self.cache.write().unwrap();
        cache.clear();
        for proc in processes {
            cache.insert(proc.pid, proc);
        }
        
        *self.last_refresh.lock().unwrap() = Instant::now();
        Ok(())
    }
    
    /// Get all processes (refreshes cache if stale)
    pub fn get_all(&self) -> Result<Vec<ProcessInfo>, MapperError> {
        self.ensure_fresh()?;
        Ok(self.cache.read().unwrap().values().cloned().collect())
    }
    
    /// Get a specific process by PID
    pub fn get(&self, pid: ProcessId) -> Result<Option<ProcessInfo>, MapperError> {
        self.ensure_fresh()?;
        Ok(self.cache.read().unwrap().get(&pid).cloned())
    }
    
    /// Find processes by name
    pub fn find_by_name(&self, name: &str) -> Result<Vec<ProcessInfo>, MapperError> {
        self.ensure_fresh()?;
        let name_lower = name.to_lowercase();
        Ok(self
            .cache
            .read()
            .unwrap()
            .values()
            .filter(|p| p.name.to_lowercase().contains(&name_lower))
            .cloned()
            .collect())
    }
    
    fn ensure_fresh(&self) -> Result<(), MapperError> {
        let last = *self.last_refresh.lock().unwrap();
        if last.elapsed() > self.cache_ttl {
            self.refresh()?;
        }
        Ok(())
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

// Provide a way to get CPU count without external dependency
mod num_cpus {
    pub fn get() -> usize {
        // Simple fallback - in production would use actual system call
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct TestTask {
        value: i32,
    }
    
    impl Executable for TestTask {
        fn execute(&mut self) -> Result<(), MapperError> {
            self.value *= 2;
            Ok(())
        }
        
        fn description(&self) -> &str {
            "test task"
        }
    }
    
    #[test]
    fn test_task_handle_creation() {
        let handle = TaskHandle::new(1);
        assert_eq!(handle.id(), 1);
        assert_eq!(handle.state(), TaskState::Pending);
        assert!(!handle.is_finished());
    }
    
    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert!(config.max_threads >= 4);
        assert_eq!(config.default_priority, ExecutionPriority::Normal);
        assert!(config.enable_metrics);
    }
    
    #[test]
    fn test_execution_priority_ordering() {
        assert!(ExecutionPriority::Critical > ExecutionPriority::High);
        assert!(ExecutionPriority::High > ExecutionPriority::Normal);
        assert!(ExecutionPriority::Normal > ExecutionPriority::Low);
    }
}