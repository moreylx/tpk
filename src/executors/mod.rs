//! Process management and thread operations module
//!
//! Provides safe abstractions for process and thread management operations
//! using RAII patterns and idiomatic Rust error handling.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
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
    fn execute(&mut self) -> Result<ExecutionResult, MapperError>;
    
    /// Get the task's priority
    fn priority(&self) -> ExecutionPriority {
        ExecutionPriority::Normal
    }
    
    /// Get an optional task name for debugging
    fn name(&self) -> Option<&str> {
        None
    }
    
    /// Called when the task is about to be cancelled
    fn on_cancel(&mut self) {}
}

/// Result of task execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub status: TaskState,
    pub duration: Duration,
    pub output: Option<Vec<u8>>,
    pub exit_code: i32,
}

impl ExecutionResult {
    pub fn success(duration: Duration) -> Self {
        Self {
            status: TaskState::Completed,
            duration,
            output: None,
            exit_code: 0,
        }
    }
    
    pub fn with_output(mut self, output: Vec<u8>) -> Self {
        self.output = Some(output);
        self
    }
    
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = code;
        self
    }
}

/// Unique identifier for submitted tasks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskHandle(u64);

impl TaskHandle {
    fn new(id: u64) -> Self {
        Self(id)
    }
    
    pub fn id(&self) -> u64 {
        self.0
    }
}

/// Internal task wrapper with metadata
struct ManagedTask {
    handle: TaskHandle,
    executable: Box<dyn Executable>,
    state: TaskState,
    priority: ExecutionPriority,
    submitted_at: Instant,
    started_at: Option<Instant>,
    retry_count: u32,
    max_retries: u32,
}

impl ManagedTask {
    fn new(
        handle: TaskHandle,
        executable: Box<dyn Executable>,
        priority: ExecutionPriority,
        max_retries: u32,
    ) -> Self {
        Self {
            handle,
            executable,
            state: TaskState::Pending,
            priority,
            submitted_at: Instant::now(),
            started_at: None,
            retry_count: 0,
            max_retries,
        }
    }
}

/// Observer trait for task lifecycle events
pub trait TaskObserver: Send + Sync {
    fn on_task_submitted(&self, handle: TaskHandle);
    fn on_task_started(&self, handle: TaskHandle);
    fn on_task_completed(&self, handle: TaskHandle, result: &ExecutionResult);
    fn on_task_failed(&self, handle: TaskHandle, error: &MapperError);
    fn on_task_cancelled(&self, handle: TaskHandle);
}

/// Strategy trait for task scheduling
pub trait SchedulingStrategy: Send + Sync {
    fn select_next(&self, tasks: &[&ManagedTask]) -> Option<usize>;
    fn name(&self) -> &'static str;
}

/// Priority-based scheduling strategy
pub struct PriorityScheduler;

impl SchedulingStrategy for PriorityScheduler {
    fn select_next(&self, tasks: &[&ManagedTask]) -> Option<usize> {
        tasks
            .iter()
            .enumerate()
            .filter(|(_, t)| t.state == TaskState::Pending)
            .max_by_key(|(_, t)| t.priority)
            .map(|(idx, _)| idx)
    }
    
    fn name(&self) -> &'static str {
        "PriorityScheduler"
    }
}

/// FIFO scheduling strategy
pub struct FifoScheduler;

impl SchedulingStrategy for FifoScheduler {
    fn select_next(&self, tasks: &[&ManagedTask]) -> Option<usize> {
        tasks
            .iter()
            .enumerate()
            .filter(|(_, t)| t.state == TaskState::Pending)
            .min_by_key(|(_, t)| t.submitted_at)
            .map(|(idx, _)| idx)
    }
    
    fn name(&self) -> &'static str {
        "FifoScheduler"
    }
}

/// Thread-safe task result storage
struct TaskResultStore {
    results: RwLock<HashMap<TaskHandle, Result<ExecutionResult, MapperError>>>,
    completion_signals: Mutex<HashMap<TaskHandle, Arc<(Mutex<bool>, Condvar)>>>,
}

impl TaskResultStore {
    fn new() -> Self {
        Self {
            results: RwLock::new(HashMap::new()),
            completion_signals: Mutex::new(HashMap::new()),
        }
    }
    
    fn register(&self, handle: TaskHandle) -> Arc<(Mutex<bool>, Condvar)> {
        let signal = Arc::new((Mutex::new(false), Condvar::new()));
        self.completion_signals
            .lock()
            .unwrap()
            .insert(handle, Arc::clone(&signal));
        signal
    }
    
    fn store(&self, handle: TaskHandle, result: Result<ExecutionResult, MapperError>) {
        self.results.write().unwrap().insert(handle, result);
        
        if let Some(signal) = self.completion_signals.lock().unwrap().get(&handle) {
            let (lock, cvar) = &**signal;
            let mut completed = lock.lock().unwrap();
            *completed = true;
            cvar.notify_all();
        }
    }
    
    fn get(&self, handle: TaskHandle) -> Option<Result<ExecutionResult, MapperError>> {
        self.results.read().unwrap().get(&handle).cloned()
    }
    
    fn wait_for(&self, handle: TaskHandle, timeout: Option<Duration>) -> Option<Result<ExecutionResult, MapperError>> {
        let signal = self.completion_signals.lock().unwrap().get(&handle).cloned()?;
        let (lock, cvar) = &*signal;
        let mut completed = lock.lock().unwrap();
        
        while !*completed {
            match timeout {
                Some(dur) => {
                    let result = cvar.wait_timeout(completed, dur).unwrap();
                    completed = result.0;
                    if result.1.timed_out() {
                        return None;
                    }
                }
                None => {
                    completed = cvar.wait(completed).unwrap();
                }
            }
        }
        
        self.get(handle)
    }
}

/// Worker thread state
struct WorkerState {
    id: usize,
    active: AtomicBool,
    current_task: Mutex<Option<TaskHandle>>,
}

impl WorkerState {
    fn new(id: usize) -> Self {
        Self {
            id,
            active: AtomicBool::new(true),
            current_task: Mutex::new(None),
        }
    }
}

/// Main executor for managing task execution
pub struct TaskExecutor {
    config: ExecutorConfig,
    task_queue: Arc<Mutex<Vec<ManagedTask>>>,
    result_store: Arc<TaskResultStore>,
    workers: Vec<JoinHandle<()>>,
    worker_states: Vec<Arc<WorkerState>>,
    shutdown_flag: Arc<AtomicBool>,
    task_counter: AtomicU64,
    metrics: Arc<RwLock<ExecutionMetrics>>,
    observers: Arc<RwLock<Vec<Arc<dyn TaskObserver>>>>,
    scheduler: Arc<dyn SchedulingStrategy>,
    queue_signal: Arc<(Mutex<bool>, Condvar)>,
}

impl TaskExecutor {
    /// Create a new executor with default configuration
    pub fn new() -> Self {
        Self::with_config(ExecutorConfig::default())
    }
    
    /// Create a new executor with custom configuration
    pub fn with_config(config: ExecutorConfig) -> Self {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let task_queue = Arc::new(Mutex::new(Vec::new()));
        let result_store = Arc::new(TaskResultStore::new());
        let metrics = Arc::new(RwLock::new(ExecutionMetrics::default()));
        let observers: Arc<RwLock<Vec<Arc<dyn TaskObserver>>>> = Arc::new(RwLock::new(Vec::new()));
        let scheduler: Arc<dyn SchedulingStrategy> = Arc::new(PriorityScheduler);
        let queue_signal = Arc::new((Mutex::new(false), Condvar::new()));
        
        let mut workers = Vec::with_capacity(config.max_threads);
        let mut worker_states = Vec::with_capacity(config.max_threads);
        
        for i in 0..config.max_threads {
            let state = Arc::new(WorkerState::new(i));
            worker_states.push(Arc::clone(&state));
            
            let worker = Self::spawn_worker(
                i,
                Arc::clone(&state),
                Arc::clone(&task_queue),
                Arc::clone(&result_store),
                Arc::clone(&shutdown_flag),
                Arc::clone(&metrics),
                Arc::clone(&observers),
                Arc::clone(&scheduler),
                Arc::clone(&queue_signal),
                config.task_timeout,
            );
            workers.push(worker);
        }
        
        Self {
            config,
            task_queue,
            result_store,
            workers,
            worker_states,
            shutdown_flag,
            task_counter: AtomicU64::new(0),
            metrics,
            observers,
            scheduler,
            queue_signal,
        }
    }
    
    fn spawn_worker(
        id: usize,
        state: Arc<WorkerState>,
        task_queue: Arc<Mutex<Vec<ManagedTask>>>,
        result_store: Arc<TaskResultStore>,
        shutdown_flag: Arc<AtomicBool>,
        metrics: Arc<RwLock<ExecutionMetrics>>,
        observers: Arc<RwLock<Vec<Arc<dyn TaskObserver>>>>,
        scheduler: Arc<dyn SchedulingStrategy>,
        queue_signal: Arc<(Mutex<bool>, Condvar)>,
        timeout: Option<Duration>,
    ) -> JoinHandle<()> {
        thread::Builder::new()
            .name(format!("executor-worker-{}", id))
            .spawn(move || {
                while !shutdown_flag.load(Ordering::Relaxed) {
                    let task = {
                        let (lock, cvar) = &*queue_signal;
                        let mut has_work = lock.lock().unwrap();
                        
                        while !*has_work && !shutdown_flag.load(Ordering::Relaxed) {
                            has_work = cvar.wait_timeout(has_work, Duration::from_millis(100))
                                .unwrap()
                                .0;
                        }
                        
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        
                        let mut queue = task_queue.lock().unwrap();
                        let task_refs: Vec<&ManagedTask> = queue.iter().collect();
                        
                        if let Some(idx) = scheduler.select_next(&task_refs) {
                            let mut task = queue.remove(idx);
                            task.state = TaskState::Running;
                            task.started_at = Some(Instant::now());
                            *state.current_task.lock().unwrap() = Some(task.handle);
                            
                            if queue.iter().all(|t| t.state != TaskState::Pending) {
                                *has_work = false;
                            }
                            
                            Some(task)
                        } else {
                            *has_work = false;
                            None
                        }
                    };
                    
                    if let Some(mut task) = task {
                        let handle = task.handle;
                        
                        for observer in observers.read().unwrap().iter() {
                            observer.on_task_started(handle);
                        }
                        
                        let start_time = Instant::now();
                        let result = Self::execute_with_timeout(&mut task, timeout);
                        let duration = start_time.elapsed();
                        
                        match &result {
                            Ok(exec_result) => {
                                if metrics.read().unwrap().tasks_completed > 0 {
                                    let mut m = metrics.write().unwrap();
                                    m.tasks_completed += 1;
                                    m.total_execution_time += duration;
                                } else {
                                    let mut m = metrics.write().unwrap();
                                    m.tasks_completed = 1;
                                    m.total_execution_time = duration;
                                }
                                
                                for observer in observers.read().unwrap().iter() {
                                    observer.on_task_completed(handle, exec_result);
                                }
                            }
                            Err(e) => {
                                metrics.write().unwrap().tasks_failed += 1;
                                
                                for observer in observers.read().unwrap().iter() {
                                    observer.on_task_failed(handle, e);
                                }
                            }
                        }
                        
                        result_store.store(handle, result);
                        *state.current_task.lock().unwrap() = None;
                    }
                }
                
                state.active.store(false, Ordering::Relaxed);
            })
            .expect("Failed to spawn worker thread")
    }
    
    fn execute_with_timeout(
        task: &mut ManagedTask,
        timeout: Option<Duration>,
    ) -> Result<ExecutionResult, MapperError> {
        let start = Instant::now();
        
        match task.executable.execute() {
            Ok(mut result) => {
                if let Some(max_duration) = timeout {
                    if result.duration > max_duration {
                        return Err(MapperError::Timeout {
                            operation: task.executable.name().unwrap_or("unknown").to_string(),
                            elapsed: result.duration,
                        });
                    }
                }
                result.duration = start.elapsed();
                Ok(result)
            }
            Err(e) => {
                if task.retry_count < task.max_retries {
                    task.retry_count += 1;
                    task.state = TaskState::Pending;
                    Err(e)
                } else {
                    task.state = TaskState::Failed;
                    Err(e)
                }
            }
        }
    }
    
    /// Submit a task for execution
    pub fn submit<T: Executable>(&self, task: T) -> TaskHandle {
        self.submit_with_priority(task, self.config.default_priority)
    }
    
    /// Submit a task with specific priority
    pub fn submit_with_priority<T: Executable>(
        &self,
        task: T,
        priority: ExecutionPriority,
    ) -> TaskHandle {
        let id = self.task_counter.fetch_add(1, Ordering::SeqCst);
        let handle = TaskHandle::new(id);
        
        let managed = ManagedTask::new(
            handle,
            Box::new(task),
            priority,
            self.config.retry_count,
        );
        
        self.result_store.register(handle);
        
        {
            let mut queue = self.task_queue.lock().unwrap();
            queue.push(managed);
        }
        
        {
            let (lock, cvar) = &*self.queue_signal;
            let mut has_work = lock.lock().unwrap();
            *has_work = true;
            cvar.notify_one();
        }
        
        if self.config.enable_metrics {
            self.metrics.write().unwrap().tasks_submitted += 1;
        }
        
        for observer in self.observers.read().unwrap().iter() {
            observer.on_task_submitted(handle);
        }
        
        handle
    }
    
    /// Wait for a task to complete
    pub fn wait(&self, handle: TaskHandle) -> Result<ExecutionResult, MapperError> {
        self.result_store
            .wait_for(handle, self.config.task_timeout)
            .ok_or_else(|| MapperError::Timeout {
                operation: format!("wait for task {}", handle.id()),
                elapsed: self.config.task_timeout.unwrap_or(Duration::ZERO),
            })?
    }
    
    /// Try to get a task result without blocking
    pub fn try_get(&self, handle: TaskHandle) -> Option<Result<ExecutionResult, MapperError>> {
        self.result_store.get(handle)
    }
    
    /// Cancel a pending task
    pub fn cancel(&self, handle: TaskHandle) -> bool {
        let mut queue = self.task_queue.lock().unwrap();
        
        if let Some(pos) = queue.iter().position(|t| t.handle == handle && t.state == TaskState::Pending) {
            let mut task = queue.remove(pos);
            task.executable.on_cancel();
            task.state = TaskState::Cancelled;
            
            for observer in self.observers.read().unwrap().iter() {
                observer.on_task_cancelled(handle);
            }
            
            self.result_store.store(
                handle,
                Err(MapperError::OperationCancelled {
                    operation: "task execution".to_string(),
                }),
            );
            
            true
        } else {
            false
        }
    }
    
    /// Add an observer for task lifecycle events
    pub fn add_observer(&self, observer: Arc<dyn TaskObserver>) {
        self.observers.write().unwrap().push(observer);
    }
    
    /// Get current execution metrics
    pub fn metrics(&self) -> ExecutionMetrics {
        self.metrics.read().unwrap().clone()
    }
    
    /// Get the number of pending tasks
    pub fn pending_count(&self) -> usize {
        self.task_queue
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.state == TaskState::Pending)
            .count()
    }
    
    /// Get the number of active workers
    pub fn active_workers(&self) -> usize {
        self.worker_states
            .iter()
            .filter(|s| s.active.load(Ordering::Relaxed))
            .count()
    }
    
    /// Shutdown the executor gracefully
    pub fn shutdown(self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        
        {
            let (lock, cvar) = &*self.queue_signal;
            let mut has_work = lock.lock().unwrap();
            *has_work = true;
            cvar.notify_all();
        }
        
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

impl Default for TaskExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple closure-based task implementation
pub struct ClosureTask<F>
where
    F: FnMut() -> Result<ExecutionResult, MapperError> + Send + 'static,
{
    func: F,
    name: Option<String>,
    priority: ExecutionPriority,
}

impl<F> ClosureTask<F>
where
    F: FnMut() -> Result<ExecutionResult, MapperError> + Send + 'static,
{
    pub fn new(func: F) -> Self {
        Self {
            func,
            name: None,
            priority: ExecutionPriority::Normal,
        }
    }
    
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    
    pub fn with_priority(mut self, priority: ExecutionPriority) -> Self {
        self.priority = priority;
        self
    }
}

impl<F> Executable for ClosureTask<F>
where
    F: FnMut() -> Result<ExecutionResult, MapperError> + Send + 'static,
{
    fn execute(&mut self) -> Result<ExecutionResult, MapperError> {
        (self.func)()
    }
    
    fn priority(&self) -> ExecutionPriority {
        self.priority
    }
    
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
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
    pub start_time: Option<Instant>,
}

/// Thread information structure
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub tid: ThreadId,
    pub owner_pid: ProcessId,
    pub state: TaskState,
    pub priority: ExecutionPriority,
    pub cpu_time: Duration,
}

/// Process manager for system process operations
pub struct ProcessManager {
    tracked_processes: RwLock<HashMap<ProcessId, ProcessInfo>>,
    process_observers: RwLock<Vec<Arc<dyn ProcessObserver>>>,
}

/// Observer trait for process lifecycle events
pub trait ProcessObserver: Send + Sync {
    fn on_process_created(&self, info: &ProcessInfo);
    fn on_process_terminated(&self, pid: ProcessId, exit_code: i32);
    fn on_process_state_changed(&self, pid: ProcessId, new_state: TaskState);
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            tracked_processes: RwLock::new(HashMap::new()),
            process_observers: RwLock::new(Vec::new()),
        }
    }
    
    /// Track a process by its ID
    pub fn track(&self, info: ProcessInfo) {
        let pid = info.pid;
        
        for observer in self.process_observers.read().unwrap().iter() {
            observer.on_process_created(&info);
        }
        
        self.tracked_processes.write().unwrap().insert(pid, info);
    }
    
    /// Stop tracking a process
    pub fn untrack(&self, pid: ProcessId) -> Option<ProcessInfo> {
        self.tracked_processes.write().unwrap().remove(&pid)
    }
    
    /// Get information about a tracked process
    pub fn get_info(&self, pid: ProcessId) -> Option<ProcessInfo> {
        self.tracked_processes.read().unwrap().get(&pid).cloned()
    }
    
    /// List all tracked processes
    pub fn list_tracked(&self) -> Vec<ProcessInfo> {
        self.tracked_processes.read().unwrap().values().cloned().collect()
    }
    
    /// Add a process observer
    pub fn add_observer(&self, observer: Arc<dyn ProcessObserver>) {
        self.process_observers.write().unwrap().push(observer);
    }
    
    /// Notify observers of process termination
    pub fn notify_terminated(&self, pid: ProcessId, exit_code: i32) {
        for observer in self.process_observers.read().unwrap().iter() {
            observer.on_process_terminated(pid, exit_code);
        }
        
        self.untrack(pid);
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating executors with different configurations
pub struct ExecutorFactory;

impl ExecutorFactory {
    /// Create a single-threaded executor
    pub fn single_threaded() -> TaskExecutor {
        TaskExecutor::with_config(ExecutorConfig {
            max_threads: 1,
            ..Default::default()
        })
    }
    
    /// Create a high-performance executor
    pub fn high_performance() -> TaskExecutor {
        let cpu_count = num_cpus::get();
        TaskExecutor::with_config(ExecutorConfig {
            max_threads: cpu_count * 2,
            default_priority: ExecutionPriority::High,
            task_timeout: Some(Duration::from_secs(60)),
            enable_metrics: true,
            retry_count: 1,
        })
    }
    
    /// Create an executor optimized for I/O-bound tasks
    pub fn io_optimized() -> TaskExecutor {
        let cpu_count = num_cpus::get();
        TaskExecutor::with_config(ExecutorConfig {
            max_threads: cpu_count * 4,
            default_priority: ExecutionPriority::Normal,
            task_timeout: Some(Duration::from_secs(600)),
            enable_metrics: true,
            retry_count: 5,
        })
    }
    
    /// Create an executor with custom thread count
    pub fn with_threads(count: usize) -> TaskExecutor {
        TaskExecutor::with_config(ExecutorConfig {
            max_threads: count.max(1),
            ..Default::default()
        })
    }
}

/// Scoped executor that ensures all tasks complete before dropping
pub struct ScopedExecutor {
    executor: TaskExecutor,
    pending_handles: Mutex<Vec<TaskHandle>>,
}

impl ScopedExecutor {
    pub fn new() -> Self {
        Self {
            executor: TaskExecutor::new(),
            pending_handles: Mutex::new(Vec::new()),
        }
    }
    
    pub fn with_config(config: ExecutorConfig) -> Self {
        Self {
            executor: TaskExecutor::with_config(config),
            pending_handles: Mutex::new(Vec::new()),
        }
    }
    
    pub fn submit<T: Executable>(&self, task: T) -> TaskHandle {
        let handle = self.executor.submit(task);
        self.pending_handles.lock().unwrap().push(handle);
        handle
    }
    
    pub fn wait_all(&self) -> Vec<Result<ExecutionResult, MapperError>> {
        let handles: Vec<TaskHandle> = self.pending_handles.lock().unwrap().drain(..).collect();
        handles.into_iter().map(|h| self.executor.wait(h)).collect()
    }
}

impl Default for ScopedExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScopedExecutor {
    fn drop(&mut self) {
        let _ = self.wait_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_task_handle_creation() {
        let handle = TaskHandle::new(42);
        assert_eq!(handle.id(), 42);
    }
    
    #[test]
    fn test_execution_priority_ordering() {
        assert!(ExecutionPriority::Critical > ExecutionPriority::High);
        assert!(ExecutionPriority::High > ExecutionPriority::Normal);
        assert!(ExecutionPriority::Normal > ExecutionPriority::Low);
    }
    
    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert!(config.max_threads >= 4);
        assert_eq!(config.default_priority, ExecutionPriority::Normal);
        assert!(config.enable_metrics);
    }
    
    #[test]
    fn test_execution_result_builder() {
        let result = ExecutionResult::success(Duration::from_secs(1))
            .with_output(vec![1, 2, 3])
            .with_exit_code(0);
        
        assert_eq!(result.status, TaskState::Completed);
        assert_eq!(result.output, Some(vec![1, 2, 3]));
        assert_eq!(result.exit_code, 0);
    }
}