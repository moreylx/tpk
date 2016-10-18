//! Transformer module for data transformation and mapping operations.
//! 
//! This module provides a flexible transformation pipeline using the Strategy pattern,
//! allowing for composable data transformations with proper error handling.

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};
use std::any::TypeId;
use std::time::{Duration, Instant};

use crate::error::MapperError;

/// Result type for transformer operations
pub type TransformResult<T> = Result<T, MapperError>;

/// Boundary conditions for transformation validation
#[derive(Debug, Clone)]
pub struct BoundaryCondition<T> {
    /// Minimum allowed value (inclusive)
    pub min: Option<T>,
    /// Maximum allowed value (inclusive)
    pub max: Option<T>,
    /// Custom validation predicate
    validator: Option<Arc<dyn Fn(&T) -> bool + Send + Sync>>,
}

impl<T> Default for BoundaryCondition<T> {
    fn default() -> Self {
        Self {
            min: None,
            max: None,
            validator: None,
        }
    }
}

impl<T> BoundaryCondition<T>
where
    T: PartialOrd + Clone,
{
    /// Create a new boundary condition with no constraints
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum boundary (inclusive)
    pub fn with_min(mut self, min: T) -> Self {
        self.min = Some(min);
        self
    }

    /// Set maximum boundary (inclusive)
    pub fn with_max(mut self, max: T) -> Self {
        self.max = Some(max);
        self
    }

    /// Set a range boundary (inclusive on both ends)
    pub fn with_range(mut self, min: T, max: T) -> Self {
        self.min = Some(min);
        self.max = Some(max);
        self
    }

    /// Add a custom validator function
    pub fn with_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&T) -> bool + Send + Sync + 'static,
    {
        self.validator = Some(Arc::new(validator));
        self
    }

    /// Check if a value satisfies all boundary conditions
    pub fn check(&self, value: &T) -> bool {
        if let Some(ref min) = self.min {
            if value < min {
                return false;
            }
        }
        if let Some(ref max) = self.max {
            if value > max {
                return false;
            }
        }
        if let Some(ref validator) = self.validator {
            if !validator(value) {
                return false;
            }
        }
        true
    }

    /// Validate and return error if boundary check fails
    pub fn validate(&self, value: &T) -> TransformResult<()> {
        if self.check(value) {
            Ok(())
        } else {
            Err(MapperError::ValidationFailed("Boundary condition violated".into()))
        }
    }
}

/// Strategy trait for transformation operations
pub trait TransformStrategy<I, O>: Send + Sync {
    /// Transform input to output
    fn transform(&self, input: I) -> TransformResult<O>;
    
    /// Get strategy identifier for caching
    fn strategy_id(&self) -> &str;
}

/// Performance metrics for transformation operations
#[derive(Debug, Clone, Default)]
pub struct TransformMetrics {
    pub total_transforms: u64,
    pub successful_transforms: u64,
    pub failed_transforms: u64,
    pub total_duration_ns: u64,
    pub min_duration_ns: u64,
    pub max_duration_ns: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl TransformMetrics {
    pub fn new() -> Self {
        Self {
            min_duration_ns: u64::MAX,
            ..Default::default()
        }
    }

    #[inline]
    pub fn record_success(&mut self, duration_ns: u64) {
        self.total_transforms += 1;
        self.successful_transforms += 1;
        self.total_duration_ns = self.total_duration_ns.saturating_add(duration_ns);
        self.min_duration_ns = self.min_duration_ns.min(duration_ns);
        self.max_duration_ns = self.max_duration_ns.max(duration_ns);
    }

    #[inline]
    pub fn record_failure(&mut self) {
        self.total_transforms += 1;
        self.failed_transforms += 1;
    }

    #[inline]
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    #[inline]
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    pub fn average_duration_ns(&self) -> u64 {
        if self.successful_transforms == 0 {
            0
        } else {
            self.total_duration_ns / self.successful_transforms
        }
    }

    pub fn cache_hit_ratio(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

/// Cache entry with expiration tracking
struct CacheEntry<T> {
    value: T,
    created_at: Instant,
    access_count: u32,
}

impl<T: Clone> CacheEntry<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            created_at: Instant::now(),
            access_count: 0,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }

    fn access(&mut self) -> &T {
        self.access_count += 1;
        &self.value
    }
}

/// High-performance LRU cache with TTL support
pub struct TransformCache<K, V> {
    entries: HashMap<K, CacheEntry<V>>,
    capacity: usize,
    ttl: Duration,
    eviction_threshold: usize,
}

impl<K, V> TransformCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
            ttl,
            eviction_threshold: capacity * 3 / 4,
        }
    }

    pub fn get(&mut self, key: &K) -> Option<V> {
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.is_expired(self.ttl) {
                self.entries.remove(key);
                return None;
            }
            Some(entry.access().clone())
        } else {
            None
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.entries.len() >= self.capacity {
            self.evict_expired();
        }
        if self.entries.len() >= self.capacity {
            self.evict_lru();
        }
        self.entries.insert(key, CacheEntry::new(value));
    }

    fn evict_expired(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired(self.ttl));
    }

    fn evict_lru(&mut self) {
        if self.entries.len() <= self.eviction_threshold {
            return;
        }

        let mut entries_by_access: Vec<_> = self.entries.iter()
            .map(|(k, v)| (k.clone(), v.access_count))
            .collect();
        
        entries_by_access.sort_by_key(|(_, count)| *count);
        
        let to_remove = self.entries.len() - self.eviction_threshold;
        for (key, _) in entries_by_access.into_iter().take(to_remove) {
            self.entries.remove(&key);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Support ticket priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupportPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl SupportPriority {
    fn weight(&self) -> u32 {
        match self {
            SupportPriority::Critical => 1000,
            SupportPriority::High => 100,
            SupportPriority::Medium => 10,
            SupportPriority::Low => 1,
        }
    }
}

/// Support request data structure
#[derive(Debug, Clone)]
pub struct SupportRequest {
    pub id: u64,
    pub priority: SupportPriority,
    pub category: String,
    pub payload: Vec<u8>,
    pub timestamp: Instant,
}

/// Processed support response
#[derive(Debug, Clone)]
pub struct SupportResponse {
    pub request_id: u64,
    pub status: SupportStatus,
    pub result: Option<Vec<u8>>,
    pub processing_time_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportStatus {
    Completed,
    Pending,
    Failed,
    Cached,
}

/// Handler trait for support request processing
pub trait SupportHandler: Send + Sync {
    fn handle(&self, request: &SupportRequest) -> TransformResult<Vec<u8>>;
    fn category(&self) -> &str;
    fn supports_caching(&self) -> bool {
        true
    }
}

/// Optimized support manager with batching and priority queuing
pub struct SupportManager {
    handlers: RwLock<HashMap<String, Arc<dyn SupportHandler>>>,
    metrics: RwLock<HashMap<String, TransformMetrics>>,
    response_cache: RwLock<TransformCache<u64, SupportResponse>>,
    batch_size: usize,
    enable_metrics: bool,
    priority_weights: [u32; 4],
}

impl SupportManager {
    /// Create a new support manager with default configuration
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            metrics: RwLock::new(HashMap::new()),
            response_cache: RwLock::new(TransformCache::new(1024, Duration::from_secs(300))),
            batch_size: 64,
            enable_metrics: true,
            priority_weights: [1000, 100, 10, 1],
        }
    }

    /// Create with custom configuration
    pub fn with_config(cache_capacity: usize, cache_ttl: Duration, batch_size: usize) -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            metrics: RwLock::new(HashMap::new()),
            response_cache: RwLock::new(TransformCache::new(cache_capacity, cache_ttl)),
            batch_size,
            enable_metrics: true,
            priority_weights: [1000, 100, 10, 1],
        }
    }

    /// Register a handler for a specific category
    pub fn register_handler<H: SupportHandler + 'static>(&self, handler: H) -> TransformResult<()> {
        let category = handler.category().to_string();
        let mut handlers = self.handlers.write().map_err(|_| {
            MapperError::LockError("Failed to acquire handlers write lock".into())
        })?;
        
        handlers.insert(category.clone(), Arc::new(handler));
        
        if self.enable_metrics {
            let mut metrics = self.metrics.write().map_err(|_| {
                MapperError::LockError("Failed to acquire metrics write lock".into())
            })?;
            metrics.insert(category, TransformMetrics::new());
        }
        
        Ok(())
    }

    /// Process a single support request with caching
    #[inline]
    pub fn process(&self, request: &SupportRequest) -> TransformResult<SupportResponse> {
        // Check cache first
        {
            let mut cache = self.response_cache.write().map_err(|_| {
                MapperError::LockError("Failed to acquire cache write lock".into())
            })?;
            
            if let Some(cached) = cache.get(&request.id) {
                if self.enable_metrics {
                    self.record_cache_hit(&request.category)?;
                }
                return Ok(SupportResponse {
                    status: SupportStatus::Cached,
                    ..cached
                });
            }
        }

        if self.enable_metrics {
            self.record_cache_miss(&request.category)?;
        }

        let start = Instant::now();
        let result = self.execute_handler(request);
        let duration_ns = start.elapsed().as_nanos() as u64;

        let response = match result {
            Ok(data) => {
                if self.enable_metrics {
                    self.record_success(&request.category, duration_ns)?;
                }
                SupportResponse {
                    request_id: request.id,
                    status: SupportStatus::Completed,
                    result: Some(data),
                    processing_time_ns: duration_ns,
                }
            }
            Err(e) => {
                if self.enable_metrics {
                    self.record_failure(&request.category)?;
                }
                return Err(e);
            }
        };

        // Cache the response if handler supports it
        if self.should_cache(&request.category)? {
            let mut cache = self.response_cache.write().map_err(|_| {
                MapperError::LockError("Failed to acquire cache write lock".into())
            })?;
            cache.insert(request.id, response.clone());
        }

        Ok(response)
    }

    /// Process multiple requests in batch with priority ordering
    pub fn process_batch(&self, mut requests: Vec<SupportRequest>) -> Vec<TransformResult<SupportResponse>> {
        // Sort by priority weight (higher weight = higher priority)
        requests.sort_by(|a, b| {
            b.priority.weight().cmp(&a.priority.weight())
        });

        let mut results = Vec::with_capacity(requests.len());
        
        for chunk in requests.chunks(self.batch_size) {
            for request in chunk {
                results.push(self.process(request));
            }
        }

        results
    }

    /// Process requests with parallel execution for independent categories
    #[cfg(feature = "parallel")]
    pub fn process_parallel(&self, requests: Vec<SupportRequest>) -> Vec<TransformResult<SupportResponse>> {
        use rayon::prelude::*;
        
        let mut sorted_requests = requests;
        sorted_requests.sort_by(|a, b| b.priority.weight().cmp(&a.priority.weight()));
        
        sorted_requests
            .par_iter()
            .map(|req| self.process(req))
            .collect()
    }

    #[inline]
    fn execute_handler(&self, request: &SupportRequest) -> TransformResult<Vec<u8>> {
        let handlers = self.handlers.read().map_err(|_| {
            MapperError::LockError("Failed to acquire handlers read lock".into())
        })?;

        let handler = handlers.get(&request.category).ok_or_else(|| {
            MapperError::NotFound(format!("No handler for category: {}", request.category))
        })?;

        handler.handle(request)
    }

    fn should_cache(&self, category: &str) -> TransformResult<bool> {
        let handlers = self.handlers.read().map_err(|_| {
            MapperError::LockError("Failed to acquire handlers read lock".into())
        })?;

        Ok(handlers
            .get(category)
            .map(|h| h.supports_caching())
            .unwrap_or(false))
    }

    #[inline]
    fn record_success(&self, category: &str, duration_ns: u64) -> TransformResult<()> {
        let mut metrics = self.metrics.write().map_err(|_| {
            MapperError::LockError("Failed to acquire metrics write lock".into())
        })?;
        
        if let Some(m) = metrics.get_mut(category) {
            m.record_success(duration_ns);
        }
        Ok(())
    }

    #[inline]
    fn record_failure(&self, category: &str) -> TransformResult<()> {
        let mut metrics = self.metrics.write().map_err(|_| {
            MapperError::LockError("Failed to acquire metrics write lock".into())
        })?;
        
        if let Some(m) = metrics.get_mut(category) {
            m.record_failure();
        }
        Ok(())
    }

    #[inline]
    fn record_cache_hit(&self, category: &str) -> TransformResult<()> {
        let mut metrics = self.metrics.write().map_err(|_| {
            MapperError::LockError("Failed to acquire metrics write lock".into())
        })?;
        
        if let Some(m) = metrics.get_mut(category) {
            m.record_cache_hit();
        }
        Ok(())
    }

    #[inline]
    fn record_cache_miss(&self, category: &str) -> TransformResult<()> {
        let mut metrics = self.metrics.write().map_err(|_| {
            MapperError::LockError("Failed to acquire metrics write lock".into())
        })?;
        
        if let Some(m) = metrics.get_mut(category) {
            m.record_cache_miss();
        }
        Ok(())
    }

    /// Get metrics for a specific category
    pub fn get_metrics(&self, category: &str) -> TransformResult<Option<TransformMetrics>> {
        let metrics = self.metrics.read().map_err(|_| {
            MapperError::LockError("Failed to acquire metrics read lock".into())
        })?;
        
        Ok(metrics.get(category).cloned())
    }

    /// Get aggregated metrics across all categories
    pub fn get_aggregate_metrics(&self) -> TransformResult<TransformMetrics> {
        let metrics = self.metrics.read().map_err(|_| {
            MapperError::LockError("Failed to acquire metrics read lock".into())
        })?;

        let mut aggregate = TransformMetrics::new();
        
        for m in metrics.values() {
            aggregate.total_transforms += m.total_transforms;
            aggregate.successful_transforms += m.successful_transforms;
            aggregate.failed_transforms += m.failed_transforms;
            aggregate.total_duration_ns = aggregate.total_duration_ns.saturating_add(m.total_duration_ns);
            aggregate.min_duration_ns = aggregate.min_duration_ns.min(m.min_duration_ns);
            aggregate.max_duration_ns = aggregate.max_duration_ns.max(m.max_duration_ns);
            aggregate.cache_hits += m.cache_hits;
            aggregate.cache_misses += m.cache_misses;
        }

        Ok(aggregate)
    }

    /// Clear all caches
    pub fn clear_cache(&self) -> TransformResult<()> {
        let mut cache = self.response_cache.write().map_err(|_| {
            MapperError::LockError("Failed to acquire cache write lock".into())
        })?;
        cache.clear();
        Ok(())
    }

    /// Reset all metrics
    pub fn reset_metrics(&self) -> TransformResult<()> {
        let mut metrics = self.metrics.write().map_err(|_| {
            MapperError::LockError("Failed to acquire metrics write lock".into())
        })?;
        
        for m in metrics.values_mut() {
            *m = TransformMetrics::new();
        }
        Ok(())
    }

    /// Get current cache size
    pub fn cache_size(&self) -> TransformResult<usize> {
        let cache = self.response_cache.read().map_err(|_| {
            MapperError::LockError("Failed to acquire cache read lock".into())
        })?;
        Ok(cache.len())
    }
}

impl Default for SupportManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Transformer pipeline for chaining multiple transformations
pub struct TransformPipeline<I, O> {
    stages: Vec<Box<dyn Fn(I) -> TransformResult<O> + Send + Sync>>,
    _phantom: PhantomData<(I, O)>,
}

impl<T> TransformPipeline<T, T>
where
    T: Clone + Send + 'static,
{
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub fn add_stage<F>(mut self, stage: F) -> Self
    where
        F: Fn(T) -> TransformResult<T> + Send + Sync + 'static,
    {
        self.stages.push(Box::new(stage));
        self
    }

    pub fn execute(&self, input: T) -> TransformResult<T> {
        let mut current = input;
        for stage in &self.stages {
            current = stage(current)?;
        }
        Ok(current)
    }
}

impl<T: Clone + Send + 'static> Default for TransformPipeline<T, T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Identity transformation strategy
pub struct IdentityStrategy<T> {
    _phantom: PhantomData<T>,
}

impl<T> IdentityStrategy<T> {
    pub fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<T> Default for IdentityStrategy<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Send + Sync> TransformStrategy<T, T> for IdentityStrategy<T> {
    fn transform(&self, input: T) -> TransformResult<T> {
        Ok(input)
    }

    fn strategy_id(&self) -> &str {
        "identity"
    }
}

/// Mapping transformation strategy
pub struct MappingStrategy<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    mapper: F,
    id: String,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O, F> MappingStrategy<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    pub fn new(id: impl Into<String>, mapper: F) -> Self {
        Self {
            mapper,
            id: id.into(),
            _phantom: PhantomData,
        }
    }
}

impl<I, O, F> TransformStrategy<I, O> for MappingStrategy<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    fn transform(&self, input: I) -> TransformResult<O> {
        (self.mapper)(input)
    }

    fn strategy_id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_condition_range() {
        let boundary = BoundaryCondition::new()
            .with_range(0i32, 100);
        
        assert!(boundary.check(&50));
        assert!(boundary.check(&0));
        assert!(boundary.check(&100));
        assert!(!boundary.check(&-1));
        assert!(!boundary.check(&101));
    }

    #[test]
    fn test_boundary_condition_validator() {
        let boundary = BoundaryCondition::new()
            .with_validator(|x: &i32| x % 2 == 0);
        
        assert!(boundary.check(&2));
        assert!(boundary.check(&0));
        assert!(!boundary.check(&1));
    }

    #[test]
    fn test_transform_cache() {
        let mut cache: TransformCache<u64, String> = TransformCache::new(10, Duration::from_secs(60));
        
        cache.insert(1, "one".to_string());
        cache.insert(2, "two".to_string());
        
        assert_eq!(cache.get(&1), Some("one".to_string()));
        assert_eq!(cache.get(&2), Some("two".to_string()));
        assert_eq!(cache.get(&3), None);
    }

    #[test]
    fn test_transform_metrics() {
        let mut metrics = TransformMetrics::new();
        
        metrics.record_success(100);
        metrics.record_success(200);
        metrics.record_failure();
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        
        assert_eq!(metrics.total_transforms, 3);
        assert_eq!(metrics.successful_transforms, 2);
        assert_eq!(metrics.failed_transforms, 1);
        assert_eq!(metrics.average_duration_ns(), 150);
        assert!((metrics.cache_hit_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_identity_strategy() {
        let strategy = IdentityStrategy::<i32>::new();
        assert_eq!(strategy.transform(42).unwrap(), 42);
        assert_eq!(strategy.strategy_id(), "identity");
    }

    #[test]
    fn test_mapping_strategy() {
        let strategy = MappingStrategy::new("double", |x: i32| Ok(x * 2));
        assert_eq!(strategy.transform(21).unwrap(), 42);
        assert_eq!(strategy.strategy_id(), "double");
    }

    #[test]
    fn test_transform_pipeline() {
        let pipeline = TransformPipeline::<i32, i32>::new()
            .add_stage(|x| Ok(x + 1))
            .add_stage(|x| Ok(x * 2));
        
        assert_eq!(pipeline.execute(5).unwrap(), 12);
    }
}