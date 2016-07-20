//! Transformer module for data transformation and mapping operations.
//! 
//! This module provides a flexible transformation pipeline using the Strategy pattern,
//! allowing for composable data transformations with proper error handling.

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};
use std::any::TypeId;

use crate::error::MapperError;

/// Result type for transformer operations
pub type TransformResult<T> = Result<T, MapperError>;

/// Trait defining a transformation strategy
pub trait TransformStrategy<I, O>: Send + Sync {
    /// Transform input to output
    fn transform(&self, input: I) -> TransformResult<O>;
    
    /// Get the name of this transformation strategy
    fn name(&self) -> &str;
    
    /// Check if this strategy can handle the given input
    fn can_transform(&self, input: &I) -> bool;
}

/// A composable transformer that chains multiple transformations
pub struct TransformPipeline<I, O> {
    stages: Vec<Box<dyn TransformStrategy<I, O>>>,
    fallback: Option<Box<dyn TransformStrategy<I, O>>>,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O> TransformPipeline<I, O>
where
    I: Clone + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    /// Create a new empty pipeline
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            fallback: None,
            _phantom: PhantomData,
        }
    }

    /// Add a transformation stage to the pipeline
    pub fn add_stage<S>(mut self, strategy: S) -> Self
    where
        S: TransformStrategy<I, O> + 'static,
    {
        self.stages.push(Box::new(strategy));
        self
    }

    /// Set a fallback strategy when no other strategy matches
    pub fn with_fallback<S>(mut self, strategy: S) -> Self
    where
        S: TransformStrategy<I, O> + 'static,
    {
        self.fallback = Some(Box::new(strategy));
        self
    }

    /// Execute the pipeline, trying each stage until one succeeds
    pub fn execute(&self, input: I) -> TransformResult<O> {
        for stage in &self.stages {
            if stage.can_transform(&input) {
                match stage.transform(input.clone()) {
                    Ok(output) => return Ok(output),
                    Err(_) => continue,
                }
            }
        }

        if let Some(ref fallback) = self.fallback {
            return fallback.transform(input);
        }

        Err(MapperError::TransformationFailed(
            "No suitable transformation strategy found".to_string(),
        ))
    }

    /// Get the number of stages in the pipeline
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Check if the pipeline has a fallback strategy
    pub fn has_fallback(&self) -> bool {
        self.fallback.is_some()
    }
}

impl<I, O> Default for TransformPipeline<I, O>
where
    I: Clone + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Observer trait for monitoring transformation events
pub trait TransformObserver<I, O>: Send + Sync {
    /// Called before a transformation begins
    fn on_transform_start(&self, input: &I, strategy_name: &str);
    
    /// Called after a successful transformation
    fn on_transform_success(&self, input: &I, output: &O, strategy_name: &str);
    
    /// Called when a transformation fails
    fn on_transform_failure(&self, input: &I, error: &MapperError, strategy_name: &str);
}

/// Observable transformer that notifies observers of transformation events
pub struct ObservableTransformer<I, O> {
    pipeline: TransformPipeline<I, O>,
    observers: Arc<RwLock<Vec<Arc<dyn TransformObserver<I, O>>>>>,
}

impl<I, O> ObservableTransformer<I, O>
where
    I: Clone + Send + Sync + Debug + 'static,
    O: Clone + Send + Sync + Debug + 'static,
{
    /// Create a new observable transformer with the given pipeline
    pub fn new(pipeline: TransformPipeline<I, O>) -> Self {
        Self {
            pipeline,
            observers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register an observer
    pub fn add_observer(&self, observer: Arc<dyn TransformObserver<I, O>>) {
        if let Ok(mut observers) = self.observers.write() {
            observers.push(observer);
        }
    }

    /// Execute transformation with observer notifications
    pub fn execute(&self, input: I) -> TransformResult<O> {
        let observers = self.observers.read().ok();
        
        // Notify start
        if let Some(ref obs) = observers {
            for observer in obs.iter() {
                observer.on_transform_start(&input, "pipeline");
            }
        }

        match self.pipeline.execute(input.clone()) {
            Ok(output) => {
                if let Some(ref obs) = observers {
                    for observer in obs.iter() {
                        observer.on_transform_success(&input, &output, "pipeline");
                    }
                }
                Ok(output)
            }
            Err(e) => {
                if let Some(ref obs) = observers {
                    for observer in obs.iter() {
                        observer.on_transform_failure(&input, &e, "pipeline");
                    }
                }
                Err(e)
            }
        }
    }
}

/// Factory for creating common transformation strategies
pub struct TransformFactory;

impl TransformFactory {
    /// Create an identity transformation that returns input unchanged
    pub fn identity<T>() -> IdentityTransform<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        IdentityTransform::new()
    }

    /// Create a mapping transformation using a closure
    pub fn map<I, O, F>(name: &str, mapper: F) -> MapTransform<I, O, F>
    where
        I: Send + Sync + 'static,
        O: Send + Sync + 'static,
        F: Fn(I) -> TransformResult<O> + Send + Sync + 'static,
    {
        MapTransform::new(name.to_string(), mapper)
    }

    /// Create a filtering transformation
    pub fn filter<T, P>(name: &str, predicate: P) -> FilterTransform<T, P>
    where
        T: Clone + Send + Sync + 'static,
        P: Fn(&T) -> bool + Send + Sync + 'static,
    {
        FilterTransform::new(name.to_string(), predicate)
    }

    /// Create a caching transformation wrapper
    pub fn cached<I, O, S>(strategy: S, capacity: usize) -> CachedTransform<I, O, S>
    where
        I: Clone + std::hash::Hash + Eq + Send + Sync + 'static,
        O: Clone + Send + Sync + 'static,
        S: TransformStrategy<I, O> + 'static,
    {
        CachedTransform::new(strategy, capacity)
    }
}

/// Identity transformation - returns input unchanged
pub struct IdentityTransform<T> {
    _phantom: PhantomData<T>,
}

impl<T> IdentityTransform<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> Default for IdentityTransform<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TransformStrategy<T, T> for IdentityTransform<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn transform(&self, input: T) -> TransformResult<T> {
        Ok(input)
    }

    fn name(&self) -> &str {
        "identity"
    }

    fn can_transform(&self, _input: &T) -> bool {
        true
    }
}

/// Map transformation using a closure
pub struct MapTransform<I, O, F> {
    name: String,
    mapper: F,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O, F> MapTransform<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    pub fn new(name: String, mapper: F) -> Self {
        Self {
            name,
            mapper,
            _phantom: PhantomData,
        }
    }
}

impl<I, O, F> TransformStrategy<I, O> for MapTransform<I, O, F>
where
    I: Send + Sync + 'static,
    O: Send + Sync + 'static,
    F: Fn(I) -> TransformResult<O> + Send + Sync + 'static,
{
    fn transform(&self, input: I) -> TransformResult<O> {
        (self.mapper)(input)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn can_transform(&self, _input: &I) -> bool {
        true
    }
}

/// Filter transformation that passes through or rejects input
pub struct FilterTransform<T, P> {
    name: String,
    predicate: P,
    _phantom: PhantomData<T>,
}

impl<T, P> FilterTransform<T, P>
where
    P: Fn(&T) -> bool + Send + Sync,
{
    pub fn new(name: String, predicate: P) -> Self {
        Self {
            name,
            predicate,
            _phantom: PhantomData,
        }
    }
}

impl<T, P> TransformStrategy<T, T> for FilterTransform<T, P>
where
    T: Clone + Send + Sync + 'static,
    P: Fn(&T) -> bool + Send + Sync + 'static,
{
    fn transform(&self, input: T) -> TransformResult<T> {
        if (self.predicate)(&input) {
            Ok(input)
        } else {
            Err(MapperError::TransformationFailed(
                format!("Filter '{}' rejected input", self.name),
            ))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn can_transform(&self, input: &T) -> bool {
        (self.predicate)(input)
    }
}

/// Cached transformation wrapper using LRU-style eviction
pub struct CachedTransform<I, O, S> {
    inner: S,
    cache: Arc<RwLock<LruCache<I, O>>>,
}

impl<I, O, S> CachedTransform<I, O, S>
where
    I: Clone + std::hash::Hash + Eq + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    S: TransformStrategy<I, O>,
{
    pub fn new(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
        }
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Get current cache size
    pub fn cache_size(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }
}

impl<I, O, S> TransformStrategy<I, O> for CachedTransform<I, O, S>
where
    I: Clone + std::hash::Hash + Eq + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
    S: TransformStrategy<I, O> + 'static,
{
    fn transform(&self, input: I) -> TransformResult<O> {
        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(cached) = cache.get(&input) {
                return Ok(cached.clone());
            }
        }

        // Transform and cache result
        let result = self.inner.transform(input.clone())?;
        
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(input, result.clone());
        }

        Ok(result)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn can_transform(&self, input: &I) -> bool {
        self.inner.can_transform(input)
    }
}

/// Simple LRU cache implementation
struct LruCache<K, V> {
    capacity: usize,
    entries: HashMap<K, V>,
    order: Vec<K>,
}

impl<K, V> LruCache<K, V>
where
    K: Clone + std::hash::Hash + Eq,
    V: Clone,
{
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::with_capacity(capacity),
            order: Vec::with_capacity(capacity),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: K, value: V) {
        if self.entries.contains_key(&key) {
            self.entries.insert(key.clone(), value);
            // Move to end of order
            self.order.retain(|k| k != &key);
            self.order.push(key);
        } else {
            if self.entries.len() >= self.capacity {
                // Evict oldest entry
                if let Some(oldest) = self.order.first().cloned() {
                    self.entries.remove(&oldest);
                    self.order.remove(0);
                }
            }
            self.entries.insert(key.clone(), value);
            self.order.push(key);
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

/// Batch transformer for processing multiple inputs
pub struct BatchTransformer<I, O> {
    pipeline: Arc<TransformPipeline<I, O>>,
    parallel: bool,
}

impl<I, O> BatchTransformer<I, O>
where
    I: Clone + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    /// Create a new batch transformer
    pub fn new(pipeline: TransformPipeline<I, O>) -> Self {
        Self {
            pipeline: Arc::new(pipeline),
            parallel: false,
        }
    }

    /// Enable parallel processing (requires rayon feature)
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.parallel = enabled;
        self
    }

    /// Transform a batch of inputs
    pub fn transform_batch(&self, inputs: Vec<I>) -> Vec<TransformResult<O>> {
        inputs
            .into_iter()
            .map(|input| self.pipeline.execute(input))
            .collect()
    }

    /// Transform batch, collecting only successful results
    pub fn transform_batch_ok(&self, inputs: Vec<I>) -> Vec<O> {
        self.transform_batch(inputs)
            .into_iter()
            .filter_map(Result::ok)
            .collect()
    }
}

/// Type-erased transformation registry
pub struct TransformRegistry {
    strategies: Arc<RwLock<HashMap<String, Box<dyn std::any::Any + Send + Sync>>>>,
}

impl TransformRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            strategies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a transformation strategy
    pub fn register<I, O, S>(&self, name: &str, strategy: S) -> bool
    where
        I: 'static,
        O: 'static,
        S: TransformStrategy<I, O> + 'static,
    {
        if let Ok(mut strategies) = self.strategies.write() {
            strategies.insert(name.to_string(), Box::new(strategy));
            true
        } else {
            false
        }
    }

    /// Check if a strategy is registered
    pub fn contains(&self, name: &str) -> bool {
        self.strategies
            .read()
            .map(|s| s.contains_key(name))
            .unwrap_or(false)
    }

    /// Get the number of registered strategies
    pub fn len(&self) -> usize {
        self.strategies.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TransformRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Conditional transformer that applies different strategies based on predicates
pub struct ConditionalTransformer<I, O> {
    conditions: Vec<(Box<dyn Fn(&I) -> bool + Send + Sync>, Box<dyn TransformStrategy<I, O>>)>,
    default: Option<Box<dyn TransformStrategy<I, O>>>,
}

impl<I, O> ConditionalTransformer<I, O>
where
    I: Clone + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    /// Create a new conditional transformer
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
            default: None,
        }
    }

    /// Add a condition-strategy pair
    pub fn when<P, S>(mut self, predicate: P, strategy: S) -> Self
    where
        P: Fn(&I) -> bool + Send + Sync + 'static,
        S: TransformStrategy<I, O> + 'static,
    {
        self.conditions.push((Box::new(predicate), Box::new(strategy)));
        self
    }

    /// Set the default strategy when no conditions match
    pub fn otherwise<S>(mut self, strategy: S) -> Self
    where
        S: TransformStrategy<I, O> + 'static,
    {
        self.default = Some(Box::new(strategy));
        self
    }

    /// Execute the conditional transformation
    pub fn execute(&self, input: I) -> TransformResult<O> {
        for (predicate, strategy) in &self.conditions {
            if predicate(&input) {
                return strategy.transform(input);
            }
        }

        if let Some(ref default) = self.default {
            return default.transform(input);
        }

        Err(MapperError::TransformationFailed(
            "No matching condition found".to_string(),
        ))
    }
}

impl<I, O> Default for ConditionalTransformer<I, O>
where
    I: Clone + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics collector for transformation statistics
#[derive(Debug, Clone, Default)]
pub struct TransformMetrics {
    pub total_transforms: u64,
    pub successful_transforms: u64,
    pub failed_transforms: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl TransformMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful transformation
    pub fn record_success(&mut self) {
        self.total_transforms += 1;
        self.successful_transforms += 1;
    }

    /// Record a failed transformation
    pub fn record_failure(&mut self) {
        self.total_transforms += 1;
        self.failed_transforms += 1;
    }

    /// Record a cache hit
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    /// Record a cache miss
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_transforms == 0 {
            0.0
        } else {
            (self.successful_transforms as f64 / self.total_transforms as f64) * 100.0
        }
    }

    /// Get cache hit rate as percentage
    pub fn cache_hit_rate(&self) -> f64 {
        let total_cache_ops = self.cache_hits + self.cache_misses;
        if total_cache_ops == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total_cache_ops as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_transform() {
        let transform = IdentityTransform::<i32>::new();
        assert_eq!(transform.transform(42).unwrap(), 42);
        assert!(transform.can_transform(&42));
    }

    #[test]
    fn test_map_transform() {
        let transform = TransformFactory::map("double", |x: i32| Ok(x * 2));
        assert_eq!(transform.transform(21).unwrap(), 42);
    }

    #[test]
    fn test_filter_transform() {
        let transform = TransformFactory::filter("positive", |x: &i32| *x > 0);
        assert!(transform.transform(42).is_ok());
        assert!(transform.transform(-1).is_err());
    }

    #[test]
    fn test_pipeline() {
        let pipeline = TransformPipeline::<i32, i32>::new()
            .add_stage(TransformFactory::filter("positive", |x: &i32| *x > 0))
            .add_stage(TransformFactory::map("double", |x: i32| Ok(x * 2)));

        assert_eq!(pipeline.execute(21).unwrap(), 42);
    }

    #[test]
    fn test_cached_transform() {
        let inner = TransformFactory::map("expensive", |x: i32| Ok(x * 2));
        let cached = TransformFactory::cached(inner, 10);

        assert_eq!(cached.transform(21).unwrap(), 42);
        assert_eq!(cached.cache_size(), 1);
        assert_eq!(cached.transform(21).unwrap(), 42); // Cache hit
    }

    #[test]
    fn test_conditional_transformer() {
        let transformer = ConditionalTransformer::<i32, String>::new()
            .when(|x| *x > 0, TransformFactory::map("positive", |_| Ok("positive".to_string())))
            .when(|x| *x < 0, TransformFactory::map("negative", |_| Ok("negative".to_string())))
            .otherwise(TransformFactory::map("zero", |_| Ok("zero".to_string())));

        assert_eq!(transformer.execute(1).unwrap(), "positive");
        assert_eq!(transformer.execute(-1).unwrap(), "negative");
        assert_eq!(transformer.execute(0).unwrap(), "zero");
    }

    #[test]
    fn test_metrics() {
        let mut metrics = TransformMetrics::new();
        metrics.record_success();
        metrics.record_success();
        metrics.record_failure();

        assert_eq!(metrics.total_transforms, 3);
        assert!((metrics.success_rate() - 66.666).abs() < 1.0);
    }
}