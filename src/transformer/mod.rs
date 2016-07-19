//! Transformer module for data transformation and mapping operations.
//! 
//! This module provides a flexible transformation pipeline using the Strategy pattern,
//! allowing for composable data transformations with proper error handling.

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

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

        Err(MapperError::from_raw(0xC0000001)) // STATUS_UNSUCCESSFUL
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

/// Observer trait for transformation events
pub trait TransformObserver<I, O>: Send + Sync {
    /// Called before a transformation begins
    fn on_transform_start(&self, input: &I);
    
    /// Called after a successful transformation
    fn on_transform_complete(&self, input: &I, output: &O);
    
    /// Called when a transformation fails
    fn on_transform_error(&self, input: &I, error: &MapperError);
}

/// Observable transformer that notifies observers of transformation events
pub struct ObservableTransformer<I, O> {
    inner: Box<dyn TransformStrategy<I, O>>,
    observers: Arc<RwLock<Vec<Arc<dyn TransformObserver<I, O>>>>>,
}

impl<I, O> ObservableTransformer<I, O>
where
    I: Clone + Send + Sync + 'static,
    O: Clone + Send + Sync + 'static,
{
    /// Create a new observable transformer wrapping an existing strategy
    pub fn new<S>(strategy: S) -> Self
    where
        S: TransformStrategy<I, O> + 'static,
    {
        Self {
            inner: Box::new(strategy),
            observers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register an observer
    pub fn register_observer(&self, observer: Arc<dyn TransformObserver<I, O>>) {
        if let Ok(mut observers) = self.observers.write() {
            observers.push(observer);
        }
    }

    /// Execute transformation with observer notifications
    pub fn transform(&self, input: I) -> TransformResult<O> {
        self.notify_start(&input);

        match self.inner.transform(input.clone()) {
            Ok(output) => {
                self.notify_complete(&input, &output);
                Ok(output)
            }
            Err(e) => {
                self.notify_error(&input, &e);
                Err(e)
            }
        }
    }

    fn notify_start(&self, input: &I) {
        if let Ok(observers) = self.observers.read() {
            for observer in observers.iter() {
                observer.on_transform_start(input);
            }
        }
    }

    fn notify_complete(&self, input: &I, output: &O) {
        if let Ok(observers) = self.observers.read() {
            for observer in observers.iter() {
                observer.on_transform_complete(input, output);
            }
        }
    }

    fn notify_error(&self, input: &I, error: &MapperError) {
        if let Ok(observers) = self.observers.read() {
            for observer in observers.iter() {
                observer.on_transform_error(input, error);
            }
        }
    }
}

/// Factory for creating common transformation strategies
pub struct TransformFactory;

impl TransformFactory {
    /// Create an identity transformation
    pub fn identity<T>() -> IdentityTransform<T>
    where
        T: Clone + Send + Sync,
    {
        IdentityTransform::new()
    }

    /// Create a mapping transformation from a closure
    pub fn map<I, O, F>(name: &str, f: F) -> ClosureTransform<I, O, F>
    where
        F: Fn(I) -> TransformResult<O> + Send + Sync,
    {
        ClosureTransform::new(name.to_string(), f)
    }

    /// Create a conditional transformation
    pub fn conditional<I, O, P, S>(predicate: P, strategy: S) -> ConditionalTransform<I, O, P, S>
    where
        P: Fn(&I) -> bool + Send + Sync,
        S: TransformStrategy<I, O>,
    {
        ConditionalTransform::new(predicate, strategy)
    }
}

/// Identity transformation that returns the input unchanged
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
    T: Clone + Send + Sync,
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

/// Transformation using a closure
pub struct ClosureTransform<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    name: String,
    transform_fn: F,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O, F> ClosureTransform<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    pub fn new(name: String, transform_fn: F) -> Self {
        Self {
            name,
            transform_fn,
            _phantom: PhantomData,
        }
    }
}

impl<I, O, F> TransformStrategy<I, O> for ClosureTransform<I, O, F>
where
    I: Send + Sync,
    O: Send + Sync,
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    fn transform(&self, input: I) -> TransformResult<O> {
        (self.transform_fn)(input)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn can_transform(&self, _input: &I) -> bool {
        true
    }
}

/// Conditional transformation that only applies when predicate is true
pub struct ConditionalTransform<I, O, P, S>
where
    P: Fn(&I) -> bool + Send + Sync,
    S: TransformStrategy<I, O>,
{
    predicate: P,
    strategy: S,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O, P, S> ConditionalTransform<I, O, P, S>
where
    P: Fn(&I) -> bool + Send + Sync,
    S: TransformStrategy<I, O>,
{
    pub fn new(predicate: P, strategy: S) -> Self {
        Self {
            predicate,
            strategy,
            _phantom: PhantomData,
        }
    }
}

impl<I, O, P, S> TransformStrategy<I, O> for ConditionalTransform<I, O, P, S>
where
    I: Send + Sync,
    O: Send + Sync,
    P: Fn(&I) -> bool + Send + Sync,
    S: TransformStrategy<I, O>,
{
    fn transform(&self, input: I) -> TransformResult<O> {
        self.strategy.transform(input)
    }

    fn name(&self) -> &str {
        self.strategy.name()
    }

    fn can_transform(&self, input: &I) -> bool {
        (self.predicate)(input) && self.strategy.can_transform(input)
    }
}

/// Registry for named transformation strategies
pub struct TransformRegistry<I, O> {
    strategies: HashMap<String, Arc<dyn TransformStrategy<I, O>>>,
}

impl<I, O> TransformRegistry<I, O>
where
    I: Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            strategies: HashMap::new(),
        }
    }

    /// Register a strategy with a given name
    pub fn register<S>(&mut self, name: &str, strategy: S)
    where
        S: TransformStrategy<I, O> + 'static,
    {
        self.strategies.insert(name.to_string(), Arc::new(strategy));
    }

    /// Get a strategy by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn TransformStrategy<I, O>>> {
        self.strategies.get(name).cloned()
    }

    /// Remove a strategy by name
    pub fn unregister(&mut self, name: &str) -> Option<Arc<dyn TransformStrategy<I, O>>> {
        self.strategies.remove(name)
    }

    /// List all registered strategy names
    pub fn list_strategies(&self) -> Vec<&str> {
        self.strategies.keys().map(|s| s.as_str()).collect()
    }
}

impl<I, O> Default for TransformRegistry<I, O>
where
    I: Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Byte buffer transformation utilities
pub mod bytes {
    use super::*;

    /// Transform bytes to hexadecimal string
    pub struct BytesToHex;

    impl TransformStrategy<Vec<u8>, String> for BytesToHex {
        fn transform(&self, input: Vec<u8>) -> TransformResult<String> {
            Ok(input.iter().map(|b| format!("{:02x}", b)).collect())
        }

        fn name(&self) -> &str {
            "bytes_to_hex"
        }

        fn can_transform(&self, _input: &Vec<u8>) -> bool {
            true
        }
    }

    /// Transform hexadecimal string to bytes
    pub struct HexToBytes;

    impl TransformStrategy<String, Vec<u8>> for HexToBytes {
        fn transform(&self, input: String) -> TransformResult<Vec<u8>> {
            let input = input.trim();
            if input.len() % 2 != 0 {
                return Err(MapperError::from_raw(0xC000000D)); // STATUS_INVALID_PARAMETER
            }

            (0..input.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&input[i..i + 2], 16)
                        .map_err(|_| MapperError::from_raw(0xC000000D))
                })
                .collect()
        }

        fn name(&self) -> &str {
            "hex_to_bytes"
        }

        fn can_transform(&self, input: &String) -> bool {
            input.chars().all(|c| c.is_ascii_hexdigit())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_transform() {
        let transform = TransformFactory::identity::<i32>();
        assert_eq!(transform.transform(42).unwrap(), 42);
    }

    #[test]
    fn test_closure_transform() {
        let transform = TransformFactory::map("double", |x: i32| Ok(x * 2));
        assert_eq!(transform.transform(21).unwrap(), 42);
    }

    #[test]
    fn test_bytes_to_hex() {
        let transform = bytes::BytesToHex;
        let result = transform.transform(vec![0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(result, "deadbeef");
    }

    #[test]
    fn test_hex_to_bytes() {
        let transform = bytes::HexToBytes;
        let result = transform.transform("deadbeef".to_string()).unwrap();
        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}