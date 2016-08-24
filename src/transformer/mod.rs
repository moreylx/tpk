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
    pub fn check(&self, value: &T) -> BoundaryCheckResult {
        // Check minimum boundary
        if let Some(ref min) = self.min {
            if value < min {
                return BoundaryCheckResult::BelowMinimum;
            }
        }

        // Check maximum boundary
        if let Some(ref max) = self.max {
            if value > max {
                return BoundaryCheckResult::AboveMaximum;
            }
        }

        // Check custom validator
        if let Some(ref validator) = self.validator {
            if !validator(value) {
                return BoundaryCheckResult::ValidationFailed;
            }
        }

        BoundaryCheckResult::Valid
    }

    /// Returns true if the value is within bounds
    pub fn is_valid(&self, value: &T) -> bool {
        matches!(self.check(value), BoundaryCheckResult::Valid)
    }
}

/// Result of a boundary condition check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryCheckResult {
    /// Value is within all boundaries
    Valid,
    /// Value is below the minimum boundary
    BelowMinimum,
    /// Value is above the maximum boundary
    AboveMaximum,
    /// Value failed custom validation
    ValidationFailed,
}

impl BoundaryCheckResult {
    /// Returns true if the check passed
    pub fn is_valid(&self) -> bool {
        matches!(self, BoundaryCheckResult::Valid)
    }

    /// Convert to a MapperError if invalid
    pub fn to_error(&self, context: &str) -> Option<MapperError> {
        match self {
            BoundaryCheckResult::Valid => None,
            BoundaryCheckResult::BelowMinimum => {
                Some(MapperError::ValidationError(format!(
                    "{}: value below minimum boundary",
                    context
                )))
            }
            BoundaryCheckResult::AboveMaximum => {
                Some(MapperError::ValidationError(format!(
                    "{}: value above maximum boundary",
                    context
                )))
            }
            BoundaryCheckResult::ValidationFailed => {
                Some(MapperError::ValidationError(format!(
                    "{}: custom validation failed",
                    context
                )))
            }
        }
    }
}

/// Trait defining a transformation strategy
pub trait TransformStrategy<I, O>: Send + Sync {
    /// Transform input to output
    fn transform(&self, input: I) -> TransformResult<O>;
    
    /// Get the name of this transformation strategy
    fn name(&self) -> &str;
    
    /// Check if this strategy can handle the given input
    fn can_transform(&self, input: &I) -> bool;
}

/// A bounded transformation strategy that validates input before transformation
pub struct BoundedStrategy<I, O, S>
where
    S: TransformStrategy<I, O>,
{
    inner: S,
    input_bounds: BoundaryCondition<I>,
    output_bounds: Option<BoundaryCondition<O>>,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O, S> BoundedStrategy<I, O, S>
where
    I: PartialOrd + Clone,
    O: PartialOrd + Clone,
    S: TransformStrategy<I, O>,
{
    /// Create a new bounded strategy wrapping an existing strategy
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            input_bounds: BoundaryCondition::default(),
            output_bounds: None,
            _phantom: PhantomData,
        }
    }

    /// Set input boundary conditions
    pub fn with_input_bounds(mut self, bounds: BoundaryCondition<I>) -> Self {
        self.input_bounds = bounds;
        self
    }

    /// Set output boundary conditions
    pub fn with_output_bounds(mut self, bounds: BoundaryCondition<O>) -> Self {
        self.output_bounds = Some(bounds);
        self
    }
}

impl<I, O, S> TransformStrategy<I, O> for BoundedStrategy<I, O, S>
where
    I: PartialOrd + Clone + Send + Sync,
    O: PartialOrd + Clone + Send + Sync,
    S: TransformStrategy<I, O>,
{
    fn transform(&self, input: I) -> TransformResult<O> {
        // Check input boundaries
        let input_check = self.input_bounds.check(&input);
        if let Some(err) = input_check.to_error(&format!("{}::input", self.name())) {
            return Err(err);
        }

        // Perform the transformation
        let output = self.inner.transform(input)?;

        // Check output boundaries if configured
        if let Some(ref output_bounds) = self.output_bounds {
            let output_check = output_bounds.check(&output);
            if let Some(err) = output_check.to_error(&format!("{}::output", self.name())) {
                return Err(err);
            }
        }

        Ok(output)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn can_transform(&self, input: &I) -> bool {
        self.input_bounds.is_valid(input) && self.inner.can_transform(input)
    }
}

/// A composable transformer that chains multiple transformations
pub struct TransformPipeline<I, O> {
    stages: Vec<Box<dyn TransformStrategy<I, O>>>,
    fallback: Option<Box<dyn TransformStrategy<I, O>>>,
    global_input_bounds: Option<BoundaryCondition<I>>,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O> TransformPipeline<I, O>
where
    I: Clone + PartialOrd + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    /// Create a new empty pipeline
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            fallback: None,
            global_input_bounds: None,
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

    /// Set global input boundary conditions that apply before any stage
    pub fn with_global_input_bounds(mut self, bounds: BoundaryCondition<I>) -> Self {
        self.global_input_bounds = Some(bounds);
        self
    }

    /// Execute the pipeline, trying each stage until one succeeds
    pub fn execute(&self, input: I) -> TransformResult<O> {
        // Check global input boundaries first
        if let Some(ref bounds) = self.global_input_bounds {
            let check = bounds.check(&input);
            if let Some(err) = check.to_error("pipeline::global_input") {
                return Err(err);
            }
        }

        // Try each stage in order
        for stage in &self.stages {
            if stage.can_transform(&input) {
                match stage.transform(input.clone()) {
                    Ok(output) => return Ok(output),
                    Err(e) => {
                        // Log error and continue to next stage
                        log::debug!(
                            "Stage '{}' failed with error: {:?}, trying next stage",
                            stage.name(),
                            e
                        );
                    }
                }
            }
        }

        // Try fallback if available
        if let Some(ref fallback) = self.fallback {
            return fallback.transform(input);
        }

        Err(MapperError::TransformError(
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

    /// Validate input against global bounds without executing transformation
    pub fn validate_input(&self, input: &I) -> BoundaryCheckResult {
        match &self.global_input_bounds {
            Some(bounds) => bounds.check(input),
            None => BoundaryCheckResult::Valid,
        }
    }
}

impl<I, O> Default for TransformPipeline<I, O>
where
    I: Clone + PartialOrd + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// A registry for managing multiple transformation pipelines
pub struct TransformRegistry<I, O> {
    pipelines: RwLock<HashMap<String, Arc<TransformPipeline<I, O>>>>,
    default_pipeline: RwLock<Option<String>>,
}

impl<I, O> TransformRegistry<I, O>
where
    I: Clone + PartialOrd + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            pipelines: RwLock::new(HashMap::new()),
            default_pipeline: RwLock::new(None),
        }
    }

    /// Register a pipeline with a given name
    pub fn register(&self, name: impl Into<String>, pipeline: TransformPipeline<I, O>) -> TransformResult<()> {
        let name = name.into();
        let mut pipelines = self.pipelines.write().map_err(|_| {
            MapperError::LockError("Failed to acquire write lock on pipelines".to_string())
        })?;
        pipelines.insert(name, Arc::new(pipeline));
        Ok(())
    }

    /// Set the default pipeline by name
    pub fn set_default(&self, name: impl Into<String>) -> TransformResult<()> {
        let name = name.into();
        
        // Verify pipeline exists
        let pipelines = self.pipelines.read().map_err(|_| {
            MapperError::LockError("Failed to acquire read lock on pipelines".to_string())
        })?;
        
        if !pipelines.contains_key(&name) {
            return Err(MapperError::NotFound(format!(
                "Pipeline '{}' not found in registry",
                name
            )));
        }
        drop(pipelines);

        let mut default = self.default_pipeline.write().map_err(|_| {
            MapperError::LockError("Failed to acquire write lock on default pipeline".to_string())
        })?;
        *default = Some(name);
        Ok(())
    }

    /// Get a pipeline by name
    pub fn get(&self, name: &str) -> TransformResult<Arc<TransformPipeline<I, O>>> {
        let pipelines = self.pipelines.read().map_err(|_| {
            MapperError::LockError("Failed to acquire read lock on pipelines".to_string())
        })?;
        
        pipelines.get(name).cloned().ok_or_else(|| {
            MapperError::NotFound(format!("Pipeline '{}' not found", name))
        })
    }

    /// Get the default pipeline
    pub fn get_default(&self) -> TransformResult<Arc<TransformPipeline<I, O>>> {
        let default = self.default_pipeline.read().map_err(|_| {
            MapperError::LockError("Failed to acquire read lock on default pipeline".to_string())
        })?;
        
        match default.as_ref() {
            Some(name) => self.get(name),
            None => Err(MapperError::NotFound("No default pipeline configured".to_string())),
        }
    }

    /// Execute transformation using the default pipeline
    pub fn transform(&self, input: I) -> TransformResult<O> {
        let pipeline = self.get_default()?;
        pipeline.execute(input)
    }

    /// Execute transformation using a named pipeline
    pub fn transform_with(&self, name: &str, input: I) -> TransformResult<O> {
        let pipeline = self.get(name)?;
        pipeline.execute(input)
    }

    /// List all registered pipeline names
    pub fn list_pipelines(&self) -> TransformResult<Vec<String>> {
        let pipelines = self.pipelines.read().map_err(|_| {
            MapperError::LockError("Failed to acquire read lock on pipelines".to_string())
        })?;
        Ok(pipelines.keys().cloned().collect())
    }
}

impl<I, O> Default for TransformRegistry<I, O>
where
    I: Clone + PartialOrd + Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Identity transformation that returns input unchanged
pub struct IdentityTransform<T> {
    name: String,
    _phantom: PhantomData<T>,
}

impl<T> IdentityTransform<T> {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            _phantom: PhantomData,
        }
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
        &self.name
    }

    fn can_transform(&self, _input: &T) -> bool {
        true
    }
}

/// Mapping transformation using a closure
pub struct MapTransform<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    name: String,
    mapper: F,
    _phantom: PhantomData<(I, O)>,
}

impl<I, O, F> MapTransform<I, O, F>
where
    F: Fn(I) -> TransformResult<O> + Send + Sync,
{
    pub fn new(name: impl Into<String>, mapper: F) -> Self {
        Self {
            name: name.into(),
            mapper,
            _phantom: PhantomData,
        }
    }
}

impl<I, O, F> TransformStrategy<I, O> for MapTransform<I, O, F>
where
    I: Send + Sync,
    O: Send + Sync,
    F: Fn(I) -> TransformResult<O> + Send + Sync,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_condition_range() {
        let bounds = BoundaryCondition::new()
            .with_min(0i32)
            .with_max(100i32);

        assert!(bounds.is_valid(&50));
        assert!(bounds.is_valid(&0));
        assert!(bounds.is_valid(&100));
        assert!(!bounds.is_valid(&-1));
        assert!(!bounds.is_valid(&101));
    }

    #[test]
    fn test_boundary_condition_custom_validator() {
        let bounds = BoundaryCondition::<i32>::new()
            .with_validator(|v| v % 2 == 0);

        assert!(bounds.is_valid(&2));
        assert!(bounds.is_valid(&0));
        assert!(!bounds.is_valid(&1));
        assert!(!bounds.is_valid(&3));
    }

    #[test]
    fn test_boundary_check_result() {
        assert!(BoundaryCheckResult::Valid.is_valid());
        assert!(!BoundaryCheckResult::BelowMinimum.is_valid());
        assert!(!BoundaryCheckResult::AboveMaximum.is_valid());
        assert!(!BoundaryCheckResult::ValidationFailed.is_valid());
    }

    #[test]
    fn test_identity_transform() {
        let transform = IdentityTransform::<i32>::new("identity");
        assert_eq!(transform.transform(42).unwrap(), 42);
        assert_eq!(transform.name(), "identity");
    }

    #[test]
    fn test_map_transform() {
        let transform = MapTransform::new("double", |x: i32| Ok(x * 2));
        assert_eq!(transform.transform(21).unwrap(), 42);
    }

    #[test]
    fn test_bounded_strategy() {
        let inner = MapTransform::new("double", |x: i32| Ok(x * 2));
        let bounded = BoundedStrategy::new(inner)
            .with_input_bounds(BoundaryCondition::new().with_range(0, 50))
            .with_output_bounds(BoundaryCondition::new().with_max(100));

        assert_eq!(bounded.transform(25).unwrap(), 50);
        assert!(bounded.transform(51).is_err()); // Input out of bounds
    }

    #[test]
    fn test_pipeline_with_global_bounds() {
        let pipeline = TransformPipeline::<i32, i32>::new()
            .with_global_input_bounds(BoundaryCondition::new().with_range(0, 100))
            .add_stage(IdentityTransform::new("identity"));

        assert_eq!(pipeline.execute(50).unwrap(), 50);
        assert!(pipeline.execute(-1).is_err());
        assert!(pipeline.execute(101).is_err());
    }
}