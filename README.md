# nt_mapper_rust

A robust Rust implementation for Windows NT system utilities and process management. This library provides safe abstractions over low-level Windows NT APIs, enabling efficient process manipulation, memory mapping, and system resource management.

## Features

- **Safe Handle Management**: RAII-based resource management with automatic cleanup
- **NT Status Handling**: Comprehensive error handling with NT status code support
- **Process Management**: Tools for process enumeration, manipulation, and monitoring
- **Memory Mapping**: Safe abstractions for memory-mapped operations
- **Trace Management**: Built-in tracing and diagnostic capabilities

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
nt_mapper_rust = "0.1.0"
```

## Quick Start

```rust
use nt_mapper_rust::{initialize, shutdown, is_initialized};
use nt_mapper_rust::error::{MapperError, NtStatus};

fn main() -> Result<(), MapperError> {
    // Initialize the library
    initialize()?;
    
    // Verify initialization
    assert!(is_initialized());
    
    // Your code here...
    
    // Clean shutdown
    shutdown()?;
    
    Ok(())
}
```

## Core Components

### NtStatus

The `NtStatus` type provides a safe wrapper around Windows NT status codes:

```rust
use nt_mapper_rust::error::NtStatus;

fn check_operation() {
    let status = NtStatus::from_raw(0x00000000); // STATUS_SUCCESS
    
    if status.is_success() {
        println!("Operation completed successfully");
    } else {
        println!("Operation failed with status: 0x{:08X}", status.raw());
    }
}
```

### MapperError

Comprehensive error handling with detailed context:

```rust
use nt_mapper_rust::error::MapperError;

fn perform_mapping() -> Result<(), MapperError> {
    // Operations that may fail will return MapperError
    // with full context about what went wrong
    Ok(())
}
```

### SafeHandle

RAII-based handle management ensuring proper resource cleanup:

```rust
use nt_mapper_rust::TraceManager::SafeHandle;

fn work_with_handle() {
    // SafeHandle automatically closes the handle when dropped
    let handle = SafeHandle::new(raw_handle);
    
    // Use the handle...
    
    // Handle is automatically closed here
}
```

### Process Handle Management

Specialized handle types for process operations:

```rust
use nt_mapper_rust::TraceManager::{ProcessHandleDrop, FileHandleDrop};

fn manage_process_resources() {
    // ProcessHandleDrop ensures process handles are properly closed
    let process_dropper = ProcessHandleDrop::new(process_handle);
    
    // FileHandleDrop handles file-specific cleanup
    let file_dropper = FileHandleDrop::new(file_handle);
    
    // Resources are automatically cleaned up on scope exit
}
```

## Design Patterns

This library employs several design patterns for maintainability and safety:

### RAII (Resource Acquisition Is Initialization)

All system resources are wrapped in types that implement `Drop`, ensuring cleanup even in the presence of panics:

```rust
{
    let handle = SafeHandle::new(acquire_resource()?);
    // Work with handle...
} // Resource automatically released here
```

### Observer Pattern

The TraceManager supports observer-style event notifications:

```rust
use nt_mapper_rust::TraceManager;

// Register callbacks for system events
// Events are dispatched to all registered observers
```

### Strategy Pattern

Configurable behaviors through trait objects:

```rust
// Different strategies can be plugged in for:
// - Handle cleanup (ProcessHandleDrop, FileHandleDrop)
// - Error handling
// - Logging and tracing
```

### Factory Pattern

Resource creation through factory methods:

```rust
let handle = SafeHandle::new(raw_handle);
let status = NtStatus::from_raw(raw_status);
```

## Error Handling

The library uses Rust's `Result` type throughout, with `MapperError` providing detailed error information:

```rust
use nt_mapper_rust::error::MapperError;

fn example() -> Result<(), MapperError> {
    initialize()?;
    
    // Chain operations with ?
    let result = perform_operation()?;
    
    shutdown()?;
    Ok(())
}
```

## Thread Safety

All public types are designed with thread safety in mind:

- `NtStatus` is `Copy` and safe to share across threads
- `SafeHandle` uses interior mutability where needed
- Global state is protected by appropriate synchronization primitives

## Platform Support

This library targets Windows platforms and requires:

- Windows 10 or later (recommended)
- Windows Server 2016 or later
- Rust 1.70.0 or later

## Building

```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

## Examples

### Basic Initialization

```rust
use nt_mapper_rust::{initialize, shutdown, is_initialized};

fn main() {
    if let Err(e) = initialize() {
        eprintln!("Failed to initialize: {:?}", e);
        return;
    }
    
    println!("Library initialized: {}", is_initialized());
    
    // Perform operations...
    
    if let Err(e) = shutdown() {
        eprintln!("Shutdown error: {:?}", e);
    }
}
```

### Working with NT Status Codes

```rust
use nt_mapper_rust::error::NtStatus;

const STATUS_SUCCESS: u32 = 0x00000000;
const STATUS_ACCESS_DENIED: u32 = 0xC0000022;
const STATUS_INVALID_HANDLE: u32 = 0xC0000008;

fn interpret_status(raw: u32) {
    let status = NtStatus::from_raw(raw);
    
    match status.raw() {
        STATUS_SUCCESS => println!("Success"),
        STATUS_ACCESS_DENIED => println!("Access denied"),
        STATUS_INVALID_HANDLE => println!("Invalid handle"),
        _ => println!("Unknown status: 0x{:08X}", status.raw()),
    }
}
```

### Safe Resource Management

```rust
use nt_mapper_rust::TraceManager::SafeHandle;

fn process_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Acquire handle (pseudo-code)
    let raw_handle = open_file(path)?;
    
    // Wrap in SafeHandle for automatic cleanup
    let handle = SafeHandle::new(raw_handle);
    
    // Even if this panics, the handle will be closed
    process_data(&handle)?;
    
    Ok(())
    // handle dropped here, resource released
}
```

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Rust idioms and best practices
2. All public APIs are documented
3. Tests are included for new functionality
4. `cargo clippy` passes without warnings
5. `cargo fmt` has been run

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Built with Rust's powerful type system and ownership model to provide memory-safe system programming abstractions.