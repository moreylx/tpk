# nt_wrapper

A Rust wrapper library around native Windows system APIs.

## Features

- **Process manipulation** - Open, read/write memory, suspend/resume, terminate
- **Thread management** - Create, suspend/resume, context manipulation, APC queuing
- **Memory operations** - Virtual allocation, protection changes, memory queries
- **RAII handles** - Automatic cleanup with proper ownership semantics
- **Error handling** - Native NTSTATUS codes with Result types

## Installation

```toml
[dependencies]
nt_wrapper = { git = "https://github.com/moreylx/nt-wrapper-rs" }
```

## Usage

### Process Operations

```rust
use nt_wrapper::{Process, ProcessAccess};

fn main() -> nt_wrapper::Result<()> {
    let proc = Process::open(1234, ProcessAccess::vm_read().with(ProcessAccess::vm_write()))?;
    
    let value: u32 = proc.read_memory(0x7FF00000)?;
    println!("Read: {}", value);
    
    proc.write_memory(0x7FF00000, &42u32)?;
    Ok(())
}
```

### Thread Operations

```rust
use nt_wrapper::thread::{Thread, ThreadBuilder};

fn main() -> nt_wrapper::Result<()> {
    let thread = ThreadBuilder::new()
        .suspended()
        .spawn(|| {
            println!("Hello from thread!");
        })?;
    
    thread.resume()?;
    Ok(())
}
```

### Memory Allocation

```rust
use nt_wrapper::memory::{VirtualAlloc, Protection};

fn main() -> nt_wrapper::Result<()> {
    let mem = VirtualAlloc::allocate(4096, Protection::readwrite())?;
    
    unsafe {
        let ptr = mem.base() as *mut u8;
        *ptr = 0x90;
    }
    
    mem.protect(Protection::execute_read())?;
    Ok(())
}
```

## Building

```bash
cargo build --release
```

## License

Apache-2.0

