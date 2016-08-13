//! NTDLL Native API bindings and utilities for process manipulation
//! 
//! This module provides safe Rust abstractions over Windows NT native APIs
//! for process memory operations, thread management, and code injection.

use std::ffi::c_void;
use std::mem::{self, MaybeUninit};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{MapperError, NtStatus};

mod syscall;
mod memory;
mod thread;
mod injection;

pub use memory::*;
pub use thread::*;
pub use injection::*;

/// Module initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Windows type definitions
pub type Handle = *mut c_void;
pub type ProcessId = u32;
pub type ThreadId = u32;

pub const INVALID_HANDLE: Handle = -1isize as Handle;
pub const NULL_HANDLE: Handle = ptr::null_mut();

/// Process access rights
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAccess {
    Terminate = 0x0001,
    CreateThread = 0x0002,
    VmOperation = 0x0008,
    VmRead = 0x0010,
    VmWrite = 0x0020,
    DupHandle = 0x0040,
    QueryInformation = 0x0400,
    QueryLimitedInformation = 0x1000,
    AllAccess = 0x001FFFFF,
}

impl ProcessAccess {
    /// Combine multiple access rights
    pub fn combine(rights: &[ProcessAccess]) -> u32 {
        rights.iter().fold(0u32, |acc, r| acc | (*r as u32))
    }
}

/// Memory protection constants
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Memory allocation type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationType {
    Commit = 0x1000,
    Reserve = 0x2000,
    Reset = 0x80000,
    TopDown = 0x100000,
    Physical = 0x400000,
    LargePages = 0x20000000,
}

impl AllocationType {
    pub fn combine(types: &[AllocationType]) -> u32 {
        types.iter().fold(0u32, |acc, t| acc | (*t as u32))
    }
}

/// Memory free type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeType {
    Decommit = 0x4000,
    Release = 0x8000,
}

/// Object attributes for NT API calls
#[repr(C)]
#[derive(Debug)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: Handle,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

impl Default for ObjectAttributes {
    fn default() -> Self {
        Self {
            length: mem::size_of::<ObjectAttributes>() as u32,
            root_directory: NULL_HANDLE,
            object_name: ptr::null_mut(),
            attributes: 0,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        }
    }
}

/// Unicode string structure for NT APIs
#[repr(C)]
#[derive(Debug)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl Default for UnicodeString {
    fn default() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        }
    }
}

/// Client ID structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientId {
    pub unique_process: Handle,
    pub unique_thread: Handle,
}

impl ClientId {
    pub fn from_process_id(pid: ProcessId) -> Self {
        Self {
            unique_process: pid as Handle,
            unique_thread: NULL_HANDLE,
        }
    }

    pub fn from_thread_id(tid: ThreadId) -> Self {
        Self {
            unique_process: NULL_HANDLE,
            unique_thread: tid as Handle,
        }
    }
}

/// Process basic information
#[repr(C)]
#[derive(Debug)]
pub struct ProcessBasicInformation {
    pub exit_status: i32,
    pub peb_base_address: *mut c_void,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}

/// Safe wrapper around a process handle
#[derive(Debug)]
pub struct ProcessHandle {
    handle: Handle,
    owns_handle: bool,
}

impl ProcessHandle {
    /// Open a process by ID with specified access rights
    pub fn open(pid: ProcessId, access: u32) -> Result<Self, MapperError> {
        ensure_initialized()?;
        
        let mut handle: Handle = NULL_HANDLE;
        let mut object_attrs = ObjectAttributes::default();
        let client_id = ClientId::from_process_id(pid);

        let status = unsafe {
            syscall::nt_open_process(
                &mut handle,
                access,
                &mut object_attrs,
                &client_id,
            )
        };

        let nt_status = NtStatus::from_raw(status);
        if nt_status.is_success() {
            Ok(Self {
                handle,
                owns_handle: true,
            })
        } else {
            Err(MapperError::NtStatusError(nt_status))
        }
    }

    /// Get the raw handle value
    pub fn as_raw(&self) -> Handle {
        self.handle
    }

    /// Create from an existing handle (takes ownership)
    pub unsafe fn from_raw_owned(handle: Handle) -> Self {
        Self {
            handle,
            owns_handle: true,
        }
    }

    /// Create from an existing handle (does not take ownership)
    pub unsafe fn from_raw_borrowed(handle: Handle) -> Self {
        Self {
            handle,
            owns_handle: false,
        }
    }

    /// Query basic process information
    pub fn query_basic_info(&self) -> Result<ProcessBasicInformation, MapperError> {
        let mut info = MaybeUninit::<ProcessBasicInformation>::uninit();
        let mut return_length: u32 = 0;

        let status = unsafe {
            syscall::nt_query_information_process(
                self.handle,
                0, // ProcessBasicInformation
                info.as_mut_ptr() as *mut c_void,
                mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            )
        };

        let nt_status = NtStatus::from_raw(status);
        if nt_status.is_success() {
            Ok(unsafe { info.assume_init() })
        } else {
            Err(MapperError::NtStatusError(nt_status))
        }
    }

    /// Check if the process is still running
    pub fn is_alive(&self) -> bool {
        self.query_basic_info()
            .map(|info| info.exit_status == 259) // STILL_ACTIVE
            .unwrap_or(false)
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.owns_handle && self.handle != NULL_HANDLE && self.handle != INVALID_HANDLE {
            unsafe {
                syscall::nt_close(self.handle);
            }
        }
    }
}

unsafe impl Send for ProcessHandle {}
unsafe impl Sync for ProcessHandle {}

/// Safe wrapper around a thread handle
#[derive(Debug)]
pub struct ThreadHandle {
    handle: Handle,
    owns_handle: bool,
}

impl ThreadHandle {
    /// Get the raw handle value
    pub fn as_raw(&self) -> Handle {
        self.handle
    }

    /// Create from an existing handle (takes ownership)
    pub unsafe fn from_raw_owned(handle: Handle) -> Self {
        Self {
            handle,
            owns_handle: true,
        }
    }

    /// Resume the thread
    pub fn resume(&self) -> Result<u32, MapperError> {
        let mut suspend_count: u32 = 0;
        
        let status = unsafe {
            syscall::nt_resume_thread(self.handle, &mut suspend_count)
        };

        let nt_status = NtStatus::from_raw(status);
        if nt_status.is_success() {
            Ok(suspend_count)
        } else {
            Err(MapperError::NtStatusError(nt_status))
        }
    }

    /// Suspend the thread
    pub fn suspend(&self) -> Result<u32, MapperError> {
        let mut suspend_count: u32 = 0;
        
        let status = unsafe {
            syscall::nt_suspend_thread(self.handle, &mut suspend_count)
        };

        let nt_status = NtStatus::from_raw(status);
        if nt_status.is_success() {
            Ok(suspend_count)
        } else {
            Err(MapperError::NtStatusError(nt_status))
        }
    }

    /// Wait for the thread to complete
    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<(), MapperError> {
        let timeout = timeout_ms.map(|ms| -(ms as i64 * 10000));
        
        let status = unsafe {
            syscall::nt_wait_for_single_object(
                self.handle,
                false,
                timeout.as_ref().map(|t| t as *const i64).unwrap_or(ptr::null()),
            )
        };

        let nt_status = NtStatus::from_raw(status);
        if nt_status.is_success() || status == 0 {
            Ok(())
        } else {
            Err(MapperError::NtStatusError(nt_status))
        }
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        if self.owns_handle && self.handle != NULL_HANDLE && self.handle != INVALID_HANDLE {
            unsafe {
                syscall::nt_close(self.handle);
            }
        }
    }
}

unsafe impl Send for ThreadHandle {}
unsafe impl Sync for ThreadHandle {}

/// Initialize the NTDLL module
pub fn initialize() -> Result<(), MapperError> {
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    // Resolve syscall numbers dynamically
    syscall::initialize()?;

    INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Check if the module is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Shutdown the NTDLL module
pub fn shutdown() {
    INITIALIZED.store(false, Ordering::SeqCst);
}

/// Ensure the module is initialized before use
fn ensure_initialized() -> Result<(), MapperError> {
    if !is_initialized() {
        return Err(MapperError::NotInitialized);
    }
    Ok(())
}

/// Syscall implementations
mod syscall {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut SYSCALL_TABLE: Option<SyscallTable> = None;

    #[derive(Debug)]
    struct SyscallTable {
        nt_open_process: u32,
        nt_close: u32,
        nt_allocate_virtual_memory: u32,
        nt_free_virtual_memory: u32,
        nt_write_virtual_memory: u32,
        nt_read_virtual_memory: u32,
        nt_protect_virtual_memory: u32,
        nt_create_thread_ex: u32,
        nt_resume_thread: u32,
        nt_suspend_thread: u32,
        nt_wait_for_single_object: u32,
        nt_query_information_process: u32,
    }

    pub fn initialize() -> Result<(), MapperError> {
        let mut result = Ok(());
        
        INIT.call_once(|| {
            match resolve_syscalls() {
                Ok(table) => {
                    unsafe { SYSCALL_TABLE = Some(table); }
                }
                Err(e) => {
                    result = Err(e);
                }
            }
        });

        result
    }

    fn resolve_syscalls() -> Result<SyscallTable, MapperError> {
        // In a real implementation, this would parse ntdll.dll exports
        // and extract syscall numbers from the stubs
        Ok(SyscallTable {
            nt_open_process: 0x26,
            nt_close: 0x0F,
            nt_allocate_virtual_memory: 0x18,
            nt_free_virtual_memory: 0x1E,
            nt_write_virtual_memory: 0x3A,
            nt_read_virtual_memory: 0x3F,
            nt_protect_virtual_memory: 0x50,
            nt_create_thread_ex: 0xC1,
            nt_resume_thread: 0x52,
            nt_suspend_thread: 0x1BC,
            nt_wait_for_single_object: 0x04,
            nt_query_information_process: 0x19,
        })
    }

    fn get_table() -> &'static SyscallTable {
        unsafe { SYSCALL_TABLE.as_ref().expect("Syscall table not initialized") }
    }

    #[cfg(target_arch = "x86_64")]
    macro_rules! syscall {
        ($num:expr) => {{
            let result: i32;
            std::arch::asm!(
                "syscall",
                inout("rax") $num => result,
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
            result
        }};
        ($num:expr, $a1:expr) => {{
            let result: i32;
            std::arch::asm!(
                "syscall",
                inout("rax") $num => result,
                in("r10") $a1,
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
            result
        }};
        ($num:expr, $a1:expr, $a2:expr) => {{
            let result: i32;
            std::arch::asm!(
                "syscall",
                inout("rax") $num => result,
                in("r10") $a1,
                in("rdx") $a2,
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
            result
        }};
        ($num:expr, $a1:expr, $a2:expr, $a3:expr) => {{
            let result: i32;
            std::arch::asm!(
                "syscall",
                inout("rax") $num => result,
                in("r10") $a1,
                in("rdx") $a2,
                in("r8") $a3,
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
            result
        }};
        ($num:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
            let result: i32;
            std::arch::asm!(
                "syscall",
                inout("rax") $num => result,
                in("r10") $a1,
                in("rdx") $a2,
                in("r8") $a3,
                in("r9") $a4,
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
            result
        }};
    }

    #[cfg(not(target_arch = "x86_64"))]
    macro_rules! syscall {
        ($($args:tt)*) => {
            compile_error!("Syscalls only supported on x86_64")
        };
    }

    pub unsafe fn nt_open_process(
        handle: *mut Handle,
        access: u32,
        object_attrs: *mut ObjectAttributes,
        client_id: *const ClientId,
    ) -> i32 {
        let table = get_table();
        syscall!(
            table.nt_open_process as usize,
            handle as usize,
            access as usize,
            object_attrs as usize,
            client_id as usize
        )
    }

    pub unsafe fn nt_close(handle: Handle) -> i32 {
        let table = get_table();
        syscall!(table.nt_close as usize, handle as usize)
    }

    pub unsafe fn nt_allocate_virtual_memory(
        process: Handle,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protection: u32,
    ) -> i32 {
        let table = get_table();
        
        // For syscalls with more than 4 args, we need stack setup
        let args: [usize; 6] = [
            process as usize,
            base_address as usize,
            zero_bits,
            region_size as usize,
            allocation_type as usize,
            protection as usize,
        ];
        
        syscall_with_stack(table.nt_allocate_virtual_memory, &args)
    }

    pub unsafe fn nt_free_virtual_memory(
        process: Handle,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        free_type: u32,
    ) -> i32 {
        let table = get_table();
        syscall!(
            table.nt_free_virtual_memory as usize,
            process as usize,
            base_address as usize,
            region_size as usize,
            free_type as usize
        )
    }

    pub unsafe fn nt_write_virtual_memory(
        process: Handle,
        base_address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        bytes_written: *mut usize,
    ) -> i32 {
        let table = get_table();
        
        let args: [usize; 5] = [
            process as usize,
            base_address as usize,
            buffer as usize,
            size,
            bytes_written as usize,
        ];
        
        syscall_with_stack(table.nt_write_virtual_memory, &args)
    }

    pub unsafe fn nt_read_virtual_memory(
        process: Handle,
        base_address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> i32 {
        let table = get_table();
        
        let args: [usize; 5] = [
            process as usize,
            base_address as usize,
            buffer as usize,
            size,
            bytes_read as usize,
        ];
        
        syscall_with_stack(table.nt_read_virtual_memory, &args)
    }

    pub unsafe fn nt_protect_virtual_memory(
        process: Handle,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protection: u32,
        old_protection: *mut u32,
    ) -> i32 {
        let table = get_table();
        
        let args: [usize; 5] = [
            process as usize,
            base_address as usize,
            region_size as usize,
            new_protection as usize,
            old_protection as usize,
        ];
        
        syscall_with_stack(table.nt_protect_virtual_memory, &args)
    }

    pub unsafe fn nt_create_thread_ex(
        thread_handle: *mut Handle,
        access: u32,
        object_attrs: *mut ObjectAttributes,
        process: Handle,
        start_address: *const c_void,
        parameter: *mut c_void,
        flags: u32,
        zero_bits: usize,
        stack_size: usize,
        max_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> i32 {
        let table = get_table();
        
        let args: [usize; 11] = [
            thread_handle as usize,
            access as usize,
            object_attrs as usize,
            process as usize,
            start_address as usize,
            parameter as usize,
            flags as usize,
            zero_bits,
            stack_size,
            max_stack_size,
            attribute_list as usize,
        ];
        
        syscall_with_stack(table.nt_create_thread_ex, &args)
    }

    pub unsafe fn nt_resume_thread(thread: Handle, suspend_count: *mut u32) -> i32 {
        let table = get_table();
        syscall!(
            table.nt_resume_thread as usize,
            thread as usize,
            suspend_count as usize
        )
    }

    pub unsafe fn nt_suspend_thread(thread: Handle, suspend_count: *mut u32) -> i32 {
        let table = get_table();
        syscall!(
            table.nt_suspend_thread as usize,
            thread as usize,
            suspend_count as usize
        )
    }

    pub unsafe fn nt_wait_for_single_object(
        handle: Handle,
        alertable: bool,
        timeout: *const i64,
    ) -> i32 {
        let table = get_table();
        syscall!(
            table.nt_wait_for_single_object as usize,
            handle as usize,
            alertable as usize,
            timeout as usize
        )
    }

    pub unsafe fn nt_query_information_process(
        process: Handle,
        info_class: u32,
        info: *mut c_void,
        info_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        let table = get_table();
        
        let args: [usize; 5] = [
            process as usize,
            info_class as usize,
            info as usize,
            info_length as usize,
            return_length as usize,
        ];
        
        syscall_with_stack(table.nt_query_information_process, &args)
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn syscall_with_stack(syscall_num: u32, args: &[usize]) -> i32 {
        let result: i32;
        
        match args.len() {
            5 => {
                std::arch::asm!(
                    "mov rax, {num}",
                    "mov r10, {a0}",
                    "mov rdx, {a1}",
                    "mov r8, {a2}",
                    "mov r9, {a3}",
                    "push {a4}",
                    "sub rsp, 32",
                    "syscall",
                    "add rsp, 40",
                    num = in(reg) syscall_num as usize,
                    a0 = in(reg) args[0],
                    a1 = in(reg) args[1],
                    a2 = in(reg) args[2],
                    a3 = in(reg) args[3],
                    a4 = in(reg) args[4],
                    out("rax") result,
                    out("rcx") _,
                    out("r11") _,
                    options(nostack),
                );
            }
            6 => {
                std::arch::asm!(
                    "mov rax, {num}",
                    "mov r10, {a0}",
                    "mov rdx, {a1}",
                    "mov r8, {a2}",
                    "mov r9, {a3}",
                    "push {a5}",
                    "push {a4}",
                    "sub rsp, 32",
                    "syscall",
                    "add rsp, 48",
                    num = in(reg) syscall_num as usize,
                    a0 = in(reg) args[0],
                    a1 = in(reg) args[1],
                    a2 = in(reg) args[2],
                    a3 = in(reg) args[3],
                    a4 = in(reg) args[4],
                    a5 = in(reg) args[5],
                    out("rax") result,
                    out("rcx") _,
                    out("r11") _,
                    options(nostack),
                );
            }
            11 => {
                std::arch::asm!(
                    "mov rax, {num}",
                    "mov r10, {a0}",
                    "mov rdx, {a1}",
                    "mov r8, {a2}",
                    "mov r9, {a3}",
                    "push {a10}",
                    "push {a9}",
                    "push {a8}",
                    "push {a7}",
                    "push {a6}",
                    "push {a5}",
                    "push {a4}",
                    "sub rsp, 32",
                    "syscall",
                    "add rsp, 88",
                    num = in(reg) syscall_num as usize,
                    a0 = in(reg) args[0],
                    a1 = in(reg) args[1],
                    a2 = in(reg) args[2],
                    a3 = in(reg) args[3],
                    a4 = in(reg) args[4],
                    a5 = in(reg) args[5],
                    a6 = in(reg) args[6],
                    a7 = in(reg) args[7],
                    a8 = in(reg) args[8],
                    a9 = in(reg) args[9],
                    a10 = in(reg) args[10],
                    out("rax") result,
                    out("rcx") _,
                    out("r11") _,
                    options(nostack),
                );
            }
            _ => panic!("Unsupported argument count: {}", args.len()),
        }
        
        result
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn syscall_with_stack(_syscall_num: u32, _args: &[usize]) -> i32 {
        panic!("Syscalls only supported on x86_64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_access_combine() {
        let combined = ProcessAccess::combine(&[
            ProcessAccess::VmRead,
            ProcessAccess::VmWrite,
            ProcessAccess::VmOperation,
        ]);
        assert_eq!(combined, 0x0038);
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
    fn test_client_id_from_process() {
        let client_id = ClientId::from_process_id(1234);
        assert_eq!(client_id.unique_process as u32, 1234);
        assert_eq!(client_id.unique_thread, NULL_HANDLE);
    }

    #[test]
    fn test_object_attributes_default() {
        let attrs = ObjectAttributes::default();
        assert_eq!(attrs.length as usize, std::mem::size_of::<ObjectAttributes>());
        assert_eq!(attrs.root_directory, NULL_HANDLE);
    }
}