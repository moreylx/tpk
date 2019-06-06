use crate::error::{Result, NtStatus};
use crate::handle::Handle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use std::ffi::c_void;
use std::mem;

#[derive(Clone, Copy, Debug)]
pub struct ProcessAccess(pub u32);

impl ProcessAccess {
    pub fn terminate() -> Self { Self(PROCESS_TERMINATE.0) }
    pub fn create_thread() -> Self { Self(PROCESS_CREATE_THREAD.0) }
    pub fn vm_operation() -> Self { Self(PROCESS_VM_OPERATION.0) }
    pub fn vm_read() -> Self { Self(PROCESS_VM_READ.0) }
    pub fn vm_write() -> Self { Self(PROCESS_VM_WRITE.0) }
    pub fn dup_handle() -> Self { Self(PROCESS_DUP_HANDLE.0) }
    pub fn query_info() -> Self { Self(PROCESS_QUERY_INFORMATION.0) }
    pub fn all() -> Self { Self(PROCESS_ALL_ACCESS.0) }
    
    pub fn with(self, other: ProcessAccess) -> Self {
        Self(self.0 | other.0)
    }
}

pub struct Process {
    handle: Handle,
    pid: u32,
}

impl Process {
    pub fn current() -> Self {
        Self {
            handle: Handle::current_process(),
            pid: unsafe { GetCurrentProcessId() },
        }
    }
    
    pub fn open(pid: u32, access: ProcessAccess) -> Result<Self> {
        let handle = unsafe {
            OpenProcess(PROCESS_ACCESS_RIGHTS(access.0), false, pid)
        };
        
        match handle {
            Ok(h) => Ok(Self {
                handle: Handle::new(h),
                pid,
            }),
            Err(_) => Err(NtStatus(unsafe { 
                windows::Win32::Foundation::GetLastError().0 as i32 
            })),
        }
    }
    
    pub fn handle(&self) -> HANDLE {
        self.handle.raw()
    }
    
    pub fn pid(&self) -> u32 {
        self.pid
    }
    
    pub fn read_memory<T: Copy>(&self, address: usize) -> Result<T> {
        let mut buffer: T = unsafe { mem::zeroed() };
        let mut bytes_read = 0;
        
        let success = unsafe {
            ReadProcessMemory(
                self.handle.raw(),
                address as *const c_void,
                &mut buffer as *mut T as *mut c_void,
                mem::size_of::<T>(),
                Some(&mut bytes_read),
            )
        };
        
        if success.is_ok() {
            Ok(buffer)
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn read_memory_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0;
        
        let success = unsafe {
            ReadProcessMemory(
                self.handle.raw(),
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                Some(&mut bytes_read),
            )
        };
        
        if success.is_ok() {
            Ok(bytes_read)
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn write_memory<T: Copy>(&self, address: usize, data: &T) -> Result<()> {
        let mut bytes_written = 0;
        
        let success = unsafe {
            WriteProcessMemory(
                self.handle.raw(),
                address as *const c_void,
                data as *const T as *const c_void,
                mem::size_of::<T>(),
                Some(&mut bytes_written),
            )
        };
        
        if success.is_ok() {
            Ok(())
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn write_memory_bytes(&self, address: usize, data: &[u8]) -> Result<usize> {
        let mut bytes_written = 0;
        
        let success = unsafe {
            WriteProcessMemory(
                self.handle.raw(),
                address as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(&mut bytes_written),
            )
        };
        
        if success.is_ok() {
            Ok(bytes_written)
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        let result = unsafe {
            TerminateProcess(self.handle.raw(), exit_code)
        };
        
        if result.is_ok() {
            Ok(())
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn suspend(&self) -> Result<()> {
        extern "system" {
            fn NtSuspendProcess(handle: HANDLE) -> i32;
        }
        
        let status = unsafe { NtSuspendProcess(self.handle.raw()) };
        if status >= 0 {
            Ok(())
        } else {
            Err(NtStatus(status))
        }
    }
    
    pub fn resume(&self) -> Result<()> {
        extern "system" {
            fn NtResumeProcess(handle: HANDLE) -> i32;
        }
        
        let status = unsafe { NtResumeProcess(self.handle.raw()) };
        if status >= 0 {
            Ok(())
        } else {
            Err(NtStatus(status))
        }
    }
}

