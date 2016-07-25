use crate::error::{Result, NtStatus};
use crate::handle::Handle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::*;

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
    
    pub fn open(pid: u32, access: u32) -> Result<Self> {
        let handle = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(access), false, pid) };
        match handle {
            Ok(h) => Ok(Self { handle: Handle::new(h), pid }),
            Err(_) => Err(NtStatus(-1)),
        }
    }
    
    pub fn handle(&self) -> HANDLE { self.handle.raw() }
    pub fn pid(&self) -> u32 { self.pid }
}
