use crate::error::{Result, NtStatus};
use crate::handle::Handle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::*;

pub struct Thread {
    handle: Handle,
    tid: u32,
}

impl Thread {
    pub fn current() -> Self {
        Self {
            handle: Handle::current_thread(),
            tid: unsafe { GetCurrentThreadId() },
        }
    }
    
    pub fn open(tid: u32, access: u32) -> Result<Self> {
        let handle = unsafe { OpenThread(THREAD_ACCESS_RIGHTS(access), false, tid) };
        match handle {
            Ok(h) => Ok(Self { handle: Handle::new(h), tid }),
            Err(_) => Err(NtStatus(-1)),
        }
    }
    
    pub fn suspend(&self) -> Result<u32> {
        let result = unsafe { SuspendThread(self.handle.raw()) };
        if result != u32::MAX { Ok(result) } else { Err(NtStatus(-1)) }
    }
    
    pub fn resume(&self) -> Result<u32> {
        let result = unsafe { ResumeThread(self.handle.raw()) };
        if result != u32::MAX { Ok(result) } else { Err(NtStatus(-1)) }
    }
}
