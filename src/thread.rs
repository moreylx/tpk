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
}
