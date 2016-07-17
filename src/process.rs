use crate::handle::Handle;
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
}
