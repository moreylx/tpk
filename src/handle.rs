use windows::Win32::Foundation::{HANDLE, CloseHandle};

pub struct Handle(HANDLE);

impl Handle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
    
    pub fn raw(&self) -> HANDLE {
        self.0
    }
    
    pub fn current_process() -> Self {
        Self(HANDLE(-1isize as *mut _))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}
