use windows::Win32::Foundation::{HANDLE, CloseHandle, BOOL};
use std::ptr;

pub struct Handle(HANDLE);

impl Handle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
    
    pub fn raw(&self) -> HANDLE {
        self.0
    }
    
    pub fn is_valid(&self) -> bool {
        !self.0.is_invalid() && self.0.0 != ptr::null_mut()
    }
    
    pub fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
    
    pub fn current_process() -> Self {
        Self(HANDLE(-1isize as *mut _))
    }
    
    pub fn current_thread() -> Self {
        Self(HANDLE(-2isize as *mut _))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        use windows::Win32::Foundation::DuplicateHandle;
        use windows::Win32::System::Threading::GetCurrentProcess;
        
        let mut new_handle = HANDLE::default();
        unsafe {
            let current = GetCurrentProcess();
            let _ = DuplicateHandle(
                current,
                self.0,
                current,
                &mut new_handle,
                0,
                BOOL(0),
                windows::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            );
        }
        Self(new_handle)
    }
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

