use windows::Win32::Foundation::HANDLE;

pub struct Handle(HANDLE);

impl Handle {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }
    
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}
