use windows::Win32::System::Memory::*;
use std::ffi::c_void;

pub struct Protection(pub u32);

impl Protection {
    pub fn readwrite() -> Self { Self(PAGE_READWRITE.0) }
    pub fn execute_read() -> Self { Self(PAGE_EXECUTE_READ.0) }
}
