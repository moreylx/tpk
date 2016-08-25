use crate::error::{Result, NtStatus};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::*;
use std::ffi::c_void;

pub struct Protection(pub u32);

impl Protection {
    pub fn readwrite() -> Self { Self(PAGE_READWRITE.0) }
    pub fn execute_read() -> Self { Self(PAGE_EXECUTE_READ.0) }
}

pub struct VirtualAlloc {
    base: *mut c_void,
    size: usize,
    handle: HANDLE,
}

impl VirtualAlloc {
    pub fn allocate(handle: HANDLE, size: usize, prot: Protection) -> Result<Self> {
        let base = unsafe {
            VirtualAllocEx(handle, None, size, MEM_COMMIT | MEM_RESERVE, 
                PAGE_PROTECTION_FLAGS(prot.0))
        };
        if base.is_null() { Err(NtStatus(-1)) } else { Ok(Self { base, size, handle }) }
    }
    
    pub fn base(&self) -> *mut c_void { self.base }
}

impl Drop for VirtualAlloc {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { let _ = VirtualFreeEx(self.handle, self.base, 0, MEM_RELEASE); }
        }
    }
}
