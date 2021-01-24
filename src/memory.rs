use crate::error::{Result, NtStatus};
use crate::process::Process;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::*;
use std::ffi::c_void;

#[derive(Clone, Copy, Debug)]
pub struct Protection(pub u32);

impl Protection {
    pub fn readonly() -> Self { Self(PAGE_READONLY.0) }
    pub fn readwrite() -> Self { Self(PAGE_READWRITE.0) }
    pub fn execute() -> Self { Self(PAGE_EXECUTE.0) }
    pub fn execute_read() -> Self { Self(PAGE_EXECUTE_READ.0) }
    pub fn execute_readwrite() -> Self { Self(PAGE_EXECUTE_READWRITE.0) }
    pub fn noaccess() -> Self { Self(PAGE_NOACCESS.0) }
    pub fn guard() -> Self { Self(PAGE_GUARD.0) }
    
    pub fn with(self, other: Protection) -> Self {
        Self(self.0 | other.0)
    }
}

pub struct VirtualAlloc {
    base: *mut c_void,
    size: usize,
    handle: HANDLE,
}

impl VirtualAlloc {
    pub fn allocate(size: usize, protection: Protection) -> Result<Self> {
        Self::allocate_in(Process::current().handle(), size, protection)
    }
    
    pub fn allocate_in(handle: HANDLE, size: usize, protection: Protection) -> Result<Self> {
        let base = unsafe {
            VirtualAllocEx(
                handle,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_PROTECTION_FLAGS(protection.0),
            )
        };
        
        if base.is_null() {
            Err(NtStatus(-1))
        } else {
            Ok(Self { base, size, handle })
        }
    }
    
    pub fn allocate_at(handle: HANDLE, address: *mut c_void, size: usize, protection: Protection) -> Result<Self> {
        let base = unsafe {
            VirtualAllocEx(
                handle,
                Some(address),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_PROTECTION_FLAGS(protection.0),
            )
        };
        
        if base.is_null() {
            Err(NtStatus(-1))
        } else {
            Ok(Self { base, size, handle })
        }
    }
    
    pub fn base(&self) -> *mut c_void {
        self.base
    }
    
    pub fn size(&self) -> usize {
        self.size
    }
    
    pub fn protect(&self, protection: Protection) -> Result<Protection> {
        let mut old = PAGE_PROTECTION_FLAGS::default();
        
        let result = unsafe {
            VirtualProtectEx(
                self.handle,
                self.base,
                self.size,
                PAGE_PROTECTION_FLAGS(protection.0),
                &mut old,
            )
        };
        
        if result.is_ok() {
            Ok(Protection(old.0))
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn into_raw(self) -> *mut c_void {
        let ptr = self.base;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for VirtualAlloc {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                let _ = VirtualFreeEx(
                    self.handle,
                    self.base,
                    0,
                    MEM_RELEASE,
                );
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryBasicInfo {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
}

pub fn query_memory(handle: HANDLE, address: *const c_void) -> Result<MemoryBasicInfo> {
    let mut info = MEMORY_BASIC_INFORMATION::default();
    
    let result = unsafe {
        VirtualQueryEx(
            handle,
            Some(address),
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    
    if result > 0 {
        Ok(MemoryBasicInfo {
            base_address: info.BaseAddress,
            allocation_base: info.AllocationBase,
            allocation_protect: info.AllocationProtect.0,
            region_size: info.RegionSize,
            state: info.State.0,
            protect: info.Protect.0,
            type_: info.Type.0,
        })
    } else {
        Err(NtStatus(-1))
    }
}

pub fn protect_memory(
    handle: HANDLE,
    address: *mut c_void,
    size: usize,
    protection: Protection,
) -> Result<Protection> {
    let mut old = PAGE_PROTECTION_FLAGS::default();
    
    let result = unsafe {
        VirtualProtectEx(
            handle,
            address,
            size,
            PAGE_PROTECTION_FLAGS(protection.0),
            &mut old,
        )
    };
    
    if result.is_ok() {
        Ok(Protection(old.0))
    } else {
        Err(NtStatus(-1))
    }
}

