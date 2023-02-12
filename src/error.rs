use std::fmt;
use windows::Win32::Foundation::NTSTATUS;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NtStatus(pub i32);

impl NtStatus {
    pub const SUCCESS: Self = Self(0);
    
    pub fn is_success(&self) -> bool {
        self.0 >= 0
    }
    
    pub fn is_error(&self) -> bool {
        self.0 < 0
    }
    
    pub fn from_ntstatus(status: NTSTATUS) -> Self {
        Self(status.0)
    }
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtStatus(0x{:08X})", self.0 as u32)
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_success() {
            write!(f, "Success")
        } else {
            write!(f, "Error: 0x{:08X}", self.0 as u32)
        }
    }
}

impl std::error::Error for NtStatus {}

pub type Result<T> = std::result::Result<T, NtStatus>;

pub fn check_status(status: NTSTATUS) -> Result<()> {
    let s = NtStatus::from_ntstatus(status);
    if s.is_success() {
        Ok(())
    } else {
        Err(s)
    }
}

