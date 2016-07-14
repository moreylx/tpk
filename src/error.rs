use std::fmt;

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
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtStatus(0x{:08X})", self.0 as u32)
    }
}

pub type Result<T> = std::result::Result<T, NtStatus>;
