pub struct NtStatus(pub i32);

impl NtStatus {
    pub fn is_success(&self) -> bool {
        self.0 >= 0
    }
}

pub type Result<T> = std::result::Result<T, NtStatus>;
