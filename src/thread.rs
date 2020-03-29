use crate::error::{Result, NtStatus};
use crate::handle::Handle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::*;
use std::ffi::c_void;

#[derive(Clone, Copy, Debug)]
pub struct ThreadAccess(pub u32);

impl ThreadAccess {
    pub fn terminate() -> Self { Self(THREAD_TERMINATE.0) }
    pub fn suspend_resume() -> Self { Self(THREAD_SUSPEND_RESUME.0) }
    pub fn get_context() -> Self { Self(THREAD_GET_CONTEXT.0) }
    pub fn set_context() -> Self { Self(THREAD_SET_CONTEXT.0) }
    pub fn query_info() -> Self { Self(THREAD_QUERY_INFORMATION.0) }
    pub fn set_info() -> Self { Self(THREAD_SET_INFORMATION.0) }
    pub fn all() -> Self { Self(THREAD_ALL_ACCESS.0) }
    
    pub fn with(self, other: ThreadAccess) -> Self {
        Self(self.0 | other.0)
    }
}

pub struct Thread {
    handle: Handle,
    tid: u32,
}

impl Thread {
    pub fn current() -> Self {
        Self {
            handle: Handle::current_thread(),
            tid: unsafe { GetCurrentThreadId() },
        }
    }
    
    pub fn open(tid: u32, access: ThreadAccess) -> Result<Self> {
        let handle = unsafe {
            OpenThread(THREAD_ACCESS_RIGHTS(access.0), false, tid)
        };
        
        match handle {
            Ok(h) => Ok(Self {
                handle: Handle::new(h),
                tid,
            }),
            Err(_) => Err(NtStatus(-1)),
        }
    }
    
    pub fn handle(&self) -> HANDLE {
        self.handle.raw()
    }
    
    pub fn tid(&self) -> u32 {
        self.tid
    }
    
    pub fn suspend(&self) -> Result<u32> {
        let result = unsafe { SuspendThread(self.handle.raw()) };
        if result != u32::MAX {
            Ok(result)
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn resume(&self) -> Result<u32> {
        let result = unsafe { ResumeThread(self.handle.raw()) };
        if result != u32::MAX {
            Ok(result)
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        let result = unsafe {
            TerminateThread(self.handle.raw(), exit_code)
        };
        
        if result.is_ok() {
            Ok(())
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn get_context(&self) -> Result<CONTEXT> {
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = CONTEXT_ALL;
        
        let result = unsafe {
            GetThreadContext(self.handle.raw(), &mut ctx)
        };
        
        if result.is_ok() {
            Ok(ctx)
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn set_context(&self, ctx: &CONTEXT) -> Result<()> {
        let result = unsafe {
            SetThreadContext(self.handle.raw(), ctx)
        };
        
        if result.is_ok() {
            Ok(())
        } else {
            Err(NtStatus(-1))
        }
    }
    
    pub fn queue_apc(&self, routine: unsafe extern "system" fn(*mut c_void) -> (), arg: *mut c_void) -> Result<()> {
        let result = unsafe {
            QueueUserAPC(
                Some(std::mem::transmute(routine)),
                self.handle.raw(),
                arg as usize,
            )
        };
        
        if result.0 != 0 {
            Ok(())
        } else {
            Err(NtStatus(-1))
        }
    }
}

pub struct ThreadBuilder {
    stack_size: usize,
    suspended: bool,
}

impl ThreadBuilder {
    pub fn new() -> Self {
        Self {
            stack_size: 0,
            suspended: false,
        }
    }
    
    pub fn stack_size(mut self, size: usize) -> Self {
        self.stack_size = size;
        self
    }
    
    pub fn suspended(mut self) -> Self {
        self.suspended = true;
        self
    }
    
    pub fn spawn<F>(self, f: F) -> Result<Thread>
    where
        F: FnOnce() + Send + 'static,
    {
        let boxed = Box::new(f);
        let raw = Box::into_raw(boxed);
        
        extern "system" fn thread_start<F: FnOnce()>(param: *mut c_void) -> u32 {
            let f = unsafe { Box::from_raw(param as *mut F) };
            f();
            0
        }
        
        let flags = if self.suspended {
            CREATE_SUSPENDED
        } else {
            THREAD_CREATION_FLAGS(0)
        };
        
        let mut tid = 0u32;
        let handle = unsafe {
            CreateThread(
                None,
                self.stack_size,
                Some(thread_start::<F>),
                Some(raw as *const c_void),
                flags,
                Some(&mut tid),
            )
        };
        
        match handle {
            Ok(h) => Ok(Thread {
                handle: Handle::new(h),
                tid,
            }),
            Err(_) => {
                let _ = unsafe { Box::from_raw(raw) };
                Err(NtStatus(-1))
            }
        }
    }
}

impl Default for ThreadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

