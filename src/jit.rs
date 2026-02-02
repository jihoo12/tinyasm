use std::ptr;

pub struct JitMemory {
    addr: *mut u8,
    size: usize,
}

impl JitMemory {
    pub fn new(size: usize) -> Result<Self, String> {
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err("Failed to allocate memory via mmap".to_string());
        }

        Ok(JitMemory {
            addr: addr as *mut u8,
            size,
        })
    }

    pub fn write(&mut self, code: &[u8]) -> Result<(), String> {
        if code.len() > self.size {
            return Err(format!(
                "Code size {} exceeds allocated memory size {}",
                code.len(),
                self.size
            ));
        }

        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.addr, code.len());
        }
        Ok(())
    }

    pub fn make_executable(&self) -> Result<(), String> {
        let ret = unsafe {
            libc::mprotect(
                self.addr as *mut libc::c_void,
                self.size,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };

        if ret != 0 {
            return Err("Failed to change memory protection to RX".to_string());
        }
        Ok(())
    }

    /// Casts the memory to a function pointer `fn() -> u64`.
    ///
    /// # Safety
    /// Caller must ensure that the memory contains valid machine code for this signature.
    pub unsafe fn as_fn_u64(&self) -> extern "C" fn() -> u64 {
        unsafe { std::mem::transmute(self.addr) }
    }
}

impl Drop for JitMemory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}
