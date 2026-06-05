use std::ptr;

/// A region of memory that can hold JIT-compiled machine code.
///
/// Memory is allocated via `mmap` with initial `RW` permissions so the code
/// can be written, then switched to `RX` (read + execute) via
/// [`make_executable`].  The W^X discipline prevents a page from being
/// simultaneously writable and executable.
pub struct JitMemory {
    addr: *mut u8,
    size: usize,
}

// SAFETY: JitMemory owns a unique mmap region and doesn't alias any Rust
// reference.  Sharing it across threads is only safe once the memory has
// been made read-only/executable (i.e. after make_executable()), but since
// we model that transition explicitly we can afford to be conservative here.
unsafe impl Send for JitMemory {}

impl JitMemory {
    /// Allocate `size` bytes of anonymous, private, read-write memory.
    pub fn new(size: usize) -> Result<Self, String> {
        if size == 0 {
            return Err("JIT region size must be greater than zero".into());
        }

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
            return Err(format!(
                "mmap failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(JitMemory {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Copy machine code bytes into the allocated region.
    pub fn write(&mut self, code: &[u8]) -> Result<(), String> {
        if code.len() > self.size {
            return Err(format!(
                "code ({} bytes) exceeds allocated region ({} bytes)",
                code.len(),
                self.size
            ));
        }
        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.addr, code.len());
        }
        Ok(())
    }

    /// Switch memory protection from RW → RX (write-xor-execute).
    ///
    /// Must be called after [`write`] and before executing the code.
    pub fn make_executable(&self) -> Result<(), String> {
        let ret = unsafe {
            libc::mprotect(
                self.addr as *mut libc::c_void,
                self.size,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        if ret != 0 {
            return Err(format!(
                "mprotect failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Returns the raw pointer to the start of the executable region.
    ///
    /// # Safety
    /// The caller must ensure:
    /// - [`make_executable`] has been called.
    /// - The region contains valid machine code with the `extern "C" fn() -> u64` signature.
    pub unsafe fn as_fn_u64(&self) -> extern "C" fn() -> u64 {
        // FIX: Rust 2021+ warns about a redundant `unsafe` block *inside*
        // an `unsafe fn`.  Using a single transmute at the function body
        // level is cleaner and avoids the nested-unsafe lint.
        std::mem::transmute(self.addr)
    }
}

impl Drop for JitMemory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}