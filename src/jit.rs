use std::marker::PhantomData;
use std::ptr;

/// Tracks whether the JIT region is currently writable or executable.
/// Upholds the W^X invariant at the type level by gating APIs on state.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protection {
    /// `PROT_READ | PROT_WRITE` — code may be written, not executed.
    ReadWrite,
    /// `PROT_READ | PROT_EXEC` — code may be executed, not written.
    ReadExec,
}


/// Function-pointer types that may be constructed from JIT code.
///
/// # Safety
/// Implementors must be pointer-sized C-ABI function-pointer types.
#[cfg(target_arch = "x86_64")]
pub unsafe trait JitFunction: Copy {
    unsafe fn from_ptr(ptr: *mut u8) -> Self;
}

#[cfg(target_arch = "x86_64")]
macro_rules! impl_jit_function {
    ($(($($arg:ident),*)),* $(,)?) => {
        $(
            unsafe impl<R, $($arg,)*> JitFunction for extern "C" fn($($arg),*) -> R {
                unsafe fn from_ptr(ptr: *mut u8) -> Self {
                    unsafe { std::mem::transmute(ptr) }
                }
            }
        )*
    };
}

#[cfg(target_arch = "x86_64")]
impl_jit_function!((), (A0), (A0, A1), (A0, A1, A2), (A0, A1, A2, A3));

/// A region of executable memory for JIT-compiled machine code.
///
/// Memory is allocated via `mmap` with `RW` permissions (writable, not
/// executable) so code can be written, then switched to `RX` (readable,
/// executable) via [`JitMemory::make_executable`].  This upholds the W^X
/// invariant — a page is never simultaneously writable and executable.
///
/// The `state` field enforces the transition at runtime:
/// - [`write`] is rejected after [`make_executable`] has been called.
/// - [`as_fn`] is rejected before [`make_executable`] has been called.
///
/// # Platform notes
/// This implementation targets **x86-64 Linux/macOS** only.  On x86-64 the
/// hardware maintains coherency between the data cache (D$) and instruction
/// cache (I$), so no explicit cache flush is needed after writing code.
/// On architectures with separate I$ (AArch64, RISC-V) you would need to call
/// `__clear_cache` or equivalent before executing newly written code.
#[cfg(target_arch = "x86_64")]
pub struct JitMemory {
    addr: *mut u8,
    /// Actual allocated size (rounded up to a page boundary).
    size: usize,
    /// Current memory-protection state; enforces W^X at runtime.
    state: Protection,
    /// Number of bytes written so far; used to reject out-of-bounds writes.
    written: usize,
    /// Makes `JitMemory` non-`Sync` on stable Rust.
    ///
    /// `impl !Sync` is nightly-only (issue #68318), so we carry a
    /// `PhantomData<*mut ()>` instead.  Raw pointers are neither `Send` nor
    /// `Sync`, so this field causes the compiler to infer `!Sync` for the
    /// whole struct without affecting runtime layout (zero-sized).
    /// We then explicitly re-assert `Send` via `unsafe impl Send` below.
    _not_sync: PhantomData<*mut ()>,
}

// SAFETY: JitMemory owns a unique mmap region.  No Rust reference aliases it.
// Sending to another thread is only safe because ownership is exclusive.
// `Sync` is not implemented: the `PhantomData<*mut ()>` field makes the
// compiler infer `!Sync`, preventing shared `&JitMemory` references across
// threads (which would allow data races on `state` and the mmap region).
#[cfg(target_arch = "x86_64")]
unsafe impl Send for JitMemory {}

#[cfg(target_arch = "x86_64")]
impl JitMemory {
    /// Allocate at least `min_size` bytes of anonymous, private, read-write
    /// memory, rounded up to the system page size.
    pub fn new(min_size: usize) -> Result<Self, String> {
        if min_size == 0 {
            return Err("JIT region size must be greater than zero".into());
        }

        let page_size = Self::page_size();
        // Round up to the nearest page boundary so mprotect is always valid.
        let size = min_size
            .checked_add(page_size - 1)
            .ok_or("JIT region size overflows")?
            / page_size
            * page_size;

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
                "mmap({} bytes) failed: {}",
                size,
                std::io::Error::last_os_error()
            ));
        }

        Ok(JitMemory {
            addr: addr as *mut u8,
            size,
            state: Protection::ReadWrite,
            written: 0,
            _not_sync: PhantomData,
        })
    }

    /// Copy machine-code bytes into the allocated region at the current write
    /// cursor, advancing it by `code.len()`.
    ///
    /// # Errors
    /// - Returns an error if [`make_executable`] has already been called
    ///   (write-after-execute is prohibited).
    /// - Returns an error if `code` would exceed the allocated region.
    pub fn write(&mut self, code: &[u8]) -> Result<(), String> {
        if self.state != Protection::ReadWrite {
            return Err(
                "cannot write to JIT region after make_executable() has been called".into(),
            );
        }

        let new_written = self
            .written
            .checked_add(code.len())
            .ok_or("write length overflows")?;

        if new_written > self.size {
            return Err(format!(
                "write of {} bytes at offset {} would exceed allocated region ({} bytes)",
                code.len(),
                self.written,
                self.size
            ));
        }

        // SAFETY: Both pointers are valid and non-overlapping:
        // - `self.addr + self.written` is within the mmap region.
        // - `code` is a valid Rust slice.
        unsafe {
            ptr::copy_nonoverlapping(
                code.as_ptr(),
                self.addr.add(self.written),
                code.len(),
            );
        }

        self.written = new_written;
        Ok(())
    }

    /// Switch memory protection from `RW` → `RX` (write-xor-execute).
    ///
    /// Must be called after [`write`] and before calling [`as_fn`].
    /// After this call, [`write`] will return an error.
    pub fn make_executable(&mut self) -> Result<(), String> {
        if self.state == Protection::ReadExec {
            // Idempotent — already executable, nothing to do.
            return Ok(());
        }

        let ret = unsafe {
            libc::mprotect(
                self.addr as *mut libc::c_void,
                self.size,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };

        if ret != 0 {
            return Err(format!(
                "mprotect(RX) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        self.state = Protection::ReadExec;
        Ok(())
    }

    /// Return a callable function pointer to the start of the JIT region.
    ///
    /// # Errors
    /// Returns an error if [`make_executable`] has not yet been called,
    /// preventing execution of potentially uninitialised or still-writable
    /// memory.
    ///
    /// # Safety
    /// The caller must ensure the region contains valid x86-64 machine code
    /// conforming to the `extern "C" fn() -> u64` ABI (callee-saved registers
    /// preserved, return value in RAX).
    ///
    /// Calling the returned pointer with a mismatched ABI or with code that
    /// corrupts the stack is undefined behaviour.
    pub unsafe fn as_fn(&self) -> Result<extern "C" fn() -> u64, String> {
        if self.state != Protection::ReadExec {
            return Err(
                "cannot obtain function pointer before make_executable() has been called".into(),
            );
        }

        if self.written == 0 {
            return Err("JIT region is empty — no code has been written".into());
        }

        // SAFETY: addr is a non-null, page-aligned pointer to at least
        // `self.written` bytes of RX memory.  The caller is responsible for
        // ABI correctness.
        unsafe { self.as_typed_fn() }
    }

    /// Return the start of the JIT region as a typed C-ABI function pointer.
    ///
    /// # Safety
    /// The caller must ensure the emitted machine code obeys the exact ABI,
    /// argument types, return type, and callee-saved register requirements of F.
    pub unsafe fn as_typed_fn<F: JitFunction>(&self) -> Result<F, String> {
        if self.state != Protection::ReadExec {
            return Err(
                "cannot obtain function pointer before make_executable() has been called".into(),
            );
        }

        if self.written == 0 {
            return Err("JIT region is empty — no code has been written".into());
        }

        Ok(unsafe { F::from_ptr(self.addr) })
    }

    /// Returns the OS page size in bytes.
    fn page_size() -> usize {
        // SAFETY: sysconf is always safe to call with _SC_PAGESIZE.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps <= 0 { 4096 } else { ps as usize }
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for JitMemory {
    fn drop(&mut self) {
        unsafe {
            // Revoke all permissions before unmapping.  This limits the
            // damage if any dangling pointer to this region exists elsewhere:
            // any access will fault immediately rather than silently reading
            // or executing stale code.
            //
            // Errors from mprotect/munmap are intentionally ignored in Drop
            // (we cannot propagate them), but the sequence is best-effort.
            libc::mprotect(
                self.addr as *mut libc::c_void,
                self.size,
                libc::PROT_NONE,
            );
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_sized_region() {
        assert!(JitMemory::new(0).is_err());
    }

    #[test]
    fn function_pointer_requires_executable_memory() {
        let mut jit = JitMemory::new(1).unwrap();
        jit.write(&[0xC3]).unwrap();

        assert!(unsafe { jit.as_fn() }.is_err());
    }

    #[test]
    fn empty_executable_region_cannot_be_called() {
        let mut jit = JitMemory::new(1).unwrap();
        jit.make_executable().unwrap();

        assert!(unsafe { jit.as_fn() }.is_err());
    }

    #[test]
    fn write_is_rejected_after_make_executable() {
        let mut jit = JitMemory::new(1).unwrap();
        jit.write(&[0xC3]).unwrap();
        jit.make_executable().unwrap();

        assert!(jit.write(&[0x90]).is_err());
    }

    #[test]
    fn rejects_write_past_allocated_region() {
        let page_size = JitMemory::page_size();
        let mut jit = JitMemory::new(1).unwrap();
        let too_large = vec![0u8; page_size + 1];

        assert!(jit.write(&too_large).is_err());
    }

    #[test]
    fn executes_typed_f64_sse2_function() {
        // System V x86-64: f64 arguments arrive in XMM0/XMM1 and the result
        // is returned in XMM0.  addsd xmm0, xmm1; ret
        let code = [0xF2, 0x0F, 0x58, 0xC1, 0xC3];
        let mut jit = JitMemory::new(code.len()).unwrap();
        jit.write(&code).unwrap();
        jit.make_executable().unwrap();

        let func: extern "C" fn(f64, f64) -> f64 =
            unsafe { jit.as_typed_fn() }.unwrap();
        assert_eq!(func(1.5, 2.25), 3.75);
    }

    #[test]
    fn executes_simple_function() {
        // mov eax, 42; ret
        let code = [0xB8, 42, 0, 0, 0, 0xC3];
        let mut jit = JitMemory::new(code.len()).unwrap();
        jit.write(&code).unwrap();
        jit.make_executable().unwrap();

        let func = unsafe { jit.as_fn() }.unwrap();
        assert_eq!(func(), 42);
    }
}
