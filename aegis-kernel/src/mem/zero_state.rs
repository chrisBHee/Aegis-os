//! Secure memory wiping for zero-state execution.
//!
//! Ensures no sensitive data persists in RAM after deallocation or shutdown.
//! Critical for the "zero forensic trace" guarantee of AEGIS OS.
//!
//! Uses volatile writes to prevent compiler optimization from removing
//! the wipe operations. Performs multiple overwrite passes for security.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

/// Sensitivity classification for memory regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Public data — single zero pass sufficient
    Public,
    /// Sensitive data (user files, IPC buffers) — random + zero pass
    Sensitive,
    /// Critical data (crypto keys, passwords) — multiple random + zero passes
    Critical,
}

/// Securely wipe a memory region, preventing forensic recovery.
///
/// Uses volatile writes to ensure the compiler cannot optimize away
/// the memory writes. Number of passes depends on sensitivity level.
///
/// # Safety
/// The caller must ensure the pointer and length are valid and that
/// no other references to this memory exist during the wipe.
pub unsafe fn secure_wipe(ptr: *mut u8, len: usize, sensitivity: Sensitivity) {
    let passes = match sensitivity {
        Sensitivity::Public => 1,
        Sensitivity::Sensitive => 2,
        Sensitivity::Critical => 3,
    };

    for pass in 0..passes {
        let pattern = if pass == passes - 1 {
            0x00u8 // Final pass is always zeroes
        } else {
            0xAA ^ (pass as u8 * 0x55) // Alternating patterns
        };

        unsafe { volatile_memset(ptr, pattern, len) };
        compiler_fence(Ordering::SeqCst);
    }

    // Verification pass — ensure all bytes are zero
    unsafe { verify_zeroed(ptr, len) };
}

/// Volatile memset — writes a byte pattern to memory using volatile
/// operations that cannot be optimized away by the compiler.
unsafe fn volatile_memset(dest: *mut u8, value: u8, len: usize) {
    for i in 0..len {
        unsafe { ptr::write_volatile(dest.add(i), value) };
    }
}

/// Verify that a memory region is zeroed.
/// Used after wiping to detect hardware failures.
unsafe fn verify_zeroed(dest: *mut u8, len: usize) {
    for i in 0..len {
        let val = unsafe { ptr::read_volatile(dest.add(i)) };
        if val != 0 {
            panic!("AEGIS: Memory wipe verification failed at offset {}", i);
        }
    }
}

/// Trait for types that contain sensitive data and must be securely
/// wiped when dropped. All crypto key types implement this.
pub trait SecureZeroize {
    /// Overwrite self with zeroes using volatile writes.
    fn zeroize(&mut self);
}

impl SecureZeroize for [u8] {
    fn zeroize(&mut self) {
        unsafe {
            volatile_memset(self.as_mut_ptr(), 0, self.len());
        }
        compiler_fence(Ordering::SeqCst);
    }
}
