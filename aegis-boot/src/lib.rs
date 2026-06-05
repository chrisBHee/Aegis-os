//! AEGIS OS Bootloader
//!
//! UEFI-based bootloader that:
//! 1. Verifies the kernel image signature using ML-DSA (post-quantum)
//! 2. Sets up initial page tables with NX bits
//! 3. Loads the kernel into high memory
//! 4. Passes BootInfo to the kernel entry point
//!
//! The bootloader is the first piece of trusted code that runs.
//! It establishes the chain of trust by verifying the kernel's
//! PQ digital signature before passing control.

#![no_std]

/// Boot verification error types.
#[derive(Debug)]
pub enum BootVerifyError {
    /// Kernel signature verification failed
    SignatureInvalid,
    /// Kernel image is corrupted
    ImageCorrupted,
    /// Required boot component is missing
    MissingComponent,
    /// Memory map is invalid or insufficient
    InvalidMemoryMap,
}

/// Boot component types for measurement logging.
#[derive(Debug, Clone, Copy)]
pub enum BootComponent {
    /// The UEFI firmware itself
    Firmware,
    /// The bootloader binary
    Bootloader,
    /// The kernel binary
    Kernel,
    /// Kernel configuration
    KernelConfig,
    /// Initial ramdisk (if any)
    InitRd,
}

/// Boot measurement log entry.
/// Records a SHA3-512 hash of each boot component for attestation.
#[derive(Debug)]
pub struct BootMeasurement {
    /// Which component was measured
    pub component: BootComponent,
    /// SHA3-512 hash of the component
    pub hash: [u8; 64],
    /// Order in the boot sequence
    pub sequence: u32,
}
