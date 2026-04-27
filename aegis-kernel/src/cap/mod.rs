//! Capability-Based Security System.
//!
//! The core security model of AEGIS OS. Every resource access requires
//! presenting a valid, unforgeable capability. There is NO ambient authority —
//! a process can ONLY interact with objects it has been explicitly granted
//! capabilities for.
//!
//! Inspired by seL4 and Fuchsia/Zircon capability models.
//!
//! Key properties:
//! - Capabilities are unforgeable tokens (authenticated by kernel)
//! - Rights can only be REMOVED when deriving (monotonic reduction)
//! - Revocation cascades to all derived capabilities
//! - No confused deputy attacks possible

pub mod capability;
pub mod cspace;
pub mod rights;

use crate::serial_println;

/// Initialize the capability system.
pub fn init() {
    serial_println!("[CAP] Capability system initialized — no ambient authority");
}
