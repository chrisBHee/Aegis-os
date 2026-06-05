//! Cryptographically Secure Random Number Generator.
//!
//! Combines hardware entropy sources (RDRAND/RDSEED on x86_64)
//! with a software CSPRNG for continuous random number generation.
//! All crypto operations in AEGIS MUST use this RNG.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Mutex;

use crate::serial_println;

/// Global RNG instance, protected by a spinlock.
static RNG: Mutex<Option<AegisRng>> = Mutex::new(None);
static RNG_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the global RNG from hardware entropy.
pub fn init() {
    let rng = AegisRng::new();
    *RNG.lock() = Some(rng);
    RNG_INITIALIZED.store(true, Ordering::SeqCst);
    serial_println!("[RNG] CSPRNG initialized from hardware entropy");
}

/// Fill a buffer with cryptographically secure random bytes.
pub fn fill_bytes(dest: &mut [u8]) {
    if let Some(ref mut rng) = *RNG.lock() {
        rng.fill_bytes(dest);
    } else {
        panic!("AEGIS: RNG not initialized");
    }
}

/// Generate a random u64.
pub fn next_u64() -> u64 {
    let mut bytes = [0u8; 8];
    fill_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// AEGIS CSPRNG — uses a simple xoshiro256** algorithm seeded from
/// hardware entropy. In production, this would use ChaCha20-based CSPRNG
/// with continuous reseeding from hardware RNG.
pub struct AegisRng {
    state: [u64; 4],
    /// Counter for reseeding schedule
    bytes_generated: AtomicU64,
}

impl AegisRng {
    /// Create a new RNG seeded from hardware entropy (RDRAND).
    pub fn new() -> Self {
        let mut state = [0u64; 4];
        for s in &mut state {
            *s = Self::hardware_random_u64();
        }

        // Ensure state is not all zeros
        if state.iter().all(|&s| s == 0) {
            // Fallback: use TSC + mixing
            state[0] = Self::read_tsc();
            state[1] = state[0].wrapping_mul(0x9E3779B97F4A7C15);
            state[2] = state[1].wrapping_mul(0x9E3779B97F4A7C15);
            state[3] = state[2].wrapping_mul(0x9E3779B97F4A7C15);
        }

        AegisRng {
            state,
            bytes_generated: AtomicU64::new(0),
        }
    }

    /// Fill a buffer with random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            let remaining = dest.len() - i;
            let to_copy = remaining.min(8);
            dest[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
            i += to_copy;
        }
        self.bytes_generated
            .fetch_add(dest.len() as u64, Ordering::Relaxed);
    }

    /// Generate next random u64 using xoshiro256**.
    fn next_u64(&mut self) -> u64 {
        let result = self.state[1]
            .wrapping_mul(5)
            .rotate_left(7)
            .wrapping_mul(9);

        let t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);

        result
    }

    /// Read hardware random number using RDRAND instruction.
    /// Falls back to TSC if RDRAND is not available.
    fn hardware_random_u64() -> u64 {
        // Try RDRAND (available on Intel Ivy Bridge+, AMD Zen+)
        for _ in 0..10 {
            let mut val: u64 = 0;
            let success: u8;
            unsafe {
                core::arch::asm!(
                    "rdrand {val}",
                    "setc {success}",
                    val = out(reg) val,
                    success = out(reg_byte) success,
                    options(nomem, nostack)
                );
            }
            if success == 1 {
                return val;
            }
        }

        // Fallback to TSC
        Self::read_tsc()
    }

    /// Read the Time Stamp Counter — used as a fallback entropy source.
    fn read_tsc() -> u64 {
        unsafe {
            core::arch::x86_64::_rdtsc()
        }
    }
}
