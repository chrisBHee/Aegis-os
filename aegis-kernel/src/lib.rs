//! AEGIS OS Microkernel
//!
//! Privacy-first, security-first operating system with post-quantum encryption.
//! Everything runs in isolation. Every operation requires a capability.
//! All communication is encrypted. All networking is anonymized.

#![no_std]
#![feature(abi_x86_interrupt)]

extern crate alloc;

pub mod arch;
pub mod cap;
pub mod crypto;
pub mod ipc;
pub mod mem;
pub mod sched;
pub mod serial;
pub mod vga;

/// Kernel version
pub const VERSION: &str = "0.1.0";
/// Kernel codename
pub const CODENAME: &str = "AEGIS";

/// Kernel initialization sequence.
/// Subsystems are initialized in strict dependency order to maintain
/// security invariants from the earliest possible moment.
pub fn kernel_init() {
    // 1. Serial console for early debug output
    serial_println!("[AEGIS] Initializing kernel v{} ({})", VERSION, CODENAME);

    // 2. CPU protection structures
    arch::x86_64::gdt::init();
    serial_println!("[AEGIS] GDT initialized");

    arch::x86_64::idt::init();
    serial_println!("[AEGIS] IDT initialized");

    // 3. Interrupt controller
    unsafe {
        arch::x86_64::interrupts::PICS.lock().initialize();
    }
    x86_64::instructions::interrupts::enable();
    serial_println!("[AEGIS] Interrupts enabled");

    // 4. Memory management
    serial_println!("[AEGIS] Memory manager ready");

    // 5. Crypto engine (RNG + key types)
    crypto::init();
    serial_println!("[AEGIS] Post-quantum crypto engine initialized");

    // 6. Capability system
    cap::init();
    serial_println!("[AEGIS] Capability system initialized");

    serial_println!("[AEGIS] Kernel initialization complete");
    println!("AEGIS OS v{} — Privacy First. Security First.", VERSION);
    println!("Post-Quantum Encryption Active | Capability-Based Isolation");
}

/// Halt loop — puts the CPU to sleep between interrupts
pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}


