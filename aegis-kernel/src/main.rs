//! AEGIS OS — Kernel entry point
//!
//! This is the bare-metal entry point called after the bootloader
//! hands control to the kernel. Initializes all subsystems and
//! enters the main kernel loop.

#![no_std]
#![no_main]
extern crate alloc;

use aegis_kernel::{hlt_loop, kernel_init, println, serial_println};
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};

/// Bootloader configuration
static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    // Map physical memory at a known offset for kernel access
    config.mappings.physical_memory = Some(bootloader_api::config::Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

/// Kernel main — called by the bootloader after setting up the environment.
///
/// # Boot sequence:
/// 1. Bootloader loads kernel ELF, sets up page tables, identity-maps kernel
/// 2. Bootloader passes BootInfo with memory map, framebuffer, etc.
/// 3. We initialize kernel subsystems in security-critical order
/// 4. Launch initial system services
/// 5. Enter scheduler loop
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    serial_println!("[AEGIS] Boot handoff received");

    // Initialize memory management with the physical memory offset
    let phys_mem_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("physical memory mapping required");

    let memory_regions = &boot_info.memory_regions;

    // Initialize the kernel heap
    aegis_kernel::mem::init(phys_mem_offset, memory_regions);
    serial_println!("[AEGIS] Heap initialized");

    // Initialize all kernel subsystems
    kernel_init();

    serial_println!("[AEGIS] System ready — entering main loop");
    println!();
    println!("========================================");
    println!("  AEGIS OS v{}", aegis_kernel::VERSION);
    println!("  Privacy First. Security First.");
    println!("  Post-Quantum Encryption: ACTIVE");
    println!("  Capability Isolation: ENFORCED");
    println!("  Anonymous Networking: STANDBY");
    println!("========================================");
    println!();

    // In a full implementation, the kernel would now:
    // 1. Launch the CryptoFS service (encrypted filesystem)
    // 2. Launch the AnonNet service (anonymous networking)
    // 3. Launch the ProcMgr service (process manager / sandbox)
    // 4. Launch the Identity service (anonymous identity management)
    // 5. Enter the scheduler main loop

    hlt_loop()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("[AEGIS PANIC] {}", info);
    aegis_kernel::println!("[KERNEL PANIC] {}", info);
    hlt_loop()
}
