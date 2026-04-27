//! AEGIS OS Hardware Abstraction Layer (HAL)
//!
//! Provides a unified interface to hardware devices, abstracting
//! platform-specific details. All hardware access goes through
//! the capability system — no driver can access hardware without
//! the appropriate device capability.
//!
//! Supported hardware (planned):
//! - Serial UART (COM1) — debug console
//! - VGA/Framebuffer — display output
//! - NVMe/AHCI — storage (encrypted by CryptoFS)
//! - virtio-net — networking (routed through AnonNet)
//! - HPET/APIC — timers
//! - Hardware RNG (RDRAND/RDSEED)

#![no_std]

/// Hardware device types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Serial port (UART)
    Serial,
    /// Display (VGA text mode or framebuffer)
    Display,
    /// Block storage device
    BlockStorage,
    /// Network interface controller
    Network,
    /// Timer device
    Timer,
    /// Hardware random number generator
    HardwareRng,
    /// Interrupt controller
    InterruptController,
}

/// Hardware device descriptor.
#[derive(Debug)]
pub struct DeviceDescriptor {
    /// Type of device
    pub device_type: DeviceType,
    /// Base I/O port or MMIO address
    pub base_address: u64,
    /// Size of the device's address range
    pub size: u64,
    /// IRQ number (if interrupt-driven)
    pub irq: Option<u8>,
    /// Human-readable name
    pub name: &'static str,
}
