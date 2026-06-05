//! Interrupt handlers for CPU exceptions and hardware interrupts.
//! All handlers follow AEGIS security principles:
//!   - No information leakage in error messages
//!   - Secure handling of faults (no recovery from double faults)
//!   - Timer-based preemptive scheduling support

use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

use crate::{hlt_loop, print, serial_println};

/// PIC interrupt offset — hardware interrupts start at IRQ 32.
pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

/// Chained 8259 PIC (Programmable Interrupt Controller).
pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

/// Hardware interrupt indices.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

/// Breakpoint exception handler (#BP).
pub extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("[AEGIS] BREAKPOINT\n{:#?}", stack_frame);
}

/// Double fault handler (#DF) — runs on a dedicated stack (IST).
/// A double fault means the kernel is in an unrecoverable state.
/// In a full AEGIS implementation, this would trigger secure memory wipe.
pub extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    serial_println!(
        "[AEGIS] DOUBLE FAULT (error_code={})\n{:#?}",
        error_code,
        stack_frame
    );
    // TODO: Trigger SecureWiper::wipe_all_memory() before halting
    hlt_loop()
}

/// Page fault handler (#PF).
/// Logs the faulting address and error code for debugging.
/// In production, capability violations would be detected here.
pub extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    serial_println!("[AEGIS] PAGE FAULT");
    serial_println!("  Address: {:?}", Cr2::read());
    serial_println!("  Error:   {:?}", error_code);
    serial_println!("{:#?}", stack_frame);

    // In a full implementation:
    // - Check if this is a valid lazy-mapping request
    // - Check capability permissions for the faulting address
    // - If unauthorized, terminate the offending process
    hlt_loop()
}

/// General protection fault handler (#GP).
/// Catches privilege violations and invalid segment accesses.
pub extern "x86-interrupt" fn general_protection_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_println!(
        "[AEGIS] GENERAL PROTECTION FAULT (error_code={})\n{:#?}",
        error_code,
        stack_frame
    );
    hlt_loop()
}

/// Timer interrupt handler (IRQ 0).
/// Drives the preemptive scheduler. Each tick is an opportunity
/// for context switching between isolated processes.
pub extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // In a full implementation:
    // - Decrement current thread's time quantum
    // - If quantum expired, trigger context switch via scheduler
    // - Randomize next quantum to resist timing side-channels

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

/// Keyboard interrupt handler (IRQ 1).
/// Reads scancodes from the PS/2 keyboard controller.
pub extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use x86_64::instructions::port::Port;

    lazy_static::lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(
                ScancodeSet1::new(),
                layouts::Us104Key,
                HandleControl::Ignore,
            ));
    }

    let mut keyboard = KEYBOARD.lock();
    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };

    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(character) => print!("{}", character),
                DecodedKey::RawKey(key) => print!("{:?}", key),
            }
        }
    }

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
