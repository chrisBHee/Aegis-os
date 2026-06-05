//! Interrupt Descriptor Table (IDT) setup.
//! Registers handlers for CPU exceptions and hardware interrupts.
//! Double fault handler uses a dedicated stack (IST) for safety.

use lazy_static::lazy_static;
use x86_64::structures::idt::InterruptDescriptorTable;

use super::gdt;
use super::interrupts;

lazy_static! {
    /// Interrupt Descriptor Table with all exception and interrupt handlers.
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();

        // CPU exception handlers
        idt.breakpoint.set_handler_fn(interrupts::breakpoint_handler);

        unsafe {
            idt.double_fault
                .set_handler_fn(interrupts::double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }

        idt.page_fault.set_handler_fn(interrupts::page_fault_handler);
        idt.general_protection_fault.set_handler_fn(interrupts::general_protection_handler);

        // Hardware interrupt handlers (PIC)
        idt[interrupts::InterruptIndex::Timer.as_u8()]
            .set_handler_fn(interrupts::timer_interrupt_handler);
        idt[interrupts::InterruptIndex::Keyboard.as_u8()]
            .set_handler_fn(interrupts::keyboard_interrupt_handler);

        idt
    };
}

/// Load the IDT into the CPU.
pub fn init() {
    IDT.load();
}
