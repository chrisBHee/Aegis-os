//! x86_64 architecture support.
//! GDT, IDT, interrupt handling, and syscall entry.

pub mod gdt;
pub mod idt;
pub mod interrupts;
