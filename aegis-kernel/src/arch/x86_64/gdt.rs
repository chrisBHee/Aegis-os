//! Global Descriptor Table (GDT) setup.
//! Configures segmentation for kernel and user mode with proper isolation.
//! Includes a Task State Segment (TSS) with a separate interrupt stack
//! to prevent kernel stack overflow attacks.

use lazy_static::lazy_static;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// Interrupt Stack Table index for double fault handler.
/// Uses a dedicated stack to handle double faults safely even when
/// the kernel stack is corrupted — prevents triple faults.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Size of the interrupt stack (64 KiB).
const STACK_SIZE: usize = 4096 * 16;

lazy_static! {
    /// Task State Segment with a dedicated interrupt stack.
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            stack_start + STACK_SIZE as u64
        };
        tss
    };
}

lazy_static! {
    /// Global Descriptor Table with kernel code/data segments and TSS.
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        let data_selector = gdt.append(Descriptor::kernel_data_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(&TSS));
        (gdt, Selectors {
            code_selector,
            data_selector,
            tss_selector,
        })
    };
}

struct Selectors {
    code_selector: SegmentSelector,
    #[allow(dead_code)]
    data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

/// Initialize the GDT with kernel segments and TSS.
/// Must be called early in kernel_init before any interrupts are enabled.
pub fn init() {
    use x86_64::instructions::segmentation::{CS, Segment};
    use x86_64::instructions::tables::load_tss;

    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.code_selector);
        load_tss(GDT.1.tss_selector);
    }
}
