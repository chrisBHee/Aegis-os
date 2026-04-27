//! Memory management subsystem.
//!
//! Provides physical frame allocation, virtual memory management,
//! kernel heap, and secure memory wiping for zero-state execution.
//!
//! Security properties:
//! - All freed pages are securely wiped before reuse
//! - Kernel heap is separate from user-space memory
//! - Guard pages protect against buffer overflows
//! - No user-space page can map kernel memory

pub mod heap;
pub mod phys;
pub mod virt;
pub mod zero_state;

use bootloader_api::info::MemoryRegions;

use self::heap::ALLOCATOR;
use self::phys::BootInfoFrameAllocator;
use self::virt::PHYS_MEM_OFFSET;

/// Kernel heap start address (mapped in virtual memory).
pub const HEAP_START: u64 = 0x_4444_4444_0000;
/// Kernel heap size: 1 MiB initial allocation.
pub const HEAP_SIZE: u64 = 1024 * 1024;

/// Initialize the memory subsystem.
///
/// Must be called early in kernel_init with the physical memory offset
/// from the bootloader and the memory map describing available regions.
pub fn init(phys_mem_offset: u64, memory_regions: &'static MemoryRegions) {
    // Store the physical memory offset for page table access
    PHYS_MEM_OFFSET.store(phys_mem_offset, core::sync::atomic::Ordering::SeqCst);

    // Initialize the physical frame allocator from the bootloader's memory map
    let mut frame_allocator = BootInfoFrameAllocator::init(memory_regions);

    // Set up kernel page tables and map the heap region
    let mut mapper = unsafe { virt::init(phys_mem_offset) };
    heap::init_heap(&mut mapper, &mut frame_allocator)
        .expect("heap initialization failed");

    // Initialize the global allocator
    unsafe {
        ALLOCATOR
            .lock()
            .init(HEAP_START as *mut u8, HEAP_SIZE as usize);
    }
}
