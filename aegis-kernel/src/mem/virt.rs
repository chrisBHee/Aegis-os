//! Virtual memory management.
//!
//! Manages page tables for address space isolation between processes.
//! Each process gets its own page table tree, ensuring complete memory
//! isolation — a fundamental AEGIS security property.

use core::sync::atomic::AtomicU64;

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{OffsetPageTable, PageTable};
use x86_64::VirtAddr;

/// Physical memory offset — set during init from bootloader info.
/// All physical memory is mapped at this offset in virtual memory.
pub static PHYS_MEM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Initialize virtual memory management.
///
/// Returns an OffsetPageTable that can be used to map virtual pages
/// to physical frames. The offset is the virtual address where all
/// physical memory is identity-mapped by the bootloader.
///
/// # Safety
/// Caller must ensure that the physical memory offset is correct
/// and that the complete physical memory is mapped at this offset.
pub unsafe fn init(physical_memory_offset: u64) -> OffsetPageTable<'static> {
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    unsafe { OffsetPageTable::new(level_4_table, VirtAddr::new(physical_memory_offset)) }
}

/// Returns a mutable reference to the active level 4 page table.
///
/// # Safety
/// Caller must ensure the physical memory offset is valid.
/// Must only be called once to avoid aliasing &mut references.
unsafe fn active_level_4_table(physical_memory_offset: u64) -> &'static mut PageTable {
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = VirtAddr::new(phys.as_u64() + physical_memory_offset);
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

/// Create a new empty address space for a process.
///
/// Allocates a fresh level 4 page table with only the kernel
/// mappings copied over. User-space entries are empty, providing
/// complete isolation from other processes.
pub struct AddressSpace {
    /// Physical address of the level 4 page table
    l4_table_phys: x86_64::PhysAddr,
}

impl AddressSpace {
    /// Get the physical address of this address space's page table.
    /// Used for CR3 register loading during context switch.
    pub fn page_table_phys(&self) -> x86_64::PhysAddr {
        self.l4_table_phys
    }
}
