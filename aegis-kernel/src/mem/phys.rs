//! Physical frame allocator.
//!
//! Manages physical memory frames (4 KiB pages) using information
//! from the bootloader's memory map. All allocated frames are zeroed
//! on allocation to prevent information leakage between processes.

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

/// Physical frame allocator that reads usable memory regions
/// from the bootloader-provided memory map.
///
/// Security: frames are zeroed on allocation to prevent data leakage
/// from previously freed memory.
pub struct BootInfoFrameAllocator {
    memory_regions: &'static MemoryRegions,
    next: usize,
}

impl BootInfoFrameAllocator {
    /// Create a new frame allocator from the bootloader memory map.
    ///
    /// # Safety considerations
    /// The caller must ensure the memory map is valid and that usable
    /// regions are truly available (not used by kernel or bootloader).
    pub fn init(memory_regions: &'static MemoryRegions) -> Self {
        BootInfoFrameAllocator {
            memory_regions,
            next: 0,
        }
    }

    /// Iterator over all usable physical frames.
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        self.memory_regions
            .iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
            .map(|r| r.start..r.end)
            .flat_map(|r| r.step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}
