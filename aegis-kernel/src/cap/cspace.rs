//! Capability Space (CSpace) — per-process capability table.
//!
//! Each process owns exactly one CSpace that defines ALL resources
//! it can access. A process cannot reference any kernel object
//! without a valid capability in its CSpace.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::capability::{CapError, CapSlotIndex, Capability};
use super::rights::Rights;

/// Maximum capabilities per process.
const MAX_CAPS_PER_PROCESS: usize = 1024;

/// Capability Space — the complete set of capabilities owned by a process.
///
/// Provides the ONLY mechanism for a process to reference kernel objects.
/// Operations:
/// - lookup: find a capability by slot index
/// - insert: add a new capability (kernel-only)
/// - derive: create a child capability with reduced rights
/// - revoke: destroy a capability and ALL its derivatives (cascade)
pub struct CSpace {
    /// Capability slots indexed by slot number
    slots: BTreeMap<CapSlotIndex, Capability>,
    /// Next available slot index
    next_slot: u32,
    /// Owning process ID
    owner: u64,
}

impl CSpace {
    /// Create a new empty capability space for a process.
    pub fn new(owner: u64) -> Self {
        Self {
            slots: BTreeMap::new(),
            next_slot: 0,
            owner,
        }
    }

    /// Look up a capability by slot index.
    ///
    /// Returns the capability if the slot is occupied, error otherwise.
    /// This is the first step of every syscall — find the capability
    /// the caller is presenting.
    pub fn lookup(&self, slot: CapSlotIndex) -> Result<&Capability, CapError> {
        self.slots.get(&slot).ok_or(CapError::SlotEmpty)
    }

    /// Insert a new capability into the space.
    ///
    /// Only the kernel can call this directly (when creating root capabilities
    /// for a process or when a capability is granted to this process).
    pub fn insert(&mut self, cap: Capability) -> Result<CapSlotIndex, CapError> {
        if self.slots.len() >= MAX_CAPS_PER_PROCESS {
            return Err(CapError::CSpaceFull);
        }

        let slot = CapSlotIndex::new(self.next_slot);
        self.next_slot += 1;
        self.slots.insert(slot, cap);
        Ok(slot)
    }

    /// Derive a new capability with reduced rights from an existing one.
    ///
    /// The new capability's rights must be a strict subset of the source's.
    /// This is how a parent process grants a child access to resources:
    /// it derives a reduced-rights capability and transfers it.
    pub fn derive(
        &mut self,
        source_slot: CapSlotIndex,
        new_rights: Rights,
    ) -> Result<CapSlotIndex, CapError> {
        let source = self.slots.get(&source_slot).ok_or(CapError::SlotEmpty)?;
        let derived = source.derive(new_rights, source_slot)?;
        self.insert(derived)
    }

    /// Revoke a capability and ALL capabilities derived from it.
    ///
    /// Cascade revocation ensures that when authority is revoked,
    /// ALL downstream delegations are also revoked. This prevents
    /// a child process from retaining access after the parent revokes.
    pub fn revoke(&mut self, slot: CapSlotIndex) -> Result<(), CapError> {
        if !self.slots.contains_key(&slot) {
            return Err(CapError::SlotEmpty);
        }

        // Find all capabilities derived from this slot (cascade)
        let derived_slots: Vec<CapSlotIndex> = self
            .slots
            .iter()
            .filter(|(_, cap)| cap.parent() == Some(slot))
            .map(|(s, _)| *s)
            .collect();

        // Recursively revoke derived capabilities first
        for derived_slot in derived_slots {
            let _ = self.revoke(derived_slot);
        }

        // Remove the capability itself
        self.slots.remove(&slot);
        Ok(())
    }

    /// Remove a single capability without cascade.
    #[allow(dead_code)]
    pub fn remove(&mut self, slot: CapSlotIndex) -> Result<Capability, CapError> {
        self.slots.remove(&slot).ok_or(CapError::SlotEmpty)
    }

    /// Number of capabilities in this space.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Check if the space is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Get the owning process ID.
    #[allow(dead_code)]
    pub fn owner(&self) -> u64 {
        self.owner
    }
}
