//! Core capability types.
//!
//! A Capability is an unforgeable token that grants specific access rights
//! to a kernel object. Capabilities are the ONLY way to access any resource
//! in AEGIS OS — there is no other mechanism.

use super::rights::Rights;

/// Unique identifier for a kernel object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(u64);

impl ObjectId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Types of kernel objects that capabilities can reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    /// Physical or virtual memory region
    MemoryRegion,
    /// IPC endpoint for cross-process communication
    IpcEndpoint,
    /// Thread execution context
    Thread,
    /// Process (group of threads + address space)
    Process,
    /// Hardware interrupt handler
    Interrupt,
    /// Device MMIO access
    DeviceAccess,
    /// Cryptographic key handle
    CryptoKey,
    /// Network socket (forced through AnonNet)
    NetworkSocket,
    /// Filesystem node
    FsNode,
    /// Timer
    Timer,
}

/// Generation counter for use-after-revoke protection.
/// Incremented every time an object is re-created at the same ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation(u64);

impl Generation {
    pub fn new(generation: u64) -> Self {
        Self(generation)
    }

    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// A Capability — the fundamental security token of AEGIS OS.
///
/// An unforgeable, kernel-managed token granting specific rights
/// to a specific kernel object. Every syscall requires presenting
/// a valid capability with sufficient rights.
#[derive(Debug, Clone)]
pub struct Capability {
    /// The kernel object this capability references
    object_id: ObjectId,
    /// Type of the referenced object
    object_type: ObjectType,
    /// Permitted operations (bitmask)
    rights: Rights,
    /// Prevents use-after-revoke: must match object's current generation
    generation: Generation,
    /// ID of the parent capability this was derived from (None for root caps)
    parent: Option<CapSlotIndex>,
}

/// Index into a process's capability space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapSlotIndex(u32);

impl CapSlotIndex {
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl Capability {
    /// Create a new root capability (only the kernel can do this).
    pub fn new_root(
        object_id: ObjectId,
        object_type: ObjectType,
        rights: Rights,
        generation: Generation,
    ) -> Self {
        Self {
            object_id,
            object_type,
            rights,
            generation,
            parent: None,
        }
    }

    /// Derive a child capability with reduced rights.
    ///
    /// The new capability's rights MUST be a subset of this capability's rights.
    /// This ensures authority can only decrease through the delegation chain.
    pub fn derive(
        &self,
        new_rights: Rights,
        parent_slot: CapSlotIndex,
    ) -> Result<Self, CapError> {
        if !new_rights.is_subset_of(self.rights) {
            return Err(CapError::RightsEscalation);
        }

        if !self.rights.contains(Rights::GRANT) {
            return Err(CapError::InsufficientRights);
        }

        Ok(Self {
            object_id: self.object_id,
            object_type: self.object_type,
            rights: new_rights,
            generation: self.generation,
            parent: Some(parent_slot),
        })
    }

    /// Check if this capability has specific rights.
    pub fn has_rights(&self, required: Rights) -> bool {
        self.rights.contains(required)
    }

    /// Get the object ID this capability references.
    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Get the object type.
    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }

    /// Get the rights.
    pub fn rights(&self) -> Rights {
        self.rights
    }

    /// Get the generation counter.
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Get the parent slot index (None for root capabilities).
    pub fn parent(&self) -> Option<CapSlotIndex> {
        self.parent
    }
}

/// Errors from capability operations.
#[derive(Debug)]
pub enum CapError {
    /// Attempted to add rights during derivation
    RightsEscalation,
    /// Capability does not have the required rights
    InsufficientRights,
    /// Capability slot is empty
    SlotEmpty,
    /// Capability slot is already occupied
    SlotOccupied,
    /// Maximum CSpace capacity reached
    CSpaceFull,
    /// Capability's generation doesn't match object's current generation
    GenerationMismatch,
    /// Object has been destroyed
    ObjectDestroyed,
}
