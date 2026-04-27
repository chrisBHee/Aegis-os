//! Access rights for capabilities.
//!
//! Rights are a bitmask attached to each capability. When deriving
//! a child capability, rights can only be REMOVED, never added.
//! This ensures monotonic authority reduction through the delegation chain.

use bitflags::bitflags;

bitflags! {
    /// Fine-grained access rights for capability-based access control.
    ///
    /// Each bit represents a specific permission. When deriving a capability
    /// for a child process, the parent can only mask OFF bits — never add new ones.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Rights: u32 {
        /// Read data from the referenced object
        const READ       = 0b0000_0000_0001;
        /// Write data to the referenced object
        const WRITE      = 0b0000_0000_0010;
        /// Execute code from the referenced object
        const EXECUTE    = 0b0000_0000_0100;
        /// Grant (delegate) this capability to another process
        const GRANT      = 0b0000_0000_1000;
        /// Revoke derived capabilities
        const REVOKE     = 0b0000_0001_0000;
        /// Map memory pages
        const MAP        = 0b0000_0010_0000;
        /// Establish IPC connections
        const CONNECT    = 0b0000_0100_0000;
        /// Use associated cryptographic key
        const ENCRYPT    = 0b0000_1000_0000;
        /// Create child objects
        const CREATE     = 0b0001_0000_0000;
        /// Destroy/delete objects
        const DESTROY    = 0b0010_0000_0000;
        /// Query object metadata (non-sensitive)
        const INSPECT    = 0b0100_0000_0000;
        /// Send data through network (requires AnonNet routing)
        const NETWORK    = 0b1000_0000_0000;

        /// Full rights — only the kernel has this initially
        const ALL = Self::READ.bits()
            | Self::WRITE.bits()
            | Self::EXECUTE.bits()
            | Self::GRANT.bits()
            | Self::REVOKE.bits()
            | Self::MAP.bits()
            | Self::CONNECT.bits()
            | Self::ENCRYPT.bits()
            | Self::CREATE.bits()
            | Self::DESTROY.bits()
            | Self::INSPECT.bits()
            | Self::NETWORK.bits();

        /// Read-only rights
        const READ_ONLY = Self::READ.bits() | Self::INSPECT.bits();

        /// Standard IPC rights
        const IPC = Self::READ.bits()
            | Self::WRITE.bits()
            | Self::CONNECT.bits();
    }
}

impl Rights {
    /// Check if these rights are a subset of another (used for derivation validation).
    /// A derived capability's rights must be a subset of the parent's rights.
    pub fn is_subset_of(self, parent: Rights) -> bool {
        self & parent == self
    }

    /// Remove rights (for capability derivation).
    pub fn remove_rights(self, to_remove: Rights) -> Rights {
        self & !to_remove
    }
}
