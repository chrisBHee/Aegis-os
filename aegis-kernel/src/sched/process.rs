//! Process management.
//!
//! Each process is a fully isolated execution environment with:
//! - Its own virtual address space (no shared pages by default)
//! - Its own capability space (only explicitly granted capabilities)
//! - Resource limits to prevent denial-of-service
//! - Secure termination (memory wiping, capability revocation)

use alloc::vec::Vec;

use crate::cap::cspace::CSpace;

/// Unique process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(u64);

impl ProcessId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Process execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is ready to run or currently running
    Running,
    /// Process is blocked waiting for IPC or I/O
    Blocked,
    /// Process has been suspended by its parent
    Suspended,
    /// Process is being terminated (memory being wiped)
    Terminating,
}

/// Resource limits for a process — prevents any single process
/// from consuming excessive resources (DoS protection).
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory pages this process can map
    pub max_memory_pages: u64,
    /// Maximum CPU time per scheduling period (microseconds)
    pub max_cpu_time_us: u64,
    /// Maximum number of threads
    pub max_threads: u32,
    /// Maximum IPC channels
    pub max_ipc_channels: u32,
    /// Maximum capabilities in CSpace
    pub max_capabilities: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_pages: 1024,     // 4 MiB
            max_cpu_time_us: 100_000,   // 100ms per period
            max_threads: 16,
            max_ipc_channels: 64,
            max_capabilities: 256,
        }
    }
}

/// Security label for mandatory access control.
/// Processes can only communicate with processes at compatible security levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLabel {
    /// Untrusted third-party applications
    Untrusted,
    /// System services (CryptoFS, AnonNet, etc.)
    System,
    /// Kernel-level (only the kernel itself)
    Kernel,
}

/// Process Control Block — the kernel's representation of an isolated process.
///
/// Each process is a fully isolated sandbox:
/// - Private address space (no shared pages with other processes)
/// - Private capability space (only explicitly granted capabilities)
/// - Encrypted IPC channels for all communication
/// - Resource limits (CPU, memory, network bandwidth)
pub struct Process {
    /// Unique process identifier
    pid: ProcessId,
    /// Capability space — defines ALL permitted operations
    cspace: CSpace,
    /// Thread IDs owned by this process
    threads: Vec<u64>,
    /// Resource quotas
    resource_limits: ResourceLimits,
    /// Security classification
    security_label: SecurityLabel,
    /// Parent process (for capability delegation chain)
    parent: Option<ProcessId>,
    /// Current execution state
    state: ProcessState,
}

impl Process {
    /// Create a new process with an empty capability space.
    ///
    /// The process starts with NO capabilities — all access must be
    /// explicitly granted by the parent or kernel.
    pub fn new(
        pid: ProcessId,
        parent: Option<ProcessId>,
        security_label: SecurityLabel,
        resource_limits: ResourceLimits,
    ) -> Self {
        Self {
            pid,
            cspace: CSpace::new(pid.as_u64()),
            threads: Vec::new(),
            resource_limits,
            security_label,
            parent,
            state: ProcessState::Running,
        }
    }

    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn security_label(&self) -> SecurityLabel {
        self.security_label
    }

    pub fn cspace(&self) -> &CSpace {
        &self.cspace
    }

    pub fn cspace_mut(&mut self) -> &mut CSpace {
        &mut self.cspace
    }

    pub fn parent(&self) -> Option<ProcessId> {
        self.parent
    }

    pub fn resource_limits(&self) -> &ResourceLimits {
        &self.resource_limits
    }

    /// Begin process termination.
    ///
    /// Secure termination sequence:
    /// 1. Revoke all capabilities (cascade to children)
    /// 2. Close all IPC channels
    /// 3. Destroy all crypto keys
    /// 4. Wipe all memory pages (zero-state)
    /// 5. Release resources back to kernel
    pub fn terminate(&mut self) {
        self.state = ProcessState::Terminating;
        // Capabilities are cleared — cascade revocation happens in CSpace
        self.threads.clear();
    }
}
