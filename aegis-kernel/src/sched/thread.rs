//! Thread management.
//!
//! Threads are the unit of CPU scheduling within a process.
//! Each thread has its own register state but shares the process's
//! address space and capability space.

/// Unique thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(u64);

impl ThreadId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Thread execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Thread is ready to be scheduled
    Ready,
    /// Thread is currently executing on a CPU
    Running,
    /// Thread is blocked waiting for an event (IPC, timer, etc.)
    Blocked,
    /// Thread has been suspended
    Suspended,
    /// Thread has exited
    Exited,
}

/// Thread priority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(u8);

impl Priority {
    /// Lowest priority (background tasks)
    pub const LOW: Self = Self(0);
    /// Normal priority (user applications)
    pub const NORMAL: Self = Self(128);
    /// High priority (system services)
    pub const HIGH: Self = Self(192);
    /// Highest priority (kernel tasks, interrupt handlers)
    pub const CRITICAL: Self = Self(255);

    pub fn new(level: u8) -> Self {
        Self(level)
    }

    pub fn as_u8(self) -> u8 {
        self.0
    }
}

/// CPU register state saved/restored during context switches.
///
/// All general-purpose registers are saved to prevent information
/// leakage between processes during context switch.
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct CpuContext {
    // General-purpose registers
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Instruction pointer and flags
    pub rip: u64,
    pub rflags: u64,
    // Segment registers
    pub cs: u64,
    pub ss: u64,
    // CR3 — page table base (for address space switching)
    pub cr3: u64,
}

/// Thread Control Block — the kernel's representation of a thread.
pub struct Thread {
    /// Unique thread identifier
    tid: ThreadId,
    /// Process that owns this thread
    owning_process: u64,
    /// Saved CPU register state (for context switching)
    context: CpuContext,
    /// Thread scheduling priority
    priority: Priority,
    /// Current execution state
    state: ThreadState,
    /// Time quantum remaining (in timer ticks)
    quantum_remaining: u32,
}

impl Thread {
    /// Create a new thread in a process.
    pub fn new(
        tid: ThreadId,
        owning_process: u64,
        priority: Priority,
        entry_point: u64,
        stack_pointer: u64,
    ) -> Self {
        let mut context = CpuContext::default();
        context.rip = entry_point;
        context.rsp = stack_pointer;

        Self {
            tid,
            owning_process,
            context,
            priority,
            state: ThreadState::Ready,
            quantum_remaining: 10, // Default time quantum
        }
    }

    pub fn tid(&self) -> ThreadId {
        self.tid
    }

    pub fn state(&self) -> ThreadState {
        self.state
    }

    pub fn priority(&self) -> Priority {
        self.priority
    }

    pub fn owning_process(&self) -> u64 {
        self.owning_process
    }

    pub fn set_state(&mut self, state: ThreadState) {
        self.state = state;
    }

    /// Save current CPU context (called during context switch).
    pub fn save_context(&mut self, ctx: &CpuContext) {
        self.context = ctx.clone();
    }

    /// Get the saved context for restoring (called during context switch).
    pub fn context(&self) -> &CpuContext {
        &self.context
    }

    /// Decrement the time quantum. Returns true if quantum is exhausted.
    pub fn tick(&mut self) -> bool {
        if self.quantum_remaining > 0 {
            self.quantum_remaining -= 1;
        }
        self.quantum_remaining == 0
    }

    /// Reset the time quantum for a new scheduling period.
    pub fn reset_quantum(&mut self, quantum: u32) {
        self.quantum_remaining = quantum;
    }
}
