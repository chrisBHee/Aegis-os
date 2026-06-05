# AEGIS OS

**Anonymous Encrypted Guardian & Isolation System**

A privacy-first, security-first operating system built from the ground up in Rust. Everything runs in isolation. Everything is encrypted with post-quantum cryptography. Every network connection is anonymized.

## Why AEGIS?

| Feature | Windows | macOS | Linux | **AEGIS OS** |
|---------|---------|-------|-------|-------------|
| Kernel Language | C/C++ | C/C++ | C | **Rust** (memory-safe) |
| Isolation | ACL-based | Sandbox + ACL | DAC/MAC | **Capability-based** |
| Encryption | BitLocker (AES) | FileVault (AES) | LUKS (AES) | **PQ-hybrid (ML-KEM + AES-256)** |
| Anonymity | None | None | Opt-in | **Kernel-level onion routing** |
| Telemetry | Extensive | Some | None | **Impossible by design** |
| Attack Surface | ~50M LOC | ~20M LOC | ~30M LOC | **<50K LOC microkernel** |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                 USER SPACE                        │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│   │ App      │  │ App      │  │ App      │      │
│   │ Sandbox  │  │ Sandbox  │  │ Sandbox  │      │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│        └──────────────┼──────────────┘            │
│   ┌───────────────────┴───────────────────┐      │
│   │        System Services                 │      │
│   │  AnonNet │ CryptoFS │ ProcMgr │ ID    │      │
│   └───────────────────┬───────────────────┘      │
├───────────────────────┼──────────────────────────┤
│   ┌───────────────────┴───────────────────┐      │
│   │          AEGIS MICROKERNEL             │      │
│   │  Capabilities │ PQ Crypto │ Scheduler  │      │
│   │  Encrypted IPC │ Memory  │ Interrupts  │      │
│   └───────────────────────────────────────┘      │
├──────────────────────────────────────────────────┤
│   Hardware Abstraction Layer                      │
└──────────────────────────────────────────────────┘
```

## Core Security Features

### Post-Quantum Encryption (NIST FIPS 203/204/205)
- **ML-KEM-1024** — Key encapsulation for IPC, networking, filesystem
- **ML-DSA-65** — Digital signatures for boot, capabilities, code signing
- **SLH-DSA** — Hash-based signature fallback
- **Hybrid mode** — X25519 + ML-KEM (secure if either algorithm holds)
- **AES-256-GCM** — Symmetric encryption for bulk data
- **SHA3-512** — Quantum-resistant hashing

### Capability-Based Isolation
- Zero ambient authority — every operation requires a valid capability
- Rights can only decrease through delegation chains
- Cascade revocation — revoking a capability revokes all derivatives
- No confused deputy attacks possible

### Encrypted IPC
- All inter-process communication is end-to-end encrypted
- Even the kernel cannot read IPC message payloads
- Per-channel session keys from hybrid PQ key exchange

### Anonymous Networking
- ALL traffic is onion-routed at the kernel level
- Applications cannot bypass anonymization
- Metadata stripping (MAC, TCP timestamps, OS fingerprints)
- Anonymous DNS resolution via DoH over onion routing

### Zero-State Execution
- RAM-only operation mode available
- Secure memory wiping on process termination
- Full memory wipe on shutdown (zero forensic trace)
- Crypto keys are securely zeroized on destruction

## Building

### Prerequisites

- Rust nightly toolchain
- `rust-src` component
- QEMU (for testing)

### Build

```bash
# Install nightly toolchain (handled by rust-toolchain.toml)
rustup install nightly
rustup component add rust-src llvm-tools-preview --toolchain nightly

# Build the kernel
cargo build

# Build in release mode
cargo build --release
```

### Run in QEMU

```bash
# Coming soon — requires bootimage integration
# cargo run
```

## Project Structure

```
aegis-os/
├── aegis-boot/          # UEFI bootloader (PQ-signed secure boot)
├── aegis-kernel/        # Microkernel core
│   ├── arch/            # Architecture-specific (x86_64, future aarch64)
│   ├── cap/             # Capability system (core security model)
│   ├── crypto/          # Post-quantum crypto engine
│   ├── ipc/             # Encrypted inter-process communication
│   ├── mem/             # Memory management + secure wiping
│   └── sched/           # Process isolation + scheduler
├── aegis-hal/           # Hardware Abstraction Layer
└── docs/                # Architecture documentation
```

## Roadmap

- [x] Phase 1: Kernel skeleton, memory management, crypto RNG
- [ ] Phase 2: Full PQ crypto, capability enforcement, process isolation
- [ ] Phase 3: Encrypted IPC, CryptoFS, system services
- [ ] Phase 4: AnonNet (onion routing), metadata stripping
- [ ] Phase 5: Identity service, ZK proofs, application SDK

## License

AGPL-3.0 — because privacy infrastructure should be open and auditable.
