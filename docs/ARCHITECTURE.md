# AEGIS OS Architecture

## Design Principles

1. **Zero Ambient Authority**: No process has any implicit permissions. Every single resource access requires presenting a valid capability.

2. **Defense in Depth**: Multiple layers of security — memory safety (Rust), capability isolation, encrypted IPC, PQ encryption, anonymous networking.

3. **Minimal Trusted Computing Base**: The microkernel is the ONLY trusted code. All drivers, filesystems, and services run in user space with minimal capabilities.

4. **Quantum Resistance**: All cryptographic operations use NIST-standardized post-quantum algorithms in hybrid mode with classical algorithms.

5. **Privacy by Architecture**: Anonymity is not an add-on but a fundamental architectural property enforced at the kernel level.

## Kernel Subsystems

### Capability System (`cap/`)
The capability system is the cornerstone of AEGIS security. It implements seL4-style capability-based access control where:
- Every kernel object is accessed exclusively through capabilities
- Capabilities can be derived (with reduced rights) and delegated
- Revocation cascades through the entire derivation tree
- Capabilities are authenticated with PQ-MAC tags

### Post-Quantum Crypto Engine (`crypto/`)
Provides kernel-level cryptographic services:
- **ML-KEM-1024** (FIPS 203): Key encapsulation for establishing shared secrets
- **ML-DSA-65** (FIPS 204): Digital signatures for authentication
- **AES-256-GCM**: Symmetric authenticated encryption for bulk data
- **Hybrid schemes**: Combine classical (X25519) + PQ (ML-KEM) for defense in depth
- **SecureKeyStore**: Keys stored exclusively in kernel memory, never exposed to user space
- **AegisRng**: Hardware-seeded CSPRNG for all randomness needs

### Memory Management (`mem/`)
- Physical frame allocator with security metadata
- Per-process virtual address spaces for isolation
- Kernel heap with guard pages
- Secure memory wiping (zero-state execution support)

### Scheduler (`sched/`)
- Preemptive fair-share scheduling
- Randomized time quanta (timing side-channel resistance)
- Resource quotas per process (DoS prevention)
- Secure context switching (registers cleared between processes)

### Encrypted IPC (`ipc/`)
- End-to-end encrypted channels between processes
- Kernel handles routing only — cannot read payloads
- Hybrid PQ key exchange per channel
- Sequence numbers prevent replay attacks

## Trust Boundaries

```
TRUSTED:     Hardware → UEFI Firmware → Bootloader → Microkernel
UNTRUSTED:   Everything in user space (drivers, services, apps)
```

The microkernel mediates ALL access between untrusted components through capabilities and encrypted IPC.
