# AEGIS OS Threat Model

## Protected Against

### Quantum Computer Attacks
- All key exchange uses ML-KEM-1024 (NIST Level 5)
- All signatures use ML-DSA-65 (NIST Level 3)
- Hybrid mode (classical + PQ) provides defense in depth
- Hashing uses SHA3-512 (quantum-resistant)

### Memory Corruption Exploits
- Kernel written in Rust — no buffer overflows, use-after-free, or data races
- Stack overflow protection via guard pages and IST
- Heap overflow detection via guard pages
- NX bit enforcement on all data pages

### Privilege Escalation
- Capability-based security — no ambient authority
- Rights can only decrease through delegation
- No setuid/setgid equivalent
- Kernel validates every capability on every syscall

### Network Surveillance
- All traffic onion-routed through 3+ hops
- Metadata stripping (MAC, TCP timestamps, OS fingerprints)
- Anonymous DNS via DoH over onion routing
- Per-application circuit isolation
- Traffic analysis resistance (packet padding)

### Forensic Recovery
- Zero-state execution mode (RAM-only)
- Secure memory wiping (volatile writes, multi-pass)
- Crypto keys zeroized on destruction
- Full memory wipe on shutdown

### Side-Channel Attacks
- Randomized scheduler time quanta
- Constant-time crypto operations (planned)
- Address space isolation prevents Spectre-class attacks
- No shared memory by default between processes

### Supply Chain Attacks
- PQ-signed boot chain (ML-DSA)
- All application binaries signature-verified
- Application manifests declare required capabilities
- Users approve capability grants before launch

## Assumptions

### Trusted
- CPU hardware (Intel/AMD x86_64)
- Physical RAM during operation
- UEFI firmware
- The microkernel code itself

### Not Trusted
- Network infrastructure
- Onion routing exit nodes (end-to-end encryption)
- User-space drivers and services
- Third-party applications
- Storage devices (encrypted at rest)
