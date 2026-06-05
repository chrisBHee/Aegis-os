# AEGIS OS Cryptographic Specification

## Algorithms

### Key Encapsulation (FIPS 203)
- **Algorithm**: ML-KEM-1024 (CRYSTALS-Kyber)
- **Security Level**: NIST Level 5
- **Public Key**: 1568 bytes
- **Private Key**: 3168 bytes
- **Ciphertext**: 1568 bytes
- **Shared Secret**: 32 bytes
- **Usage**: IPC key exchange, network circuit keys, filesystem key wrapping

### Digital Signatures (FIPS 204)
- **Algorithm**: ML-DSA-65 (CRYSTALS-Dilithium)
- **Security Level**: NIST Level 3
- **Public Key**: 1952 bytes
- **Signing Key**: 4032 bytes
- **Signature**: 3309 bytes
- **Usage**: Boot verification, capability auth tags, code signing

### Hash-Based Signatures (FIPS 205)
- **Algorithm**: SLH-DSA (SPHINCS+)
- **Security Level**: NIST Level 3
- **Usage**: Fallback signatures, root of trust

### Symmetric Encryption
- **Algorithm**: AES-256-GCM
- **Key Size**: 256 bits
- **Nonce**: 96 bits (unique per message)
- **Tag**: 128 bits
- **Usage**: IPC message encryption, filesystem content encryption

### Hashing
- **Algorithm**: SHA3-512 (Keccak)
- **Output**: 512 bits
- **Usage**: Integrity verification, Merkle trees, key derivation

### Key Derivation
- **Algorithm**: HKDF-SHA3-512
- **Usage**: Deriving purpose-bound keys from shared secrets
- **Context Binding**: Each derived key is bound to a specific purpose string

### Password Hashing
- **Algorithm**: Argon2id
- **Usage**: Deriving filesystem master key from user passphrase

### Hybrid Key Exchange
- **Classical**: X25519 (Curve25519 ECDH)
- **Post-Quantum**: ML-KEM-1024
- **Combination**: HKDF-SHA3-512(X25519_SS || ML-KEM_SS, context)
- **Security**: Secure if EITHER algorithm remains unbroken

## Key Management

### SecureKeyStore
- Keys stored exclusively in pinned kernel memory
- User space accesses keys through opaque handles (KeyId)
- Keys are securely zeroized on destruction (volatile writes)
- Maximum 4096 keys per store instance

### Key Lifecycle
1. **Generation**: Keys generated using AegisRng (hardware-seeded CSPRNG)
2. **Storage**: Raw material stored in SecureKeyStore
3. **Usage**: Operations executed in kernel context via `use_key()` closure
4. **Rotation**: Periodic re-keying for long-lived channels
5. **Destruction**: Secure zeroization via `destroy_key()`

## Random Number Generation

### AegisRng
- **Primary Source**: RDRAND/RDSEED (x86_64 hardware RNG)
- **CSPRNG**: xoshiro256** (production: ChaCha20-based)
- **Reseeding**: Automatic reseeding from hardware entropy
- **Minimum Entropy**: 512 bits at initialization
- **Fallback**: TSC-based entropy if RDRAND unavailable
