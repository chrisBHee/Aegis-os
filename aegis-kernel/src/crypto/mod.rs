//! Post-Quantum Cryptography Engine.
//!
//! Provides quantum-resistant cryptographic primitives for all AEGIS subsystems:
//! - ML-KEM-1024 (FIPS 203): Key encapsulation for IPC, networking, filesystem
//! - ML-DSA-65 (FIPS 204): Digital signatures for boot, capabilities, code signing
//! - SLH-DSA (FIPS 205): Hash-based signatures as a stateless fallback
//! - Hybrid schemes: X25519 + ML-KEM for defense in depth
//! - AES-256-GCM: Symmetric encryption for bulk data
//! - SHA3-512: Quantum-resistant hashing
//!
//! All key material is stored in the SecureKeyStore and never exposed
//! to user space. Keys are securely wiped (zeroized) on destruction.

pub mod hybrid;
pub mod keystore;
pub mod pq_kem;
pub mod pq_sign;
pub mod rng;
pub mod symmetric;

use alloc::string::String;

use crate::serial_println;

/// Initialize the crypto engine.
/// Sets up the CSPRNG from hardware entropy and prepares the key store.
pub fn init() {
    rng::init();
    keystore::init();
    serial_println!("[CRYPTO] Post-quantum crypto engine initialized");
    serial_println!("[CRYPTO] Algorithms: ML-KEM-1024, ML-DSA-65, AES-256-GCM, SHA3-512");
}

/// Unique identifier for a cryptographic key stored in the kernel key store.
/// User space receives these handles but never the raw key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(u64);

impl KeyId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Errors that can occur during cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    /// Insufficient entropy for key generation
    InsufficientEntropy,
    /// Key not found in key store
    KeyNotFound(KeyId),
    /// Decryption failed (wrong key or tampered ciphertext)
    DecryptionFailed,
    /// Signature verification failed
    SignatureInvalid,
    /// Key store is full
    KeyStoreFull,
    /// Invalid key length
    InvalidKeyLength,
    /// Internal crypto error
    InternalError(String),
}

/// Metadata about a stored key.
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// Type of key (symmetric, KEM public/private, signing)
    pub key_type: KeyType,
    /// What this key is used for
    pub purpose: KeyPurpose,
    /// Creation timestamp (monotonic clock ticks)
    pub created_at: u64,
    /// Owner process ID (or kernel if 0)
    pub owner: u64,
}

/// Types of cryptographic keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// AES-256 symmetric key
    Symmetric256,
    /// ML-KEM-1024 public key
    MlKemPublic,
    /// ML-KEM-1024 private key (decapsulation)
    MlKemPrivate,
    /// ML-DSA-65 public key (verification)
    MlDsaPublic,
    /// ML-DSA-65 signing key
    MlDsaSigning,
    /// X25519 public key (classical ECDH)
    X25519Public,
    /// X25519 private key
    X25519Private,
    /// Hybrid public key (X25519 + ML-KEM)
    HybridPublic,
    /// Hybrid private key
    HybridPrivate,
}

/// Purpose of a key — binds keys to specific uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// IPC channel encryption
    IpcChannel,
    /// Filesystem data encryption key
    FilesystemDek,
    /// Filesystem master key
    FilesystemMaster,
    /// Boot verification
    BootVerification,
    /// Capability authentication
    CapabilityAuth,
    /// Network circuit encryption
    NetworkCircuit,
    /// Ephemeral identity
    EphemeralIdentity,
    /// General purpose
    General,
}
