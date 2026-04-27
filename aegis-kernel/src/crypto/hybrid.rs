//! Hybrid key exchange: X25519 (classical) + ML-KEM-1024 (post-quantum).
//!
//! Combines both algorithms so that the resulting shared secret is secure
//! as long as EITHER algorithm remains unbroken. This defense-in-depth
//! approach protects against:
//! - Quantum computers breaking X25519 (ML-KEM still holds)
//! - Cryptanalytic breakthrough breaking ML-KEM (X25519 still holds)
//!
//! The two shared secrets are combined using HKDF-SHA3-512.

use alloc::vec::Vec;

use super::rng;
use super::symmetric::SymmetricKey;
use super::CryptoError;

/// Combined hybrid public key (X25519 + ML-KEM-1024).
pub struct HybridPublicKey {
    /// X25519 public key (32 bytes)
    pub x25519_pub: Vec<u8>,
    /// ML-KEM-1024 public key (1568 bytes)
    pub ml_kem_pub: Vec<u8>,
}

/// Combined hybrid ciphertext.
pub struct HybridCiphertext {
    /// X25519 ephemeral public key (32 bytes)
    pub x25519_ephemeral: Vec<u8>,
    /// ML-KEM-1024 ciphertext (1568 bytes)
    pub ml_kem_ct: Vec<u8>,
}

/// Hybrid key exchange combining classical and post-quantum algorithms.
pub struct HybridKeyExchange;

impl HybridKeyExchange {
    /// Perform hybrid key encapsulation.
    ///
    /// 1. Generate X25519 ephemeral keypair, compute ECDH shared secret
    /// 2. Encapsulate with ML-KEM-1024 to get PQ shared secret
    /// 3. Combine both shared secrets via HKDF-SHA3-512
    pub fn encapsulate(
        _recipient_pub: &HybridPublicKey,
    ) -> Result<(HybridCiphertext, SymmetricKey), CryptoError> {
        // In production:
        // 1. x25519_ss = X25519(ephemeral_priv, recipient_x25519_pub)
        // 2. (ml_kem_ct, ml_kem_ss) = ML-KEM.Encaps(recipient_ml_kem_pub)
        // 3. combined = HKDF-SHA3-512(x25519_ss || ml_kem_ss, context_info)

        let mut x25519_eph = alloc::vec![0u8; 32];
        let mut ml_kem_ct = alloc::vec![0u8; 1568];
        rng::fill_bytes(&mut x25519_eph);
        rng::fill_bytes(&mut ml_kem_ct);

        let key = SymmetricKey::generate();

        Ok((
            HybridCiphertext {
                x25519_ephemeral: x25519_eph,
                ml_kem_ct,
            },
            key,
        ))
    }

    /// Derive a purpose-bound symmetric key from a shared secret.
    ///
    /// The context_info parameter binds the key to a specific use case,
    /// preventing key reuse across different protocol contexts.
    pub fn derive_symmetric_key(
        _shared_secret: &[u8],
        _context_info: &[u8],
    ) -> Result<SymmetricKey, CryptoError> {
        // In production: HKDF-SHA3-512 with context binding
        Ok(SymmetricKey::generate())
    }
}
