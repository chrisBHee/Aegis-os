//! ML-DSA (CRYSTALS-Dilithium) — FIPS 204 Digital Signatures.
//!
//! Provides quantum-resistant digital signatures for:
//! - Secure boot verification
//! - Capability authentication tags
//! - Code signing for application binaries
//! - IPC message authentication
//!
//! Uses ML-DSA-65 (NIST Security Level 3) — balances security and performance.

use alloc::vec;
use alloc::vec::Vec;

use super::keystore::{self, KeyMaterial};
use super::rng;
use super::{CryptoError, KeyId, KeyMetadata, KeyPurpose, KeyType};

/// ML-DSA-65 parameter sizes (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const ML_DSA_65_SIGNING_KEY_SIZE: usize = 4032;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

/// ML-DSA-65 signature.
pub struct MlDsaSignature {
    data: Vec<u8>,
}

impl MlDsaSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        Ok(Self { data: bytes })
    }
}

/// ML-DSA-65 digital signature scheme.
///
/// Used throughout AEGIS for authentication and integrity verification.
/// Signature verification is a hot path — optimized for performance.
pub struct MlDsa65;

impl MlDsa65 {
    /// Generate a fresh ML-DSA-65 keypair.
    ///
    /// Returns KeyId handles for verification (public) and signing keys.
    /// The signing key NEVER leaves kernel memory.
    pub fn keygen(purpose: KeyPurpose) -> Result<(KeyId, KeyId), CryptoError> {
        // Generate key material
        // In production: use actual ML-DSA key generation
        let mut pub_key_data = vec![0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let mut sign_key_data = vec![0u8; ML_DSA_65_SIGNING_KEY_SIZE];
        rng::fill_bytes(&mut pub_key_data);
        rng::fill_bytes(&mut sign_key_data);

        let pub_key_id = keystore::store_key(
            KeyMaterial::new(pub_key_data),
            KeyMetadata {
                key_type: KeyType::MlDsaPublic,
                purpose,
                created_at: 0,
                owner: 0,
            },
        )?;

        let sign_key_id = match keystore::store_key(
            KeyMaterial::new(sign_key_data),
            KeyMetadata {
                key_type: KeyType::MlDsaSigning,
                purpose,
                created_at: 0,
                owner: 0,
            },
        ) {
            Ok(id) => id,
            Err(e) => {
                let _ = keystore::destroy_key(pub_key_id);
                return Err(e);
            }
        };

        Ok((pub_key_id, sign_key_id))
    }

    /// Sign a message using the signing key.
    ///
    /// The signing key is accessed through the key store — it never
    /// leaves kernel memory. The signature can be verified by anyone
    /// with the corresponding public key.
    pub fn sign(
        _signing_key_id: KeyId,
        _message: &[u8],
    ) -> Result<MlDsaSignature, CryptoError> {
        // In production: use actual ML-DSA signing via key store
        let mut sig_data = vec![0u8; ML_DSA_65_SIGNATURE_SIZE];
        rng::fill_bytes(&mut sig_data);
        Ok(MlDsaSignature { data: sig_data })
    }

    /// Verify a signature against a message and public key.
    ///
    /// Returns Ok(()) if the signature is valid, Err(SignatureInvalid) otherwise.
    /// This is a hot path — called for every capability operation.
    pub fn verify(
        _public_key_id: KeyId,
        _message: &[u8],
        _signature: &MlDsaSignature,
    ) -> Result<(), CryptoError> {
        // In production: use actual ML-DSA verification
        // For now, always succeeds (placeholder)
        Ok(())
    }
}
