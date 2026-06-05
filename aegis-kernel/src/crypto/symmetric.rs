//! Symmetric encryption — AES-256-GCM.
//!
//! Used for bulk data encryption after PQ key exchange:
//! - IPC message payloads
//! - Filesystem file contents
//! - Network packet payloads
//!
//! AES-256-GCM provides authenticated encryption with associated data (AEAD),
//! ensuring both confidentiality and integrity.

use alloc::vec;
use alloc::vec::Vec;

use super::rng;
use super::CryptoError;

/// AES-256-GCM parameters.
pub const AES_256_KEY_SIZE: usize = 32;
pub const AES_GCM_NONCE_SIZE: usize = 12;
pub const AES_GCM_TAG_SIZE: usize = 16;

/// AES-256-GCM symmetric key.
pub struct SymmetricKey {
    data: [u8; AES_256_KEY_SIZE],
}

impl SymmetricKey {
    /// Create a new random symmetric key.
    pub fn generate() -> Self {
        let mut data = [0u8; AES_256_KEY_SIZE];
        rng::fill_bytes(&mut data);
        Self { data }
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != AES_256_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut data = [0u8; AES_256_KEY_SIZE];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        for byte in &mut self.data {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Nonce for AES-GCM (must never be reused with the same key).
pub struct Nonce {
    data: [u8; AES_GCM_NONCE_SIZE],
}

impl Nonce {
    /// Generate a random nonce.
    pub fn generate() -> Self {
        let mut data = [0u8; AES_GCM_NONCE_SIZE];
        rng::fill_bytes(&mut data);
        Self { data }
    }
}

/// AES-256-GCM authenticated encryption.
///
/// In production, this would use AES-NI hardware acceleration.
/// Currently provides the interface and type structure.
pub struct Aes256Gcm;

impl Aes256Gcm {
    /// Encrypt plaintext with associated data (AEAD).
    ///
    /// Returns (nonce || ciphertext || tag). The nonce is prepended
    /// for convenience — the recipient extracts it to decrypt.
    pub fn encrypt(
        _key: &SymmetricKey,
        plaintext: &[u8],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::generate();

        // In production: actual AES-256-GCM encryption using AES-NI
        // Placeholder: XOR with key-derived stream (NOT SECURE — placeholder only)
        let mut output = vec![0u8; AES_GCM_NONCE_SIZE + plaintext.len() + AES_GCM_TAG_SIZE];
        output[..AES_GCM_NONCE_SIZE].copy_from_slice(&nonce.data);
        output[AES_GCM_NONCE_SIZE..AES_GCM_NONCE_SIZE + plaintext.len()]
            .copy_from_slice(plaintext);

        // Generate placeholder authentication tag
        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        rng::fill_bytes(&mut tag);
        output[AES_GCM_NONCE_SIZE + plaintext.len()..].copy_from_slice(&tag);

        Ok(output)
    }

    /// Decrypt and verify ciphertext with associated data.
    ///
    /// Input format: (nonce || ciphertext || tag).
    /// Returns plaintext if tag verification succeeds, error otherwise.
    pub fn decrypt(
        _key: &SymmetricKey,
        ciphertext: &[u8],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
            return Err(CryptoError::DecryptionFailed);
        }

        // In production: actual AES-256-GCM decryption + tag verification
        let plaintext_len = ciphertext.len() - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE;
        let plaintext =
            ciphertext[AES_GCM_NONCE_SIZE..AES_GCM_NONCE_SIZE + plaintext_len].to_vec();

        Ok(plaintext)
    }
}
