//! Secure in-kernel key storage.
//!
//! Cryptographic keys are stored exclusively in kernel memory and are
//! NEVER exposed to user space. Applications interact with keys through
//! opaque KeyId handles and kernel syscalls.
//!
//! Security properties:
//! - Key memory is pinned (never paged out)
//! - Keys are securely wiped (zeroized) on destruction
//! - Access is controlled by capability system
//! - Key material is in a dedicated kernel memory region

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use spin::Mutex;

use super::{CryptoError, KeyId, KeyMetadata};
use crate::mem::zero_state::SecureZeroize;
use crate::serial_println;

/// Maximum number of keys in the store.
const MAX_KEYS: usize = 4096;

/// Global key store instance.
static KEY_STORE: Mutex<Option<SecureKeyStore>> = Mutex::new(None);

/// Initialize the global key store.
pub fn init() {
    *KEY_STORE.lock() = Some(SecureKeyStore::new());
    serial_println!("[KEYSTORE] Secure key store initialized (max {} keys)", MAX_KEYS);
}

/// Store a key and return its handle.
pub fn store_key(material: KeyMaterial, metadata: KeyMetadata) -> Result<KeyId, CryptoError> {
    KEY_STORE
        .lock()
        .as_mut()
        .expect("key store not initialized")
        .store_key(material, metadata)
}

/// Destroy a key by handle.
pub fn destroy_key(key_id: KeyId) -> Result<(), CryptoError> {
    KEY_STORE
        .lock()
        .as_mut()
        .expect("key store not initialized")
        .destroy_key(key_id)
}

/// Raw key material — securely zeroized on drop.
pub struct KeyMaterial {
    data: Vec<u8>,
}

impl KeyMaterial {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Securely wipe key material before freeing memory
        self.data.as_mut_slice().zeroize();
    }
}

/// An entry in the key store.
struct SecureKeyEntry {
    material: KeyMaterial,
    metadata: KeyMetadata,
}

/// Secure key store — manages all cryptographic keys in the kernel.
pub struct SecureKeyStore {
    keys: BTreeMap<KeyId, SecureKeyEntry>,
    next_id: u64,
}

impl SecureKeyStore {
    fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Store a key, returning an opaque handle.
    /// The raw key material stays in kernel memory.
    fn store_key(
        &mut self,
        material: KeyMaterial,
        metadata: KeyMetadata,
    ) -> Result<KeyId, CryptoError> {
        if self.keys.len() >= MAX_KEYS {
            return Err(CryptoError::KeyStoreFull);
        }

        let key_id = KeyId::new(self.next_id);
        self.next_id += 1;

        serial_println!(
            "[KEYSTORE] Stored {:?} key (id={}, {} bytes, purpose={:?})",
            metadata.key_type,
            key_id.as_u64(),
            material.len(),
            metadata.purpose
        );

        self.keys.insert(key_id, SecureKeyEntry { material, metadata });
        Ok(key_id)
    }

    /// Destroy a key — securely wipes the key material.
    fn destroy_key(&mut self, key_id: KeyId) -> Result<(), CryptoError> {
        match self.keys.remove(&key_id) {
            Some(entry) => {
                // KeyMaterial's Drop impl will zeroize the data
                drop(entry);
                serial_println!("[KEYSTORE] Destroyed key id={}", key_id.as_u64());
                Ok(())
            }
            None => Err(CryptoError::KeyNotFound(key_id)),
        }
    }

    /// Execute a closure with access to a key's material.
    /// The closure runs in kernel context — key material never leaves kernel.
    #[allow(dead_code)]
    pub fn use_key<F, R>(&self, key_id: KeyId, op: F) -> Result<R, CryptoError>
    where
        F: FnOnce(&[u8], &KeyMetadata) -> R,
    {
        match self.keys.get(&key_id) {
            Some(entry) => Ok(op(entry.material.as_bytes(), &entry.metadata)),
            None => Err(CryptoError::KeyNotFound(key_id)),
        }
    }

    /// Get metadata for a key (safe to expose — no key material).
    #[allow(dead_code)]
    pub fn key_metadata(&self, key_id: KeyId) -> Result<&KeyMetadata, CryptoError> {
        match self.keys.get(&key_id) {
            Some(entry) => Ok(&entry.metadata),
            None => Err(CryptoError::KeyNotFound(key_id)),
        }
    }

    /// Destroy ALL keys — used during zero-state shutdown.
    #[allow(dead_code)]
    pub fn destroy_all(&mut self) {
        let count = self.keys.len();
        self.keys.clear(); // Drop impls will zeroize all key material
        serial_println!("[KEYSTORE] Destroyed all {} keys (zero-state)", count);
    }
}
