//! Encrypted Inter-Process Communication (IPC).
//!
//! ALL communication between processes in AEGIS is encrypted end-to-end.
//! Even the kernel cannot read IPC message payloads — it only handles
//! routing and delivery.
//!
//! Key exchange uses hybrid PQ-KEM (X25519 + ML-KEM-1024).
//! Message encryption uses AES-256-GCM with per-channel keys.
//! Sequence numbers prevent replay attacks.

pub mod channel;
