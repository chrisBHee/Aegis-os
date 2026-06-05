//! Encrypted IPC channels.
//!
//! A channel is a bidirectional, encrypted communication pipe between
//! two processes. The kernel facilitates key exchange and message routing
//! but cannot read message contents.
//!
//! Protocol:
//! 1. Two processes present IPC endpoint capabilities
//! 2. Kernel performs hybrid PQ key exchange on their behalf
//! 3. Derived symmetric key stored in SecureKeyStore
//! 4. Both processes get channel capability handles
//! 5. Messages are encrypted with AES-256-GCM using the session key

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::KeyId;

/// Unique channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(u64);

impl ChannelId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Key exchange in progress
    Establishing,
    /// Channel is active and ready for messages
    Active,
    /// Channel is being closed
    Closing,
    /// Channel has been closed and keys destroyed
    Closed,
}

/// An encrypted IPC message in transit.
pub struct IpcMessage {
    /// Sequence number (monotonically increasing per channel)
    pub sequence: u64,
    /// Encrypted payload (AES-256-GCM: nonce || ciphertext || tag)
    pub encrypted_payload: Vec<u8>,
    /// Sender process ID (routing metadata — not encrypted)
    pub sender: u64,
}

/// Encrypted IPC channel between two processes.
///
/// Security properties:
/// - End-to-end encrypted (kernel cannot read payloads)
/// - Sequence numbers prevent replay attacks
/// - Session key from hybrid PQ key exchange
/// - Keys are destroyed when channel closes
pub struct EncryptedChannel {
    id: ChannelId,
    /// Process IDs of the two endpoints
    endpoint_a: u64,
    endpoint_b: u64,
    /// Session key handle (in SecureKeyStore)
    session_key: KeyId,
    /// Next sequence number for each direction
    seq_a_to_b: AtomicU64,
    seq_b_to_a: AtomicU64,
    /// Message queues (kernel holds encrypted messages until delivered)
    queue_a_to_b: VecDeque<IpcMessage>,
    queue_b_to_a: VecDeque<IpcMessage>,
    /// Channel state
    state: ChannelState,
}

impl EncryptedChannel {
    /// Create a new encrypted IPC channel.
    ///
    /// The session_key is the result of a hybrid PQ key exchange
    /// performed by the kernel on behalf of the two processes.
    pub fn new(
        id: ChannelId,
        endpoint_a: u64,
        endpoint_b: u64,
        session_key: KeyId,
    ) -> Self {
        Self {
            id,
            endpoint_a,
            endpoint_b,
            session_key,
            seq_a_to_b: AtomicU64::new(0),
            seq_b_to_a: AtomicU64::new(0),
            queue_a_to_b: VecDeque::new(),
            queue_b_to_a: VecDeque::new(),
            state: ChannelState::Active,
        }
    }

    pub fn id(&self) -> ChannelId {
        self.id
    }

    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// Enqueue an encrypted message for delivery.
    ///
    /// The sender provides an already-encrypted payload. The kernel
    /// only handles routing — it never decrypts the message.
    pub fn send(&mut self, sender: u64, encrypted_payload: Vec<u8>) -> Result<(), IpcError> {
        if self.state != ChannelState::Active {
            return Err(IpcError::ChannelClosed);
        }

        let (seq, queue) = if sender == self.endpoint_a {
            (&self.seq_a_to_b, &mut self.queue_a_to_b)
        } else if sender == self.endpoint_b {
            (&self.seq_b_to_a, &mut self.queue_b_to_a)
        } else {
            return Err(IpcError::NotAnEndpoint);
        };

        let sequence = seq.fetch_add(1, Ordering::SeqCst);

        queue.push_back(IpcMessage {
            sequence,
            encrypted_payload,
            sender,
        });

        Ok(())
    }

    /// Dequeue the next message for a receiver.
    pub fn receive(&mut self, receiver: u64) -> Result<IpcMessage, IpcError> {
        if self.state != ChannelState::Active {
            return Err(IpcError::ChannelClosed);
        }

        let queue = if receiver == self.endpoint_b {
            &mut self.queue_a_to_b
        } else if receiver == self.endpoint_a {
            &mut self.queue_b_to_a
        } else {
            return Err(IpcError::NotAnEndpoint);
        };

        queue.pop_front().ok_or(IpcError::NoMessages)
    }

    /// Close the channel and schedule key destruction.
    pub fn close(&mut self) -> KeyId {
        self.state = ChannelState::Closed;
        self.queue_a_to_b.clear();
        self.queue_b_to_a.clear();
        // Return the key ID so the caller can destroy it
        self.session_key
    }
}

/// IPC errors.
#[derive(Debug)]
pub enum IpcError {
    /// Channel has been closed
    ChannelClosed,
    /// Caller is not an endpoint of this channel
    NotAnEndpoint,
    /// No messages available
    NoMessages,
    /// Channel capacity exceeded
    QueueFull,
    /// Key exchange failed
    KeyExchangeFailed,
}
