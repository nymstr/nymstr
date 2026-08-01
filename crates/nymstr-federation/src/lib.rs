//! Transparency-log core for the per-node namespace directory
//! (docs/SERVER_SPEC.md). Shared by the discovery server (prover), the desktop
//! app (verifier), and the group server. Every module here is pure logic — no
//! I/O, no async, no database — deterministic and testable in isolation. The
//! runtime that persists what these produce lives in `nymstr-server`.
//!
//! Layout:
//! - [`canonical`] — RFC 8785 (JCS) canonical JSON (spec §4)
//! - [`merkle`] — domain-separated SHA-256 Merkle trees, RFC 6962 shape (spec §4)
//! - [`entry`] — directory entries and leaf hashing (spec §5.1)
//! - [`mutation`] — mutation envelopes and validation (spec §6)
//! - [`epoch`] — epoch headers, batch ordering, batch application (spec §5.2, §7)
//! - [`node`] — node descriptors, signed tree heads, inclusion promises,
//!   witness signatures, fork certificates (spec §2, §5.3, §7, §12)
//! - [`witness`] — peer auditing and conflict detection (spec §12)
//! - [`verify`] — client-side lookup verification and mutation builders (spec §8.3, §13)

pub mod canonical;
pub mod entry;
pub mod epoch;
pub mod merkle;
pub mod mutation;
pub mod node;
pub mod verify;
pub mod witness;

use sha2::{Digest, Sha256};

/// Domain-separation labels (spec §2). A hash or signature computed in one
/// context must never verify in another.
pub mod labels {
    pub const LEAF: &str = "nymstr-leaf-v2:";
    pub const NODE: &str = "nymstr-node-v2:";
    pub const EMPTY: &str = "nymstr-empty-v2";
    pub const EPOCH: &str = "nymstr-epoch-v2:";
    pub const MUTATION: &str = "nymstr-mutation-v2:";
    pub const ROTATE: &str = "nymstr-rotate-v2:";
    pub const COSIGN: &str = "nymstr-cosign-v2:";
    pub const PROMISE: &str = "nymstr-promise-v2:";
    pub const BATCH: &str = "nymstr-batch-v2:";
    pub const DESCRIPTOR: &str = "nymstr-descriptor-v2:";
    pub const WITNESS: &str = "nymstr-witness-v2:";
    pub const KEY_PACKAGE: &str = "nymstr-keypackage-v2:";
    pub const GROUP_ADDR: &str = "nymstr-groupaddr-v2:";
}

/// SHA-256 over a domain label followed by arbitrary bytes.
pub fn labeled_hash(label: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// Lowercase hex encoding of a 32-byte hash (the wire representation of all
/// hashes in the protocol).
pub fn hash_hex(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

/// Parse a lowercase hex hash back into bytes.
pub fn hash_from_hex(s: &str) -> Result<[u8; 32], FederationError> {
    let bytes = hex::decode(s).map_err(|_| FederationError::MalformedHash)?;
    bytes.try_into().map_err(|_| FederationError::MalformedHash)
}

/// `nodeId = lowercase hex SHA256(armored node public key)` (spec §2.1).
pub fn node_id_for(node_pk_armored: &str) -> String {
    hash_hex(&Sha256::digest(node_pk_armored.as_bytes()).into())
}

/// Signature verification abstraction so the protocol logic does not depend on
/// the PGP stack directly. All protocol messages are UTF-8 (labels plus
/// canonical JSON), hence `&str`. The production implementation is
/// [`PgpVerifier`], bridging to `nymstr_crypto`.
pub trait SignatureVerifier {
    fn verify(&self, public_key_armored: &str, message: &str, signature: &str) -> bool;
}

/// PGP-backed [`SignatureVerifier`] using the shared `nymstr-crypto` stack.
/// The single verifier used by server, app, and group alike.
pub struct PgpVerifier;

impl SignatureVerifier for PgpVerifier {
    fn verify(&self, public_key_armored: &str, message: &str, signature: &str) -> bool {
        nymstr_crypto::PgpSigner::verify(public_key_armored, message, signature)
    }
}

/// Errors produced by federation-core validation and verification. Variants
/// are specific so that `fedObjection`/client warnings can carry a precise
/// machine-readable reason. Unifies what were previously separate server
/// (validation) and client (verification) error sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationError {
    // Serialization
    NonCanonicalNumber,
    MalformedHash,
    // Mutation validation (spec §6)
    MalformedKey,
    MalformedTimestamp,
    TimestampOutOfWindow,
    MalformedNonce,
    MissingField(&'static str),
    EntryAlreadyExists,
    EntryNotFound,
    EntryRevoked,
    EntryMigrated,
    WrongSeqNo { expected: u64, got: u64 },
    BadSignature,
    BadNewKeySignature,
    BadPrevEntryHash,
    // Batch / epoch validation (spec §7)
    BatchNotOrdered,
    DuplicateMutation,
    HeaderMismatch(&'static str),
    // Descriptors / STHs / witnessing (spec §2, §5.3, §12)
    ThresholdNotMet { have: usize, need: usize },
    DuplicateSigner(String),
    BadDescriptor(&'static str),
    BadPromise(&'static str),
    // Merkle proofs
    BadProof,
    // Client verification outcomes (spec §8.3, §13)
    Inconsistent(&'static str),
    KeyChanged,
    Rollback,
    Migrated(String),
    Revoked,
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalNumber => write!(f, "non-integer or unsafe number in canonical JSON"),
            Self::MalformedHash => write!(f, "malformed hex hash"),
            Self::MalformedKey => write!(f, "malformed directory key"),
            Self::MalformedTimestamp => write!(f, "malformed RFC3339 timestamp"),
            Self::TimestampOutOfWindow => write!(f, "timestamp outside validity window"),
            Self::MalformedNonce => write!(f, "nonce must be 32 lowercase hex chars"),
            Self::MissingField(field) => write!(f, "missing or invalid field: {field}"),
            Self::EntryAlreadyExists => write!(f, "active entry already exists for key"),
            Self::EntryNotFound => write!(f, "no entry exists for key"),
            Self::EntryRevoked => write!(f, "entry is revoked"),
            Self::EntryMigrated => write!(f, "entry is migrated"),
            Self::WrongSeqNo { expected, got } => {
                write!(f, "wrong seqNo: expected {expected}, got {got}")
            }
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::BadNewKeySignature => write!(f, "new-key signature verification failed"),
            Self::BadPrevEntryHash => write!(f, "prevEntryHash does not match current entry"),
            Self::BatchNotOrdered => write!(f, "batch is not in canonical order"),
            Self::DuplicateMutation => write!(f, "duplicate mutation in batch"),
            Self::HeaderMismatch(what) => write!(f, "recomputed header mismatch: {what}"),
            Self::ThresholdNotMet { have, need } => {
                write!(f, "threshold not met: {have} of {need} required signatures")
            }
            Self::DuplicateSigner(id) => write!(f, "duplicate signer: {id}"),
            Self::BadDescriptor(what) => write!(f, "invalid node descriptor: {what}"),
            Self::BadPromise(what) => write!(f, "invalid inclusion promise: {what}"),
            Self::BadProof => write!(f, "merkle proof verification failed"),
            Self::Inconsistent(what) => write!(f, "log inconsistency: {what}"),
            Self::KeyChanged => write!(f, "identity key changed unexpectedly"),
            Self::Rollback => write!(f, "entry rolled back below pinned state"),
            Self::Migrated(to) => write!(f, "identity migrated to {to}"),
            Self::Revoked => write!(f, "identity revoked"),
        }
    }
}

impl std::error::Error for FederationError {}

#[cfg(test)]
pub(crate) mod testutil {
    use super::SignatureVerifier;
    use std::collections::HashSet;

    /// Deterministic fake signature scheme for logic tests: a signature is
    /// valid iff it equals `sig(<pk>, <message>)`.
    #[derive(Default)]
    pub struct MockVerifier {
        pub broken_keys: HashSet<String>,
    }

    pub fn mock_sign(public_key: &str, message: &str) -> String {
        format!("sig({public_key},{message})")
    }

    impl SignatureVerifier for MockVerifier {
        fn verify(&self, public_key_armored: &str, message: &str, signature: &str) -> bool {
            !self.broken_keys.contains(public_key_armored)
                && signature == mock_sign(public_key_armored, message)
        }
    }
}
