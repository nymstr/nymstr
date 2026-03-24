//! Nymstr cryptographic operations — PGP key management, signing, and verification.
//!
//! This crate provides the canonical PGP implementation shared by all Nymstr
//! components (server, group server, desktop client).

pub mod keypair;
pub mod server_key_manager;
pub mod signing;

pub use keypair::{PgpKeyManager, SecurePassphrase};
pub use server_key_manager::ServerKeyManager;
pub use signing::{PgpSigner, VerifiedSignature};

use pgp::composed::{SignedPublicKey, SignedSecretKey};
use std::sync::Arc;

/// Arc-wrapped secret key for efficient sharing across async tasks.
pub type ArcSecretKey = Arc<SignedSecretKey>;

/// Arc-wrapped public key for efficient sharing across async tasks.
pub type ArcPublicKey = Arc<SignedPublicKey>;

/// Arc-wrapped passphrase for efficient sharing across async tasks.
pub type ArcPassphrase = Arc<SecurePassphrase>;
