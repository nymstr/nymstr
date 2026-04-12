//! MLS (Message Layer Security) implementation — RFC 9420
//!
//! Provides:
//! - MLS client with PGP-based identity credentials
//! - Key package generation and exchange
//! - Group conversation management
//! - Epoch-aware message buffering for out-of-order delivery

pub mod client;
pub mod epoch_buffer;
pub mod key_packages;
pub mod types;

pub use client::{MlsClient, MlsKeyManager, PgpCredential, PgpIdentityProvider};
pub use epoch_buffer::{BufferStats, BufferedMessage, EpochAwareBuffer, PendingMlsMessage};
pub use key_packages::{
    generate_signed_bundle, verify_bundle, KeyPackageManager, KeyPackageValidationResult,
    SignedKeyPackageBundle,
};
pub use types::{
    ConversationInfo, ConversationType, CredentialValidationResult, EncryptedMessage,
    MlsAddMemberResult, MlsCredential, MlsGroupInfo, MlsGroupInfoPublic, MlsMessageType,
    MlsWelcome, StoredWelcome,
};
