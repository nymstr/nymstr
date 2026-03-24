//! Server-specific pending entry types for tracking in-progress operations.

pub use nymstr_common::pending::PendingEntry;

/// Pending user registration data (username, public_key, nonce)
pub type PendingUserData = (String, String, String);

/// Pending login data (username, public_key, nonce)
pub type PendingLoginData = (String, String, String);

/// Pending group registration data
pub struct PendingGroupData {
    pub group_id: String,
    pub name: String,
    pub nym_address: String,
    pub public_key: String,
    pub description: Option<String>,
    pub is_public: bool,
    pub nonce: String,
}
