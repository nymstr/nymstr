//! Server-compatible key manager wrapper.
//!
//! Provides the same API surface as the old `CryptoUtils` struct used by
//! nymstr-server and nymstr-group, backed by the shared PGP implementation.

use crate::keypair::{PgpKeyManager, SecurePassphrase};
use crate::signing::PgpSigner;
use anyhow::Result;
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use std::path::PathBuf;

/// Server-oriented key manager that stores keys in a directory keyed by username.
///
/// Provides the same API as the old `CryptoUtils` so server migration is mechanical:
/// - `new(key_dir, password)` → constructor
/// - `generate_key_pair(username)` → returns armored public key
/// - `sign_message(username, message)` → returns base64 signature
/// - `verify_signature(public_key_armored, message, signature)` → bool
pub struct ServerKeyManager {
    key_dir: PathBuf,
    passphrase: SecurePassphrase,
}

impl ServerKeyManager {
    pub fn new(key_dir: PathBuf, password: String) -> Result<Self> {
        if !key_dir.exists() {
            std::fs::create_dir_all(&key_dir)?;
        }
        Ok(Self {
            key_dir,
            passphrase: SecurePassphrase::new(password),
        })
    }

    fn user_key_dir(&self, username: &str) -> PathBuf {
        self.key_dir.join(username)
    }

    /// Generate and store a new PGP keypair for the given username.
    /// Returns the armored public key string.
    pub fn generate_key_pair(&self, username: &str) -> Result<String> {
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair(username, &self.passphrase)?;
        let key_dir = self.user_key_dir(username);
        PgpKeyManager::save_keypair(&key_dir, &secret_key, &public_key, &self.passphrase)?;
        PgpKeyManager::public_key_armored(&public_key)
    }

    /// Load the secret key for a username.
    pub fn load_private_key(&self, username: &str) -> Result<SignedSecretKey> {
        let key_dir = self.user_key_dir(username);
        match PgpKeyManager::load_keypair(&key_dir, &self.passphrase)? {
            Some((secret_key, _)) => Ok(secret_key),
            None => anyhow::bail!("No keys found for user: {}", username),
        }
    }

    /// Load the public key for a username.
    pub fn load_public_key(&self, username: &str) -> Result<SignedPublicKey> {
        let key_dir = self.user_key_dir(username);
        match PgpKeyManager::load_keypair(&key_dir, &self.passphrase)? {
            Some((_, public_key)) => Ok(public_key),
            None => anyhow::bail!("No keys found for user: {}", username),
        }
    }

    /// Check if keys exist for a username.
    pub fn keys_exist(&self, username: &str) -> bool {
        PgpKeyManager::keys_exist(&self.user_key_dir(username))
    }

    /// Sign a message using the user's private key.
    /// Returns a base64-encoded signature (matching the old server format).
    pub fn sign_message(&self, username: &str, message: &str) -> Result<String> {
        let secret_key = self.load_private_key(username)?;
        PgpSigner::sign_detached_base64(&secret_key, message.as_bytes(), &self.passphrase)
    }

    /// Verify a signature against an armored public key string.
    pub fn verify_signature(
        &self,
        public_key_armored: &str,
        message: &str,
        signature: &str,
    ) -> bool {
        PgpSigner::verify(public_key_armored, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let temp = tempfile::TempDir::new().unwrap();
        let mgr = ServerKeyManager::new(temp.path().to_path_buf(), "test-password".into()).unwrap();

        let public_key = mgr.generate_key_pair("alice").unwrap();
        assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));

        let message = "hello world";
        let signature = mgr.sign_message("alice", message).unwrap();

        assert!(mgr.verify_signature(&public_key, message, &signature));
        assert!(!mgr.verify_signature(&public_key, "wrong", &signature));
    }

    #[test]
    fn test_cross_user_verification_fails() {
        let temp = tempfile::TempDir::new().unwrap();
        let mgr = ServerKeyManager::new(temp.path().to_path_buf(), "test-password".into()).unwrap();

        let _alice_pk = mgr.generate_key_pair("alice").unwrap();
        let bob_pk = mgr.generate_key_pair("bob").unwrap();

        let signature = mgr.sign_message("alice", "test").unwrap();
        assert!(!mgr.verify_signature(&bob_pk, "test", &signature));
    }

    #[test]
    fn test_keys_exist() {
        let temp = tempfile::TempDir::new().unwrap();
        let mgr = ServerKeyManager::new(temp.path().to_path_buf(), "test-password".into()).unwrap();

        assert!(!mgr.keys_exist("alice"));
        mgr.generate_key_pair("alice").unwrap();
        assert!(mgr.keys_exist("alice"));
    }
}
