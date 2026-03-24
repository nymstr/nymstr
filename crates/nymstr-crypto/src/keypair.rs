//! PGP key generation and management using rPGP 0.16

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use pgp::composed::{
    Deserializable, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::types::Password;
use rand::thread_rng;
use sha2::Sha256;
use std::{
    fs,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

type HmacSha256 = Hmac<Sha256>;

/// Secure passphrase for PGP operations.
///
/// Implements ZeroizeOnDrop to securely clear passphrase from memory when dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecurePassphrase {
    passphrase: String,
}

impl SecurePassphrase {
    pub fn new(passphrase: String) -> Self {
        Self { passphrase }
    }

    /// Generate a strong random passphrase (32 alphanumeric characters).
    pub fn generate_strong() -> Self {
        use rand::distributions::{Alphanumeric, DistString};
        let passphrase = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        Self::new(passphrase)
    }

    pub fn as_str(&self) -> &str {
        &self.passphrase
    }

    /// Convert to PGP Password type for use with rPGP.
    pub fn to_pgp_password(&self) -> Password {
        Password::from(self.passphrase.as_str())
    }
}

/// PGP key management utilities using rPGP 0.16.
pub struct PgpKeyManager;

impl PgpKeyManager {
    /// Generate secure PGP keypair with Ed25519 keys.
    ///
    /// Creates a keypair with:
    /// - Ed25519 primary key (certification only)
    /// - Ed25519 signing subkey
    /// - Curve25519 encryption subkey
    pub fn generate_keypair(
        user_id: &str,
        passphrase: &SecurePassphrase,
    ) -> Result<(SignedSecretKey, SignedPublicKey)> {
        log::info!("Generating Ed25519 PGP keypair for user: {}", user_id);

        let mut signkey = SubkeyParamsBuilder::default();
        signkey
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_encrypt(false)
            .can_authenticate(false);

        let mut encryptkey = SubkeyParamsBuilder::default();
        encryptkey
            .key_type(KeyType::ECDH(ECCCurve::Curve25519))
            .can_sign(false)
            .can_encrypt(true)
            .can_authenticate(false);

        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(false)
            .can_encrypt(false)
            .primary_user_id(user_id.into())
            .subkeys(vec![
                signkey
                    .build()
                    .map_err(|e| anyhow!("Failed to build signing subkey: {}", e))?,
                encryptkey
                    .build()
                    .map_err(|e| anyhow!("Failed to build encryption subkey: {}", e))?,
            ]);

        let secret_key_params = key_params
            .build()
            .map_err(|e| anyhow!("Failed to build secret key params: {}", e))?;
        let secret_key = secret_key_params
            .generate(thread_rng())
            .map_err(|e| anyhow!("Failed to generate secret key: {}", e))?;

        let signed_secret_key = secret_key
            .sign(&mut thread_rng(), &passphrase.to_pgp_password())
            .map_err(|e| anyhow!("Failed to sign secret key: {}", e))?;

        let signed_public_key = SignedPublicKey::from(signed_secret_key.clone());

        log::info!("Successfully generated Ed25519 PGP keypair for user: {}", user_id);
        Ok((signed_secret_key, signed_public_key))
    }

    /// Get armored public key string from a SignedPublicKey.
    pub fn public_key_armored(public_key: &SignedPublicKey) -> Result<String> {
        public_key
            .to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor public key: {}", e))
    }

    /// Save PGP keypair to a directory with HMAC integrity protection.
    pub fn save_keypair(
        key_dir: &Path,
        secret_key: &SignedSecretKey,
        public_key: &SignedPublicKey,
        passphrase: &SecurePassphrase,
    ) -> Result<()> {
        fs::create_dir_all(key_dir)?;

        #[cfg(unix)]
        {
            let mut dir_perms = fs::metadata(key_dir)?.permissions();
            dir_perms.set_mode(0o700);
            fs::set_permissions(key_dir, dir_perms)?;
        }

        // Save secret key with HMAC
        let secret_armored = secret_key
            .to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor secret key: {}", e))?;
        let secret_path = key_dir.join("secret.asc");
        let secret_hmac = Self::compute_hmac(&secret_armored, passphrase)?;

        fs::write(&secret_path, &secret_armored)?;
        fs::write(secret_path.with_extension("hmac"), secret_hmac)?;

        #[cfg(unix)]
        {
            let mut secret_perms = fs::metadata(&secret_path)?.permissions();
            secret_perms.set_mode(0o600);
            fs::set_permissions(&secret_path, secret_perms)?;
        }

        // Save public key with HMAC
        let public_armored = public_key
            .to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor public key: {}", e))?;
        let public_path = key_dir.join("public.asc");
        let public_hmac = Self::compute_hmac(&public_armored, passphrase)?;

        fs::write(&public_path, &public_armored)?;
        fs::write(public_path.with_extension("hmac"), public_hmac)?;

        Ok(())
    }

    /// Load PGP keypair from a directory with integrity verification.
    pub fn load_keypair(
        key_dir: &Path,
        passphrase: &SecurePassphrase,
    ) -> Result<Option<(SignedSecretKey, SignedPublicKey)>> {
        let secret_path = key_dir.join("secret.asc");
        let public_path = key_dir.join("public.asc");

        if !secret_path.exists() || !public_path.exists() {
            return Ok(None);
        }

        // Load and verify secret key
        let secret_armored = fs::read_to_string(&secret_path)?;
        Self::verify_file_hmac(&secret_armored, &secret_path.with_extension("hmac"), passphrase)?;

        let (secret_key, _) = SignedSecretKey::from_string(&secret_armored)
            .map_err(|e| anyhow!("Failed to parse secret key: {}", e))?;

        // Load and verify public key
        let public_armored = fs::read_to_string(&public_path)?;
        Self::verify_file_hmac(&public_armored, &public_path.with_extension("hmac"), passphrase)?;

        let (public_key, _) = SignedPublicKey::from_string(&public_armored)
            .map_err(|e| anyhow!("Failed to parse public key: {}", e))?;

        Ok(Some((secret_key, public_key)))
    }

    /// Check if keys exist in a directory.
    pub fn keys_exist(key_dir: &Path) -> bool {
        key_dir.join("secret.asc").exists() && key_dir.join("public.asc").exists()
    }

    /// Parse and validate a PGP public key from armored string.
    pub fn parse_public_key(public_key_armored: &str) -> Result<SignedPublicKey> {
        let (public_key, _) = SignedPublicKey::from_string(public_key_armored)
            .map_err(|e| anyhow!("Failed to parse PGP public key: {}", e))?;
        Ok(public_key)
    }

    fn compute_hmac(content: &str, passphrase: &SecurePassphrase) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
        mac.update(content.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn verify_file_hmac(content: &str, hmac_path: &Path, passphrase: &SecurePassphrase) -> Result<()> {
        if !hmac_path.exists() {
            log::warn!("No HMAC file found at {:?} - integrity verification skipped", hmac_path);
            return Ok(());
        }

        let stored_hmac = fs::read_to_string(hmac_path)?;
        let computed_hmac = Self::compute_hmac(content, passphrase)?;

        if !bool::from(
            stored_hmac
                .trim()
                .as_bytes()
                .ct_eq(computed_hmac.as_bytes()),
        ) {
            return Err(anyhow!("File integrity verification failed for {:?}", hmac_path));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let passphrase = SecurePassphrase::new("test-passphrase".into());
        let (secret_key, public_key) = PgpKeyManager::generate_keypair("testuser", &passphrase).unwrap();

        let armored = PgpKeyManager::public_key_armored(&public_key).unwrap();
        assert!(armored.contains("BEGIN PGP PUBLIC KEY BLOCK"));

        let _ = secret_key
            .to_armored_string(Default::default())
            .unwrap();
    }

    #[test]
    fn test_save_and_load_keypair() {
        let temp = tempfile::TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        let passphrase = SecurePassphrase::new("test-passphrase".into());

        let (secret_key, public_key) = PgpKeyManager::generate_keypair("testuser", &passphrase).unwrap();
        PgpKeyManager::save_keypair(&key_dir, &secret_key, &public_key, &passphrase).unwrap();

        assert!(PgpKeyManager::keys_exist(&key_dir));

        let loaded = PgpKeyManager::load_keypair(&key_dir, &passphrase).unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn test_hmac_integrity_check() {
        let temp = tempfile::TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        let passphrase = SecurePassphrase::new("test-passphrase".into());

        let (secret_key, public_key) = PgpKeyManager::generate_keypair("testuser", &passphrase).unwrap();
        PgpKeyManager::save_keypair(&key_dir, &secret_key, &public_key, &passphrase).unwrap();

        // Tamper with the secret key file
        let secret_path = key_dir.join("secret.asc");
        fs::write(&secret_path, "tampered content").unwrap();

        let result = PgpKeyManager::load_keypair(&key_dir, &passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent() {
        let temp = tempfile::TempDir::new().unwrap();
        let passphrase = SecurePassphrase::new("test".into());
        let result = PgpKeyManager::load_keypair(temp.path(), &passphrase).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_secure_passphrase_generate() {
        let p = SecurePassphrase::generate_strong();
        assert_eq!(p.as_str().len(), 32);
    }
}
