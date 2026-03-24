//! PGP digital signatures using rPGP 0.16

use crate::keypair::SecurePassphrase;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey, StandaloneSignature};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize as PgpSerialize;
use pgp::types::{KeyDetails, PublicKeyTrait};
use rand::thread_rng;
use std::time::SystemTime;

/// PGP signing operations.
pub struct PgpSigner;

/// Result of signature verification.
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    pub signer_user_id: String,
    pub is_valid: bool,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl PgpSigner {
    /// Create detached PGP signature, returned as armored string.
    pub fn sign_detached(
        secret_key: &SignedSecretKey,
        data: &[u8],
        passphrase: &SecurePassphrase,
    ) -> Result<String> {
        let mut config = SignatureConfig::from_key(
            thread_rng(),
            &secret_key.primary_key,
            SignatureType::Binary,
        )
        .map_err(|e| anyhow!("Failed to create signature config: {}", e))?;

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(secret_key.fingerprint()))
                .map_err(|e| anyhow!("Failed to create fingerprint subpacket: {}", e))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(SystemTime::now().into()))
                .map_err(|e| anyhow!("Failed to create creation time subpacket: {}", e))?,
        ];

        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(
            secret_key.key_id(),
        ))
        .map_err(|e| anyhow!("Failed to create issuer subpacket: {}", e))?];

        let signature = config
            .sign(&secret_key.primary_key, &passphrase.to_pgp_password(), data)
            .map_err(|e| anyhow!("Failed to create signature: {}", e))?;

        let standalone = StandaloneSignature::new(signature);
        standalone
            .to_armored_string(Default::default())
            .map_err(|e| anyhow!("Failed to armor signature: {}", e))
    }

    /// Create detached PGP signature, returned as base64-encoded binary.
    /// This is the format the servers use for signing responses.
    pub fn sign_detached_base64(
        secret_key: &SignedSecretKey,
        data: &[u8],
        passphrase: &SecurePassphrase,
    ) -> Result<String> {
        let mut config = SignatureConfig::from_key(
            thread_rng(),
            &secret_key.primary_key,
            SignatureType::Binary,
        )
        .map_err(|e| anyhow!("Failed to create signature config: {}", e))?;

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(secret_key.fingerprint()))
                .map_err(|e| anyhow!("Failed to create fingerprint subpacket: {}", e))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(SystemTime::now().into()))
                .map_err(|e| anyhow!("Failed to create creation time subpacket: {}", e))?,
        ];

        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(
            secret_key.key_id(),
        ))
        .map_err(|e| anyhow!("Failed to create issuer subpacket: {}", e))?];

        let signature = config
            .sign(&secret_key.primary_key, &passphrase.to_pgp_password(), data)
            .map_err(|e| anyhow!("Failed to create signature: {}", e))?;

        let standalone = StandaloneSignature::new(signature);
        let bytes = PgpSerialize::to_bytes(&standalone)?;
        Ok(general_purpose::STANDARD.encode(bytes))
    }

    /// Verify a PGP signature in either armored or base64-encoded binary format.
    pub fn verify_any_format(
        public_key: &SignedPublicKey,
        data: &[u8],
        signature_str: &str,
    ) -> Result<VerifiedSignature> {
        let standalone_sig = if signature_str.starts_with("-----BEGIN PGP SIGNATURE-----") {
            let (sig, _) =
                StandaloneSignature::from_armor_single(std::io::Cursor::new(signature_str))
                    .map_err(|e| anyhow!("Failed to parse armored signature: {}", e))?;
            sig
        } else {
            let signature_bytes = general_purpose::STANDARD
                .decode(signature_str)
                .map_err(|e| anyhow!("Failed to base64-decode signature: {}", e))?;
            StandaloneSignature::from_bytes(signature_bytes.as_slice())
                .map_err(|e| anyhow!("Failed to parse binary signature: {}", e))?
        };

        let is_valid = standalone_sig
            .verify(&public_key.primary_key, data)
            .map(|_| true)
            .unwrap_or(false);

        let signer_user_id = public_key
            .details
            .users
            .first()
            .map(|uid| String::from_utf8_lossy(uid.id.id()).to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let created_at = standalone_sig.signature.config().and_then(|config| {
            config
                .hashed_subpackets
                .iter()
                .find_map(|subpkt| match &subpkt.data {
                    SubpacketData::SignatureCreationTime(dt) => Some(dt.clone()),
                    _ => None,
                })
        });

        Ok(VerifiedSignature {
            signer_user_id,
            is_valid,
            created_at,
        })
    }

    /// Convenience: verify signature and return bool.
    pub fn verify(public_key_armored: &str, message: &str, signature_str: &str) -> bool {
        let public_key = match pgp::composed::SignedPublicKey::from_string(public_key_armored) {
            Ok((pk, _)) => pk,
            Err(_) => return false,
        };
        match Self::verify_any_format(&public_key, message.as_bytes(), signature_str) {
            Ok(result) => result.is_valid,
            Err(_) => false,
        }
    }

    /// Validate that a public key is suitable for signing.
    pub fn validate_signing_key(public_key: &SignedPublicKey) -> Result<()> {
        let has_user_ids = !public_key.details.users.is_empty();
        if !has_user_ids {
            log::warn!("PGP key has no user IDs - this may cause issues");
        }

        let created = public_key.primary_key.created_at();
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let created_timestamp = created.timestamp() as u32;
        if now.saturating_sub(created_timestamp) > (10 * 365 * 24 * 60 * 60) {
            log::warn!("PGP key is older than 10 years, consider renewal");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::PgpKeyManager;

    #[test]
    fn test_sign_and_verify_armored() {
        let passphrase = SecurePassphrase::new("test-passphrase".into());
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair("testuser", &passphrase).unwrap();

        let message = b"test message to sign";
        let signature = PgpSigner::sign_detached(&secret_key, message, &passphrase).unwrap();

        let result =
            PgpSigner::verify_any_format(&public_key, message, &signature).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.signer_user_id, "testuser");
    }

    #[test]
    fn test_sign_and_verify_base64() {
        let passphrase = SecurePassphrase::new("test-passphrase".into());
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair("testuser", &passphrase).unwrap();

        let message = b"test message";
        let signature = PgpSigner::sign_detached_base64(&secret_key, message, &passphrase).unwrap();

        // base64 signatures don't start with PGP header
        assert!(!signature.starts_with("-----BEGIN"));

        let result = PgpSigner::verify_any_format(&public_key, message, &signature).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let passphrase = SecurePassphrase::new("test-passphrase".into());
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair("testuser", &passphrase).unwrap();

        let signature =
            PgpSigner::sign_detached(&secret_key, b"original", &passphrase).unwrap();

        let result =
            PgpSigner::verify_any_format(&public_key, b"tampered", &signature).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_verify_wrong_key() {
        let passphrase = SecurePassphrase::new("test-passphrase".into());
        let (secret_key, _) = PgpKeyManager::generate_keypair("alice", &passphrase).unwrap();
        let (_, other_public) = PgpKeyManager::generate_keypair("bob", &passphrase).unwrap();

        let message = b"test";
        let signature = PgpSigner::sign_detached(&secret_key, message, &passphrase).unwrap();

        let result = PgpSigner::verify_any_format(&other_public, message, &signature).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_convenience_verify() {
        let passphrase = SecurePassphrase::new("test-passphrase".into());
        let (secret_key, public_key) =
            PgpKeyManager::generate_keypair("testuser", &passphrase).unwrap();
        let public_armored = PgpKeyManager::public_key_armored(&public_key).unwrap();

        let message = "hello world";
        let signature =
            PgpSigner::sign_detached_base64(&secret_key, message.as_bytes(), &passphrase).unwrap();

        assert!(PgpSigner::verify(&public_armored, message, &signature));
        assert!(!PgpSigner::verify(&public_armored, "wrong", &signature));
    }
}
