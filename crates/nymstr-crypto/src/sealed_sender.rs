//! Sealed sender encryption for hiding sender identity from the relay server.
//!
//! The sender encrypts their identity, signature, and payload inside an envelope
//! that only the recipient can open using their Curve25519 ECDH subkey.
//!
//! Wire format of sealed_payload:
//!   [ephemeral_public_key: 32 bytes]
//!   [nonce: 12 bytes]
//!   [ciphertext + GCM tag: variable]
//!
//! The plaintext inside is JSON:
//! ```json
//! {
//!   "sender": "alice",
//!   "sender_key_fingerprint": "hex...",
//!   "payload": { "conversation_id": "...", "mls_message": "..." },
//!   "signature": "PGP signature over sender+payload",
//!   "timestamp": 1234567890
//! }
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

const HKDF_INFO: &[u8] = b"nymstr-sealed-sender-v1";
const EPHEMERAL_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// The plaintext content inside a sealed envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedContent {
    /// Sender's username
    pub sender: String,
    /// Hex fingerprint of sender's PGP key (for recipient to look up full key)
    pub sender_key_fingerprint: String,
    /// The actual message payload (conversation_id + mls_message)
    pub payload: serde_json::Value,
    /// PGP signature over "{sender}:{timestamp}:{payload_json}"
    pub signature: String,
    /// Unix epoch timestamp
    pub timestamp: i64,
}

/// Seal a message so only the recipient can read the sender's identity.
///
/// - `content`: the plaintext SealedContent to encrypt
/// - `recipient_curve25519_pub`: the recipient's 32-byte Curve25519 public key
///
/// Returns the sealed envelope bytes (ephemeral_key || nonce || ciphertext).
pub fn seal(content: &SealedContent, recipient_curve25519_pub: &[u8; 32]) -> Result<Vec<u8>> {
    let plaintext =
        serde_json::to_vec(content).context("Failed to serialize sealed content")?;

    let recipient_pub = PublicKey::from(*recipient_curve25519_pub);

    // Ephemeral X25519 keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);

    // Derive AES-256 key via HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("Failed to create AES cipher"))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;

    // Zero the key
    zeroize::Zeroize::zeroize(&mut aes_key);

    // Assemble: ephemeral_pub (32) || nonce (12) || ciphertext
    let mut envelope = Vec::with_capacity(EPHEMERAL_KEY_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

/// Unseal a sealed sender envelope using the recipient's secret key.
///
/// - `envelope`: the raw sealed bytes (ephemeral_key || nonce || ciphertext)
/// - `recipient_secret`: the recipient's 32-byte Curve25519 secret key
///
/// Returns the decrypted SealedContent.
pub fn unseal(envelope: &[u8], recipient_secret: &[u8; 32]) -> Result<SealedContent> {
    let min_len = EPHEMERAL_KEY_LEN + NONCE_LEN + 16; // 16 = GCM tag
    if envelope.len() < min_len {
        return Err(anyhow!(
            "Sealed envelope too short ({} bytes, need at least {})",
            envelope.len(),
            min_len
        ));
    }

    // Parse components
    let ephemeral_pub_bytes: [u8; 32] = envelope[..EPHEMERAL_KEY_LEN]
        .try_into()
        .map_err(|_| anyhow!("Invalid ephemeral key length"))?;
    let nonce_bytes: [u8; NONCE_LEN] = envelope[EPHEMERAL_KEY_LEN..EPHEMERAL_KEY_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow!("Invalid nonce length"))?;
    let ciphertext = &envelope[EPHEMERAL_KEY_LEN + NONCE_LEN..];

    let ephemeral_pub = PublicKey::from(ephemeral_pub_bytes);
    let secret = StaticSecret::from(*recipient_secret);

    // ECDH shared secret
    let shared_secret = secret.diffie_hellman(&ephemeral_pub);

    // Derive AES-256 key via HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    // Decrypt
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("Failed to create AES cipher"))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("AES-GCM decryption failed — wrong recipient or tampered data"))?;

    // Zero the key
    zeroize::Zeroize::zeroize(&mut aes_key);

    // Parse JSON
    serde_json::from_slice(&plaintext).context("Failed to parse sealed content JSON")
}

/// Extract the raw 32-byte Curve25519 public key from a PGP public key's ECDH subkey.
pub fn extract_curve25519_public(pubkey: &pgp::composed::SignedPublicKey) -> Result<[u8; 32]> {
    use pgp::types::{EcdhPublicParams, PublicKeyTrait, PublicParams};

    for subkey in &pubkey.public_subkeys {
        if let PublicParams::ECDH(EcdhPublicParams::Curve25519 { ref p, .. }) =
            subkey.key.public_params()
        {
            return Ok(*p.as_bytes());
        }
    }

    Err(anyhow!("No Curve25519 ECDH subkey found in PGP public key"))
}

/// Extract the raw 32-byte Curve25519 secret key from a PGP secret key's ECDH subkey.
pub fn extract_curve25519_secret(
    secret_key: &pgp::composed::SignedSecretKey,
    passphrase: &str,
) -> Result<[u8; 32]> {
    use pgp::crypto::ecdh::SecretKey as EcdhSecretKey;
    use pgp::types::{Password, PlainSecretParams};

    let pw: Password = passphrase.into();

    for subkey in &secret_key.secret_subkeys {
        let result = subkey
            .unlock(&pw, |_pub_params, plain_secret| {
                if let PlainSecretParams::ECDH(EcdhSecretKey::Curve25519(ref curve_key)) =
                    plain_secret
                {
                    Ok(Some(*curve_key.as_bytes()))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| anyhow!("Failed to unlock subkey: {:?}", e))?
            .map_err(|e| anyhow!("Failed to extract key: {:?}", e))?;

        if let Some(bytes) = result {
            return Ok(bytes);
        }
    }

    Err(anyhow!("No Curve25519 ECDH secret subkey found in PGP secret key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        // Generate a static X25519 keypair for the recipient
        let recipient_secret_bytes: [u8; 32] = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };
        let recipient_secret = StaticSecret::from(recipient_secret_bytes);
        let recipient_public = PublicKey::from(&recipient_secret);

        let content = SealedContent {
            sender: "alice".to_string(),
            sender_key_fingerprint: "abcdef1234567890".to_string(),
            payload: serde_json::json!({
                "conversation_id": "dGVzdA==",
                "mls_message": "ZW5jcnlwdGVk"
            }),
            signature: "test_signature".to_string(),
            timestamp: 1726350000,
        };

        let sealed = seal(&content, recipient_public.as_bytes()).unwrap();

        // Verify structure: 32 + 12 + ciphertext
        assert!(sealed.len() > 32 + 12 + 16);

        let unsealed = unseal(&sealed, &recipient_secret_bytes).unwrap();
        assert_eq!(unsealed.sender, "alice");
        assert_eq!(unsealed.sender_key_fingerprint, "abcdef1234567890");
        assert_eq!(unsealed.signature, "test_signature");
        assert_eq!(unsealed.timestamp, 1726350000);
        assert_eq!(unsealed.payload["conversation_id"], "dGVzdA==");
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let recipient_secret_bytes: [u8; 32] = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };
        let recipient_secret = StaticSecret::from(recipient_secret_bytes);
        let recipient_public = PublicKey::from(&recipient_secret);

        let content = SealedContent {
            sender: "alice".to_string(),
            sender_key_fingerprint: "abc".to_string(),
            payload: serde_json::json!({}),
            signature: "sig".to_string(),
            timestamp: 0,
        };

        let sealed = seal(&content, recipient_public.as_bytes()).unwrap();

        // Try to unseal with a different secret key
        let wrong_secret: [u8; 32] = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };

        let result = unseal(&sealed, &wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let recipient_secret_bytes: [u8; 32] = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };
        let recipient_secret = StaticSecret::from(recipient_secret_bytes);
        let recipient_public = PublicKey::from(&recipient_secret);

        let content = SealedContent {
            sender: "alice".to_string(),
            sender_key_fingerprint: "abc".to_string(),
            payload: serde_json::json!({}),
            signature: "sig".to_string(),
            timestamp: 0,
        };

        let mut sealed = seal(&content, recipient_public.as_bytes()).unwrap();

        // Tamper with the ciphertext
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;

        let result = unseal(&sealed, &recipient_secret_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_too_short() {
        let result = unseal(&[0u8; 10], &[0u8; 32]);
        assert!(result.is_err());
    }
}
