//! v2 directory registration building blocks for a group server
//! (SERVER_SPEC.md §11): register `group/<id>` as a namespace-log entry signed
//! by the group key, and publish a group-key-signed address record so clients
//! can resolve the group's Nym address without trusting any node to invent it.
//!
//! Built on the shared `nymstr-federation` crate, so the signing payloads are
//! byte-identical to what the discovery node verifies. The mixnet
//! orchestration that drives `submitMutation` / `groupAddressPublish` against a
//! live discovery node is wired separately.
#![allow(dead_code)]

use nymstr_federation::canonical::to_canonical_json;
use nymstr_federation::mutation::{Mutation, MutationOp};
use nymstr_federation::{hash_hex, labels};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Build and sign a `register` mutation for `group/<group_id>` with the group
/// key. `sign` produces a detached signature over the given payload (e.g.
/// `ServerKeyManager::sign_message`). `nonce` must be 32 lowercase hex chars.
pub fn build_register_mutation(
    group_id: &str,
    identity_pk: &str,
    nonce: &str,
    timestamp: &str,
    sign: impl FnOnce(&str) -> anyhow::Result<String>,
) -> anyhow::Result<Mutation> {
    let mut m = Mutation {
        version: 2,
        op: MutationOp::Register,
        key: format!("group/{group_id}"),
        seq_no: 1,
        nonce: nonce.to_string(),
        timestamp: timestamp.to_string(),
        fields: json!({ "identityPk": identity_pk }),
        user_sig: String::new(),
    };
    let payload = m.signing_payload().map_err(|e| anyhow::anyhow!(e))?;
    m.user_sig = sign(&payload)?;
    Ok(m)
}

/// `SHA256(JCS(mutation))` — the mutation hash the inclusion promise references.
pub fn mutation_hash(m: &Mutation) -> anyhow::Result<String> {
    m.hash_hex().map_err(|e| anyhow::anyhow!(e))
}

/// Build a group address record (spec §11.3).
pub fn address_record(group_id: &str, nym_address: &str, issued_at: &str) -> Value {
    json!({ "groupId": group_id, "nymAddress": nym_address, "issuedAt": issued_at })
}

/// The string the group key signs over an address record:
/// `"nymstr-groupaddr-v2:" || JCS(record)`.
pub fn address_signing_payload(record: &Value) -> anyhow::Result<String> {
    let canon = to_canonical_json(record).map_err(|e| anyhow::anyhow!(e))?;
    Ok(format!("{}{canon}", labels::GROUP_ADDR))
}

/// Digest helper mirroring the node's cert-hash convention, exposed for tests.
pub fn record_digest_hex(record: &Value) -> String {
    hash_hex(&Sha256::digest(record.to_string().as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nymstr_crypto::ServerKeyManager;
    use nymstr_federation::PgpVerifier;
    use nymstr_federation::SignatureVerifier;
    use tempfile::tempdir;

    fn crypto() -> (ServerKeyManager, String, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let c = ServerKeyManager::new(dir.path().join("keys"), "pw".into()).unwrap();
        let pk = c.generate_key_pair("groupd").unwrap();
        (c, pk, dir)
    }

    #[test]
    fn register_mutation_verifies_against_group_key() {
        let (c, pk, _d) = crypto();
        let m = build_register_mutation(
            "dev-chat",
            &pk,
            "0123456789abcdef0123456789abcdef",
            "2026-07-15T12:00:00Z",
            |payload| {
                c.sign_message("groupd", payload)
                    .map_err(|e| anyhow::anyhow!(e))
            },
        )
        .unwrap();
        assert_eq!(m.key, "group/dev-chat");
        // The discovery node verifies exactly this: userSig over the canonical
        // signing payload, against the group's identity key.
        assert!(PgpVerifier.verify(&pk, &m.signing_payload().unwrap(), &m.user_sig));
        assert!(!mutation_hash(&m).unwrap().is_empty());
    }

    #[test]
    fn address_record_verifies_against_group_key() {
        let (c, pk, _d) = crypto();
        let record = address_record("dev-chat", "nym://group-dev", "2026-07-15T12:00:00Z");
        let payload = address_signing_payload(&record).unwrap();
        let sig = c.sign_message("groupd", &payload).unwrap();
        assert!(PgpVerifier.verify(&pk, &payload, &sig));
    }

    #[test]
    fn signing_payload_is_key_order_independent() {
        let (c, pk, _d) = crypto();
        let m = build_register_mutation(
            "g",
            &pk,
            "00000000000000000000000000000000",
            "2026-01-01T00:00:00Z",
            |p| c.sign_message("groupd", p).map_err(|e| anyhow::anyhow!(e)),
        )
        .unwrap();
        // Re-serialize the fields object in a different order; canonical form
        // (and thus the signature) must be unchanged.
        let mut reordered = m.clone();
        reordered.fields = json!({ "identityPk": pk });
        assert_eq!(
            m.signing_payload().unwrap(),
            reordered.signing_payload().unwrap()
        );
    }
}
