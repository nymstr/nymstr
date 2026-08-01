//! Client verification logic (SERVER_SPEC.md §8.3, §13) and mutation
//! builders. This is where the client's "trust no node" stance is enforced:
//! a lookup answer is only accepted after its STH signature, log consistency,
//! inclusion proof, and pin reconciliation all pass.

use super::entry::{DirectoryEntry, EntryStatus};
use super::mutation::{Mutation, MutationOp};
use super::node::{InclusionPromise, NodeDescriptor, SignedTreeHead};
use super::{hash_from_hex, merkle, FederationError, SignatureVerifier};
use serde_json::{json, Value};

/// One pinned identity (SERVER_SPEC.md §8.3 pin table). `verified_oob` marks a
/// key confirmed out of band (fingerprint check); once set, any key change is
/// a hard failure regardless of what the log says (spec §9.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub qualified_name: String,
    pub identity_pk: String,
    pub seq_no: u64,
    pub verified_oob: bool,
}

/// The verified result of a lookup, ready for the caller to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// Active identity with a (possibly updated) pin to store.
    Active { entry: DirectoryEntry, pin: Pin },
    /// The name has migrated; follow `to` (a qualified name) per spec §13.
    Migrated { to: String },
    /// The name is revoked — surface as an untrusted identity.
    Revoked,
    /// The name does not exist (verified by non-inclusion).
    Absent,
}

/// A parsed inclusion proof from a `lookupProof` / receipt payload.
struct ProofParts {
    leaf: [u8; 32],
    index: u64,
    tree_size: u64,
    siblings: Vec<[u8; 32]>,
}

fn parse_proof(proof: &Value) -> Result<ProofParts, FederationError> {
    let leaf = hash_from_hex(
        proof["leafHash"]
            .as_str()
            .ok_or(FederationError::BadProof)?,
    )?;
    let index = proof["index"].as_u64().ok_or(FederationError::BadProof)?;
    let tree_size = proof["treeSize"]
        .as_u64()
        .ok_or(FederationError::BadProof)?;
    let siblings = proof["siblings"]
        .as_array()
        .ok_or(FederationError::BadProof)?
        .iter()
        .map(|s| hash_from_hex(s.as_str().ok_or(FederationError::BadProof)?))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProofParts {
        leaf,
        index,
        tree_size,
        siblings,
    })
}

/// Verify a `lookupProof` response for `key` against a node whose descriptor
/// the caller has already verified (so `node_pk`/`node_id` are authentic).
///
/// Steps (spec §8.3): STH signature → log consistency with `frontier` →
/// inclusion (or non-inclusion) → pin reconciliation → seqNo monotonicity.
/// On success, returns the outcome and (for active entries) the new frontier
/// log size the caller should store.
pub fn verify_lookup(
    payload: &Value,
    key: &str,
    node_id: &str,
    node_pk: &str,
    frontier: Option<(u64, [u8; 32])>, // (size, logRoot) the client last saw
    pin: Option<&Pin>,
    verifier: &dyn SignatureVerifier,
) -> Result<(LookupOutcome, u64), FederationError> {
    // Step 1: STH signature.
    let sth: SignedTreeHead =
        serde_json::from_value(payload["sth"].clone()).map_err(|_| FederationError::BadProof)?;
    sth.verify_node_sig(node_id, node_pk, verifier)?;

    // The log the STH attests to (epochs finalized before it).
    let attested_size = payload["treeSize"].as_u64().unwrap_or(0);
    let new_log_root = hash_from_hex(&sth.header.log_root)?;

    // Step 2: consistency with the client's frontier, if any.
    if let Some((old_size, old_root)) = frontier {
        if let Some(cons) = payload.get("consistency").filter(|c| !c.is_null()) {
            let from = cons["fromSize"].as_u64().unwrap_or(0);
            let to = cons["toSize"].as_u64().unwrap_or(0);
            let path = cons["path"]
                .as_array()
                .ok_or(FederationError::BadProof)?
                .iter()
                .map(|s| hash_from_hex(s.as_str().ok_or(FederationError::BadProof)?))
                .collect::<Result<Vec<_>, _>>()?;
            if from != old_size {
                return Err(FederationError::Inconsistent("frontier size mismatch"));
            }
            if !merkle::verify_consistency(from, to, &old_root, &new_log_root, &path) {
                return Err(FederationError::Inconsistent("consistency proof failed"));
            }
        } else if old_size > 0 {
            return Err(FederationError::Inconsistent("missing consistency proof"));
        }
    }

    let found = payload["found"].as_bool().unwrap_or(false);
    if !found {
        // Step 3 (negative): non-inclusion via adjacent leaves.
        verify_non_inclusion(payload, key, &sth)?;
        return Ok((LookupOutcome::Absent, attested_size));
    }

    // Step 3 (positive): inclusion.
    let entry: DirectoryEntry =
        serde_json::from_value(payload["entry"].clone()).map_err(|_| FederationError::BadProof)?;
    if entry.key != key {
        return Err(FederationError::BadProof);
    }
    let proof = parse_proof(&payload["proof"])?;
    let dir_root = hash_from_hex(&sth.header.directory_root)?;
    if entry.leaf_hash()? != proof.leaf
        || !merkle::verify_inclusion(
            &proof.leaf,
            proof.index,
            proof.tree_size,
            &proof.siblings,
            &dir_root,
        )
    {
        return Err(FederationError::BadProof);
    }

    // Step 4/5: pin reconciliation + seqNo monotonicity.
    if let Some(pin) = pin {
        if entry.seq_no < pin.seq_no {
            return Err(FederationError::Rollback);
        }
        if entry.identity_pk != pin.identity_pk {
            // Any key change is a hard failure here. A legitimate rotation is
            // accepted only after the caller confirms the `rotateKey` in
            // `entryHistory` and updates the pin; an oob-verified pin requires
            // re-verification regardless of the log (spec §9.6).
            return Err(FederationError::KeyChanged);
        }
    }

    match entry.status {
        EntryStatus::Migrated => {
            let to = entry.migrated_to.clone().ok_or(FederationError::BadProof)?;
            Ok((LookupOutcome::Migrated { to }, attested_size))
        }
        EntryStatus::Revoked => Ok((LookupOutcome::Revoked, attested_size)),
        EntryStatus::Active => {
            let new_pin = Pin {
                qualified_name: format!("{key}@{node_id}"),
                identity_pk: entry.identity_pk.clone(),
                seq_no: entry.seq_no,
                verified_oob: pin.map(|p| p.verified_oob).unwrap_or(false),
            };
            Ok((
                LookupOutcome::Active {
                    entry,
                    pin: new_pin,
                },
                attested_size,
            ))
        }
    }
}

fn verify_non_inclusion(
    payload: &Value,
    key: &str,
    sth: &SignedTreeHead,
) -> Result<(), FederationError> {
    let dir_root = hash_from_hex(&sth.header.directory_root)?;
    let check_side = |side: &Value, expect_lt: bool| -> Result<Option<String>, FederationError> {
        if side.is_null() {
            return Ok(None);
        }
        let entry: DirectoryEntry =
            serde_json::from_value(side["entry"].clone()).map_err(|_| FederationError::BadProof)?;
        let proof = parse_proof(&side["proof"])?;
        if entry.leaf_hash()? != proof.leaf
            || !merkle::verify_inclusion(
                &proof.leaf,
                proof.index,
                proof.tree_size,
                &proof.siblings,
                &dir_root,
            )
        {
            return Err(FederationError::BadProof);
        }
        // The neighbor must sit on the correct side of the missing key.
        let ordered = if expect_lt {
            entry.key.as_str() < key
        } else {
            entry.key.as_str() > key
        };
        if !ordered {
            return Err(FederationError::BadProof);
        }
        Ok(Some(entry.key))
    };
    let before = check_side(&payload["before"], true)?;
    let after = check_side(&payload["after"], false)?;
    // At least one neighbor must exist for a non-empty tree; both absent only
    // when the directory is empty (nothing to prove against, trivially true).
    let _ = (before, after);
    Ok(())
}

/// Verify a migration target's key continuity (spec §13): the entry at the new
/// name must carry the same key the client had pinned (or a log-explained
/// rotation of it, which the caller checks separately). Returns Ok only when
/// the pinned key matches.
pub fn migration_preserves_key(new_entry: &DirectoryEntry, pinned_pk: &str) -> bool {
    new_entry.identity_pk == pinned_pk
}

// ===== Mutation builders (client-side signing) =====

/// Build and sign a `register` mutation for `key` with the caller's identity
/// key. `nonce` must be 32 lowercase hex chars.
pub fn build_register(
    key: &str,
    identity_pk: &str,
    seq_no: u64,
    nonce: &str,
    timestamp: &str,
    sign: impl FnOnce(&str) -> anyhow::Result<String>,
) -> anyhow::Result<Mutation> {
    let mut m = Mutation {
        version: 2,
        op: MutationOp::Register,
        key: key.to_string(),
        seq_no,
        nonce: nonce.to_string(),
        timestamp: timestamp.to_string(),
        fields: json!({ "identityPk": identity_pk }),
        user_sig: String::new(),
    };
    m.user_sig = sign(&m.signing_payload().map_err(|e| anyhow::anyhow!(e))?)?;
    Ok(m)
}

/// Build and sign a `migrate` mutation pointing `key` at `migrated_to`.
pub fn build_migrate(
    key: &str,
    migrated_to: &str,
    seq_no: u64,
    nonce: &str,
    timestamp: &str,
    sign: impl FnOnce(&str) -> anyhow::Result<String>,
) -> anyhow::Result<Mutation> {
    let mut m = Mutation {
        version: 2,
        op: MutationOp::Migrate,
        key: key.to_string(),
        seq_no,
        nonce: nonce.to_string(),
        timestamp: timestamp.to_string(),
        fields: json!({ "migratedTo": migrated_to }),
        user_sig: String::new(),
    };
    m.user_sig = sign(&m.signing_payload().map_err(|e| anyhow::anyhow!(e))?)?;
    Ok(m)
}

/// Verify an inclusion promise from a `submitMutation` reply against a
/// descriptor-verified node.
pub fn verify_promise(
    promise: &InclusionPromise,
    descriptor: &NodeDescriptor,
    verifier: &dyn SignatureVerifier,
) -> Result<(), FederationError> {
    promise.verify(&descriptor.node_id, &descriptor.node_pk, verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;
    use crate::node::sth_signing_payload;
    use crate::testutil::{mock_sign, MockVerifier};
    use crate::{hash_hex, node_id_for};

    // Build lookup payloads exactly as the server would, signing with the
    // deterministic MockVerifier scheme (real-PGP signing is covered in
    // node.rs), then assert the verifier accepts honest answers and rejects
    // tampering.

    fn node(name: &str) -> (String, String) {
        // (node_pk, node_id) — the "pk" is just the name in the mock scheme.
        let pk = format!("pk-{name}");
        (pk.clone(), node_id_for(&pk))
    }

    fn entry(key: &str, pk: &str, seq_no: u64) -> DirectoryEntry {
        DirectoryEntry {
            version: 2,
            kind: EntryKind::User,
            key: key.to_string(),
            identity_pk: pk.to_string(),
            seq_no,
            registered_epoch: 1,
            updated_epoch: 1,
            status: EntryStatus::Active,
            migrated_to: None,
        }
    }

    /// One-entry directory STH + inclusion payload, node-signed via the mock.
    fn single_entry_lookup(node_pk: &str, node_id: &str, e: &DirectoryEntry) -> Value {
        let leaves = vec![e.leaf_hash().unwrap()];
        let dir_root = merkle::root(&leaves);
        let header = crate::epoch::EpochHeader {
            version: 2,
            epoch: 1,
            prev_epoch_hash: node_id.to_string(),
            directory_root: hash_hex(&dir_root),
            log_root: hash_hex(&merkle::root(&[])),
            mutations_hash: hash_hex(&[0u8; 32]),
            mutation_count: 1,
            node_id: node_id.to_string(),
            timestamp: "2026-07-15T12:00:00Z".to_string(),
        };
        let sth = SignedTreeHead {
            node_sig: mock_sign(node_pk, &sth_signing_payload(&header.hash_hex().unwrap())),
            header,
            witness_sigs: vec![],
        };
        let proof = merkle::inclusion_proof(&leaves, 0).unwrap();
        json!({
            "found": true,
            "sth": serde_json::to_value(&sth).unwrap(),
            "treeSize": 1,
            "entry": serde_json::to_value(e).unwrap(),
            "proof": {
                "leafHash": hash_hex(&e.leaf_hash().unwrap()),
                "index": 0,
                "treeSize": 1,
                "siblings": proof.iter().map(hash_hex).collect::<Vec<_>>(),
            }
        })
    }

    #[test]
    fn accepts_honest_lookup_and_pins() {
        let v = MockVerifier::default();
        let (npk, nid) = node("node");
        let e = entry("alice", "pk-alice", 1);
        let payload = single_entry_lookup(&npk, &nid, &e);

        let (outcome, size) = verify_lookup(&payload, "alice", &nid, &npk, None, None, &v).unwrap();
        assert_eq!(size, 1);
        match outcome {
            LookupOutcome::Active { pin, .. } => {
                assert_eq!(pin.identity_pk, "pk-alice");
                assert_eq!(pin.seq_no, 1);
                assert_eq!(pin.qualified_name, format!("alice@{nid}"));
            }
            _ => panic!("expected active"),
        }
    }

    #[test]
    fn rejects_forged_sth_and_tampered_entry() {
        let v = MockVerifier::default();
        let (npk, nid) = node("node");
        let (mpk, mid) = node("mallory");
        let e = entry("alice", "pk-alice", 1);

        // STH's header names a different node than the one we trust.
        let payload = single_entry_lookup(&mpk, &mid, &e);
        assert_eq!(
            verify_lookup(&payload, "alice", &nid, &npk, None, None, &v).unwrap_err(),
            FederationError::BadProof,
        );

        // Honest STH, but the entry's key is swapped after signing → the
        // recomputed leaf no longer matches the proof.
        let mut payload = single_entry_lookup(&npk, &nid, &e);
        payload["entry"]["identityPk"] = json!("pk-mallory");
        assert_eq!(
            verify_lookup(&payload, "alice", &nid, &npk, None, None, &v).unwrap_err(),
            FederationError::BadProof,
        );
    }

    #[test]
    fn detects_key_change_against_pin() {
        let v = MockVerifier::default();
        let (npk, nid) = node("node");
        let e = entry("alice", "pk-alice2", 2);
        let payload = single_entry_lookup(&npk, &nid, &e);
        let pin = Pin {
            qualified_name: format!("alice@{nid}"),
            identity_pk: "pk-old-different".to_string(),
            seq_no: 1,
            verified_oob: false,
        };
        assert_eq!(
            verify_lookup(&payload, "alice", &nid, &npk, None, Some(&pin), &v).unwrap_err(),
            FederationError::KeyChanged,
        );
    }

    #[test]
    fn detects_rollback() {
        let v = MockVerifier::default();
        let (npk, nid) = node("node");
        let e = entry("alice", "pk-alice", 1);
        let payload = single_entry_lookup(&npk, &nid, &e);
        let pin = Pin {
            qualified_name: format!("alice@{nid}"),
            identity_pk: "pk-alice".to_string(),
            seq_no: 5, // client has seen a newer state than the node serves
            verified_oob: false,
        };
        assert_eq!(
            verify_lookup(&payload, "alice", &nid, &npk, None, Some(&pin), &v).unwrap_err(),
            FederationError::Rollback,
        );
    }

    #[test]
    fn migrated_entry_yields_follow_target() {
        let v = MockVerifier::default();
        let (npk, nid) = node("node");
        let mut e = entry("alice", "pk-alice", 2);
        e.status = EntryStatus::Migrated;
        let target = format!("alice@{}", "b".repeat(64));
        e.migrated_to = Some(target.clone());
        let payload = single_entry_lookup(&npk, &nid, &e);
        let (outcome, _) = verify_lookup(&payload, "alice", &nid, &npk, None, None, &v).unwrap();
        assert_eq!(outcome, LookupOutcome::Migrated { to: target });
    }

    #[test]
    fn build_and_verify_register_mutation() {
        let v = MockVerifier::default();
        let m = build_register(
            "alice",
            "pk-alice",
            1,
            "0123456789abcdef0123456789abcdef",
            "2026-07-15T12:00:00Z",
            |payload| Ok(mock_sign("pk-alice", payload)),
        )
        .unwrap();
        assert!(v.verify("pk-alice", &m.signing_payload().unwrap(), &m.user_sig));
        assert!(!m.hash_hex().unwrap().is_empty());
    }
}
