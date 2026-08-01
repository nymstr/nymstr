//! Mutation envelopes and validation (spec §5). A mutation is a client-signed
//! request to change exactly one directory entry; validation rules are
//! applied identically by every node, so this module is the single source of
//! truth both for accepting mutations into the pool and for replaying
//! batches announced by an epoch leader.

use super::canonical::canonicalize;
use super::entry::{
    validate_key, validate_qualified_name, DirectoryEntry, DirectoryState, EntryStatus,
};
use super::merkle::Hash;
use super::{hash_hex, labels, FederationError, SignatureVerifier};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Maximum clock skew between a mutation's timestamp and the reference time
/// (submission clock for live validation, epoch header time for replay).
pub const TIMESTAMP_WINDOW_SECS: i64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationOp {
    #[serde(rename = "register")]
    Register,
    #[serde(rename = "migrate")]
    Migrate,
    #[serde(rename = "rotateKey")]
    RotateKey,
    #[serde(rename = "revoke")]
    Revoke,
}

/// The unified mutation envelope (spec §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mutation {
    pub version: u32,
    pub op: MutationOp,
    pub key: String,
    pub seq_no: u64,
    pub nonce: String,
    pub timestamp: String,
    pub fields: Value,
    pub user_sig: String,
}

impl Mutation {
    /// The exact string `userSig` must sign:
    /// `"nymstr-mutation-v2:" || JCS(envelope without userSig)`.
    pub fn signing_payload(&self) -> Result<String, FederationError> {
        let mut json =
            serde_json::to_value(self).map_err(|_| FederationError::NonCanonicalNumber)?;
        json.as_object_mut()
            .expect("mutation serializes to an object")
            .remove("userSig");
        Ok(format!(
            "{}{}",
            labels::MUTATION,
            super::canonical::to_canonical_json(&json)?
        ))
    }

    /// `SHA256(JCS(mutation))` — identity for dedupe, gossip, promises, and
    /// the deterministic batch-order tiebreak.
    pub fn hash(&self) -> Result<Hash, FederationError> {
        let canon = canonicalize(self)?;
        Ok(Sha256::digest(canon.as_bytes()).into())
    }

    pub fn hash_hex(&self) -> Result<String, FederationError> {
        Ok(hash_hex(&self.hash()?))
    }

    fn field_str(&self, name: &'static str) -> Result<&str, FederationError> {
        self.fields
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(FederationError::MissingField(name))
    }

    /// Validate against directory state `state` (spec §5.5). `reference_time`
    /// is the local clock at submission for live validation, or the epoch
    /// header timestamp when replaying a historical batch (fedSync) — a
    /// synced batch must not fail because it is being replayed later.
    pub fn validate(
        &self,
        state: &DirectoryState,
        verifier: &dyn SignatureVerifier,
        reference_time: DateTime<Utc>,
    ) -> Result<(), FederationError> {
        // Rule 1: envelope well-formedness.
        if self.version != 2 {
            return Err(FederationError::MissingField("version"));
        }
        validate_key(&self.key)?;
        if self.nonce.len() != 32
            || !self
                .nonce
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(FederationError::MalformedNonce);
        }
        let ts = DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|_| FederationError::MalformedTimestamp)?
            .with_timezone(&Utc);
        if (reference_time - ts).num_seconds().abs() > TIMESTAMP_WINDOW_SECS {
            return Err(FederationError::TimestampOutOfWindow);
        }

        let existing = state.get(&self.key);
        let signing_payload = self.signing_payload()?;

        match self.op {
            // Register requires no active entry. A terminal (revoked or
            // migrated) entry may be succeeded, but only when the prior key
            // itself signs the new registration (key succession); the
            // name is otherwise burned (spec §6).
            MutationOp::Register => {
                let identity_pk = self.field_str("identityPk")?;
                match existing {
                    None => {
                        if self.seq_no != 1 {
                            return Err(FederationError::WrongSeqNo {
                                expected: 1,
                                got: self.seq_no,
                            });
                        }
                        if !verifier.verify(identity_pk, &signing_payload, &self.user_sig) {
                            return Err(FederationError::BadSignature);
                        }
                    }
                    Some(prev) if prev.status.is_terminal() => {
                        self.check_seq_no(prev)?;
                        if !verifier.verify(&prev.identity_pk, &signing_payload, &self.user_sig) {
                            return Err(FederationError::BadSignature);
                        }
                    }
                    Some(_) => return Err(FederationError::EntryAlreadyExists),
                }
            }
            // Every other op requires an active entry, a signature by its
            // current key, and the exact next seqNo (spec §6).
            MutationOp::Migrate => {
                let prev = self.require_active(existing)?;
                validate_qualified_name(self.field_str("migratedTo")?)?;
                self.check_seq_no(prev)?;
                if !verifier.verify(&prev.identity_pk, &signing_payload, &self.user_sig) {
                    return Err(FederationError::BadSignature);
                }
            }
            MutationOp::RotateKey => {
                let prev = self.require_active(existing)?;
                let new_pk = self.field_str("newIdentityPk")?;
                let new_key_sig = self.field_str("newKeySig")?;
                self.check_seq_no(prev)?;
                if !verifier.verify(&prev.identity_pk, &signing_payload, &self.user_sig) {
                    return Err(FederationError::BadSignature);
                }
                let rotate_payload = rotate_signing_payload(&self.key, self.seq_no, new_pk);
                if !verifier.verify(new_pk, &rotate_payload, new_key_sig) {
                    return Err(FederationError::BadNewKeySignature);
                }
            }
            MutationOp::Revoke => {
                let prev = self.require_active(existing)?;
                let claimed = self.field_str("prevEntryHash")?;
                self.check_seq_no(prev)?;
                if claimed != hash_hex(&prev.leaf_hash()?) {
                    return Err(FederationError::BadPrevEntryHash);
                }
                if !verifier.verify(&prev.identity_pk, &signing_payload, &self.user_sig) {
                    return Err(FederationError::BadSignature);
                }
            }
        }
        Ok(())
    }

    fn require_active<'a>(
        &self,
        existing: Option<&'a DirectoryEntry>,
    ) -> Result<&'a DirectoryEntry, FederationError> {
        let prev = existing.ok_or(FederationError::EntryNotFound)?;
        match prev.status {
            EntryStatus::Active => Ok(prev),
            EntryStatus::Revoked => Err(FederationError::EntryRevoked),
            EntryStatus::Migrated => Err(FederationError::EntryMigrated),
        }
    }

    fn check_seq_no(&self, prev: &DirectoryEntry) -> Result<(), FederationError> {
        let expected = prev.seq_no + 1;
        if self.seq_no != expected {
            return Err(FederationError::WrongSeqNo {
                expected,
                got: self.seq_no,
            });
        }
        Ok(())
    }

    /// Apply a validated mutation to produce the new entry state for its key.
    /// MUST only be called after `validate` succeeded against the same state.
    pub fn apply(
        &self,
        existing: Option<&DirectoryEntry>,
        epoch: u64,
    ) -> Result<DirectoryEntry, FederationError> {
        let kind = validate_key(&self.key)?;
        match self.op {
            MutationOp::Register => Ok(DirectoryEntry {
                version: 2,
                kind,
                key: self.key.clone(),
                identity_pk: self.field_str("identityPk")?.to_string(),
                seq_no: self.seq_no,
                registered_epoch: existing.map_or(epoch, |e| e.registered_epoch),
                updated_epoch: epoch,
                status: EntryStatus::Active,
                migrated_to: None,
            }),
            MutationOp::Migrate => {
                let prev = existing.ok_or(FederationError::EntryNotFound)?;
                Ok(DirectoryEntry {
                    seq_no: self.seq_no,
                    updated_epoch: epoch,
                    status: EntryStatus::Migrated,
                    migrated_to: Some(self.field_str("migratedTo")?.to_string()),
                    ..prev.clone()
                })
            }
            MutationOp::RotateKey => {
                let prev = existing.ok_or(FederationError::EntryNotFound)?;
                Ok(DirectoryEntry {
                    identity_pk: self.field_str("newIdentityPk")?.to_string(),
                    seq_no: self.seq_no,
                    updated_epoch: epoch,
                    ..prev.clone()
                })
            }
            MutationOp::Revoke => {
                let prev = existing.ok_or(FederationError::EntryNotFound)?;
                Ok(DirectoryEntry {
                    seq_no: self.seq_no,
                    updated_epoch: epoch,
                    status: EntryStatus::Revoked,
                    ..prev.clone()
                })
            }
        }
    }
}

/// The string the NEW key signs during rotation (spec §5.2):
/// `"nymstr-rotate-v2:" || key || ":" || seqNo || ":" || SHA256(newIdentityPk)`.
pub fn rotate_signing_payload(key: &str, seq_no: u64, new_identity_pk: &str) -> String {
    let pk_hash = hash_hex(&Sha256::digest(new_identity_pk.as_bytes()).into());
    format!("{}{key}:{seq_no}:{pk_hash}", labels::ROTATE)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::{mock_sign, MockVerifier};
    use serde_json::json;

    pub(crate) const NONCE: &str = "00112233445566778899aabbccddeeff";

    pub(crate) fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    pub(crate) fn signed(mut m: Mutation, signer_pk: &str) -> Mutation {
        m.user_sig = mock_sign(signer_pk, &m.signing_payload().unwrap());
        m
    }

    pub(crate) fn register(key: &str, pk: &str, home: &str) -> Mutation {
        signed(
            Mutation {
                version: 2,
                op: MutationOp::Register,
                key: key.to_string(),
                seq_no: 1,
                nonce: NONCE.to_string(),
                timestamp: "2026-07-15T12:00:00Z".to_string(),
                fields: json!({"identityPk": pk, "homeNode": home}),
                user_sig: String::new(),
            },
            pk,
        )
    }

    fn state_with(key: &str, pk: &str) -> DirectoryState {
        let mut state = DirectoryState::new();
        let m = register(key, pk, "node-a");
        let entry = m.apply(None, 1).unwrap();
        state.insert(entry);
        state
    }

    #[test]
    fn register_roundtrip() {
        let v = MockVerifier::default();
        let state = DirectoryState::new();
        let m = register("alice", "pk-alice", "node-a");
        m.validate(&state, &v, now()).unwrap();
        let entry = m.apply(None, 5).unwrap();
        assert_eq!(entry.key, "alice");
        assert_eq!(entry.seq_no, 1);
        assert_eq!(entry.registered_epoch, 5);
        assert_eq!(entry.status, EntryStatus::Active);
    }

    #[test]
    fn register_rejects_existing_wrong_seq_bad_sig() {
        let v = MockVerifier::default();
        let state = state_with("alice", "pk-alice");

        // Duplicate username.
        let dup = register("alice", "pk-mallory", "node-b");
        assert_eq!(
            dup.validate(&state, &v, now()).unwrap_err(),
            FederationError::EntryAlreadyExists
        );

        // seqNo must be 1 for a fresh registration.
        let mut m = register("bob", "pk-bob", "node-a");
        m.seq_no = 2;
        let m = signed(m, "pk-bob");
        assert!(matches!(
            m.validate(&state, &v, now()).unwrap_err(),
            FederationError::WrongSeqNo {
                expected: 1,
                got: 2
            }
        ));

        // Signature by a different key than the claimed identityPk.
        let forged = signed(register("carol", "pk-carol", "node-a"), "pk-mallory");
        assert_eq!(
            forged.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadSignature
        );
    }

    #[test]
    fn signature_covers_every_envelope_field() {
        let v = MockVerifier::default();
        let state = DirectoryState::new();
        let m = register("alice", "pk-alice", "node-a");
        m.validate(&state, &v, now()).unwrap();

        // Any post-signing tamper must invalidate.
        let mut t = m.clone();
        t.fields["homeNode"] = json!("node-evil");
        assert_eq!(
            t.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadSignature
        );

        let mut t = m.clone();
        t.nonce = "ffffffffffffffffffffffffffffffff".to_string();
        assert_eq!(
            t.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadSignature
        );

        let mut t = m;
        t.timestamp = "2026-07-15T12:00:01Z".to_string();
        assert_eq!(
            t.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadSignature
        );
    }

    #[test]
    fn timestamp_window_enforced_against_reference_time() {
        let v = MockVerifier::default();
        let state = DirectoryState::new();
        let m = register("alice", "pk-alice", "node-a");

        let late = now() + chrono::Duration::seconds(TIMESTAMP_WINDOW_SECS + 1);
        assert_eq!(
            m.validate(&state, &v, late).unwrap_err(),
            FederationError::TimestampOutOfWindow
        );
        // Replay against a historical reference time (fedSync) still passes.
        m.validate(&state, &v, now()).unwrap();
    }

    #[test]
    fn nonce_format_enforced() {
        let v = MockVerifier::default();
        let state = DirectoryState::new();
        for bad in [
            "",
            "short",
            &"A".repeat(32),
            &"g".repeat(32),
            &"0".repeat(31),
        ] {
            let mut m = register("alice", "pk-alice", "node-a");
            m.nonce = bad.to_string();
            let m = signed(m, "pk-alice");
            assert_eq!(
                m.validate(&state, &v, now()).unwrap_err(),
                FederationError::MalformedNonce,
                "nonce {bad:?} must be rejected"
            );
        }
    }

    pub(crate) fn migrate_target() -> String {
        format!("alice@{}", "b".repeat(64))
    }

    #[test]
    fn migrate_happy_path_and_seq_gap() {
        let v = MockVerifier::default();
        let state = state_with("alice", "pk-alice");

        let migrate = signed(
            Mutation {
                version: 2,
                op: MutationOp::Migrate,
                key: "alice".to_string(),
                seq_no: 2,
                nonce: NONCE.to_string(),
                timestamp: "2026-07-15T12:00:00Z".to_string(),
                fields: json!({"migratedTo": migrate_target()}),
                user_sig: String::new(),
            },
            "pk-alice",
        );
        migrate.validate(&state, &v, now()).unwrap();
        let entry = migrate.apply(state.get("alice"), 9).unwrap();
        assert_eq!(entry.status, EntryStatus::Migrated);
        assert_eq!(
            entry.migrated_to.as_deref(),
            Some(migrate_target().as_str())
        );
        assert_eq!(entry.seq_no, 2);
        assert_eq!(entry.registered_epoch, 1);
        assert_eq!(entry.updated_epoch, 9);

        // An unqualified target is rejected.
        let mut bad_target = migrate.clone();
        bad_target.fields = json!({"migratedTo": "alice"});
        let bad_target = signed(bad_target, "pk-alice");
        assert_eq!(
            bad_target.validate(&state, &v, now()).unwrap_err(),
            FederationError::MalformedKey
        );

        // Gap and replay both rejected.
        for bad_seq in [1, 3, 4] {
            let mut m = migrate.clone();
            m.seq_no = bad_seq;
            let m = signed(m, "pk-alice");
            let err = m.validate(&state, &v, now()).unwrap_err();
            assert!(
                matches!(err, FederationError::WrongSeqNo { expected: 2, .. }),
                "{err}"
            );
        }

        // A migrated entry is terminal: further ops fail, but the migrated
        // key may still succeed itself (re-register back).
        let mut state2 = state.clone();
        state2.insert(migrate.apply(state.get("alice"), 9).unwrap());
        let mut again = migrate.clone();
        again.seq_no = 3;
        let again = signed(again, "pk-alice");
        assert_eq!(
            again.validate(&state2, &v, now()).unwrap_err(),
            FederationError::EntryMigrated
        );
        let comeback = {
            let mut m = register("alice", "pk-alice-3", "node-a");
            m.seq_no = 3;
            signed(m, "pk-alice")
        };
        comeback.validate(&state2, &v, now()).unwrap();
        let entry = comeback.apply(state2.get("alice"), 12).unwrap();
        assert_eq!(entry.status, EntryStatus::Active);
        assert_eq!(entry.migrated_to, None);
    }

    #[test]
    fn rotate_requires_both_keys() {
        let v = MockVerifier::default();
        let state = state_with("alice", "pk-alice");
        let rotate_payload = rotate_signing_payload("alice", 2, "pk-alice-new");

        let good = signed(
            Mutation {
                version: 2,
                op: MutationOp::RotateKey,
                key: "alice".to_string(),
                seq_no: 2,
                nonce: NONCE.to_string(),
                timestamp: "2026-07-15T12:00:00Z".to_string(),
                fields: json!({
                    "newIdentityPk": "pk-alice-new",
                    "newKeySig": mock_sign("pk-alice-new", &rotate_payload),
                }),
                user_sig: String::new(),
            },
            "pk-alice",
        );
        good.validate(&state, &v, now()).unwrap();
        let entry = good.apply(state.get("alice"), 3).unwrap();
        assert_eq!(entry.identity_pk, "pk-alice-new");

        // Old-key signature by the wrong key.
        let bad_old = signed(good.clone(), "pk-mallory");
        assert_eq!(
            bad_old.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadSignature
        );

        // New-key proof signed by the wrong key.
        let mut bad_new = good.clone();
        bad_new.fields["newKeySig"] = json!(mock_sign("pk-mallory", &rotate_payload));
        let bad_new = signed(bad_new, "pk-alice");
        assert_eq!(
            bad_new.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadNewKeySignature
        );

        // New-key proof bound to a different seqNo.
        let mut wrong_ctx = good;
        wrong_ctx.fields["newKeySig"] = json!(mock_sign(
            "pk-alice-new",
            &rotate_signing_payload("alice", 3, "pk-alice-new")
        ));
        let wrong_ctx = signed(wrong_ctx, "pk-alice");
        assert_eq!(
            wrong_ctx.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadNewKeySignature
        );
    }

    #[test]
    fn revoke_binds_to_exact_prior_state() {
        let v = MockVerifier::default();
        let state = state_with("alice", "pk-alice");
        let prev_hash = hash_hex(&state.get("alice").unwrap().leaf_hash().unwrap());

        let revoke = signed(
            Mutation {
                version: 2,
                op: MutationOp::Revoke,
                key: "alice".to_string(),
                seq_no: 2,
                nonce: NONCE.to_string(),
                timestamp: "2026-07-15T12:00:00Z".to_string(),
                fields: json!({"prevEntryHash": prev_hash}),
                user_sig: String::new(),
            },
            "pk-alice",
        );
        revoke.validate(&state, &v, now()).unwrap();

        let mut stale = revoke.clone();
        stale.fields["prevEntryHash"] = json!(hash_hex(&[0u8; 32]));
        let stale = signed(stale, "pk-alice");
        assert_eq!(
            stale.validate(&state, &v, now()).unwrap_err(),
            FederationError::BadPrevEntryHash
        );

        // After revocation only key succession may re-register.
        let mut state2 = state.clone();
        state2.insert(revoke.apply(state.get("alice"), 2).unwrap());

        let squatter = {
            let mut m = register("alice", "pk-squatter", "node-b");
            m.seq_no = 3;
            signed(m, "pk-squatter")
        };
        assert_eq!(
            squatter.validate(&state2, &v, now()).unwrap_err(),
            FederationError::BadSignature
        );

        let successor = {
            let mut m = register("alice", "pk-alice-2", "node-b");
            m.seq_no = 3;
            signed(m, "pk-alice") // revoked key signs the succession
        };
        successor.validate(&state2, &v, now()).unwrap();
        let entry = successor.apply(state2.get("alice"), 7).unwrap();
        assert_eq!(entry.status, EntryStatus::Active);
        assert_eq!(entry.identity_pk, "pk-alice-2");
        assert_eq!(
            entry.registered_epoch, 1,
            "succession keeps original registration epoch"
        );

        // And ops on a revoked entry (other than succession) fail.
        let migrate_revoked = signed(
            Mutation {
                version: 2,
                op: MutationOp::Migrate,
                key: "alice".to_string(),
                seq_no: 3,
                nonce: NONCE.to_string(),
                timestamp: "2026-07-15T12:00:00Z".to_string(),
                fields: json!({"migratedTo": migrate_target()}),
                user_sig: String::new(),
            },
            "pk-alice",
        );
        assert_eq!(
            migrate_revoked.validate(&state2, &v, now()).unwrap_err(),
            FederationError::EntryRevoked
        );
    }

    #[test]
    fn mutation_hash_is_canonical() {
        let m1 = register("alice", "pk-alice", "node-a");
        // Same logical mutation with fields object in different insertion order.
        let mut m2 = m1.clone();
        m2.fields = json!({"homeNode": "node-a", "identityPk": "pk-alice"});
        assert_eq!(m1.hash().unwrap(), m2.hash().unwrap());

        let mut m3 = m1.clone();
        m3.nonce = "ffffffffffffffffffffffffffffffff".to_string();
        assert_ne!(m1.hash().unwrap(), m3.hash().unwrap());
    }
}
