//! Directory entries (spec §4.2) and the in-memory directory state that
//! mutations are validated against and epochs are computed from.

use super::canonical::canonicalize;
use super::merkle::{self, Hash};
use super::{labeled_hash, labels, FederationError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_USERNAME_LEN: usize = 64;
pub const MAX_GROUP_ID_LEN: usize = 128;
pub const GROUP_KEY_PREFIX: &str = "group/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    User,
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryStatus {
    Active,
    Revoked,
    Migrated,
}

impl EntryStatus {
    /// Terminal states permit no further mutations except key-succession
    /// `register` (spec §6).
    pub fn is_terminal(self) -> bool {
        self != EntryStatus::Active
    }
}

/// One directory tree leaf (spec §5.1). Identity only — senderTags and nym
/// addresses never appear here. Entries are node-scoped: the log they live
/// in belongs to one node, so no home-node field is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntry {
    pub version: u32,
    pub kind: EntryKind,
    pub key: String,
    pub identity_pk: String,
    pub seq_no: u64,
    pub registered_epoch: u64,
    pub updated_epoch: u64,
    pub status: EntryStatus,
    /// Qualified successor name; present iff `status` is `migrated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrated_to: Option<String>,
}

impl DirectoryEntry {
    /// `SHA256("nymstr-leaf-v2:" || JCS(entry))` (spec §4.3).
    pub fn leaf_hash(&self) -> Result<Hash, FederationError> {
        let canon = canonicalize(self)?;
        Ok(labeled_hash(labels::LEAF, canon.as_bytes()))
    }
}

/// Validate a directory key: a bare username or `group/<groupId>`.
pub fn validate_key(key: &str) -> Result<EntryKind, FederationError> {
    fn valid_ident(s: &str, max: usize) -> bool {
        !s.is_empty()
            && s.len() <= max
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }
    if let Some(group_id) = key.strip_prefix(GROUP_KEY_PREFIX) {
        if valid_ident(group_id, MAX_GROUP_ID_LEN) {
            Ok(EntryKind::Group)
        } else {
            Err(FederationError::MalformedKey)
        }
    } else if valid_ident(key, MAX_USERNAME_LEN) {
        Ok(EntryKind::User)
    } else {
        Err(FederationError::MalformedKey)
    }
}

/// Validate a qualified name `<key>@<nodeId>` (spec §3): the local part is a
/// valid directory key and the node part is a 64-char lowercase hex
/// fingerprint. Returns (key, nodeId).
pub fn validate_qualified_name(name: &str) -> Result<(&str, &str), FederationError> {
    let (key, node_id) = name.rsplit_once('@').ok_or(FederationError::MalformedKey)?;
    validate_key(key)?;
    if node_id.len() != 64
        || !node_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(FederationError::MalformedKey);
    }
    Ok((key, node_id))
}

/// The full directory state at some epoch: every live entry, keyed by
/// directory key. BTreeMap keeps keys in lexicographic (byte) order, which
/// is exactly the leaf order of the directory tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectoryState {
    entries: BTreeMap<String, DirectoryEntry>,
}

impl DirectoryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: impl IntoIterator<Item = DirectoryEntry>) -> Self {
        Self {
            entries: entries.into_iter().map(|e| (e.key.clone(), e)).collect(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&DirectoryEntry> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, entry: DirectoryEntry) {
        self.entries.insert(entry.key.clone(), entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &DirectoryEntry> {
        self.entries.values()
    }

    /// Leaf hashes in tree order.
    pub fn leaf_hashes(&self) -> Result<Vec<Hash>, FederationError> {
        self.entries.values().map(|e| e.leaf_hash()).collect()
    }

    /// Root of the directory tree over the current state.
    pub fn directory_root(&self) -> Result<Hash, FederationError> {
        Ok(merkle::root(&self.leaf_hashes()?))
    }

    /// Zero-based leaf index of `key`, if present.
    pub fn index_of(&self, key: &str) -> Option<usize> {
        self.entries.keys().position(|k| k == key)
    }

    /// Inclusion proof for `key` against the current directory root.
    pub fn prove_inclusion(&self, key: &str) -> Result<(usize, Vec<Hash>), FederationError> {
        let index = self.index_of(key).ok_or(FederationError::EntryNotFound)?;
        let leaves = self.leaf_hashes()?;
        Ok((index, merkle::inclusion_proof(&leaves, index)?))
    }

    /// Non-inclusion evidence for an absent key: the lexicographically
    /// adjacent entries (either side may be None at the extremes), each with
    /// its inclusion proof. A verifier checks both proofs and that the
    /// missing key falls strictly between them in tree order.
    #[allow(clippy::type_complexity)]
    pub fn prove_absence(
        &self,
        key: &str,
    ) -> Result<
        (
            Option<(DirectoryEntry, usize, Vec<Hash>)>,
            Option<(DirectoryEntry, usize, Vec<Hash>)>,
        ),
        FederationError,
    > {
        if self.entries.contains_key(key) {
            return Err(FederationError::EntryAlreadyExists);
        }
        let leaves = self.leaf_hashes()?;
        let prove = |k: &str| -> Result<(DirectoryEntry, usize, Vec<Hash>), FederationError> {
            let index = self.index_of(k).ok_or(FederationError::EntryNotFound)?;
            Ok((
                self.entries[k].clone(),
                index,
                merkle::inclusion_proof(&leaves, index)?,
            ))
        };
        let before = self
            .entries
            .range::<str, _>((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(key)))
            .next_back()
            .map(|(k, _)| k.clone());
        let after = self
            .entries
            .range::<str, _>((std::ops::Bound::Excluded(key), std::ops::Bound::Unbounded))
            .next()
            .map(|(k, _)| k.clone());
        Ok((
            before.map(|k| prove(&k)).transpose()?,
            after.map(|k| prove(&k)).transpose()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::verify_inclusion;

    pub(crate) fn entry(key: &str, seq_no: u64) -> DirectoryEntry {
        DirectoryEntry {
            version: 2,
            kind: if key.starts_with(GROUP_KEY_PREFIX) {
                EntryKind::Group
            } else {
                EntryKind::User
            },
            key: key.to_string(),
            identity_pk: format!("pk-{key}"),
            seq_no,
            registered_epoch: 1,
            updated_epoch: 1,
            status: EntryStatus::Active,
            migrated_to: None,
        }
    }

    #[test]
    fn qualified_name_validation() {
        let node = "a".repeat(64);
        let user_name = format!("alice@{node}");
        let (key, node_id) = validate_qualified_name(&user_name).unwrap();
        assert_eq!(key, "alice");
        assert_eq!(node_id, node);
        let group_name = format!("group/dev@{node}");
        let (key, _) = validate_qualified_name(&group_name).unwrap();
        assert_eq!(key, "group/dev");

        assert!(validate_qualified_name("alice").is_err());
        assert!(validate_qualified_name(&format!("bad name@{node}")).is_err());
        assert!(validate_qualified_name("alice@shortid").is_err());
        assert!(validate_qualified_name(&format!("alice@{}", "A".repeat(64))).is_err());
        assert!(validate_qualified_name(&format!("alice@{}", "g".repeat(64))).is_err());
    }

    #[test]
    fn key_validation() {
        assert_eq!(validate_key("alice_99-x").unwrap(), EntryKind::User);
        assert_eq!(validate_key("group/dev-chat").unwrap(), EntryKind::Group);
        assert!(validate_key("").is_err());
        assert!(validate_key("bad name").is_err());
        assert!(validate_key("group/").is_err());
        assert!(validate_key("group/bad name").is_err());
        assert!(validate_key(&"a".repeat(65)).is_err());
        assert!(validate_key(&"a".repeat(64)).is_ok());
        assert!(validate_key(&format!("group/{}", "g".repeat(128))).is_ok());
        assert!(validate_key(&format!("group/{}", "g".repeat(129))).is_err());
        // A group id may not itself contain '/'.
        assert!(validate_key("group/a/b").is_err());
    }

    #[test]
    fn leaf_hash_is_stable_and_field_sensitive() {
        let e = entry("alice", 1);
        let h1 = e.leaf_hash().unwrap();
        let h2 = e.clone().leaf_hash().unwrap();
        assert_eq!(h1, h2);
        let mut changed = e;
        changed.seq_no = 2;
        assert_ne!(changed.leaf_hash().unwrap(), h1);
    }

    #[test]
    fn serde_field_names_match_spec() {
        let json = serde_json::to_value(entry("alice", 1)).unwrap();
        for field in [
            "version",
            "kind",
            "key",
            "identityPk",
            "seqNo",
            "registeredEpoch",
            "updatedEpoch",
            "status",
        ] {
            assert!(json.get(field).is_some(), "missing spec field {field}");
        }
        assert_eq!(json["status"], "active");
        assert_eq!(json["kind"], "user");
        // migratedTo is omitted entirely unless the entry is migrated.
        assert!(json.get("migratedTo").is_none());
        let mut migrated = entry("alice", 2);
        migrated.status = EntryStatus::Migrated;
        migrated.migrated_to = Some(format!("alice@{}", "b".repeat(64)));
        let json = serde_json::to_value(&migrated).unwrap();
        assert_eq!(json["status"], "migrated");
        assert!(json.get("migratedTo").is_some());
    }

    #[test]
    fn inclusion_proof_roundtrip_through_state() {
        let state = DirectoryState::from_entries(
            ["alice", "bob", "carol", "group/dev", "zed"].map(|k| entry(k, 1)),
        );
        let root = state.directory_root().unwrap();
        let (index, proof) = state.prove_inclusion("carol").unwrap();
        let leaf = state.get("carol").unwrap().leaf_hash().unwrap();
        assert!(verify_inclusion(
            &leaf,
            index as u64,
            state.len() as u64,
            &proof,
            &root
        ));
    }

    #[test]
    fn absence_proof_gives_adjacent_entries() {
        let state = DirectoryState::from_entries(["alice", "carol"].map(|k| entry(k, 1)));
        let (before, after) = state.prove_absence("bob").unwrap();
        assert_eq!(before.unwrap().0.key, "alice");
        assert_eq!(after.unwrap().0.key, "carol");

        let (before, after) = state.prove_absence("aaa").unwrap();
        assert!(before.is_none());
        assert_eq!(after.unwrap().0.key, "alice");

        assert!(state.prove_absence("alice").is_err());
    }
}
