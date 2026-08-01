//! Epoch headers (spec §5.2) and the batch pipeline (spec §7): the node
//! orders and applies its mutation pool with `build_epoch`; witnesses and
//! auditors replay published batches with `replay_batch` and endorse only a
//! header they reproduce bit for bit.

use super::canonical::canonicalize;
use super::entry::DirectoryState;
use super::merkle::{self, Hash};
use super::mutation::Mutation;
use super::{hash_hex, labeled_hash, labels, FederationError, SignatureVerifier};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochHeader {
    pub version: u32,
    pub epoch: u64,
    pub prev_epoch_hash: String,
    pub directory_root: String,
    pub log_root: String,
    pub mutations_hash: String,
    pub mutation_count: u64,
    pub node_id: String,
    pub timestamp: String,
}

impl EpochHeader {
    /// `SHA256("nymstr-epoch-v2:" || JCS(header))`.
    pub fn hash(&self) -> Result<Hash, FederationError> {
        let canon = canonicalize(self)?;
        Ok(labeled_hash(labels::EPOCH, canon.as_bytes()))
    }

    pub fn hash_hex(&self) -> Result<String, FederationError> {
        Ok(hash_hex(&self.hash()?))
    }
}

/// `SHA256("nymstr-batch-v2:" || JCS(ordered mutation array))`.
pub fn batch_hash(batch: &[Mutation]) -> Result<String, FederationError> {
    let canon = canonicalize(&batch)?;
    let mut hasher = Sha256::new();
    hasher.update(labels::BATCH.as_bytes());
    hasher.update(canon.as_bytes());
    Ok(hash_hex(&hasher.finalize().into()))
}

/// Canonical batch order (spec §6.3): lexicographic by key, then ascending
/// seqNo, then ascending mutation hash. Returns the ordered batch.
pub fn order_batch(mut batch: Vec<Mutation>) -> Result<Vec<Mutation>, FederationError> {
    let mut keyed: Vec<(String, u64, Hash, Mutation)> = Vec::with_capacity(batch.len());
    for m in batch.drain(..) {
        keyed.push((m.key.clone(), m.seq_no, m.hash()?, m));
    }
    keyed.sort_by(|a, b| (&a.0, a.1, a.2).cmp(&(&b.0, b.1, b.2)));
    Ok(keyed.into_iter().map(|(_, _, _, m)| m).collect())
}

/// Inputs that identify where in the chain the new epoch sits.
pub struct EpochContext<'a> {
    pub epoch: u64,
    /// Hash of the last finalized epoch header (hex), or the nodeId for
    /// epoch 1 (spec §5.2: the chain is bound to the node key from birth).
    pub prev_epoch_hash: String,
    pub node_id: String,
    pub timestamp: DateTime<Utc>,
    /// Epoch hashes of all previously finalized epochs, in order — the leaves
    /// of the append-only log tree BEFORE this epoch.
    pub log_leaves: &'a [Hash],
}

/// Node path: validate + drop invalid mutations from the pool, order the
/// survivors, apply, and produce the header. Invalid pool entries are
/// returned with their reasons so the node can mark them rejected.
#[allow(clippy::type_complexity)]
pub fn build_epoch(
    state: &DirectoryState,
    pool: Vec<Mutation>,
    ctx: &EpochContext,
    verifier: &dyn SignatureVerifier,
) -> Result<
    (
        DirectoryState,
        EpochHeader,
        Vec<Mutation>,
        Vec<(Mutation, FederationError)>,
    ),
    FederationError,
> {
    let ordered = order_batch(pool)?;
    let mut new_state = state.clone();
    let mut accepted: Vec<Mutation> = Vec::with_capacity(ordered.len());
    let mut rejected: Vec<(Mutation, FederationError)> = Vec::new();
    let mut seen: HashSet<Hash> = HashSet::new();

    for m in ordered {
        let h = m.hash()?;
        if !seen.insert(h) {
            rejected.push((m, FederationError::DuplicateMutation));
            continue;
        }
        // Validation is sequential against the evolving state so that e.g.
        // register + rotateKey for the same key can land in one epoch.
        match m.validate(&new_state, verifier, ctx.timestamp) {
            Ok(()) => {
                let entry = m.apply(new_state.get(&m.key), ctx.epoch)?;
                new_state.insert(entry);
                accepted.push(m);
            }
            Err(e) => rejected.push((m, e)),
        }
    }

    let header = header_for(&new_state, &accepted, ctx)?;
    Ok((new_state, header, accepted, rejected))
}

/// Witness/auditor path (spec §12.1): replay a published batch exactly. Any
/// invalid or misordered mutation fails the whole batch — an honest node
/// never publishes one — and the recomputed header must match the STH.
pub fn replay_batch(
    state: &DirectoryState,
    announced_header: &EpochHeader,
    batch: &[Mutation],
    ctx: &EpochContext,
    verifier: &dyn SignatureVerifier,
) -> Result<DirectoryState, FederationError> {
    // The announced batch must already be in canonical order.
    let reordered = order_batch(batch.to_vec())?;
    if reordered != batch {
        return Err(FederationError::BatchNotOrdered);
    }

    let mut new_state = state.clone();
    let mut seen: HashSet<Hash> = HashSet::new();
    for m in batch {
        if !seen.insert(m.hash()?) {
            return Err(FederationError::DuplicateMutation);
        }
        // Replayed mutations are checked against the header's timestamp, not
        // the local clock, so fedSync of historical epochs validates.
        m.validate(&new_state, verifier, ctx.timestamp)?;
        let entry = m.apply(new_state.get(&m.key), ctx.epoch)?;
        new_state.insert(entry);
    }

    let recomputed = header_for(&new_state, batch, ctx)?;
    if recomputed != *announced_header {
        let what = if recomputed.directory_root != announced_header.directory_root {
            "directoryRoot"
        } else if recomputed.log_root != announced_header.log_root {
            "logRoot"
        } else if recomputed.mutations_hash != announced_header.mutations_hash {
            "mutationsHash"
        } else if recomputed.prev_epoch_hash != announced_header.prev_epoch_hash {
            "prevEpochHash"
        } else {
            "header"
        };
        return Err(FederationError::HeaderMismatch(what));
    }
    Ok(new_state)
}

fn header_for(
    state: &DirectoryState,
    batch: &[Mutation],
    ctx: &EpochContext,
) -> Result<EpochHeader, FederationError> {
    Ok(EpochHeader {
        version: 2,
        epoch: ctx.epoch,
        prev_epoch_hash: ctx.prev_epoch_hash.clone(),
        directory_root: hash_hex(&state.directory_root()?),
        log_root: hash_hex(&merkle::root(ctx.log_leaves)),
        mutations_hash: batch_hash(batch)?,
        mutation_count: batch.len() as u64,
        node_id: ctx.node_id.clone(),
        timestamp: ctx
            .timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::tests::{now, register, signed, NONCE};
    use crate::mutation::{Mutation, MutationOp};
    use crate::testutil::MockVerifier;
    use serde_json::json;

    fn ctx<'a>(epoch: u64, log_leaves: &'a [Hash]) -> EpochContext<'a> {
        EpochContext {
            epoch,
            prev_epoch_hash: hash_hex(&[7u8; 32]),
            node_id: "node-a".to_string(),
            timestamp: now(),
            log_leaves,
        }
    }

    #[test]
    fn build_orders_deterministically_regardless_of_pool_order() {
        let v = MockVerifier::default();
        let state = DirectoryState::new();
        let pool: Vec<Mutation> = ["carol", "alice", "bob"]
            .iter()
            .map(|k| register(k, &format!("pk-{k}"), "node-a"))
            .collect();
        let mut pool_rev = pool.clone();
        pool_rev.reverse();

        let (s1, h1, a1, r1) = build_epoch(&state, pool, &ctx(1, &[]), &v).unwrap();
        let (s2, h2, a2, r2) = build_epoch(&state, pool_rev, &ctx(1, &[]), &v).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(s1, s2);
        assert_eq!(a1, a2);
        assert!(r1.is_empty() && r2.is_empty());
        assert_eq!(
            a1.iter().map(|m| m.key.as_str()).collect::<Vec<_>>(),
            vec!["alice", "bob", "carol"]
        );
        assert_eq!(h1.mutation_count, 3);
    }

    #[test]
    fn register_then_rotate_in_one_epoch() {
        use crate::mutation::rotate_signing_payload;
        use crate::testutil::mock_sign;
        let v = MockVerifier::default();
        let reg = register("alice", "pk-alice", "node-a");
        let rotate = signed(
            Mutation {
                version: 2,
                op: MutationOp::RotateKey,
                key: "alice".to_string(),
                seq_no: 2,
                nonce: NONCE.to_string(),
                timestamp: "2026-07-15T12:00:00Z".to_string(),
                fields: json!({
                    "newIdentityPk": "pk-alice-2",
                    "newKeySig": mock_sign(
                        "pk-alice-2",
                        &rotate_signing_payload("alice", 2, "pk-alice-2")
                    ),
                }),
                user_sig: String::new(),
            },
            "pk-alice",
        );
        let (state, header, accepted, rejected) =
            build_epoch(&DirectoryState::new(), vec![rotate, reg], &ctx(1, &[]), &v).unwrap();
        assert_eq!(accepted.len(), 2);
        assert!(rejected.is_empty());
        assert_eq!(state.get("alice").unwrap().identity_pk, "pk-alice-2");
        assert_eq!(state.get("alice").unwrap().seq_no, 2);
        assert_eq!(header.mutation_count, 2);
    }

    #[test]
    fn name_collision_resolves_deterministically_first_wins() {
        let v = MockVerifier::default();
        let a = register("alice", "pk-first", "node-a");
        let b = register("alice", "pk-second", "node-b");
        // Winner is fixed by hash order, not pool order.
        let winner_pk = if a.hash().unwrap() < b.hash().unwrap() {
            "pk-first"
        } else {
            "pk-second"
        };
        for pool in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
            let (state, _, accepted, rejected) =
                build_epoch(&DirectoryState::new(), pool, &ctx(1, &[]), &v).unwrap();
            assert_eq!(accepted.len(), 1);
            assert_eq!(rejected.len(), 1);
            assert_eq!(rejected[0].1, FederationError::EntryAlreadyExists);
            assert_eq!(state.get("alice").unwrap().identity_pk, winner_pk);
        }
    }

    #[test]
    fn node_drops_invalid_auditors_reject_batch() {
        let v = MockVerifier::default();
        let good = register("alice", "pk-alice", "node-a");
        let forged = signed(register("bob", "pk-bob", "node-a"), "pk-mallory");

        // Leader path: forged mutation dropped, epoch proceeds.
        let (state, header, accepted, rejected) = build_epoch(
            &DirectoryState::new(),
            vec![good.clone(), forged.clone()],
            &ctx(1, &[]),
            &v,
        )
        .unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(rejected[0].1, FederationError::BadSignature);

        // Follower path: replay of the honest batch succeeds and reproduces
        // the exact state.
        let replayed =
            replay_batch(&DirectoryState::new(), &header, &accepted, &ctx(1, &[]), &v).unwrap();
        assert_eq!(replayed, state);

        // A batch containing the forged mutation must fail wholesale.
        let dishonest = order_batch(vec![good, forged]).unwrap();
        assert_eq!(
            replay_batch(
                &DirectoryState::new(),
                &header,
                &dishonest,
                &ctx(1, &[]),
                &v
            )
            .unwrap_err(),
            FederationError::BadSignature
        );
    }

    #[test]
    fn replay_rejects_misordered_duplicate_and_tampered_header() {
        let v = MockVerifier::default();
        let pool: Vec<Mutation> = ["alice", "bob"]
            .iter()
            .map(|k| register(k, &format!("pk-{k}"), "node-a"))
            .collect();
        let (_, header, accepted, _) =
            build_epoch(&DirectoryState::new(), pool, &ctx(1, &[]), &v).unwrap();

        // Misordered.
        let mut reversed = accepted.clone();
        reversed.reverse();
        assert_eq!(
            replay_batch(&DirectoryState::new(), &header, &reversed, &ctx(1, &[]), &v).unwrap_err(),
            FederationError::BatchNotOrdered
        );

        // Duplicated mutation.
        let mut duped = accepted.clone();
        duped.push(accepted[1].clone());
        let duped = order_batch(duped).unwrap();
        assert_eq!(
            replay_batch(&DirectoryState::new(), &header, &duped, &ctx(1, &[]), &v).unwrap_err(),
            FederationError::DuplicateMutation
        );

        // Tampered directory root.
        let mut forged_header = header.clone();
        forged_header.directory_root = hash_hex(&[1u8; 32]);
        assert_eq!(
            replay_batch(
                &DirectoryState::new(),
                &forged_header,
                &accepted,
                &ctx(1, &[]),
                &v
            )
            .unwrap_err(),
            FederationError::HeaderMismatch("directoryRoot")
        );

        // Wrong epoch context (different prev hash) changes the header.
        let mut ctx2 = ctx(1, &[]);
        ctx2.prev_epoch_hash = hash_hex(&[8u8; 32]);
        assert!(matches!(
            replay_batch(&DirectoryState::new(), &header, &accepted, &ctx2, &v).unwrap_err(),
            FederationError::HeaderMismatch(_)
        ));
    }

    #[test]
    fn log_root_advances_with_chain() {
        let v = MockVerifier::default();
        let (state1, h1, _, _) = build_epoch(
            &DirectoryState::new(),
            vec![register("alice", "pk-alice", "node-a")],
            &ctx(1, &[]),
            &v,
        )
        .unwrap();

        let log_after_1 = vec![h1.hash().unwrap()];
        let mut ctx2 = ctx(2, &log_after_1);
        ctx2.prev_epoch_hash = h1.hash_hex().unwrap();
        let (_, h2, _, _) = build_epoch(
            &state1,
            vec![register("bob", "pk-bob", "node-a")],
            &ctx2,
            &v,
        )
        .unwrap();

        assert_eq!(h1.log_root, hash_hex(&merkle::root(&[])));
        assert_eq!(h2.log_root, hash_hex(&merkle::root(&log_after_1)));
        assert_eq!(h2.prev_epoch_hash, h1.hash_hex().unwrap());
        assert_ne!(h1.hash().unwrap(), h2.hash().unwrap());
    }

    #[test]
    fn header_hash_covers_every_field() {
        let v = MockVerifier::default();
        let (_, header, _, _) = build_epoch(
            &DirectoryState::new(),
            vec![register("alice", "pk-alice", "node-a")],
            &ctx(1, &[]),
            &v,
        )
        .unwrap();
        let base = header.hash().unwrap();

        let mut h = header.clone();
        h.epoch = 2;
        assert_ne!(h.hash().unwrap(), base);
        let mut h = header.clone();
        h.node_id = "node-b".into();
        assert_ne!(h.hash().unwrap(), base);
        let mut h = header;
        h.timestamp = "2026-07-15T12:00:01Z".into();
        assert_ne!(h.hash().unwrap(), base);
    }
}
