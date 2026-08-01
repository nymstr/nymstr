//! Namespace-log runtime (SERVER_SPEC.md §5–§7): owns the in-memory
//! directory state, accepts mutations into the pool with signed inclusion
//! promises, and finalizes epochs on a timer. This is the only federation
//! module with I/O — everything it persists or signs is produced by the
//! pure-logic modules.

use crate::db_utils::DbUtils;
use anyhow::{Context, Result};
use chrono::Utc;
use nymstr_crypto::ServerKeyManager;
use nymstr_federation::entry::{DirectoryEntry, DirectoryState};
use nymstr_federation::epoch::{build_epoch, EpochContext};
use nymstr_federation::merkle::Hash;
use nymstr_federation::mutation::Mutation;
use nymstr_federation::node::{
    node_id_for, sth_signing_payload, InclusionPromise, NodeDescriptor, SignedTreeHead,
    PROMISE_WINDOW_EPOCHS,
};
use nymstr_federation::FederationError;
use serde_json::json;

/// Default epoch interval (spec §2.2 descriptor field).
pub const DEFAULT_EPOCH_SECONDS: u64 = 30;

pub struct NamespaceLog {
    db: DbUtils,
    crypto: ServerKeyManager,
    /// Key name under which the node key lives in ServerKeyManager (the server's
    /// existing client_id keypair IS the node keypair).
    key_name: String,
    pub node_id: String,
    pub node_pk: String,
    pub descriptor: NodeDescriptor,
    state: DirectoryState,
    log_leaves: Vec<Hash>,
    last_epoch: u64,
    last_epoch_hash: String,
    last_sth: Option<SignedTreeHead>,
}

impl NamespaceLog {
    /// Load (or initialize) the log from the database and publish a fresh
    /// descriptor for the current address.
    pub async fn bootstrap(
        db: DbUtils,
        crypto: ServerKeyManager,
        key_name: &str,
        nym_address: &str,
        epoch_seconds: u64,
    ) -> Result<Self> {
        let node_pk = crypto
            .public_key_armored(key_name)
            .context("node keypair must exist before the namespace log starts")?;
        let node_id = node_id_for(&node_pk);

        // Rebuild in-memory state from persisted entries and epoch hashes.
        let mut entries = Vec::new();
        for entry_json in db.load_directory_entries().await? {
            let entry: DirectoryEntry =
                serde_json::from_str(&entry_json).context("corrupt directory entry in db")?;
            entries.push(entry);
        }
        let state = DirectoryState::from_entries(entries);

        let mut log_leaves = Vec::new();
        let mut last_epoch = 0u64;
        let mut last_epoch_hash = node_id.clone();
        for (epoch, hash_hex_str) in db.load_epoch_hashes().await? {
            log_leaves.push(nymstr_federation::hash_from_hex(&hash_hex_str)?);
            last_epoch = epoch;
            last_epoch_hash = hash_hex_str;
        }
        let last_sth = if last_epoch > 0 {
            let rows = db.epochs_from(last_epoch).await?;
            let (_, sth_json, _) = rows.first().context("last epoch row missing")?;
            Some(serde_json::from_str(sth_json).context("corrupt STH in db")?)
        } else {
            None
        };

        // Publish a descriptor for the current address (soft state; newest
        // issuedAt wins everywhere it is cached).
        let mut descriptor = NodeDescriptor {
            version: 2,
            node_id: node_id.clone(),
            node_pk: node_pk.clone(),
            nym_address: nym_address.to_string(),
            aliases: vec![],
            epoch_seconds,
            policy: json!({"registration": "open"}),
            issued_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            sig: String::new(),
        };
        descriptor.sig = crypto.sign_message(
            key_name,
            &descriptor
                .signing_payload()
                .map_err(|e| anyhow::anyhow!(e))?,
        )?;
        db.store_node_descriptor(
            &node_id,
            &serde_json::to_string(&descriptor)?,
            &descriptor.issued_at,
        )
        .await?;

        log::info!(
            "Namespace log ready: nodeId {}, {} entries, {} finalized epochs",
            node_id,
            state.len(),
            last_epoch
        );
        Ok(NamespaceLog {
            db,
            crypto,
            key_name: key_name.to_string(),
            node_id,
            node_pk,
            descriptor,
            state,
            log_leaves,
            last_epoch,
            last_epoch_hash,
            last_sth,
        })
    }

    pub fn last_sth(&self) -> Option<&SignedTreeHead> {
        self.last_sth.as_ref()
    }

    /// Attach a witness signature to the in-memory latest STH (the persisted
    /// copy is updated separately by the wire handler).
    pub fn attach_witness_to_last(
        &mut self,
        witness_sig: nymstr_federation::node::WitnessSignature,
    ) {
        if let Some(sth) = self.last_sth.as_mut() {
            if !sth
                .witness_sigs
                .iter()
                .any(|w| w.witness_id == witness_sig.witness_id)
            {
                sth.witness_sigs.push(witness_sig);
            }
        }
    }

    pub fn state(&self) -> &DirectoryState {
        &self.state
    }

    pub fn log_leaves(&self) -> &[Hash] {
        &self.log_leaves
    }

    pub fn last_epoch(&self) -> u64 {
        self.last_epoch
    }

    /// Accept a mutation into the pool: validate against finalized state,
    /// persist, and return the signed inclusion promise (spec §7).
    /// Validation failures are returned as `Err(FederationError)` inside Ok
    /// so callers can distinguish protocol rejections from I/O failures.
    pub async fn submit(
        &mut self,
        mutation: Mutation,
    ) -> Result<std::result::Result<InclusionPromise, FederationError>> {
        if let Err(e) = mutation.validate(&self.state, &nymstr_federation::PgpVerifier, Utc::now())
        {
            return Ok(Err(e));
        }
        let mutation_hash = mutation.hash_hex().map_err(|e| anyhow::anyhow!(e))?;
        let mut promise = InclusionPromise {
            mutation_hash: mutation_hash.clone(),
            received_epoch: self.last_epoch,
            deadline_epoch: self.last_epoch + PROMISE_WINDOW_EPOCHS,
            node_id: self.node_id.clone(),
            sig: String::new(),
        };
        promise.sig = self.crypto.sign_message(
            &self.key_name,
            &promise.signing_payload().map_err(|e| anyhow::anyhow!(e))?,
        )?;
        self.db
            .insert_fed_mutation(
                &mutation_hash,
                &mutation.key,
                mutation.seq_no,
                &serde_json::to_string(&mutation)?,
                &serde_json::to_string(&promise)?,
            )
            .await?;
        Ok(Ok(promise))
    }

    /// Finalize one epoch if the pool is non-empty (spec §7). Returns the
    /// published STH, or None for a skipped (empty) epoch.
    pub async fn tick(&mut self) -> Result<Option<SignedTreeHead>> {
        let pending = self.db.pending_fed_mutations().await?;
        if pending.is_empty() {
            return Ok(None);
        }
        let mut pool = Vec::with_capacity(pending.len());
        for (_hash, json_str) in &pending {
            let m: Mutation = serde_json::from_str(json_str).context("corrupt mutation in pool")?;
            pool.push(m);
        }

        let epoch = self.last_epoch + 1;
        let ctx = EpochContext {
            epoch,
            prev_epoch_hash: self.last_epoch_hash.clone(),
            node_id: self.node_id.clone(),
            timestamp: Utc::now(),
            log_leaves: &self.log_leaves,
        };
        let (new_state, header, accepted, rejected) =
            build_epoch(&self.state, pool, &ctx, &nymstr_federation::PgpVerifier)
                .map_err(|e| anyhow::anyhow!(e))?;

        let epoch_hash = header.hash_hex().map_err(|e| anyhow::anyhow!(e))?;
        let sth = SignedTreeHead {
            node_sig: self
                .crypto
                .sign_message(&self.key_name, &sth_signing_payload(&epoch_hash))?,
            header: header.clone(),
            witness_sigs: vec![],
        };

        // Collect changed entries (accepted mutations' keys, deduped).
        let mut changed_keys: Vec<&str> = accepted.iter().map(|m| m.key.as_str()).collect();
        changed_keys.sort_unstable();
        changed_keys.dedup();
        let mut changed_entries = Vec::with_capacity(changed_keys.len());
        for key in changed_keys {
            let entry = new_state
                .get(key)
                .expect("accepted key exists in new state");
            changed_entries.push((
                key.to_string(),
                serde_json::to_string(entry)?,
                nymstr_federation::hash_hex(&entry.leaf_hash().map_err(|e| anyhow::anyhow!(e))?),
                serde_json::to_value(entry.status)?
                    .as_str()
                    .expect("status serializes to a string")
                    .to_string(),
            ));
        }
        let finalized_hashes: Vec<String> = accepted
            .iter()
            .map(|m| m.hash_hex().map_err(|e| anyhow::anyhow!(e)))
            .collect::<Result<_>>()?;
        let rejected_rows: Vec<(String, String)> = rejected
            .iter()
            .map(|(m, e)| Ok((m.hash_hex().map_err(|e| anyhow::anyhow!(e))?, e.to_string())))
            .collect::<Result<_>>()?;

        self.db
            .finalize_epoch(
                epoch,
                &epoch_hash,
                &serde_json::to_string(&header)?,
                &serde_json::to_string(&sth)?,
                &serde_json::to_string(&accepted)?,
                &changed_entries,
                &finalized_hashes,
                &rejected_rows,
            )
            .await?;

        self.state = new_state;
        self.log_leaves
            .push(header.hash().map_err(|e| anyhow::anyhow!(e))?);
        self.last_epoch = epoch;
        self.last_epoch_hash = epoch_hash;
        self.last_sth = Some(sth.clone());
        log::info!(
            "Epoch {} finalized: {} accepted, {} rejected, directory size {}",
            epoch,
            accepted.len(),
            rejected_rows.len(),
            self.state.len()
        );
        Ok(Some(sth))
    }
}

/// Spawn the epoch timer: ticks every `epoch_seconds`, finalizing an epoch
/// whenever the pool is non-empty. Runs until the process exits.
pub fn spawn_epoch_timer(
    log: std::sync::Arc<tokio::sync::Mutex<NamespaceLog>>,
    epoch_seconds: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(epoch_seconds.max(1)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let mut log = log.lock().await;
            if let Err(e) = log.tick().await {
                log::error!("epoch tick failed: {e:#}");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nymstr_federation::entry::EntryStatus;
    use nymstr_federation::merkle;
    use nymstr_federation::mutation::MutationOp;
    use serde_json::json;
    use tempfile::tempdir;

    struct Harness {
        db: DbUtils,
        crypto: ServerKeyManager,
        _dir: tempfile::TempDir,
    }

    async fn harness() -> Harness {
        let dir = tempdir().unwrap();
        let db = DbUtils::new(dir.path().join("test.db").to_str().unwrap())
            .await
            .unwrap();
        let crypto = ServerKeyManager::new(dir.path().join("keys"), "pw".into()).unwrap();
        crypto.generate_key_pair("node").unwrap();
        Harness {
            db,
            crypto,
            _dir: dir,
        }
    }

    fn register(h: &Harness, user: &str) -> (Mutation, String) {
        let pk = h.crypto.generate_key_pair(user).unwrap();
        let mut m = Mutation {
            version: 2,
            op: MutationOp::Register,
            key: user.to_string(),
            seq_no: 1,
            nonce: "0123456789abcdef0123456789abcdef".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            fields: json!({"identityPk": pk}),
            user_sig: String::new(),
        };
        m.user_sig = h
            .crypto
            .sign_message(user, &m.signing_payload().unwrap())
            .unwrap();
        (m, pk)
    }

    #[tokio::test]
    async fn bootstrap_submit_tick_lifecycle() {
        let h = harness().await;
        let mut log = NamespaceLog::bootstrap(
            h.db.clone(),
            h.crypto.clone(),
            "node",
            "nym://test",
            DEFAULT_EPOCH_SECONDS,
        )
        .await
        .unwrap();

        // Descriptor is persisted and verifies.
        let stored =
            h.db.get_node_descriptor(&log.node_id)
                .await
                .unwrap()
                .unwrap();
        let descriptor: NodeDescriptor = serde_json::from_str(&stored).unwrap();
        descriptor.verify(&nymstr_federation::PgpVerifier).unwrap();

        // Empty pool: epoch skipped.
        assert!(log.tick().await.unwrap().is_none());
        assert_eq!(log.last_epoch(), 0);

        // Submit two registrations; promises verify; duplicate is idempotent.
        let (alice, _) = register(&h, "alice");
        let (bob, _) = register(&h, "bob");
        let promise = log.submit(alice.clone()).await.unwrap().unwrap();
        promise
            .verify(&log.node_id, &log.node_pk, &nymstr_federation::PgpVerifier)
            .unwrap();
        log.submit(bob.clone()).await.unwrap().unwrap();
        log.submit(alice.clone()).await.unwrap().unwrap(); // same hash, INSERT OR IGNORE

        // A protocol-invalid mutation is rejected without touching the pool.
        let mut forged = alice.clone();
        forged.key = "carol".to_string();
        assert_eq!(
            log.submit(forged).await.unwrap().unwrap_err(),
            FederationError::BadSignature
        );

        // Tick finalizes epoch 1 with both mutations.
        let sth = log.tick().await.unwrap().unwrap();
        assert_eq!(sth.header.epoch, 1);
        assert_eq!(sth.header.mutation_count, 2);
        assert_eq!(sth.header.prev_epoch_hash, log.node_id);
        sth.verify_node_sig(&log.node_id, &log.node_pk, &nymstr_federation::PgpVerifier)
            .unwrap();
        assert_eq!(
            log.state().get("alice").unwrap().status,
            EntryStatus::Active
        );

        // Promise honored within the deadline; status reflects finalization.
        assert!(sth.header.epoch <= promise.deadline_epoch);
        let (state, epoch, _, _) =
            h.db.fed_mutation_status(&promise.mutation_hash)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(state, "finalized");
        assert_eq!(epoch, Some(1));

        // Inclusion proof against the persisted STH verifies.
        let (index, proof) = log.state().prove_inclusion("alice").unwrap();
        assert!(merkle::verify_inclusion(
            &log.state().get("alice").unwrap().leaf_hash().unwrap(),
            index as u64,
            log.state().len() as u64,
            &proof,
            &nymstr_federation::hash_from_hex(&sth.header.directory_root).unwrap(),
        ));

        // Second tick with empty pool: skipped, epoch stays 1.
        assert!(log.tick().await.unwrap().is_none());
        assert_eq!(log.last_epoch(), 1);
    }

    #[tokio::test]
    async fn restart_resumes_chain_and_state() {
        let h = harness().await;
        let mut log = NamespaceLog::bootstrap(
            h.db.clone(),
            h.crypto.clone(),
            "node",
            "nym://test",
            DEFAULT_EPOCH_SECONDS,
        )
        .await
        .unwrap();
        let (alice, _) = register(&h, "alice");
        log.submit(alice).await.unwrap().unwrap();
        let sth1 = log.tick().await.unwrap().unwrap();

        // "Restart": rebuild from the database alone.
        let mut log2 = NamespaceLog::bootstrap(
            h.db.clone(),
            h.crypto.clone(),
            "node",
            "nym://test-after-restart",
            DEFAULT_EPOCH_SECONDS,
        )
        .await
        .unwrap();
        assert_eq!(log2.last_epoch(), 1);
        assert_eq!(log2.state().len(), 1);
        assert_eq!(
            log2.state().get("alice").unwrap(),
            log.state().get("alice").unwrap()
        );

        // The next epoch chains onto the pre-restart head.
        let (bob, _) = register(&h, "bob");
        log2.submit(bob).await.unwrap().unwrap();
        let sth2 = log2.tick().await.unwrap().unwrap();
        assert_eq!(sth2.header.epoch, 2);
        assert_eq!(sth2.header.prev_epoch_hash, sth1.header.hash_hex().unwrap());

        // Log-tree consistency across the restart boundary: sth2 attests one
        // epoch; a client whose frontier predates the restart still verifies.
        let attested = &log2.log_leaves()[..1];
        assert_eq!(
            sth2.header.log_root,
            nymstr_federation::hash_hex(&merkle::root(attested))
        );

        // sthRange serves both epochs.
        let range = h.db.epochs_from(1).await.unwrap();
        assert_eq!(range.len(), 2);
    }
}
