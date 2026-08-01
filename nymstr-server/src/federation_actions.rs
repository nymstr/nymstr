//! Wire handlers for the namespace transparency-log actions
//! (SERVER_SPEC.md §8, §10, §11). Split from `message_utils.rs` to keep the
//! legacy protocol and the v2 proof-carrying protocol separable.
//!
//! Conventions:
//! - Reads are unauthenticated but rate-limited (proof construction costs
//!   CPU); writes authenticate via the mutation's own signature plus, for
//!   `register`, the liveness challenge.
//! - Every handler replies with `<action>Response`; errors are
//!   `{"status": "error", "message": ...}` in the response payload.
//! - All hashes are lowercase hex; Merkle paths are arrays of hex strings.

use crate::message_utils::MessageUtils;
use crate::transport::ReplyTag;
use nymstr_federation::canonical::to_canonical_json;
use nymstr_federation::entry::{validate_key, DirectoryEntry};
use nymstr_federation::merkle::{self, Hash};
use nymstr_federation::mutation::{Mutation, MutationOp};
use nymstr_federation::node::{
    node_id_for, witness_signing_payload, ForkCertificate, SignedTreeHead, WitnessSignature,
};
use nymstr_federation::{hash_hex, labels};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Proof JSON for one leaf: index, tree size, and sibling path.
fn proof_json(leaf_hash: &Hash, index: usize, tree_size: usize, siblings: &[Hash]) -> Value {
    json!({
        "leafHash": hash_hex(leaf_hash),
        "index": index,
        "treeSize": tree_size,
        "siblings": siblings.iter().map(hash_hex).collect::<Vec<_>>(),
    })
}

fn entry_with_proof(
    entry: &DirectoryEntry,
    index: usize,
    tree_size: usize,
    siblings: &[Hash],
) -> Value {
    let leaf = entry.leaf_hash().unwrap_or([0u8; 32]);
    json!({
        "entry": serde_json::to_value(entry).unwrap_or(Value::Null),
        "proof": proof_json(&leaf, index, tree_size, siblings),
    })
}

fn error_payload(message: &str) -> Value {
    json!({"status": "error", "message": message})
}

impl MessageUtils {
    /// Shared preamble for log-backed reads: rate limit + log presence.
    /// Returns None (after replying) when the request must not proceed.
    async fn log_read_guard(
        &mut self,
        sender_tag: &ReplyTag,
        sender_username: &str,
        response_action: &str,
    ) -> Option<std::sync::Arc<tokio::sync::Mutex<crate::federation_driver::NamespaceLog>>> {
        if !self
            .send_rate_limiter
            .check_and_record(&sender_tag.to_string())
        {
            self.send_unified_reply(
                sender_tag,
                error_payload("rate limit exceeded, please try again later"),
                response_action,
                sender_username,
            )
            .await;
            return None;
        }
        match &self.namespace_log {
            Some(log) => Some(log.clone()),
            None => {
                self.send_unified_reply(
                    sender_tag,
                    error_payload("namespace log unavailable"),
                    response_action,
                    sender_username,
                )
                .await;
                None
            }
        }
    }

    // ===== C1: mutation write path =====

    /// `submitMutation` (spec §8.1): register mutations get a liveness
    /// challenge first; everything else pools immediately.
    pub(crate) async fn handle_submit_mutation(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        if !self.rate_limiter.check_and_record(&sender_tag.to_string()) {
            self.send_unified_reply(
                &sender_tag,
                error_payload("rate limit exceeded, please try again later"),
                "submitMutationResponse",
                sender_username,
            )
            .await;
            return;
        }
        let Some(log) = self.namespace_log.clone() else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("namespace log unavailable"),
                "submitMutationResponse",
                sender_username,
            )
            .await;
            return;
        };
        let mutation: Mutation = match payload.get("mutation").cloned().map(serde_json::from_value)
        {
            Some(Ok(m)) => m,
            _ => {
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("missing or malformed mutation"),
                    "submitMutationResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };

        if mutation.op == MutationOp::Register {
            // Liveness challenge before pooling (spec §8.1).
            let nonce = Uuid::new_v4().to_string();
            self.pending_mutations.insert(
                sender_tag.clone(),
                crate::pending::PendingEntry::new((mutation, nonce.clone())),
            );
            // Distinct action from the legacy auth `challenge` so v2 clients
            // route it without colliding with register/login flows.
            self.send_unified_reply(
                &sender_tag,
                json!({"nonce": nonce, "context": "mutation"}),
                "mutationChallenge",
                sender_username,
            )
            .await;
            return;
        }

        let result = log.lock().await.submit(mutation).await;
        self.reply_submit_result(result, &sender_tag, sender_username)
            .await;
    }

    /// `submitMutationResponse`: the signed challenge nonce for a pending
    /// register mutation. The signature must come from the NEW identity key
    /// (proof of possession).
    pub(crate) async fn handle_submit_mutation_response(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self.namespace_log.clone() else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("namespace log unavailable"),
                "submitMutationResponse",
                sender_username,
            )
            .await;
            return;
        };
        let Some(signature) = payload.get("signature").and_then(Value::as_str) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing signature"),
                "submitMutationResponse",
                sender_username,
            )
            .await;
            return;
        };
        let Some(entry) = self.pending_mutations.remove(&sender_tag) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("no pending mutation"),
                "submitMutationResponse",
                sender_username,
            )
            .await;
            return;
        };
        let (mutation, nonce) = entry.data;
        let identity_pk = mutation
            .fields
            .get("identityPk")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !self.crypto.verify_signature(identity_pk, &nonce, signature) {
            self.send_unified_reply(
                &sender_tag,
                error_payload("invalid challenge signature"),
                "submitMutationResponse",
                sender_username,
            )
            .await;
            return;
        }
        let result = log.lock().await.submit(mutation).await;
        self.reply_submit_result(result, &sender_tag, sender_username)
            .await;
    }

    async fn reply_submit_result(
        &mut self,
        result: anyhow::Result<
            Result<nymstr_federation::node::InclusionPromise, nymstr_federation::FederationError>,
        >,
        sender_tag: &ReplyTag,
        sender_username: &str,
    ) {
        let payload = match result {
            Ok(Ok(promise)) => json!({
                "status": "accepted",
                "promise": serde_json::to_value(&promise).unwrap_or(Value::Null),
            }),
            Ok(Err(reason)) => json!({"status": "rejected", "reason": reason.to_string()}),
            Err(e) => {
                log::error!("submitMutation internal error: {e:#}");
                error_payload("internal error")
            }
        };
        self.send_unified_reply(
            sender_tag,
            payload,
            "submitMutationResponse",
            sender_username,
        )
        .await;
    }

    /// `mutationStatus` (spec §8.2): pool state plus, when finalized, the
    /// receipt (STH + inclusion proof for the entry's current state).
    pub(crate) async fn handle_mutation_status(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self
            .log_read_guard(&sender_tag, sender_username, "mutationStatusResponse")
            .await
        else {
            return;
        };
        let Some(mutation_hash) = payload.get("mutationHash").and_then(Value::as_str) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing mutationHash"),
                "mutationStatusResponse",
                sender_username,
            )
            .await;
            return;
        };
        let status = match self.db.fed_mutation_status(mutation_hash).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("unknown mutation"),
                    "mutationStatusResponse",
                    sender_username,
                )
                .await;
                return;
            }
            Err(e) => {
                log::error!("mutationStatus db error: {e:#}");
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("internal error"),
                    "mutationStatusResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let (state, epoch, reason, promise_json) = status;
        let mut response = json!({
            "state": state,
            "mutationHash": mutation_hash,
        });
        if let Some(epoch) = epoch {
            response["epoch"] = json!(epoch);
        }
        if let Some(reason) = reason {
            response["reason"] = json!(reason);
        }
        if let Some(pj) = promise_json {
            if let Ok(p) = serde_json::from_str::<Value>(&pj) {
                response["promise"] = p;
            }
        }
        if state == "finalized" {
            // Receipt: current entry state + proof under the latest STH.
            if let Ok(Some(key)) = self.db.fed_mutation_key(mutation_hash).await {
                let log = log.lock().await;
                if let (Some(sth), Ok((index, siblings))) =
                    (log.last_sth(), log.state().prove_inclusion(&key))
                {
                    if let Some(entry) = log.state().get(&key) {
                        response["receipt"] = json!({
                            "sth": serde_json::to_value(sth).unwrap_or(Value::Null),
                            "entry": serde_json::to_value(entry).unwrap_or(Value::Null),
                            "proof": proof_json(
                                &entry.leaf_hash().unwrap_or([0u8; 32]),
                                index,
                                log.state().len(),
                                &siblings,
                            ),
                        });
                    }
                }
            }
        }
        self.send_unified_reply(
            &sender_tag,
            response,
            "mutationStatusResponse",
            sender_username,
        )
        .await;
    }

    /// `nodeDescriptor` (spec §8.7): own descriptor, or a cached peer's.
    pub(crate) async fn handle_node_descriptor(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self
            .log_read_guard(&sender_tag, sender_username, "nodeDescriptorResponse")
            .await
        else {
            return;
        };
        let requested = payload.get("nodeId").and_then(Value::as_str);
        let own = {
            let log = log.lock().await;
            (
                log.node_id.clone(),
                serde_json::to_value(&log.descriptor).ok(),
            )
        };
        let response = match requested {
            None => own.1,
            Some(id) if id == own.0 => own.1,
            Some(id) => match self.db.get_node_descriptor(id).await {
                Ok(Some(json_str)) => serde_json::from_str(&json_str).ok(),
                _ => None,
            },
        };
        let payload = match response {
            Some(descriptor) => json!({"descriptor": descriptor}),
            None => error_payload("unknown node"),
        };
        self.send_unified_reply(
            &sender_tag,
            payload,
            "nodeDescriptorResponse",
            sender_username,
        )
        .await;
    }

    // ===== C2: proof-carrying reads =====

    /// `lookupProof` (spec §8.3): entry + inclusion proof (or adjacent-leaf
    /// non-inclusion), the latest STH, and log consistency from the client's
    /// frontier.
    pub(crate) async fn handle_lookup_proof(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self
            .log_read_guard(&sender_tag, sender_username, "lookupProofResponse")
            .await
        else {
            return;
        };
        let Some(key) = payload.get("key").and_then(Value::as_str) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing key"),
                "lookupProofResponse",
                sender_username,
            )
            .await;
            return;
        };
        if validate_key(key).is_err() {
            self.send_unified_reply(
                &sender_tag,
                error_payload("invalid key"),
                "lookupProofResponse",
                sender_username,
            )
            .await;
            return;
        }
        let frontier_size = payload
            .get("frontierSize")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let log = log.lock().await;
        let Some(sth) = log.last_sth() else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("no finalized epochs yet"),
                "lookupProofResponse",
                sender_username,
            )
            .await;
            return;
        };
        let mut response = json!({
            "sth": serde_json::to_value(sth).unwrap_or(Value::Null),
            "treeSize": log.state().len(),
        });

        // Consistency proof from the client's frontier to the log the latest
        // STH attests (all epochs before it).
        let attested = &log.log_leaves()[..log.log_leaves().len().saturating_sub(1)];
        if frontier_size > 0 {
            if frontier_size as usize > attested.len() {
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("frontier ahead of log"),
                    "lookupProofResponse",
                    sender_username,
                )
                .await;
                return;
            }
            if let Ok(path) = merkle::consistency_proof(attested, frontier_size as usize) {
                response["consistency"] = json!({
                    "fromSize": frontier_size,
                    "toSize": attested.len(),
                    "path": path.iter().map(hash_hex).collect::<Vec<_>>(),
                });
            }
        }

        match log.state().get(key) {
            Some(entry) => {
                if let Ok((index, siblings)) = log.state().prove_inclusion(key) {
                    response["found"] = json!(true);
                    response["entry"] = serde_json::to_value(entry).unwrap_or(Value::Null);
                    response["proof"] = proof_json(
                        &entry.leaf_hash().unwrap_or([0u8; 32]),
                        index,
                        log.state().len(),
                        &siblings,
                    );
                }
            }
            None => {
                response["found"] = json!(false);
                if let Ok((before, after)) = log.state().prove_absence(key) {
                    if let Some((entry, index, siblings)) = before {
                        response["before"] =
                            entry_with_proof(&entry, index, log.state().len(), &siblings);
                    }
                    if let Some((entry, index, siblings)) = after {
                        response["after"] =
                            entry_with_proof(&entry, index, log.state().len(), &siblings);
                    }
                }
            }
        }
        drop(log);
        self.send_unified_reply(
            &sender_tag,
            response,
            "lookupProofResponse",
            sender_username,
        )
        .await;
    }

    /// `sthRange` (spec §8.5): STHs (+ optional batches) from an epoch on.
    pub(crate) async fn handle_sth_range(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        const MAX_EPOCHS_PER_RESPONSE: usize = 100;
        if self
            .log_read_guard(&sender_tag, sender_username, "sthRangeResponse")
            .await
            .is_none()
        {
            return;
        }
        let from_epoch = payload
            .get("fromEpoch")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let include_batches = payload
            .get("includeBatches")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let rows = match self.db.epochs_from(from_epoch).await {
            Ok(rows) => rows,
            Err(e) => {
                log::error!("sthRange db error: {e:#}");
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("internal error"),
                    "sthRangeResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let has_more = rows.len() > MAX_EPOCHS_PER_RESPONSE;
        let mut sths = Vec::new();
        let mut batches = Vec::new();
        for (epoch, sth_json, batch_json) in rows.into_iter().take(MAX_EPOCHS_PER_RESPONSE) {
            if let Ok(sth) = serde_json::from_str::<Value>(&sth_json) {
                sths.push(sth);
            }
            if include_batches {
                if let Ok(batch) = serde_json::from_str::<Value>(&batch_json) {
                    batches.push(json!({"epoch": epoch, "batch": batch}));
                }
            }
        }
        let mut response = json!({"sths": sths, "hasMore": has_more});
        if include_batches {
            response["batches"] = json!(batches);
        }
        self.send_unified_reply(&sender_tag, response, "sthRangeResponse", sender_username)
            .await;
    }

    /// `entryHistory` (spec §8.4): the key's finalized mutation chain
    /// (self-certifying) plus the current inclusion proof.
    pub(crate) async fn handle_entry_history(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self
            .log_read_guard(&sender_tag, sender_username, "entryHistoryResponse")
            .await
        else {
            return;
        };
        let Some(key) = payload.get("key").and_then(Value::as_str) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing key"),
                "entryHistoryResponse",
                sender_username,
            )
            .await;
            return;
        };
        let mutations = match self.db.finalized_mutations_for_key(key).await {
            Ok(rows) => rows
                .iter()
                .filter_map(|j| serde_json::from_str::<Value>(j).ok())
                .collect::<Vec<_>>(),
            Err(e) => {
                log::error!("entryHistory db error: {e:#}");
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("internal error"),
                    "entryHistoryResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let mut response = json!({"key": key, "mutations": mutations});
        {
            let log = log.lock().await;
            if let (Some(sth), Some(entry), Ok((index, siblings))) = (
                log.last_sth(),
                log.state().get(key),
                log.state().prove_inclusion(key),
            ) {
                response["sth"] = serde_json::to_value(sth).unwrap_or(Value::Null);
                response["entry"] = serde_json::to_value(entry).unwrap_or(Value::Null);
                response["proof"] = proof_json(
                    &entry.leaf_hash().unwrap_or([0u8; 32]),
                    index,
                    log.state().len(),
                    &siblings,
                );
            }
        }
        self.send_unified_reply(
            &sender_tag,
            response,
            "entryHistoryResponse",
            sender_username,
        )
        .await;
    }

    // ===== C3: auxiliary storage =====

    /// `keyPackagePublish` (spec §10): store a KeyPackage signed by the
    /// user's directory-verified identity key.
    pub(crate) async fn handle_key_package_publish(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self
            .log_read_guard(&sender_tag, sender_username, "keyPackagePublishResponse")
            .await
        else {
            return;
        };
        let (Some(username), Some(key_package), Some(sig)) = (
            payload.get("username").and_then(Value::as_str),
            payload.get("keyPackage").and_then(Value::as_str),
            payload.get("signature").and_then(Value::as_str),
        ) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing username, keyPackage, or signature"),
                "keyPackagePublishResponse",
                sender_username,
            )
            .await;
            return;
        };
        let identity_pk = {
            let log = log.lock().await;
            log.state().get(username).map(|e| e.identity_pk.clone())
        };
        let Some(identity_pk) = identity_pk else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("no directory entry for user"),
                "keyPackagePublishResponse",
                sender_username,
            )
            .await;
            return;
        };
        let signed = format!("{}{}", labels::KEY_PACKAGE, key_package);
        if !self.crypto.verify_signature(&identity_pk, &signed, sig) {
            self.send_unified_reply(
                &sender_tag,
                error_payload("bad signature"),
                "keyPackagePublishResponse",
                sender_username,
            )
            .await;
            return;
        }
        let payload = match self.db.upsert_key_package(username, key_package, sig).await {
            Ok(()) => json!({"status": "success"}),
            Err(e) => {
                log::error!("keyPackagePublish db error: {e:#}");
                error_payload("internal error")
            }
        };
        self.send_unified_reply(
            &sender_tag,
            payload,
            "keyPackagePublishResponse",
            sender_username,
        )
        .await;
    }

    /// `keyPackageFetch` (spec §10): serve a stored KeyPackage; the consumer
    /// verifies its signature against the directory-verified identity key.
    pub(crate) async fn handle_key_package_fetch(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        if self
            .log_read_guard(&sender_tag, sender_username, "keyPackageFetchResponse")
            .await
            .is_none()
        {
            return;
        }
        let Some(username) = payload.get("username").and_then(Value::as_str) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing username"),
                "keyPackageFetchResponse",
                sender_username,
            )
            .await;
            return;
        };
        let payload = match self.db.get_key_package(username).await {
            Ok(Some((key_package, sig))) => {
                json!({"username": username, "keyPackage": key_package, "signature": sig})
            }
            Ok(None) => error_payload("no key package stored"),
            Err(e) => {
                log::error!("keyPackageFetch db error: {e:#}");
                error_payload("internal error")
            }
        };
        self.send_unified_reply(
            &sender_tag,
            payload,
            "keyPackageFetchResponse",
            sender_username,
        )
        .await;
    }

    /// `groupAddressPublish` (spec §11.3): store a group's signed address
    /// record, verified against the group's directory entry.
    pub(crate) async fn handle_group_address_publish(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self
            .log_read_guard(&sender_tag, sender_username, "groupAddressPublishResponse")
            .await
        else {
            return;
        };
        let (Some(record), Some(sig)) = (
            payload.get("record"),
            payload.get("signature").and_then(Value::as_str),
        ) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing record or signature"),
                "groupAddressPublishResponse",
                sender_username,
            )
            .await;
            return;
        };
        let (Some(group_id), Some(_nym_address), Some(issued_at)) = (
            record.get("groupId").and_then(Value::as_str),
            record.get("nymAddress").and_then(Value::as_str),
            record.get("issuedAt").and_then(Value::as_str),
        ) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("record must contain groupId, nymAddress, issuedAt"),
                "groupAddressPublishResponse",
                sender_username,
            )
            .await;
            return;
        };
        let key = format!("group/{group_id}");
        let group_pk = {
            let log = log.lock().await;
            log.state().get(&key).map(|e| e.identity_pk.clone())
        };
        let Some(group_pk) = group_pk else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("no directory entry for group"),
                "groupAddressPublishResponse",
                sender_username,
            )
            .await;
            return;
        };
        let canon = match to_canonical_json(record) {
            Ok(c) => c,
            Err(_) => {
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("record not canonicalizable"),
                    "groupAddressPublishResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let signed = format!("{}{}", labels::GROUP_ADDR, canon);
        if !self.crypto.verify_signature(&group_pk, &signed, sig) {
            self.send_unified_reply(
                &sender_tag,
                error_payload("bad signature"),
                "groupAddressPublishResponse",
                sender_username,
            )
            .await;
            return;
        }
        let payload = match self
            .db
            .upsert_group_address(group_id, &record.to_string(), sig, issued_at)
            .await
        {
            Ok(()) => json!({"status": "success"}),
            Err(e) => {
                log::error!("groupAddressPublish db error: {e:#}");
                error_payload("internal error")
            }
        };
        self.send_unified_reply(
            &sender_tag,
            payload,
            "groupAddressPublishResponse",
            sender_username,
        )
        .await;
    }

    // ===== Phase E: witnessing (spec §12) =====

    /// `witnessRoot` (spec §12.1): a witness submits its signature over one of
    /// this node's epoch hashes; the node verifies it (self-authenticating
    /// witnessId) and attaches it to the stored STH.
    pub(crate) async fn handle_witness_root(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        let Some(log) = self
            .log_read_guard(&sender_tag, sender_username, "witnessRootResponse")
            .await
        else {
            return;
        };
        let (Some(epoch), Some(witness_id), Some(witness_pk), Some(sig)) = (
            payload.get("epoch").and_then(Value::as_u64),
            payload.get("witnessId").and_then(Value::as_str),
            payload.get("witnessPk").and_then(Value::as_str),
            payload.get("signature").and_then(Value::as_str),
        ) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing epoch, witnessId, witnessPk, or signature"),
                "witnessRootResponse",
                sender_username,
            )
            .await;
            return;
        };
        // Witness id is self-authenticating: hash of its public key.
        if witness_id != node_id_for(witness_pk) {
            self.send_unified_reply(
                &sender_tag,
                error_payload("witnessId does not match witnessPk"),
                "witnessRootResponse",
                sender_username,
            )
            .await;
            return;
        }
        // Load the stored STH for that epoch.
        let rows = match self.db.epochs_from(epoch).await {
            Ok(rows) => rows,
            Err(e) => {
                log::error!("witnessRoot db error: {e:#}");
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("internal error"),
                    "witnessRootResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let Some((_, sth_json, _)) = rows.into_iter().find(|(e, _, _)| *e == epoch) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("unknown epoch"),
                "witnessRootResponse",
                sender_username,
            )
            .await;
            return;
        };
        let mut sth: SignedTreeHead = match serde_json::from_str(&sth_json) {
            Ok(s) => s,
            Err(_) => {
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("internal error"),
                    "witnessRootResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let epoch_hash = match sth.header.hash_hex() {
            Ok(h) => h,
            Err(_) => {
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("internal error"),
                    "witnessRootResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        if !self
            .crypto
            .verify_signature(witness_pk, &witness_signing_payload(&epoch_hash), sig)
        {
            self.send_unified_reply(
                &sender_tag,
                error_payload("bad witness signature"),
                "witnessRootResponse",
                sender_username,
            )
            .await;
            return;
        }
        // Attach (dedup by witnessId).
        if !sth.witness_sigs.iter().any(|w| w.witness_id == witness_id) {
            sth.witness_sigs.push(WitnessSignature {
                witness_id: witness_id.to_string(),
                sig: sig.to_string(),
            });
            if let Ok(updated) = serde_json::to_string(&sth) {
                let _ = self.db.update_epoch_sth(epoch, &updated).await;
                // Keep the in-memory latest STH in sync if this is it.
                let mut log = log.lock().await;
                if log.last_epoch() == epoch {
                    log.attach_witness_to_last(WitnessSignature {
                        witness_id: witness_id.to_string(),
                        sig: sig.to_string(),
                    });
                }
            }
        }
        self.send_unified_reply(
            &sender_tag,
            json!({"status": "success", "epoch": epoch}),
            "witnessRootResponse",
            sender_username,
        )
        .await;
    }

    /// `submitConflict` (spec §12): accept a fork certificate about any node,
    /// verify it self-contained, and store it for propagation.
    pub(crate) async fn handle_submit_conflict(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        if self
            .log_read_guard(&sender_tag, sender_username, "submitConflictResponse")
            .await
            .is_none()
        {
            return;
        }
        let (Some(cert_val), Some(node_pk)) = (
            payload.get("certificate"),
            payload.get("nodePk").and_then(Value::as_str),
        ) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing certificate or nodePk"),
                "submitConflictResponse",
                sender_username,
            )
            .await;
            return;
        };
        let cert: ForkCertificate = match serde_json::from_value(cert_val.clone()) {
            Ok(c) => c,
            Err(_) => {
                self.send_unified_reply(
                    &sender_tag,
                    error_payload("malformed certificate"),
                    "submitConflictResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        // The subject key must match the certificate's claimed node id, and
        // the certificate must verify self-contained (spec §12.2).
        if node_id_for(node_pk) != cert.node_id
            || cert
                .verify(node_pk, &nymstr_federation::PgpVerifier)
                .is_err()
        {
            self.send_unified_reply(
                &sender_tag,
                error_payload("invalid conflict certificate"),
                "submitConflictResponse",
                sender_username,
            )
            .await;
            return;
        }
        let cert_hash = hash_hex(&Sha256::digest(cert_val.to_string().as_bytes()).into());
        let payload = match self
            .db
            .insert_conflict_cert(&cert_hash, &cert.node_id, &cert_val.to_string())
            .await
        {
            Ok(_) => json!({"status": "success", "certHash": cert_hash}),
            Err(e) => {
                log::error!("submitConflict db error: {e:#}");
                error_payload("internal error")
            }
        };
        self.send_unified_reply(
            &sender_tag,
            payload,
            "submitConflictResponse",
            sender_username,
        )
        .await;
    }

    /// `conflictCerts` (spec §8.6): serve known conflict certificates,
    /// optionally filtered by subject node.
    pub(crate) async fn handle_conflict_certs(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        if self
            .log_read_guard(&sender_tag, sender_username, "conflictCertsResponse")
            .await
            .is_none()
        {
            return;
        }
        let subject = payload.get("subjectNode").and_then(Value::as_str);
        let payload = match self.db.conflict_certs(subject).await {
            Ok(rows) => {
                let certs: Vec<Value> = rows
                    .iter()
                    .filter_map(|j| serde_json::from_str(j).ok())
                    .collect();
                json!({"certificates": certs})
            }
            Err(e) => {
                log::error!("conflictCerts db error: {e:#}");
                error_payload("internal error")
            }
        };
        self.send_unified_reply(
            &sender_tag,
            payload,
            "conflictCertsResponse",
            sender_username,
        )
        .await;
    }

    /// `groupAddress` (spec §11.3): serve the newest signed address record;
    /// the client verifies the signature against the group's directory key.
    pub(crate) async fn handle_group_address(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        if self
            .log_read_guard(&sender_tag, sender_username, "groupAddressResponse")
            .await
            .is_none()
        {
            return;
        }
        let Some(group_id) = payload.get("groupId").and_then(Value::as_str) else {
            self.send_unified_reply(
                &sender_tag,
                error_payload("missing groupId"),
                "groupAddressResponse",
                sender_username,
            )
            .await;
            return;
        };
        let payload = match self.db.get_group_address(group_id).await {
            Ok(Some((record_json, sig))) => {
                let record: Value = serde_json::from_str(&record_json).unwrap_or(Value::Null);
                json!({"record": record, "signature": sig})
            }
            Ok(None) => error_payload("no address record stored"),
            Err(e) => {
                log::error!("groupAddress db error: {e:#}");
                error_payload("internal error")
            }
        };
        self.send_unified_reply(
            &sender_tag,
            payload,
            "groupAddressResponse",
            sender_username,
        )
        .await;
    }
}
