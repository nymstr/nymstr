//! Transparency-log commands (SERVER_SPEC.md): publish the current user's
//! identity into the discovery node's namespace log, and verify another
//! user's identity with a proof-carrying lookup.
//!
//! These exercise the full client verifier: `publish_identity` writes an
//! entry via `submitMutation`; `verify_identity` fetches the node descriptor
//! and a `lookupProof`, runs the five-step §8.3 check, and reconciles against
//! the local pin table.

use std::time::Duration;
use tauri::State;
use uuid::Uuid;

use crate::crypto::pgp::{PgpKeyManager, PgpSigner};
use crate::state::AppState;
use crate::types::ApiError;
use nymstr_federation::node::NodeDescriptor;
use nymstr_federation::verify::{build_register, verify_lookup, LookupOutcome, Pin};
use nymstr_federation::PgpVerifier;

const FED_TIMEOUT: Duration = Duration::from_secs(20);

/// Await a federation response (resolved by the message loop) with a timeout.
async fn await_fed(
    state: &AppState,
    action: &str,
    rx: tokio::sync::oneshot::Receiver<serde_json::Value>,
) -> Result<serde_json::Value, ApiError> {
    match tokio::time::timeout(FED_TIMEOUT, rx).await {
        Ok(Ok(payload)) => Ok(payload),
        _ => {
            state.cancel_pending_fed(action).await;
            Err(ApiError::timeout(format!("timed out waiting for {action}")))
        }
    }
}

/// Fetch and verify the discovery node's descriptor. Returns (node_id, node_pk).
async fn fetch_verified_descriptor(
    state: &AppState,
    mixnet: &crate::core::mixnet_client::MixnetService,
    sender: &str,
) -> Result<(String, String), ApiError> {
    let rx = state.register_pending_fed("nodeDescriptorResponse").await;
    mixnet
        .send_node_descriptor(sender, None)
        .await
        .map_err(|e| ApiError::internal(format!("send nodeDescriptor: {e}")))?;
    let payload = await_fed(state, "nodeDescriptorResponse", rx).await?;
    if payload.get("status").and_then(|v| v.as_str()) == Some("error") {
        return Err(ApiError::internal("node returned no descriptor"));
    }
    let descriptor: NodeDescriptor = serde_json::from_value(payload["descriptor"].clone())
        .map_err(|_| ApiError::internal("malformed descriptor"))?;
    descriptor
        .verify(&PgpVerifier)
        .map_err(|e| ApiError::internal(format!("descriptor verification failed: {e}")))?;
    Ok((descriptor.node_id.clone(), descriptor.node_pk.clone()))
}

/// Publish the current user's identity key into the node's namespace log.
/// Returns a human-readable status plus the mutation hash to poll.
#[tauri::command]
pub async fn publish_identity(state: State<'_, AppState>) -> Result<serde_json::Value, ApiError> {
    let user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::authentication("Not logged in"))?;
    let mixnet = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Mixnet not connected"))?;
    let public = state
        .get_pgp_public_key()
        .await
        .ok_or_else(|| ApiError::authentication("No public key loaded"))?;
    let (secret, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::authentication("No signing key loaded"))?;
    let identity_pk = PgpKeyManager::public_key_armored(&public)
        .map_err(|e| ApiError::internal(format!("armor public key: {e}")))?;

    // Build and sign the register mutation locally.
    let nonce = Uuid::new_v4().simple().to_string(); // 32 lowercase hex
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mutation = build_register(
        &user.username,
        &identity_pk,
        1,
        &nonce,
        &timestamp,
        |payload| {
            PgpSigner::sign_detached_secure(&secret, payload.as_bytes(), &passphrase)
                .map_err(|e| anyhow::anyhow!(e))
        },
    )
    .map_err(|e| ApiError::internal(format!("build mutation: {e}")))?;
    let mutation_hash = mutation
        .hash_hex()
        .map_err(|e| ApiError::internal(format!("{e}")))?;
    let mutation_json =
        serde_json::to_value(&mutation).map_err(|e| ApiError::internal(e.to_string()))?;

    // submitMutation → mutationChallenge (register requires liveness proof).
    let rx = state.register_pending_fed("mutationChallenge").await;
    mixnet
        .send_submit_mutation(&user.username, mutation_json)
        .await
        .map_err(|e| ApiError::internal(format!("send submitMutation: {e}")))?;
    let challenge = await_fed(&state, "mutationChallenge", rx).await?;
    let server_nonce = challenge
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("challenge missing nonce"))?;

    // Sign the server nonce with the same identity key.
    let sig = PgpSigner::sign_detached_secure(&secret, server_nonce.as_bytes(), &passphrase)
        .map_err(|e| ApiError::internal(format!("sign challenge: {e}")))?;
    let rx = state.register_pending_fed("submitMutationResponse").await;
    mixnet
        .send_submit_mutation_response(&user.username, &sig)
        .await
        .map_err(|e| ApiError::internal(format!("send response: {e}")))?;
    let result = await_fed(&state, "submitMutationResponse", rx).await?;

    match result.get("status").and_then(|v| v.as_str()) {
        Some("accepted") => Ok(serde_json::json!({
            "status": "accepted",
            "message": "Identity submitted. It will be provable once the next epoch finalizes (~30s).",
            "mutationHash": mutation_hash,
        })),
        Some("rejected") => {
            let reason = result
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(serde_json::json!({
                "status": "rejected",
                "message": format!("Rejected: {reason}"),
            }))
        }
        _ => Err(ApiError::internal(format!("unexpected response: {result}"))),
    }
}

/// Verify another user's identity via a proof-carrying lookup, reconciled
/// against the local pin table. Returns the verified outcome.
#[tauri::command]
pub async fn verify_identity(
    username: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, ApiError> {
    let user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::authentication("Not logged in"))?;
    let mixnet = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Mixnet not connected"))?;

    // Step 0: descriptor (binds nodeId to node key).
    let (node_id, node_pk) = fetch_verified_descriptor(&state, &mixnet, &user.username).await?;
    let qualified = format!("{username}@{node_id}");

    // Load an existing pin for this identity, if any.
    let pin_row: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT identity_pk, seq_no, verified_oob FROM federation_pins WHERE qualified_name = ?",
    )
    .bind(&qualified)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let pin = pin_row.as_ref().map(|(pk, seq, oob)| Pin {
        qualified_name: qualified.clone(),
        identity_pk: pk.clone(),
        seq_no: *seq as u64,
        verified_oob: *oob != 0,
    });

    // Step 1-5: lookupProof + verify.
    let rx = state.register_pending_fed("lookupProofResponse").await;
    mixnet
        .send_lookup_proof(&user.username, &username, 0)
        .await
        .map_err(|e| ApiError::internal(format!("send lookupProof: {e}")))?;
    let payload = await_fed(&state, "lookupProofResponse", rx).await?;
    if payload.get("status").and_then(|v| v.as_str()) == Some("error") {
        let msg = payload
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("lookup failed");
        return Err(ApiError::internal(msg.to_string()));
    }

    let outcome = verify_lookup(
        &payload,
        &username,
        &node_id,
        &node_pk,
        None,
        pin.as_ref(),
        &PgpVerifier,
    );

    match outcome {
        Ok((LookupOutcome::Active { entry, pin }, _)) => {
            // Persist the (possibly new) pin.
            sqlx::query(
                "INSERT INTO federation_pins (qualified_name, identity_pk, seq_no, verified_oob) VALUES (?, ?, ?, ?)
                 ON CONFLICT(qualified_name) DO UPDATE SET identity_pk = excluded.identity_pk, seq_no = excluded.seq_no, updated_at = datetime('now')",
            )
            .bind(&pin.qualified_name)
            .bind(&pin.identity_pk)
            .bind(pin.seq_no as i64)
            .bind(pin.verified_oob as i64)
            .execute(&state.db)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
            Ok(serde_json::json!({
                "status": "verified",
                "qualifiedName": qualified,
                "fingerprint": fingerprint(&entry.identity_pk),
                "seqNo": entry.seq_no,
                "message": if pin_row.is_some() { "Verified — key matches your pin." } else { "Verified — key pinned." },
            }))
        }
        Ok((LookupOutcome::Migrated { to }, _)) => Ok(serde_json::json!({
            "status": "migrated",
            "migratedTo": to,
            "message": format!("Identity has moved to {to}. Follow the migration."),
        })),
        Ok((LookupOutcome::Revoked, _)) => Ok(serde_json::json!({
            "status": "revoked",
            "message": "This identity has been revoked — do not trust it.",
        })),
        Ok((LookupOutcome::Absent, _)) => Ok(serde_json::json!({
            "status": "absent",
            "message": "No such identity in this node's namespace (verified by non-inclusion).",
        })),
        Err(e) => Ok(serde_json::json!({
            "status": "failed",
            "message": format!("Verification FAILED: {e}"),
        })),
    }
}

/// A short, human-comparable fingerprint of an armored public key.
fn fingerprint(armored_pk: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(armored_pk.as_bytes());
    let hex = hex::encode(hash);
    // Group the first 16 hex chars for readability.
    hex.as_bytes()
        .chunks(4)
        .take(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}
