//! Integration tests for the v2 namespace-log wire actions (SERVER_SPEC §8):
//! a real MessageUtils + NamespaceLog over temp SQLite, real PGP keys via
//! ServerKeyManager, driven through CapturingReplySender — no mixnet. Every
//! proof is verified client-side with the shared nymstr-federation verifier.

use nymstr_crypto::ServerKeyManager;
use nymstr_federation::merkle;
use nymstr_federation::node::InclusionPromise;
use nymstr_federation::{hash_from_hex, PgpVerifier};
use nymstr_server::db_utils::DbUtils;
use nymstr_server::federation_driver::NamespaceLog;
use nymstr_server::message_utils::MessageUtils;
use nymstr_server::transport::{CapturingReplySender, ReplyTag};
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

struct World {
    utils: MessageUtils,
    sender: Arc<CapturingReplySender>,
    log: Arc<Mutex<NamespaceLog>>,
    crypto: ServerKeyManager,
    _dir: TempDir,
}

async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("t.db");
    std::fs::File::create(&db_path).unwrap();
    let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
    let crypto = ServerKeyManager::new(dir.path().join("keys"), "pw".into()).unwrap();
    crypto.generate_key_pair("server").unwrap();
    let log = Arc::new(Mutex::new(
        NamespaceLog::bootstrap(db.clone(), crypto.clone(), "server", "nym://test", 30)
            .await
            .unwrap(),
    ));
    let sender = Arc::new(CapturingReplySender::new());
    let utils = MessageUtils::new(
        "server".to_string(),
        Box::new(Arc::clone(&sender)),
        db,
        crypto.clone(),
        None,
    )
    .with_namespace_log(Arc::clone(&log));
    World {
        utils,
        sender,
        log,
        crypto,
        _dir: dir,
    }
}

async fn send(w: &mut World, tag_id: &str, action: &str, payload: Value) -> Value {
    let envelope = json!({
        "type": "message",
        "action": action,
        "sender": "client",
        "recipient": "server",
        "payload": payload,
        "signature": "unused",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    w.utils
        .process_message(
            Some(ReplyTag::Stdio(tag_id.to_string())),
            envelope.to_string().into_bytes(),
        )
        .await;
    let replies = w.sender.take_replies().await;
    assert_eq!(replies.len(), 1, "expected one reply for {action}");
    let msg: Value = serde_json::from_str(&replies[0].1).unwrap();
    msg["payload"].clone()
}

/// Build a register mutation for `user`, signed with the user's identity key.
fn register_mutation(crypto: &ServerKeyManager, user: &str) -> Value {
    let pk = crypto.generate_key_pair(user).unwrap();
    let mut envelope = json!({
        "version": 2,
        "op": "register",
        "key": user,
        "seqNo": 1,
        "nonce": "0123456789abcdef0123456789abcdef",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "fields": { "identityPk": pk },
        "userSig": "",
    });
    // Sign the canonical envelope-without-userSig via the shared type.
    let m: nymstr_federation::mutation::Mutation =
        serde_json::from_value(envelope.clone()).unwrap();
    let sig = crypto
        .sign_message(user, &m.signing_payload().unwrap())
        .unwrap();
    envelope["userSig"] = json!(sig);
    envelope
}

/// Full v2 register: submitMutation → mutationChallenge → signed response.
async fn register_via_wire(w: &mut World, tag: &str, user: &str) -> InclusionPromise {
    let mutation = register_mutation(&w.crypto, user);
    let challenge = send(w, tag, "submitMutation", json!({ "mutation": mutation })).await;
    let nonce = challenge["nonce"].as_str().expect("nonce").to_string();
    let sig = w.crypto.sign_message(user, &nonce).unwrap();
    let accepted = send(
        w,
        tag,
        "submitMutationResponse",
        json!({ "signature": sig }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    serde_json::from_value(accepted["promise"].clone()).unwrap()
}

#[tokio::test]
async fn register_roundtrip_receipt_and_verified_proof() {
    let mut w = world().await;
    let promise = register_via_wire(&mut w, "alice", "alice").await;

    // The promise verifies against the node's descriptor-bound key.
    let (node_id, node_pk) = {
        let log = w.log.lock().await;
        (log.node_id.clone(), log.node_pk.clone())
    };
    promise.verify(&node_id, &node_pk, &PgpVerifier).unwrap();

    // Pending until the epoch ticks.
    let status = send(
        &mut w,
        "alice",
        "mutationStatus",
        json!({ "mutationHash": promise.mutation_hash }),
    )
    .await;
    assert_eq!(status["state"], "pending");

    w.log.lock().await.tick().await.unwrap().unwrap();

    // Finalized, with a receipt whose inclusion proof verifies client-side.
    let status = send(
        &mut w,
        "alice",
        "mutationStatus",
        json!({ "mutationHash": promise.mutation_hash }),
    )
    .await;
    assert_eq!(status["state"], "finalized");
    let receipt = &status["receipt"];
    let dir_root =
        hash_from_hex(receipt["sth"]["header"]["directoryRoot"].as_str().unwrap()).unwrap();
    let leaf = hash_from_hex(receipt["proof"]["leafHash"].as_str().unwrap()).unwrap();
    let siblings: Vec<_> = receipt["proof"]["siblings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| hash_from_hex(s.as_str().unwrap()).unwrap())
        .collect();
    assert!(merkle::verify_inclusion(
        &leaf,
        receipt["proof"]["index"].as_u64().unwrap(),
        receipt["proof"]["treeSize"].as_u64().unwrap(),
        &siblings,
        &dir_root,
    ));
}

#[tokio::test]
async fn lookup_proof_found_and_absent() {
    let mut w = world().await;
    register_via_wire(&mut w, "s1", "alice").await;
    register_via_wire(&mut w, "s2", "carol").await;
    w.log.lock().await.tick().await.unwrap().unwrap();

    // Found: the inclusion proof verifies against the signed directory root.
    let found = send(&mut w, "s3", "lookupProof", json!({ "key": "alice" })).await;
    assert_eq!(found["found"], true);
    let dir_root =
        hash_from_hex(found["sth"]["header"]["directoryRoot"].as_str().unwrap()).unwrap();
    let leaf = hash_from_hex(found["proof"]["leafHash"].as_str().unwrap()).unwrap();
    let siblings: Vec<_> = found["proof"]["siblings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| hash_from_hex(s.as_str().unwrap()).unwrap())
        .collect();
    assert!(merkle::verify_inclusion(
        &leaf,
        found["proof"]["index"].as_u64().unwrap(),
        found["treeSize"].as_u64().unwrap(),
        &siblings,
        &dir_root,
    ));

    // Absent: adjacent neighbors straddle the missing key.
    let absent = send(&mut w, "s4", "lookupProof", json!({ "key": "bob" })).await;
    assert_eq!(absent["found"], false);
    assert_eq!(absent["before"]["entry"]["key"], "alice");
    assert_eq!(absent["after"]["entry"]["key"], "carol");
}

#[tokio::test]
async fn invalid_mutation_rejected_and_forged_challenge_denied() {
    let mut w = world().await;

    // Migrate for a nonexistent key: immediate rejection, no challenge.
    w.crypto.generate_key_pair("ghost").unwrap();
    let mut migrate = json!({
        "version": 2,
        "op": "migrate",
        "key": "ghost",
        "seqNo": 2,
        "nonce": "abcdefabcdefabcdefabcdefabcdefab",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "fields": { "migratedTo": format!("ghost@{}", "a".repeat(64)) },
        "userSig": "",
    });
    let m: nymstr_federation::mutation::Mutation = serde_json::from_value(migrate.clone()).unwrap();
    migrate["userSig"] = json!(w
        .crypto
        .sign_message("ghost", &m.signing_payload().unwrap())
        .unwrap());
    let rejected = send(
        &mut w,
        "sx",
        "submitMutation",
        json!({ "mutation": migrate }),
    )
    .await;
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["reason"], "no entry exists for key");

    // Register challenge answered with the wrong key fails.
    let mutation = register_mutation(&w.crypto, "eve");
    w.crypto.generate_key_pair("mallory").unwrap();
    let challenge = send(
        &mut w,
        "sz",
        "submitMutation",
        json!({ "mutation": mutation }),
    )
    .await;
    let nonce = challenge["nonce"].as_str().unwrap().to_string();
    let wrong_sig = w.crypto.sign_message("mallory", &nonce).unwrap();
    let denied = send(
        &mut w,
        "sz",
        "submitMutationResponse",
        json!({ "signature": wrong_sig }),
    )
    .await;
    assert_eq!(denied["status"], "error");
}
