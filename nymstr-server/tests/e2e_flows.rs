//! In-process end-to-end tests that exercise the full client initialization
//! and messaging flow: registration, login, send, and receive — with real
//! PGP cryptography, no mocks.

use serde_json::{json, Value};
use std::sync::Arc;

// Import the server's own modules.
// (integration tests can only use the crate's public API)
// We access everything through the binary crate's public items.

/// A lightweight "client" that holds PGP keys and can sign messages.
struct TestClient {
    username: String,
    public_key: String,
    crypto: nymstr_crypto::ServerKeyManager,
    tag: nymstr_server::transport::ReplyTag,
}

/// Shared test server that wraps MessageUtils + CapturingReplySender.
struct TestServer {
    message_utils: nymstr_server::message_utils::MessageUtils,
    sender: Arc<nymstr_server::transport::CapturingReplySender>,
}

impl TestServer {
    async fn new(temp_dir: &std::path::Path) -> Self {
        let db_path = temp_dir.join("server.db");
        let keys_dir = temp_dir.join("server_keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        // Write seed phrase
        let secret_path = temp_dir.join("seed");
        std::fs::write(&secret_path, "test-seed-phrase-for-e2e").unwrap();

        let crypto =
            nymstr_crypto::ServerKeyManager::new(keys_dir, "test-seed-phrase-for-e2e".into())
                .unwrap();

        // Generate server keypair
        crypto.generate_key_pair("server").unwrap();

        // Create DB
        if !db_path.exists() {
            std::fs::File::create(&db_path).unwrap();
        }
        let db = nymstr_server::db_utils::DbUtils::new(db_path.to_str().unwrap())
            .await
            .unwrap();

        let sender = Arc::new(nymstr_server::transport::CapturingReplySender::new());
        let message_utils = nymstr_server::message_utils::MessageUtils::new(
            "server".to_string(),
            Box::new(Arc::clone(&sender)),
            db,
            crypto,
            None,
        );

        TestServer {
            message_utils,
            sender,
        }
    }

    /// Send a message and return all replies generated.
    async fn send(
        &mut self,
        tag: &nymstr_server::transport::ReplyTag,
        message: Value,
    ) -> Vec<(String, Value)> {
        let bytes = message.to_string().into_bytes();
        self.message_utils
            .process_message(Some(tag.clone()), bytes)
            .await;

        self.sender
            .take_replies()
            .await
            .into_iter()
            .map(|(t, m)| {
                let parsed: Value = serde_json::from_str(&m).unwrap_or(Value::String(m));
                (t, parsed)
            })
            .collect()
    }
}

impl TestClient {
    fn new(username: &str, temp_dir: &std::path::Path) -> Self {
        let keys_dir = temp_dir.join(format!("{}_keys", username));
        std::fs::create_dir_all(&keys_dir).unwrap();

        let crypto =
            nymstr_crypto::ServerKeyManager::new(keys_dir, "client-password".into()).unwrap();
        let public_key = crypto.generate_key_pair(username).unwrap();

        let tag = nymstr_server::transport::ReplyTag::Stdio(username.to_string());

        TestClient {
            username: username.to_string(),
            public_key,
            crypto,
            tag,
        }
    }

    fn sign(&self, message: &str) -> String {
        self.crypto.sign_message(&self.username, message).unwrap()
    }

    /// Build a registration request.
    fn register_msg(&self) -> Value {
        json!({
            "action": "register",
            "username": self.username,
            "publicKey": self.public_key,
        })
    }

    /// Build a registration response (signs the nonce).
    fn registration_response_msg(&self, nonce: &str) -> Value {
        let sig = self.sign(nonce);
        json!({
            "action": "registrationResponse",
            "signature": sig,
        })
    }

    /// Build a login request.
    fn login_msg(&self) -> Value {
        json!({
            "action": "login",
            "username": self.username,
        })
    }

    /// Build a login response (signs the nonce).
    fn login_response_msg(&self, nonce: &str) -> Value {
        let sig = self.sign(nonce);
        json!({
            "action": "loginResponse",
            "signature": sig,
        })
    }

    /// Build a send message request (legacy format).
    fn send_msg(&self, recipient: &str, body: &str) -> Value {
        let content = json!({
            "sender": self.username,
            "recipient": recipient,
            "body": body,
            "senderPublicKey": self.public_key,
        });
        let content_str = content.to_string();
        let sig = self.sign(&content_str);
        json!({
            "action": "send",
            "content": content_str,
            "signature": sig,
        })
    }

    /// Build a query request.
    fn query_msg(&self, target: &str) -> Value {
        json!({
            "action": "query",
            "username": target,
        })
    }

    /// Build a fetchPending request (unified format, requires signature).
    fn fetch_pending_msg(&self) -> Value {
        let timestamp = chrono::Utc::now().timestamp();
        let to_sign = format!("fetchPending:{}:{}", self.username, timestamp);
        let sig = self.sign(&to_sign);
        json!({
            "type": "message",
            "action": "fetchPending",
            "sender": self.username,
            "payload": {
                "timestamp": timestamp
            },
            "signature": sig
        })
    }

    /// Build a unified-format relay message (keyPackageRequest, p2pWelcome, etc.)
    fn relay_msg(&self, action: &str, recipient: &str, payload: Value) -> Value {
        let sig = self.sign(&serde_json::to_string(&payload).unwrap_or_default());
        json!({
            "type": "system",
            "action": action,
            "sender": self.username,
            "recipient": recipient,
            "payload": payload,
            "signature": sig
        })
    }
}

/// Helper: register a client with the server (challenge-response flow).
async fn register_client(server: &mut TestServer, client: &TestClient) {
    let replies = server.send(&client.tag, client.register_msg()).await;
    assert!(
        !replies.is_empty(),
        "No reply to register for {}",
        client.username
    );
    let nonce = extract_nonce(&replies[0].1);
    let replies = server
        .send(&client.tag, client.registration_response_msg(&nonce))
        .await;
    assert_eq!(
        replies[0].1["content"].as_str().unwrap(),
        "success",
        "Registration failed for {}: {:?}",
        client.username,
        replies[0].1
    );
}

/// Helper: fetch pending messages for a client.
async fn fetch_pending(server: &mut TestServer, client: &TestClient) -> Vec<Value> {
    let replies = server.send(&client.tag, client.fetch_pending_msg()).await;
    assert!(
        !replies.is_empty(),
        "No reply to fetchPending for {}",
        client.username
    );
    let response = &replies[0].1;
    let payload = &response["payload"];
    let messages = payload.get("messages").and_then(Value::as_array);
    messages.cloned().unwrap_or_default()
}

/// Helper: extract nonce from a challenge response.
fn extract_nonce(reply: &Value) -> String {
    // The "content" field contains JSON-encoded data with a nonce
    if let Some(content) = reply.get("content").and_then(Value::as_str) {
        if let Ok(parsed) = serde_json::from_str::<Value>(content) {
            if let Some(nonce) = parsed.get("nonce").and_then(Value::as_str) {
                return nonce.to_string();
            }
        }
    }
    panic!("Could not extract nonce from reply: {}", reply);
}

// ============================================================
// Tests
// ============================================================

#[tokio::test]
async fn test_full_registration_flow() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());

    // Step 1: Register → get challenge
    let replies = server.send(&alice.tag, alice.register_msg()).await;
    assert_eq!(replies.len(), 1, "Expected one reply, got: {:?}", replies);
    let (tag, challenge) = &replies[0];
    assert_eq!(tag, &alice.tag.to_string());
    assert_eq!(challenge["action"], "challenge");
    let nonce = extract_nonce(challenge);

    // Step 2: Sign nonce → complete registration
    let replies = server
        .send(&alice.tag, alice.registration_response_msg(&nonce))
        .await;
    assert_eq!(replies.len(), 1, "Expected one reply, got: {:?}", replies);
    let (_, response) = &replies[0];
    assert_eq!(response["action"], "challengeResponse");
    let content = response["content"].as_str().unwrap();
    assert_eq!(content, "success", "Registration failed: {}", response);
}

#[tokio::test]
async fn test_full_login_flow() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());

    // Register first
    let replies = server.send(&alice.tag, alice.register_msg()).await;
    let nonce = extract_nonce(&replies[0].1);
    server
        .send(&alice.tag, alice.registration_response_msg(&nonce))
        .await;

    // Now login
    let replies = server.send(&alice.tag, alice.login_msg()).await;
    assert_eq!(replies.len(), 1);
    let nonce = extract_nonce(&replies[0].1);

    let replies = server
        .send(&alice.tag, alice.login_response_msg(&nonce))
        .await;
    assert_eq!(replies.len(), 1);
    let content = replies[0].1["content"].as_str().unwrap();
    assert_eq!(content, "success", "Login failed: {}", replies[0].1);
}

#[tokio::test]
async fn test_query_registered_user() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());
    let bob = TestClient::new("bob", temp.path());

    // Register alice
    let replies = server.send(&alice.tag, alice.register_msg()).await;
    let nonce = extract_nonce(&replies[0].1);
    server
        .send(&alice.tag, alice.registration_response_msg(&nonce))
        .await;

    // Query alice from bob's perspective
    let replies = server.send(&bob.tag, bob.query_msg("alice")).await;
    assert_eq!(replies.len(), 1);
    let response = &replies[0].1;
    let content_str = response["content"].as_str().unwrap();
    let content: Value = serde_json::from_str(content_str).unwrap();
    assert_eq!(content["username"], "alice");
    assert!(
        content.get("publicKey").is_some(),
        "Expected publicKey in query response"
    );
}

#[tokio::test]
async fn test_send_message_between_users() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());
    let bob = TestClient::new("bob", temp.path());

    // Register both users
    for client in [&alice, &bob] {
        let replies = server.send(&client.tag, client.register_msg()).await;
        let nonce = extract_nonce(&replies[0].1);
        let replies = server
            .send(&client.tag, client.registration_response_msg(&nonce))
            .await;
        assert_eq!(
            replies[0].1["content"].as_str().unwrap(),
            "success",
            "Registration failed for {}",
            client.username
        );
    }

    // Alice sends a message to Bob
    let replies = server
        .send(&alice.tag, alice.send_msg("bob", "Hello Bob!"))
        .await;

    // We should get 2 replies: one forwarded to Bob, one sendResponse to Alice
    // (Bob is "online" because their sender_tag is stored from registration)
    assert!(
        replies.len() >= 1,
        "Expected at least 1 reply, got: {:?}",
        replies
    );

    // Find the sendResponse to Alice
    let alice_reply = replies
        .iter()
        .find(|(tag, _)| tag == &alice.tag.to_string());
    assert!(
        alice_reply.is_some(),
        "Expected sendResponse to alice, replies: {:?}",
        replies
    );
    let alice_response = &alice_reply.unwrap().1;
    assert_eq!(
        alice_response["content"].as_str().unwrap(),
        "success",
        "Send failed: {}",
        alice_response
    );

    // Find the forwarded message to Bob
    let bob_reply = replies.iter().find(|(tag, _)| tag == &bob.tag.to_string());
    assert!(
        bob_reply.is_some(),
        "Expected forwarded message to bob, replies: {:?}",
        replies
    );
    let bob_message = &bob_reply.unwrap().1;
    assert_eq!(bob_message["action"], "incomingMessage");
    let bob_content_str = bob_message["content"].as_str().unwrap();
    let bob_content: Value = serde_json::from_str(bob_content_str).unwrap();
    assert_eq!(bob_content["sender"], "alice");
    assert_eq!(bob_content["body"], "Hello Bob!");
}

#[tokio::test]
async fn test_query_nonexistent_user() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());

    let replies = server.send(&alice.tag, alice.query_msg("nobody")).await;
    assert_eq!(replies.len(), 1);
    let content = replies[0].1["content"].as_str().unwrap();
    let content_lower = content.to_lowercase();
    assert!(
        content_lower.contains("no user")
            || content_lower.contains("not found")
            || content_lower.contains("error"),
        "Expected error or 'not found', got: {}",
        content
    );
}

#[tokio::test]
async fn test_duplicate_registration_rejected() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());

    // Register successfully
    let replies = server.send(&alice.tag, alice.register_msg()).await;
    let nonce = extract_nonce(&replies[0].1);
    server
        .send(&alice.tag, alice.registration_response_msg(&nonce))
        .await;

    // Try to register again — should fail
    let replies = server.send(&alice.tag, alice.register_msg()).await;
    let content = replies[0].1["content"].as_str().unwrap();
    assert!(
        content.contains("error") || content.contains("exists"),
        "Expected rejection, got: {}",
        content
    );
}

// ============================================================
// DM Handshake / Invitation Flow Tests
// ============================================================

/// DM key-package exchange (the cleartext portion of the handshake).
///
/// After step 4, Alice creates the MLS group and sends a *sealed* p2pWelcome
/// (`type: "sealed"`), which the server routes by recipient only. That sealed
/// path is covered by the normal sealed-send relay; it's not exercised here
/// because it requires real ECDH/MLS state.
///
///   1. Alice sends keyPackageRequest → relayed to Bob
///   2. Bob fetches pending → gets keyPackageRequest
///   3. Bob sends keyPackageResponse → relayed to Alice
///   4. Alice fetches pending → gets keyPackageResponse
#[tokio::test]
async fn test_dm_handshake_full_flow() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());
    let bob = TestClient::new("bob", temp.path());

    // Register both users
    register_client(&mut server, &alice).await;
    register_client(&mut server, &bob).await;

    // --- Step 1: Alice sends keyPackageRequest to Bob ---
    let kp_request_payload = json!({
        "keyPackage": "alice-dummy-key-package-base64",
        "senderPublicKey": alice.public_key,
    });
    let replies = server
        .send(
            &alice.tag,
            alice.relay_msg("keyPackageRequest", "bob", kp_request_payload.clone()),
        )
        .await;
    // Server may send best-effort delivery to Bob + no error to Alice
    // (relay_with_persistence doesn't send a success reply to sender for relay actions)
    // Bob should see the message when fetching pending
    let bob_got_direct = replies.iter().any(|(tag, _)| tag == &bob.tag.to_string());

    // --- Step 2: Bob fetches pending messages ---
    let pending = fetch_pending(&mut server, &bob).await;
    // Bob should have the keyPackageRequest (either from direct delivery or pending queue)
    let kp_request_in_pending = pending
        .iter()
        .any(|m| m["action"].as_str() == Some("keyPackageRequest"));
    assert!(
        bob_got_direct || kp_request_in_pending,
        "Bob should have received keyPackageRequest either directly or via pending. \
         Direct: {}, Pending: {:?}",
        bob_got_direct,
        pending
    );

    // --- Step 3: Bob sends keyPackageResponse to Alice ---
    let kp_response_payload = json!({
        "keyPackage": "bob-dummy-key-package-base64",
        "senderPublicKey": bob.public_key,
    });
    server
        .send(
            &bob.tag,
            bob.relay_msg("keyPackageResponse", "alice", kp_response_payload),
        )
        .await;

    // --- Step 4: Alice fetches pending → gets keyPackageResponse ---
    let pending = fetch_pending(&mut server, &alice).await;
    let has_kp_response = pending
        .iter()
        .any(|m| m["action"].as_str() == Some("keyPackageResponse"));
    assert!(
        has_kp_response,
        "Alice should have keyPackageResponse in pending. Got: {:?}",
        pending
    );

    // After step 4, Alice would send a sealed p2pWelcome; that is covered by
    // the sealed-send relay path, not exercised here.
}

/// Test that relay messages to nonexistent users are queued silently
/// (the server persists them — the recipient may register later).
#[tokio::test]
async fn test_relay_to_nonexistent_user_queued() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());

    register_client(&mut server, &alice).await;

    // Send keyPackageRequest to a user who doesn't exist yet
    let replies = server
        .send(
            &alice.tag,
            alice.relay_msg("keyPackageRequest", "ghost", json!({"keyPackage": "test"})),
        )
        .await;

    // Server queues silently — no error reply (fire-and-forget relay).
    // The only reply would be a best-effort delivery attempt to "ghost"
    // which can't happen since ghost has no sender_tag.
    let alice_error = replies
        .iter()
        .any(|(tag, msg)| tag == &alice.tag.to_string() && msg.to_string().contains("error"));
    assert!(
        !alice_error,
        "Should not get error for relay to unregistered user, got: {:?}",
        replies
    );
}

/// Test that fetchPending returns messages across multiple relay types.
#[tokio::test]
async fn test_pending_queue_multiple_message_types() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut server = TestServer::new(temp.path()).await;
    let alice = TestClient::new("alice", temp.path());
    let bob = TestClient::new("bob", temp.path());

    register_client(&mut server, &alice).await;
    register_client(&mut server, &bob).await;

    // Send multiple different relay types to Bob
    server
        .send(
            &alice.tag,
            alice.relay_msg("keyPackageRequest", "bob", json!({"step": 1})),
        )
        .await;
    server
        .send(
            &alice.tag,
            alice.relay_msg("keyPackageResponse", "bob", json!({"step": 2})),
        )
        .await;

    // Bob fetches — should have both
    let pending = fetch_pending(&mut server, &bob).await;
    let actions: Vec<&str> = pending
        .iter()
        .filter_map(|m| m["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"keyPackageRequest"),
        "Missing keyPackageRequest in pending: {:?}",
        actions
    );
    assert!(
        actions.contains(&"keyPackageResponse"),
        "Missing keyPackageResponse in pending: {:?}",
        actions
    );
}
