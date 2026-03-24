//! Test harness: in-process server + clients with real crypto.

use nymstr_crypto::{SecurePassphrase, ServerKeyManager};
use nymstr_crypto::mls::MlsClient;
use nymstr_transport::{CapturingReplySender, ReplyTag};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A test client with real PGP keys and optionally an MLS client.
pub struct TestClient {
    pub username: String,
    pub public_key_armored: String,
    pub tag: ReplyTag,
    key_manager: ServerKeyManager,
    mls_client: Option<MlsClient>,
    base_dir: PathBuf,
}

impl TestClient {
    /// Create a new test client with PGP keys.
    pub fn new(username: &str, temp_dir: &Path) -> Self {
        let keys_dir = temp_dir.join(format!("{}_keys", username));
        let key_manager =
            ServerKeyManager::new(keys_dir, "test-password".into()).unwrap();
        let public_key_armored = key_manager.generate_key_pair(username).unwrap();
        let tag = ReplyTag::Stdio(username.to_string());

        TestClient {
            username: username.to_string(),
            public_key_armored,
            tag,
            key_manager,
            mls_client: None,
            base_dir: temp_dir.to_path_buf(),
        }
    }

    /// Initialize the MLS client for this user.
    pub fn init_mls(&mut self) {
        let secret_key = Arc::new(self.key_manager.load_private_key(&self.username).unwrap());
        let public_key = Arc::new(self.key_manager.load_public_key(&self.username).unwrap());
        let passphrase = SecurePassphrase::new("test-password".into());

        let mls = MlsClient::new(
            &self.username,
            secret_key,
            public_key,
            &passphrase,
            self.base_dir.clone(),
        )
        .unwrap();

        self.mls_client = Some(mls);
    }

    /// Get a reference to the MLS client.
    pub fn mls(&self) -> &MlsClient {
        self.mls_client.as_ref().expect("MLS not initialized — call init_mls() first")
    }

    /// Sign a message string with PGP.
    pub fn sign(&self, message: &str) -> String {
        self.key_manager.sign_message(&self.username, message).unwrap()
    }

    /// Build a registration request (legacy format).
    pub fn register_msg(&self) -> Value {
        json!({
            "action": "register",
            "username": self.username,
            "publicKey": self.public_key_armored,
        })
    }

    /// Build a registration response (signs the nonce).
    pub fn registration_response_msg(&self, nonce: &str) -> Value {
        json!({
            "action": "registrationResponse",
            "signature": self.sign(nonce),
        })
    }

    /// Build a fetchPending request (unified format).
    pub fn fetch_pending_msg(&self) -> Value {
        let timestamp = chrono::Utc::now().timestamp();
        let to_sign = format!("fetchPending:{}:{}", self.username, timestamp);
        json!({
            "type": "message",
            "action": "fetchPending",
            "sender": self.username,
            "payload": {
                "timestamp": timestamp,
                "signature": self.sign(&to_sign)
            }
        })
    }

    /// Build a unified relay message (keyPackageRequest, p2pWelcome, etc.)
    pub fn relay_msg(&self, action: &str, recipient: &str, payload: Value) -> Value {
        json!({
            "type": "message",
            "action": action,
            "sender": self.username,
            "recipient": recipient,
            "payload": payload,
            "signature": "placeholder"
        })
    }
}

/// In-process test server with CapturingReplySender.
pub struct TestServer {
    message_utils: nymstr_server::message_utils::MessageUtils,
    sender: Arc<CapturingReplySender>,
}

impl TestServer {
    /// Create a new test server with a temporary database.
    pub async fn new(temp_dir: &Path) -> Self {
        let db_path = temp_dir.join("server.db");
        let keys_dir = temp_dir.join("server_keys");

        let crypto = ServerKeyManager::new(keys_dir, "server-password".into()).unwrap();
        crypto.generate_key_pair("server").unwrap();

        if !db_path.exists() {
            std::fs::File::create(&db_path).unwrap();
        }
        let db = nymstr_server::db_utils::DbUtils::new(db_path.to_str().unwrap())
            .await
            .unwrap();

        let sender = Arc::new(CapturingReplySender::new());
        let message_utils = nymstr_server::message_utils::MessageUtils::new(
            "server".to_string(),
            Box::new(Arc::clone(&sender)),
            db,
            crypto,
        );

        TestServer { message_utils, sender }
    }

    /// Send a message and return all replies.
    pub async fn send(&mut self, tag: &ReplyTag, message: Value) -> Vec<(String, Value)> {
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

/// Register a client with the server (challenge-response flow).
pub async fn register_client(server: &mut TestServer, client: &TestClient) {
    let replies = server.send(&client.tag, client.register_msg()).await;
    assert!(!replies.is_empty(), "No reply to register for {}", client.username);
    let nonce = extract_nonce(&replies[0].1);
    let replies = server
        .send(&client.tag, client.registration_response_msg(&nonce))
        .await;
    let content = replies[0].1["content"].as_str().unwrap();
    assert_eq!(content, "success", "Registration failed for {}: {:?}", client.username, replies[0].1);
}

/// Fetch pending messages for a client from the server.
pub async fn fetch_pending(server: &mut TestServer, client: &TestClient) -> Vec<Value> {
    let replies = server.send(&client.tag, client.fetch_pending_msg()).await;
    if replies.is_empty() {
        return vec![];
    }
    let response = &replies[0].1;
    let payload = &response["payload"];
    payload
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Extract nonce from a challenge response.
pub fn extract_nonce(reply: &Value) -> String {
    if let Some(content) = reply.get("content").and_then(Value::as_str) {
        if let Ok(parsed) = serde_json::from_str::<Value>(content) {
            if let Some(nonce) = parsed.get("nonce").and_then(Value::as_str) {
                return nonce.to_string();
            }
        }
    }
    panic!("Could not extract nonce from reply: {}", reply);
}
