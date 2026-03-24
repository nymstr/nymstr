//! Integration tests for stdio transport mode.
//!
//! These tests spawn the server binary with `--stdio` and exercise
//! the message protocol via stdin/stdout JSON pipes.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Helper: spawn the server in stdio mode with a temporary database.
struct StdioServer {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    _temp_dir: tempfile::TempDir,
}

impl StdioServer {
    fn spawn() -> Self {
        let temp_dir = tempfile::TempDir::new().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("test.db");
        let keys_dir = temp_dir.path().join("keys");
        let secret_path = temp_dir.path().join("seed_phrase");
        let log_path = temp_dir.path().join("test.log");
        std::fs::create_dir_all(&keys_dir).unwrap();

        // Write a dummy seed phrase
        std::fs::write(&secret_path, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_nymstr-server"))
            .arg("--stdio")
            .env("DATABASE_PATH", &db_path)
            .env("KEYS_DIR", keys_dir.to_str().unwrap())
            .env("SECRET_PATH", secret_path.to_str().unwrap())
            .env("LOG_FILE_PATH", log_path.to_str().unwrap())
            .env("RUST_LOG", "debug")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn server");

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = BufReader::new(stdout);

        // Give the server a moment to initialize
        std::thread::sleep(Duration::from_millis(500));

        StdioServer {
            child,
            stdin,
            reader,
            _temp_dir: temp_dir,
        }
    }

    /// Send a message and read the response.
    fn send(&mut self, tag: &str, message: Value) -> Value {
        let envelope = json!({
            "replyTag": tag,
            "message": message
        });
        writeln!(self.stdin, "{}", envelope).expect("failed to write to stdin");
        self.stdin.flush().expect("failed to flush stdin");

        let mut line = String::new();
        self.reader.read_line(&mut line).expect("failed to read response");
        let line = line.trim();
        serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("failed to parse response JSON: {e}\nRaw line: {line:?}"))
    }
}

impl Drop for StdioServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_query_nonexistent_user() {
    let mut server = StdioServer::spawn();

    let response = server.send("t1", json!({
        "type": "message",
        "action": "query",
        "sender": "alice",
        "payload": {
            "username": "nonexistent"
        }
    }));

    assert_eq!(response["replyTag"], "stdio:t1");
    let msg = &response["message"];
    // Should get a queryResponse back
    assert!(
        msg["action"].as_str().unwrap().contains("query")
            || msg["content"].as_str().map(|s| s.contains("not found")).unwrap_or(false),
        "Expected query response, got: {}",
        msg
    );
}

#[test]
fn test_reply_tag_correlation() {
    let mut server = StdioServer::spawn();

    // Send two queries with different tags
    let r1 = server.send("tag-alpha", json!({
        "type": "message",
        "action": "query",
        "sender": "alice",
        "payload": { "username": "user1" }
    }));

    let r2 = server.send("tag-beta", json!({
        "type": "message",
        "action": "query",
        "sender": "bob",
        "payload": { "username": "user2" }
    }));

    // Each response should have its own reply tag
    assert_eq!(r1["replyTag"], "stdio:tag-alpha");
    assert_eq!(r2["replyTag"], "stdio:tag-beta");
}

#[test]
fn test_register_challenge_flow() {
    let mut server = StdioServer::spawn();

    // Step 1: Send register request
    let response = server.send("reg1", json!({
        "type": "message",
        "action": "register",
        "sender": "testuser",
        "payload": {
            "username": "testuser",
            "publicKey": "dummy-key-for-test"
        }
    }));

    assert_eq!(response["replyTag"], "stdio:reg1");
    let msg = &response["message"];

    // The response should contain a nonce somewhere (challenge flow)
    let msg_str = msg.to_string();
    assert!(
        msg_str.contains("nonce") || msg_str.contains("challenge"),
        "Expected challenge with nonce, got: {}",
        msg_str
    );
}

#[test]
fn test_legacy_format_query() {
    let mut server = StdioServer::spawn();

    // Test legacy format (no "type" field)
    let response = server.send("legacy1", json!({
        "action": "query",
        "username": "nobody"
    }));

    assert_eq!(response["replyTag"], "stdio:legacy1");
    // Should still get a response
    let msg = &response["message"];
    assert!(msg.is_object(), "Expected JSON object response");
}
