//! Integration tests for stdio transport mode.
//!
//! These tests spawn the group server binary with `--stdio` and exercise
//! the message protocol via stdin/stdout JSON pipes.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Helper: spawn the group server in stdio mode with a temporary database and config.
struct StdioGroupServer {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    _temp_dir: tempfile::TempDir,
}

impl StdioGroupServer {
    fn spawn() -> Self {
        let temp_dir = tempfile::TempDir::new().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("test.db");
        let keys_dir = temp_dir.path().join("keys");
        let config_dir = temp_dir.path().join("config");
        let secret_path = temp_dir.path().join("encryption_password");
        let log_path = temp_dir.path().join("test.log");
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();

        // Write encryption password
        std::fs::write(&secret_path, "test-password-for-integration").unwrap();

        // Write a minimal group config
        let config_path = config_dir.join("group.toml");
        std::fs::write(
            &config_path,
            r#"
group_id = "test-group"
name = "Test Group"
is_public = true
registered = false
"#,
        )
        .unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_nymstr-groupd"))
            .arg("--stdio")
            .env("DATABASE_PATH", &db_path)
            .env("KEYS_DIR", keys_dir.to_str().unwrap())
            .env("SECRET_PATH", secret_path.to_str().unwrap())
            .env("CONFIG_PATH", config_path.to_str().unwrap())
            .env("LOG_FILE_PATH", log_path.to_str().unwrap())
            .env("RUST_LOG", "debug")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn group server");

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = BufReader::new(stdout);

        // Give the server a moment to initialize
        std::thread::sleep(Duration::from_millis(500));

        StdioGroupServer {
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
        self.reader
            .read_line(&mut line)
            .expect("failed to read response");
        let line = line.trim();
        serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("failed to parse response JSON: {e}\nRaw line: {line:?}"))
    }
}

impl Drop for StdioGroupServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_fetch_group_without_auth() {
    let mut server = StdioGroupServer::spawn();

    let response = server.send(
        "t1",
        json!({
            "type": "message",
            "action": "fetchGroup",
            "sender": "alice",
            "payload": {
                "lastSeenId": 0
            },
            "signature": ""
        }),
    );

    assert_eq!(response["replyTag"], "stdio:t1");
    let msg = &response["message"];
    // Should get an error response (missing/invalid auth)
    let msg_str = msg.to_string();
    assert!(
        msg_str.contains("error") || msg_str.contains("fetchGroupResponse"),
        "Expected error or fetchGroupResponse, got: {}",
        msg_str
    );
}

#[test]
fn test_reply_tag_correlation_group() {
    let mut server = StdioGroupServer::spawn();

    let r1 = server.send(
        "alpha",
        json!({
            "type": "message",
            "action": "fetchGroup",
            "sender": "alice",
            "payload": { "lastSeenId": 0 },
            "signature": ""
        }),
    );

    let r2 = server.send(
        "beta",
        json!({
            "type": "message",
            "action": "fetchGroup",
            "sender": "bob",
            "payload": { "lastSeenId": 0 },
            "signature": ""
        }),
    );

    assert_eq!(r1["replyTag"], "stdio:alpha");
    assert_eq!(r2["replyTag"], "stdio:beta");
}

#[test]
fn test_register_with_group() {
    let mut server = StdioGroupServer::spawn();

    let response = server.send(
        "reg1",
        json!({
            "type": "message",
            "action": "register",
            "sender": "testuser",
            "payload": {
                "username": "testuser",
                "publicKey": "dummy-pgp-key",
                "serverAddress": "dummy-nym-address",
                "timestamp": chrono::Utc::now().timestamp()
            },
            "signature": "dummy-sig",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }),
    );

    assert_eq!(response["replyTag"], "stdio:reg1");
    let msg = &response["message"];
    // Should get a registerResponse
    let msg_str = msg.to_string();
    assert!(
        msg_str.contains("register"),
        "Expected register response, got: {}",
        msg_str
    );
}
