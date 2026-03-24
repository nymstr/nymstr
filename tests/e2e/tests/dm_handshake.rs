//! Full DM handshake test with real PGP + MLS cryptography.
//!
//! Tests the complete flow:
//! 1. Both users register with discovery server (PGP challenge-response)
//! 2. Key package exchange via server relay
//! 3. MLS group creation with welcome + deferred commit
//! 4. Welcome acceptance and commit application
//! 5. Encrypted message exchange

use base64::Engine;
use nymstr_e2e_tests::harness::*;
use serde_json::json;

/// Full DM initialization with real MLS crypto through the server relay.
#[tokio::test]
async fn test_full_dm_handshake_with_mls() {
    let temp = tempfile::TempDir::new().unwrap();

    // Create server and clients
    let mut server = TestServer::new(temp.path()).await;
    let mut alice = TestClient::new("alice", temp.path());
    let mut bob = TestClient::new("bob", temp.path());

    // Register both with server (real PGP signing)
    register_client(&mut server, &alice).await;
    register_client(&mut server, &bob).await;

    // Initialize MLS clients
    alice.init_mls();
    bob.init_mls();

    // --- Step 1: Key package exchange ---

    // Bob generates a key package
    let bob_key_package = bob.mls().generate_key_package().unwrap();
    let bob_kp_b64 = base64::engine::general_purpose::STANDARD.encode(&bob_key_package);

    // Alice requests Bob's key package (via server relay)
    server
        .send(
            &alice.tag,
            alice.relay_msg(
                "keyPackageRequest",
                "bob",
                json!({ "senderPublicKey": alice.public_key_armored }),
            ),
        )
        .await;

    // Bob fetches pending → gets keyPackageRequest
    let pending = fetch_pending(&mut server, &bob).await;
    assert!(
        pending.iter().any(|m| m["action"].as_str() == Some("keyPackageRequest")),
        "Bob should have keyPackageRequest in pending"
    );

    // Bob sends key package response back to Alice
    server
        .send(
            &bob.tag,
            bob.relay_msg(
                "keyPackageResponse",
                "alice",
                json!({
                    "keyPackage": bob_kp_b64,
                    "senderPublicKey": bob.public_key_armored,
                }),
            ),
        )
        .await;

    // Alice fetches → gets Bob's key package
    let pending = fetch_pending(&mut server, &alice).await;
    let kp_response = pending
        .iter()
        .find(|m| m["action"].as_str() == Some("keyPackageResponse"))
        .expect("Alice should have keyPackageResponse in pending");

    // Extract Bob's key package from the response payload
    let kp_payload = &kp_response["payload"];
    let received_kp_b64 = kp_payload["keyPackage"]
        .as_str()
        .expect("Missing keyPackage in response");
    let received_kp_bytes = base64::engine::general_purpose::STANDARD
        .decode(received_kp_b64)
        .unwrap();

    // --- Step 2: Alice creates MLS group and sends welcome ---

    let conversation = alice
        .mls()
        .start_conversation(&received_kp_bytes)
        .await
        .unwrap();

    assert_eq!(conversation.participants, 2);
    assert!(conversation.welcome_message.is_some());
    assert!(conversation.commit_message.is_some());
    assert!(conversation.ratchet_tree.is_some());

    let welcome_b64 = base64::engine::general_purpose::STANDARD
        .encode(conversation.welcome_message.as_ref().unwrap());
    let commit_b64 = base64::engine::general_purpose::STANDARD
        .encode(conversation.commit_message.as_ref().unwrap());
    let ratchet_tree_b64 = base64::engine::general_purpose::STANDARD
        .encode(conversation.ratchet_tree.as_ref().unwrap());
    let conversation_id_b64 = base64::engine::general_purpose::STANDARD
        .encode(&conversation.conversation_id);

    // Alice sends p2pWelcome to Bob via server
    server
        .send(
            &alice.tag,
            alice.relay_msg(
                "p2pWelcome",
                "bob",
                json!({
                    "welcome": welcome_b64,
                    "commit": commit_b64,
                    "ratchetTree": ratchet_tree_b64,
                    "conversationId": conversation_id_b64,
                    "senderPublicKey": alice.public_key_armored,
                }),
            ),
        )
        .await;

    // --- Step 3: Bob receives welcome and joins ---

    let pending = fetch_pending(&mut server, &bob).await;
    let welcome_msg = pending
        .iter()
        .find(|m| m["action"].as_str() == Some("p2pWelcome"))
        .expect("Bob should have p2pWelcome in pending");

    let welcome_payload = &welcome_msg["payload"];
    let welcome_bytes = base64::engine::general_purpose::STANDARD
        .decode(welcome_payload["welcome"].as_str().unwrap())
        .unwrap();

    // Bob joins the conversation using real MLS
    let bob_conversation = bob.mls().join_conversation(&welcome_bytes).await.unwrap();

    assert_eq!(bob_conversation.conversation_id, conversation.conversation_id);
    assert_eq!(bob_conversation.participants, 2);

    // Bob sends p2pWelcomeAck to Alice
    server
        .send(
            &bob.tag,
            bob.relay_msg(
                "p2pWelcomeAck",
                "alice",
                json!({
                    "conversationId": conversation_id_b64,
                    "senderPublicKey": bob.public_key_armored,
                }),
            ),
        )
        .await;

    // --- Step 4: Alice receives ack and applies pending commit ---

    let pending = fetch_pending(&mut server, &alice).await;
    assert!(
        pending.iter().any(|m| m["action"].as_str() == Some("p2pWelcomeAck")),
        "Alice should have p2pWelcomeAck"
    );

    // Alice applies the deferred commit
    let new_epoch = alice
        .mls()
        .apply_pending_commit_for_group(&conversation.conversation_id)
        .unwrap();
    assert!(new_epoch > 0, "Epoch should advance after applying commit");

    // --- Step 5: Encrypted message exchange ---

    // Alice encrypts a message
    let plaintext = b"Hello Bob! This is encrypted with MLS.";
    let encrypted = alice
        .mls()
        .encrypt_message(&conversation.conversation_id, plaintext)
        .await
        .unwrap();

    assert!(!encrypted.mls_message.is_empty());
    assert_eq!(encrypted.conversation_id, conversation.conversation_id);

    // Bob decrypts the message
    let decrypted = bob
        .mls()
        .decrypt_message(&encrypted)
        .await
        .unwrap();

    assert_eq!(decrypted, plaintext, "Decrypted message should match plaintext");
}

/// Verify key package generation produces valid packages.
#[tokio::test]
async fn test_key_package_generation() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut alice = TestClient::new("alice", temp.path());
    alice.init_mls();

    let kp = alice.mls().generate_key_package().unwrap();
    assert!(!kp.is_empty(), "Key package should not be empty");

    // Generate a second one — should be different
    let kp2 = alice.mls().generate_key_package().unwrap();
    assert_ne!(kp, kp2, "Key packages should be unique");
}

/// Verify MLS credential creation with PGP binding.
#[tokio::test]
async fn test_mls_credential_with_pgp_binding() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut alice = TestClient::new("alice", temp.path());
    alice.init_mls();

    let credential = alice.mls().create_credential().unwrap();

    assert_eq!(credential.username, "alice");
    assert!(credential.is_valid());
    assert!(!credential.is_expired());

    // Verify PGP binding with the correct public key
    let pk_bytes = alice.public_key_armored.as_bytes();
    assert!(
        credential.verify_pgp_binding(pk_bytes),
        "Credential should verify against Alice's public key"
    );

    // Should fail with a different key
    assert!(
        !credential.verify_pgp_binding(b"wrong key bytes"),
        "Credential should not verify against wrong key"
    );
}
