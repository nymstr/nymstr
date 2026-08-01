//! Messaging commands with MLS encryption
//!
//! This module provides Tauri commands for:
//! - Sending MLS-encrypted direct messages
//! - Retrieving conversation history
//! - Managing message read status
//! - Handling MLS key package exchange

use chrono::Utc;
use sha2::Digest;
use tauri::State;
use uuid::Uuid;

use crate::core::db::Db;
use crate::core::message_handler::{normalize_conversation_id, DirectMessageHandler};
use crate::state::AppState;
use crate::types::{ApiError, MessageDTO, MessageStatus};

/// Check whether `hash` has at least `bits` leading zero bits.
fn has_leading_zero_bits(hash: &[u8], bits: u32) -> bool {
    let full_bytes = (bits / 8) as usize;
    let remaining_bits = bits % 8;
    if hash.len() < full_bytes + if remaining_bits > 0 { 1 } else { 0 } {
        return false;
    }
    for &b in &hash[..full_bytes] {
        if b != 0 {
            return false;
        }
    }
    if remaining_bits > 0 {
        let mask = 0xFF << (8 - remaining_bits);
        if hash[full_bytes] & mask != 0 {
            return false;
        }
    }
    true
}

/// Extract the peer username from a conversation ID like "dm:user1:user2"
fn extract_peer_username(conversation_id: &str, current_user: &str) -> Option<String> {
    let parts: Vec<&str> = conversation_id.split(':').collect();
    if parts.len() == 3 && parts[0] == "dm" {
        if parts[1] == current_user {
            Some(parts[2].to_string())
        } else if parts[2] == current_user {
            Some(parts[1].to_string())
        } else {
            None
        }
    } else {
        None
    }
}

/// Send a direct message to a contact with MLS encryption
#[tauri::command]
pub async fn send_message(
    recipient: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<MessageDTO, ApiError> {
    tracing::info!("Sending message to: {}", recipient);

    // Validate content
    if content.is_empty() {
        return Err(ApiError::validation("Message content cannot be empty"));
    }

    if content.len() > 10000 {
        return Err(ApiError::validation(
            "Message too long (max 10000 characters)",
        ));
    }

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get MLS client
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    // Get mixnet service
    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::internal("Mixnet not connected".to_string()))?;

    // Get PGP signing keys
    let (secret_key, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available".to_string()))?;

    // Extract peer username — recipient may be a conversation ID (dm:user1:user2) or a raw username
    let peer_username = extract_peer_username(&recipient, &current_user.username)
        .unwrap_or_else(|| recipient.clone());
    let conversation_id = normalize_conversation_id(&current_user.username, &peer_username);

    // Create message DTO first (for storage)
    let message = MessageDTO {
        id: Uuid::new_v4().to_string(),
        sender: current_user.username.clone(),
        content: content.clone(),
        timestamp: Utc::now().to_rfc3339(),
        status: MessageStatus::Pending,
        is_own: true,
        is_read: true,
    };
    sqlx::query(
        r#"
        INSERT INTO messages (id, conversation_id, sender, content, timestamp, status, is_own, is_read)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&message.id)
    .bind(&conversation_id)
    .bind(&message.sender)
    .bind(&message.content)
    .bind(&message.timestamp)
    .bind("pending")
    .bind(true)
    .bind(true)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to store message: {}", e)))?;

    // Create direct message handler (clone Arcs first for potential background use)
    let dm_handler = DirectMessageHandler::new(
        mls_client.clone(),
        mixnet_service.clone(),
        secret_key.clone(),
        passphrase.clone(),
        current_user.username.clone(),
        state.db.clone(),
    );

    // Check if MLS conversation exists
    if !dm_handler.conversation_exists(&peer_username).await {
        if dm_handler.handshake_in_progress(&peer_username).await {
            // Handshake already in progress — just queue the message as pending
            tracing::info!(
                "Handshake in progress with {}, message queued",
                peer_username
            );
            return Ok(MessageDTO {
                status: MessageStatus::Pending,
                ..message
            });
        }

        tracing::info!(
            "No MLS conversation with {}, initiating via pre-published key package",
            peer_username
        );

        // Store pending outreach so the message loop can drain it after handshake
        sqlx::query(
            "INSERT OR IGNORE INTO pending_outreach (recipient, message_draft) VALUES (?, ?)",
        )
        .bind(&peer_username)
        .bind(&content)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to store pending outreach: {}", e)))?;

        // Build a fresh handler with cloned Arcs for the background initiation
        let bg_mls = mls_client;
        let bg_mixnet = mixnet_service;
        let bg_sk = secret_key;
        let bg_pp = passphrase;
        let bg_user = current_user.username.clone();
        let bg_peer = peer_username.clone();
        let bg_db = state.db.clone();
        let bg_state = state.inner().clone();

        tokio::spawn(async move {
            let bg_handler = DirectMessageHandler::new(
                bg_mls,
                bg_mixnet.clone(),
                bg_sk.clone(),
                bg_pp.clone(),
                bg_user.clone(),
                bg_db.clone(),
            );

            // Step 1: fetch challenge
            let challenge_rx = bg_state
                .register_pending_query(&format!("kp_challenge:{}", bg_peer))
                .await;
            if let Err(e) = bg_mixnet.send_fetch_key_package_challenge(&bg_peer).await {
                tracing::error!("Failed to request KP challenge for {}: {}", bg_peer, e);
                return;
            }

            let challenge_data = match tokio::time::timeout(
                std::time::Duration::from_secs(15),
                challenge_rx,
            )
            .await
            {
                Ok(Ok(Some(qr))) => qr,
                _ => {
                    bg_state
                        .cancel_pending_query(&format!("kp_challenge:{}", bg_peer))
                        .await;
                    tracing::error!("KP challenge timed out for {}", bg_peer);
                    return;
                }
            };

            let challenge = challenge_data.public_key.clone();
            let difficulty: u32 = challenge_data.username.parse().unwrap_or(16);

            // Step 2: grind PoW — hash SHA256(username || challenge || nonce) with
            // incremental nonce. Pre-compute the fixed prefix to avoid re-hashing it.
            let peer_c = bg_peer.clone();
            let chal_c = challenge.clone();
            let nonce = match tokio::task::spawn_blocking(move || {
                use sha2::Digest;
                use std::io::Write;
                // Pre-compute hash state for the fixed prefix (username + challenge)
                let mut prefix_hasher = sha2::Sha256::new();
                prefix_hasher.update(peer_c.as_bytes());
                prefix_hasher.update(chal_c.as_bytes());

                let mut nonce_buf = Vec::with_capacity(20);
                let mut n: u64 = 0;
                loop {
                    nonce_buf.clear();
                    write!(&mut nonce_buf, "{}", n).unwrap();
                    let mut hasher = prefix_hasher.clone();
                    hasher.update(&nonce_buf);
                    let hash = hasher.finalize();
                    if has_leading_zero_bits(&hash, difficulty) {
                        return n.to_string();
                    }
                    n += 1;
                }
            })
            .await
            {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!("PoW task failed for {}: {}", bg_peer, e);
                    return;
                }
            };

            // Step 3: fetch key package
            let kp_rx = bg_state
                .register_pending_query(&format!("kp_fetch:{}", bg_peer))
                .await;
            if let Err(e) = bg_mixnet
                .send_fetch_key_package(&bg_peer, &challenge, &nonce)
                .await
            {
                tracing::error!("Failed to fetch KP for {}: {}", bg_peer, e);
                return;
            }

            let kp_data =
                match tokio::time::timeout(std::time::Duration::from_secs(15), kp_rx).await {
                    Ok(Ok(Some(qr))) => qr,
                    _ => {
                        bg_state
                            .cancel_pending_query(&format!("kp_fetch:{}", bg_peer))
                            .await;
                        tracing::error!("KP fetch timed out for {}", bg_peer);
                        return;
                    }
                };

            let recipient_pk_armored = kp_data.public_key.clone();
            let bundle_json = kp_data.username.clone();

            let bundle: nymstr_crypto::mls::SignedKeyPackageBundle =
                match serde_json::from_str(&bundle_json) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!("Failed to parse KP bundle for {}: {}", bg_peer, e);
                        return;
                    }
                };

            // Verify bundle
            let recipient_pgp =
                match crate::crypto::pgp::PgpKeyManager::parse_public_key(&recipient_pk_armored) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::error!("Failed to parse PGP key for {}: {}", bg_peer, e);
                        return;
                    }
                };
            match nymstr_crypto::mls::verify_bundle(&bundle, &recipient_pgp) {
                Ok(true) => {}
                Ok(false) => {
                    tracing::error!("KP bundle verification failed for {}", bg_peer);
                    return;
                }
                Err(e) => {
                    tracing::error!("KP bundle verify error for {}: {}", bg_peer, e);
                    return;
                }
            }

            // Store contact
            let _ = sqlx::query(
                "INSERT OR REPLACE INTO contacts (owner_username, username, display_name, public_key) VALUES (?, ?, ?, ?)"
            )
            .bind(&bg_user)
            .bind(&bg_peer)
            .bind(&bg_peer)
            .bind(&recipient_pk_armored)
            .execute(&bg_db)
            .await;

            // Complete handshake
            if let Err(e) = bg_handler
                .complete_handshake(&bg_peer, &bundle.key_package_b64)
                .await
            {
                tracing::error!("Failed to complete handshake with {}: {}", bg_peer, e);
                return;
            }

            // Clean up pending outreach
            let _ = sqlx::query("DELETE FROM pending_outreach WHERE recipient = ?")
                .bind(&bg_peer)
                .execute(&bg_db)
                .await;

            tracing::info!(
                "Background conversation initiation completed for {}",
                bg_peer
            );
        });

        tracing::info!(
            "Conversation initiation spawned in background, message queued pending handshake"
        );

        return Ok(MessageDTO {
            status: MessageStatus::Pending,
            ..message
        });
    }

    // Send the encrypted message
    match dm_handler.send_message(&peer_username, &content).await {
        Ok(_) => {
            // Update message status to sent
            sqlx::query("UPDATE messages SET status = 'sent' WHERE id = ?")
                .bind(&message.id)
                .execute(&state.db)
                .await
                .map_err(|e| {
                    ApiError::internal(format!("Failed to update message status: {}", e))
                })?;

            tracing::info!(
                "Message sent: {} -> {}",
                current_user.username,
                peer_username
            );

            Ok(MessageDTO {
                status: MessageStatus::Sent,
                ..message
            })
        }
        Err(e) => {
            // Update message status to failed
            sqlx::query("UPDATE messages SET status = 'failed' WHERE id = ?")
                .bind(&message.id)
                .execute(&state.db)
                .await
                .ok(); // Ignore error here

            tracing::error!("Failed to send message: {}", e);
            Err(ApiError::internal(format!("Failed to send message: {}", e)))
        }
    }
}

/// Initiate MLS handshake with a contact using pre-published key packages.
///
/// Flow:
/// 1. Send anonymous `fetchKeyPackageChallenge` to get a PoW challenge
/// 2. Grind the PoW nonce
/// 3. Send `fetchKeyPackage` with the solution
/// 4. Receive the signed key package bundle
/// 5. Verify the PGP signature on the bundle
/// 6. Store recipient's public key in contacts
/// 7. Create MLS group and send p2pWelcome via sealed sender
/// 8. Store pending handshake, return success
#[tauri::command]
pub async fn initiate_conversation(
    recipient: String,
    state: State<'_, AppState>,
) -> Result<bool, ApiError> {
    tracing::info!("Initiating MLS conversation with: {}", recipient);

    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get required components
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::internal("Mixnet not connected".to_string()))?;

    let (secret_key, passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available".to_string()))?;

    // Create handler
    let dm_handler = DirectMessageHandler::new(
        mls_client.clone(),
        mixnet_service.clone(),
        secret_key.clone(),
        passphrase.clone(),
        current_user.username.clone(),
        state.db.clone(),
    );

    // Check if conversation already exists
    if dm_handler.conversation_exists(&recipient).await {
        tracing::info!("MLS conversation already exists with {}", recipient);
        return Ok(true);
    }

    // Check if handshake is already in progress
    if dm_handler.handshake_in_progress(&recipient).await {
        tracing::info!("Handshake already in progress with {}", recipient);
        return Ok(false);
    }

    // --- Step 1: Request PoW challenge ---
    let challenge_rx = state
        .register_pending_query(&format!("kp_challenge:{}", recipient))
        .await;

    mixnet_service
        .send_fetch_key_package_challenge(&recipient)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to request KP challenge: {}", e)))?;

    // Wait for challenge response (15s timeout)
    let challenge_result =
        tokio::time::timeout(std::time::Duration::from_secs(15), challenge_rx).await;

    let challenge_data = match challenge_result {
        Ok(Ok(Some(qr))) => qr,
        Ok(Ok(None)) => {
            return Err(ApiError::internal(
                "Key package challenge returned empty".to_string(),
            ));
        }
        Ok(Err(_)) => {
            state
                .cancel_pending_query(&format!("kp_challenge:{}", recipient))
                .await;
            return Err(ApiError::internal(
                "Key package challenge canceled".to_string(),
            ));
        }
        Err(_) => {
            state
                .cancel_pending_query(&format!("kp_challenge:{}", recipient))
                .await;
            return Err(ApiError::timeout("Key package challenge timed out"));
        }
    };

    // challenge_data.public_key carries the challenge string, username carries difficulty
    let challenge = challenge_data.public_key.clone();
    let difficulty: u32 = challenge_data.username.parse().unwrap_or(16);

    tracing::info!(
        "Received KP challenge for {}, difficulty={}",
        recipient,
        difficulty
    );

    // --- Step 2: Grind PoW nonce ---
    let recipient_clone = recipient.clone();
    let challenge_clone = challenge.clone();
    let nonce = tokio::task::spawn_blocking(move || {
        let mut nonce: u64 = 0;
        loop {
            let input = format!("{}{}{}", recipient_clone, challenge_clone, nonce);
            let hash = sha2::Sha256::digest(input.as_bytes());
            if has_leading_zero_bits(&hash, difficulty) {
                return nonce.to_string();
            }
            nonce += 1;
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("PoW task failed: {}", e)))?;

    tracing::info!("PoW solved for {}, nonce={}", recipient, nonce);

    // --- Step 3: Fetch key package with PoW solution ---
    let kp_rx = state
        .register_pending_query(&format!("kp_fetch:{}", recipient))
        .await;

    mixnet_service
        .send_fetch_key_package(&recipient, &challenge, &nonce)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch key package: {}", e)))?;

    // Wait for KP bundle response (15s timeout)
    let kp_result = tokio::time::timeout(std::time::Duration::from_secs(15), kp_rx).await;

    let kp_data = match kp_result {
        Ok(Ok(Some(qr))) => qr,
        Ok(Ok(None)) => {
            return Err(ApiError::internal(
                "Key package not found for recipient".to_string(),
            ));
        }
        Ok(Err(_)) => {
            state
                .cancel_pending_query(&format!("kp_fetch:{}", recipient))
                .await;
            return Err(ApiError::internal("Key package fetch canceled".to_string()));
        }
        Err(_) => {
            state
                .cancel_pending_query(&format!("kp_fetch:{}", recipient))
                .await;
            return Err(ApiError::timeout("Key package fetch timed out"));
        }
    };

    // kp_data.public_key = recipient's PGP public key (armored)
    // kp_data.username = JSON-encoded SignedKeyPackageBundle
    let recipient_public_key_armored = kp_data.public_key.clone();
    let bundle_json = kp_data.username.clone();

    let bundle: nymstr_crypto::mls::SignedKeyPackageBundle = serde_json::from_str(&bundle_json)
        .map_err(|e| ApiError::internal(format!("Failed to parse KP bundle: {}", e)))?;

    // --- Step 5: Verify PGP signature on the bundle ---
    let recipient_pgp_pubkey =
        crate::crypto::pgp::PgpKeyManager::parse_public_key(&recipient_public_key_armored)
            .map_err(|e| ApiError::internal(format!("Failed to parse recipient PGP key: {}", e)))?;

    let verified = nymstr_crypto::mls::verify_bundle(&bundle, &recipient_pgp_pubkey)
        .map_err(|e| ApiError::internal(format!("Failed to verify KP bundle: {}", e)))?;

    if !verified {
        return Err(ApiError::internal(
            "Key package bundle signature verification failed".to_string(),
        ));
    }

    tracing::info!("Key package bundle verified for {}", recipient);

    // --- Step 6: Store recipient's public key in contacts ---
    sqlx::query(
        "INSERT OR REPLACE INTO contacts (owner_username, username, display_name, public_key) VALUES (?, ?, ?, ?)"
    )
    .bind(&current_user.username)
    .bind(&recipient)
    .bind(&recipient)
    .bind(&recipient_public_key_armored)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to store contact: {}", e)))?;

    // --- Step 7: Create MLS group and send p2pWelcome ---
    dm_handler
        .complete_handshake(&recipient, &bundle.key_package_b64)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to complete handshake: {}", e)))?;

    tracing::info!(
        "MLS handshake initiated with {} via pre-published key package",
        recipient
    );
    Ok(false)
}

/// Generate a key package for MLS handshakes
#[tauri::command]
pub async fn generate_key_package(state: State<'_, AppState>) -> Result<String, ApiError> {
    tracing::info!("Generating key package");

    // Get MLS client
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    // Generate key package
    let key_package = mls_client
        .generate_key_package()
        .map_err(|e| ApiError::internal(format!("Failed to generate key package: {}", e)))?;

    use base64::Engine;
    let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&key_package);

    tracing::info!("Key package generated successfully");
    Ok(key_package_b64)
}

/// Get conversation history with a contact
#[tauri::command]
pub async fn get_conversation(
    contact: String,
    limit: Option<i64>,
    before_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<MessageDTO>, ApiError> {
    tracing::debug!("Fetching conversation with: {}", contact);

    // Get current user for normalized conversation ID
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    let conversation_id = normalize_conversation_id(&current_user.username, &contact);
    let limit = limit.unwrap_or(50).min(100);

    let messages: Vec<(String, String, String, String, String, bool, bool)> =
        if let Some(before) = before_id {
            sqlx::query_as(
                r#"
            SELECT id, sender, content, timestamp, status, is_own, is_read
            FROM messages
            WHERE conversation_id = ? AND id < ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
            )
            .bind(&conversation_id)
            .bind(&before)
            .bind(limit)
            .fetch_all(&state.db)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
        } else {
            sqlx::query_as(
                r#"
            SELECT id, sender, content, timestamp, status, is_own, is_read
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
            )
            .bind(&conversation_id)
            .bind(limit)
            .fetch_all(&state.db)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
        };

    // Mark all incoming messages in this conversation as read
    Db::mark_conversation_read(&state.db, &conversation_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Convert to DTOs and reverse to get chronological order
    let mut result: Vec<MessageDTO> = messages
        .into_iter()
        .map(
            |(id, sender, content, timestamp, status, is_own, _is_read)| {
                MessageDTO {
                    id,
                    sender,
                    content,
                    timestamp,
                    status: match status.as_str() {
                        "pending" => MessageStatus::Pending,
                        "sent" => MessageStatus::Sent,
                        "delivered" => MessageStatus::Delivered,
                        _ => MessageStatus::Failed,
                    },
                    is_own,
                    is_read: true, // Just marked as read above
                }
            },
        )
        .collect();

    result.reverse();
    Ok(result)
}

/// Mark messages as read
#[tauri::command]
pub async fn mark_as_read(
    contact: String,
    message_id: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    let _ = message_id; // Reserved for future per-message granularity

    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    let conversation_id = normalize_conversation_id(&current_user.username, &contact);

    Db::mark_conversation_read(&state.db, &conversation_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(())
}

/// Check if MLS conversation exists with a contact
#[tauri::command]
pub async fn check_conversation_exists(
    contact: String,
    state: State<'_, AppState>,
) -> Result<bool, ApiError> {
    // Get current user
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;

    // Get MLS client
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized".to_string()))?;

    // Look up the real MLS group ID from the database
    let conversation_id = normalize_conversation_id(&current_user.username, &contact);
    let result: Option<(String,)> =
        sqlx::query_as("SELECT mls_group_id FROM conversations WHERE id = ?")
            .bind(&conversation_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to query conversation: {}", e)))?;

    let exists = if let Some((mls_group_id_b64,)) = result {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(&mls_group_id_b64) {
            Ok(mls_group_id) => mls_client.group_exists(&mls_group_id),
            Err(_) => false,
        }
    } else {
        false
    };

    Ok(exists)
}

/// Get pending messages (messages waiting for MLS handshake to complete)
#[tauri::command]
pub async fn get_pending_messages(state: State<'_, AppState>) -> Result<Vec<MessageDTO>, ApiError> {
    let messages: Vec<(String, String, String, String, String, bool)> = sqlx::query_as(
        r#"
        SELECT id, sender, content, timestamp, status, is_own
        FROM messages
        WHERE status = 'pending' AND is_own = 1
        ORDER BY timestamp ASC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let result: Vec<MessageDTO> = messages
        .into_iter()
        .map(
            |(id, sender, content, timestamp, _status, is_own)| MessageDTO {
                id,
                sender,
                content,
                timestamp,
                status: MessageStatus::Pending,
                is_own,
                is_read: false,
            },
        )
        .collect();

    Ok(result)
}
