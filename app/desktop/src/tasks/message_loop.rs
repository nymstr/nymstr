//! Message receive loop task
//!
//! This module handles the continuous processing of incoming mixnet messages.
//! It receives messages from the mixnet client, routes them to appropriate handlers,
//! and emits events to the frontend for real-time updates.

use std::sync::Arc;

use tauri::AppHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use base64::Engine;

use crate::core::db::{BufferedMessage, Db};
use crate::core::message_handler::{DirectMessageHandlerBuilder, WelcomeFlowHandler};
use crate::core::message_router::{MessageRoute, MessageRouter};
use crate::core::mixnet_client::Incoming;
use crate::crypto::mls::{MlsClient, MlsMessageType};
use crate::events::{AppEvent, EventEmitter};
use crate::state::{AppState, QueryResult};
use crate::types::{MessageDTO, MessageStatus};

/// Start the message receive loop
///
/// This spawns a background task that:
/// - Receives messages from the mixnet
/// - Routes them using MessageRouter
/// - Handles each message type appropriately
/// - Emits events to the frontend for real-time updates
pub fn start_message_receive_loop(
    app_handle: AppHandle,
    state: Arc<AppState>,
    mut rx: mpsc::Receiver<Incoming>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("Message receive loop started");
        let emitter = EventEmitter::new(app_handle.clone());

        while let Some(incoming) = rx.recv().await {
            // Route the message to determine handling
            let route = MessageRouter::route_message(&incoming);
            let description = MessageRouter::route_description(&route);

            tracing::debug!(
                "Received message: action={}, route={}",
                incoming.envelope.action,
                description
            );

            if let Err(e) = process_message(&emitter, &state, &incoming, route).await {
                tracing::error!(
                    "Error processing message (action={}): {}",
                    incoming.envelope.action,
                    e
                );
            }
        }

        tracing::info!("Message receive loop ended");
    })
}

/// Process a single incoming message based on its route
async fn process_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
    route: MessageRoute,
) -> anyhow::Result<()> {
    // Extract serverTime from every response to maintain server-relative clock
    if let Some(server_time) = incoming.envelope.server_time {
        // Determine server identifier from sender field
        let server_id = match incoming.envelope.sender.as_str() {
            "server" => "discovery".to_string(),
            "group-server" => "group-server".to_string(),
            other => other.to_string(),
        };
        state.update_server_time(&server_id, server_time).await;
    }

    // Verify server signatures for server-origin messages
    let is_server_message = matches!(
        route,
        MessageRoute::Group | MessageRoute::WelcomeFlow | MessageRoute::Query
    );
    if is_server_message && !state.verify_server_signature(&incoming.envelope).await {
        tracing::error!(
            "Dropping message with action '{}': server signature verification failed",
            incoming.envelope.action
        );
        return Ok(());
    }

    match route {
        MessageRoute::Authentication => {
            // Authentication messages are handled by the auth command flow
            // They are consumed during register_user and login_user
            tracing::debug!(
                "Authentication message received (action={}), should be handled by auth flow",
                incoming.envelope.action
            );
        }

        MessageRoute::Query => {
            // Handle query responses by resolving pending queries
            handle_query_response(state, incoming).await?;
        }

        MessageRoute::MlsProtocol => {
            handle_mls_message(emitter, state, incoming).await?;
        }

        MessageRoute::Chat => {
            // All chat messages go through MLS now
            handle_mls_message(emitter, state, incoming).await?;
        }

        MessageRoute::Handshake => {
            handle_handshake_message(emitter, state, incoming).await?;
        }

        MessageRoute::Group => {
            handle_group_message(emitter, state, incoming).await?;
        }

        MessageRoute::WelcomeFlow => {
            handle_welcome_flow_message(emitter, state, incoming).await?;
        }


        MessageRoute::Unknown => {
            tracing::warn!(
                "Unknown message type received: action={}",
                incoming.envelope.action
            );
        }
    }

    Ok(())
}

/// Handle query responses from the discovery server
async fn handle_query_response(
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let payload = &incoming.envelope.payload;

    // Extract username and public key from response
    let username = payload.get("username").and_then(|v| v.as_str());
    let public_key = payload.get("publicKey").and_then(|v| v.as_str());

    if let (Some(username), Some(public_key)) = (username, public_key) {
        tracing::info!("Received query response for user: {}", username);

        let result = QueryResult {
            username: username.to_string(),
            public_key: public_key.to_string(),
        };

        // Resolve the pending query
        state.resolve_pending_query(username, Some(result)).await;
    } else {
        // User not found - the payload might contain the queried username
        // Try to extract from different field names
        let queried_username = payload.get("identifier")
            .or_else(|| payload.get("username"))
            .and_then(|v| v.as_str());

        if let Some(username) = queried_username {
            tracing::info!("User not found: {}", username);
            state.resolve_pending_query(username, None).await;
        } else {
            tracing::warn!("Query response received but couldn't determine username");
        }
    }

    Ok(())
}

/// Handle MLS protocol messages (key packages, welcomes, encrypted messages)
async fn handle_mls_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let action = incoming.envelope.action.as_str();
    let sender = &incoming.envelope.sender;
    let payload = &incoming.envelope.payload;

    match action {
        "keyPackageRequest" => {
            // Someone wants to establish a conversation with us
            // Store the request for the user to accept/deny instead of auto-responding
            tracing::info!("Received key package request from {}", sender);

            // Store the contact request in the database (only if not already handled)
            let result = sqlx::query(
                r#"
                INSERT OR IGNORE INTO contact_requests (from_username, received_at, status)
                VALUES (?, datetime('now'), 'pending')
                "#,
            )
            .bind(sender)
            .execute(&state.db)
            .await?;

            if result.rows_affected() > 0 {
                // Only notify frontend for genuinely new requests
                emitter.contact_request_received(sender.clone());
                tracing::info!("Stored contact request from {}, pending user action", sender);
            } else {
                tracing::info!("Duplicate contact request from {}, already handled", sender);
            }
        }

        "keyPackageResponse" => {
            // Received key package from someone we requested
            tracing::info!("Received key package response from {}", sender);

            let current_user = state.get_current_user().await
                .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;
            let mls_client = state.get_mls_client().await
                .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
            let mixnet_service = state.get_mixnet_service().await
                .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
            let (pgp_secret_key, pgp_passphrase) = state.get_pgp_signing_keys().await
                .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

            let handler = DirectMessageHandlerBuilder::new()
                .mls_client(mls_client)
                .mixnet_service(mixnet_service)
                .pgp_keys(pgp_secret_key, pgp_passphrase)
                .current_user(current_user.username.clone())
                .db(state.db.clone())
                .build()?;

            // Skip if a handshake is already in progress or completed with this user
            if handler.handshake_in_progress(sender).await {
                tracing::info!("Handshake already in progress with {}, skipping duplicate keyPackageResponse", sender);
                return Ok(());
            }

            // Get their key package
            let recipient_key_package = payload
                .get("senderKeyPackage")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing senderKeyPackage in response"))?;

            // Complete the handshake (establish conversation and send welcome)
            handler.complete_handshake(sender, recipient_key_package).await?;

            tracing::info!("MLS handshake completed with {}", sender);
        }

        "fetchKeyPackageChallengeResponse" => {
            // Server responded with a PoW challenge for key package fetch
            let target_username = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let challenge = payload.get("challenge").and_then(|v| v.as_str()).unwrap_or("");
            let difficulty = payload.get("difficulty").and_then(|v| v.as_u64()).unwrap_or(16);

            tracing::info!("Received KP challenge for {}, difficulty={}", target_username, difficulty);

            // Resolve via pending query mechanism using the kp_challenge:{username} key
            let result = crate::state::QueryResult {
                username: difficulty.to_string(),
                public_key: challenge.to_string(),
            };
            state.resolve_pending_query(&format!("kp_challenge:{}", target_username), Some(result)).await;
        }

        "fetchKeyPackageResponse" => {
            // Server responded with a key package bundle
            let target_username = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let key_package_b64 = payload.get("keyPackage").and_then(|v| v.as_str()).unwrap_or("");
            let pgp_signature = payload.get("pgpSignature").and_then(|v| v.as_str()).unwrap_or("");
            let pgp_fingerprint = payload.get("pgpFingerprint").and_then(|v| v.as_str()).unwrap_or("");
            let public_key = payload.get("publicKey").and_then(|v| v.as_str()).unwrap_or("");

            tracing::info!("Received key package bundle for {}", target_username);

            // Build a SignedKeyPackageBundle JSON for the caller
            let bundle = serde_json::json!({
                "key_package_b64": key_package_b64,
                "pgp_signature": pgp_signature,
                "pgp_fingerprint": pgp_fingerprint,
            });

            let result = crate::state::QueryResult {
                username: bundle.to_string(),
                public_key: public_key.to_string(),
            };
            state.resolve_pending_query(&format!("kp_fetch:{}", target_username), Some(result)).await;
        }

        "keyPackageNeeded" => {
            // Server tells us someone tried to fetch our KP but we had none
            // Auto-generate and publish 5 key packages
            tracing::info!("Server reports key packages needed, publishing new ones");

            let current_user = state.get_current_user().await
                .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;
            let mls_client = state.get_mls_client().await
                .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
            let mixnet_service = state.get_mixnet_service().await
                .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
            let (secret_key, passphrase) = state.get_pgp_signing_keys().await
                .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

            let username = current_user.username.clone();
            tokio::spawn(async move {
                for i in 0..5 {
                    let raw_bytes = match mls_client.generate_key_package() {
                        Ok(b) => b,
                        Err(e) => { tracing::warn!("Failed to generate KP {}: {}", i, e); continue; }
                    };
                    let kp_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
                    let pgp_sig = match crate::crypto::pgp::PgpSigner::sign_detached_secure(&secret_key, &raw_bytes, &passphrase) {
                        Ok(s) => s,
                        Err(e) => { tracing::warn!("Failed to sign KP {}: {}", i, e); continue; }
                    };
                    use pgp::types::KeyDetails;
                    let fp = hex::encode(secret_key.fingerprint().as_bytes());
                    let sign_content = format!("publishKeyPackage:{}:{}", username, kp_b64);
                    let sig = match crate::crypto::pgp::PgpSigner::sign_detached_secure(&secret_key, sign_content.as_bytes(), &passphrase) {
                        Ok(s) => s,
                        Err(e) => { tracing::warn!("Failed to sign publish action {}: {}", i, e); continue; }
                    };
                    if let Err(e) = mixnet_service.send_publish_key_package(&username, &kp_b64, &pgp_sig, &fp, &sig).await {
                        tracing::warn!("Failed to publish KP {}: {}", i, e);
                    }
                }
                tracing::info!("Published key packages in response to keyPackageNeeded");
            });
        }

        "send" | "incomingMessage" => {
            // Encrypted message received
            handle_encrypted_message(emitter, state, incoming).await?;
        }

        _ => {
            tracing::debug!("Unhandled MLS action: {}", action);
        }
    }

    Ok(())
}

/// Handle encrypted incoming messages
async fn handle_encrypted_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let payload = &incoming.envelope.payload;

    // Sealed messages may need to fetch the sender's pubkey from the discovery
    // server. That fetch awaits a `queryResponse` that arrives on this same
    // receive loop — so if we await it inline we'd deadlock. Spawn the sealed
    // handler on its own task so the loop keeps draining and can dispatch the
    // query response concurrently.
    if incoming.envelope.message_type == "sealed" {
        let emitter = emitter.clone();
        let state = state.clone();
        let incoming = incoming.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_sealed_message(&emitter, &state, &incoming).await {
                tracing::error!("Error processing sealed message: {}", e);
            }
        });
        return Ok(());
    }

    let sender = &incoming.envelope.sender;

    let current_user = state.get_current_user().await
        .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;
    let mls_client = state.get_mls_client().await
        .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
    let mixnet_service = state.get_mixnet_service().await
        .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
    let (pgp_secret_key, pgp_passphrase) = state.get_pgp_signing_keys().await
        .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

    let handler = DirectMessageHandlerBuilder::new()
        .mls_client(mls_client)
        .mixnet_service(mixnet_service)
        .pgp_keys(pgp_secret_key, pgp_passphrase)
        .current_user(current_user.username.clone())
        .db(state.db.clone())
        .build()?;

    // Get the MLS message from payload
    let mls_message = payload
        .get("mls_message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing mls_message in payload"))?;

    let _conversation_id_b64 = payload
        .get("conversation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Try to decrypt the message
    match handler.process_incoming_message(sender, mls_message, MlsMessageType::Application).await {
        Ok(Some(content)) => {
            tracing::info!("Decrypted message from {}", sender);

            // Create message DTO
            let conversation_id = handler.get_conversation_id(sender);
            let message = MessageDTO {
                id: uuid::Uuid::new_v4().to_string(),
                sender: sender.clone(),
                content,
                timestamp: incoming.ts.to_rfc3339(),
                status: MessageStatus::Delivered,
                is_own: false,
                is_read: false,
            };

            // Store in database
            Db::save_message(&state.db, &conversation_id, &message).await?;

            // Emit event to frontend
            emitter.message_received(message, conversation_id);
        }
        Ok(None) => {
            // Message was a commit or other non-application message
            tracing::debug!("Processed non-application MLS message from {}", sender);
        }
        Err(e) => {
            // Check if this is an epoch mismatch - buffer for later
            let error_msg = e.to_string();
            if error_msg.contains("epoch") || error_msg.contains("Epoch") {
                tracing::info!("Message from {} has epoch mismatch, buffering", sender);

                let conversation_id = handler.get_conversation_id(sender);
                let buffered = BufferedMessage {
                    id: 0,
                    conversation_id: conversation_id.clone(),
                    sender: sender.clone(),
                    mls_message_b64: mls_message.to_string(),
                    received_at: incoming.ts.to_rfc3339(),
                    retry_count: 0,
                    processed: false,
                    failed: false,
                    error_message: Some(error_msg),
                };

                Db::buffer_message(&state.db, &buffered).await?;
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Fetch a user's PGP public key from the discovery server (used when we
/// unseal a message from someone not yet in our contacts).
async fn fetch_pubkey_from_server(
    state: &Arc<AppState>,
    username: &str,
) -> anyhow::Result<String> {
    let mixnet_service = state.get_mixnet_service().await
        .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;

    let rx = state.register_pending_query(username).await;
    mixnet_service.send_query_request(username).await
        .map_err(|e| anyhow::anyhow!("Failed to send query: {}", e))?;

    let result = tokio::time::timeout(std::time::Duration::from_secs(15), rx).await;
    match result {
        Ok(Ok(Some(qr))) => {
            // Cache for future lookups
            let _ = sqlx::query(
                "INSERT OR REPLACE INTO query_cache (username, public_key) VALUES (?, ?)"
            )
            .bind(&qr.username)
            .bind(&qr.public_key)
            .execute(&state.db)
            .await;
            Ok(qr.public_key)
        }
        Ok(Ok(None)) => {
            state.cancel_pending_query(username).await;
            Err(anyhow::anyhow!("User {} not found on server", username))
        }
        Ok(Err(_)) => {
            state.cancel_pending_query(username).await;
            Err(anyhow::anyhow!("Query was canceled"))
        }
        Err(_) => {
            state.cancel_pending_query(username).await;
            Err(anyhow::anyhow!("Query timed out fetching pubkey for {}", username))
        }
    }
}

/// Handle a sealed sender message by decrypting the outer envelope,
/// verifying the sender's PGP signature, and dispatching by `inner_action`.
async fn handle_sealed_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let payload = &incoming.envelope.payload;

    // Extract the base64-encoded sealed payload
    let sealed_payload_b64 = payload
        .get("sealed_payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing sealed_payload in sealed message"))?;

    let sealed_bytes = base64::engine::general_purpose::STANDARD
        .decode(sealed_payload_b64)
        .map_err(|e| anyhow::anyhow!("Invalid sealed_payload base64: {}", e))?;

    // Get our PGP secret key to derive the Curve25519 secret for decryption
    let (pgp_secret_key, pgp_passphrase) = state.get_pgp_signing_keys().await
        .ok_or_else(|| anyhow::anyhow!("PGP keys not available"))?;

    let recipient_curve25519_secret =
        nymstr_crypto::sealed_sender::extract_curve25519_secret(&pgp_secret_key, pgp_passphrase.as_str())?;

    let sealed_content = nymstr_crypto::sealed_sender::unseal(&sealed_bytes, &recipient_curve25519_secret)?;

    let real_sender = sealed_content.sender.clone();
    tracing::info!("Unsealed message from sender: {}", real_sender);

    let current_user = state.get_current_user().await
        .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;

    // Look up sender's PGP public key from contacts; if unknown, fetch from server
    let sender_pubkey_armored = match crate::core::db::ContactDb::get_contact_public_key(
        &state.db, &current_user.username, &real_sender,
    ).await? {
        Some(pk) => pk,
        None => {
            tracing::info!(
                "Sender {} not in contacts, querying discovery server for public key",
                real_sender
            );
            fetch_pubkey_from_server(state, &real_sender).await?
        }
    };

    let sender_pgp_pubkey = crate::crypto::pgp::PgpKeyManager::parse_public_key(&sender_pubkey_armored)?;

    // Verify PGP signature over "{sender}:{timestamp}:{payload_json}"
    let payload_str = serde_json::to_string(&sealed_content.payload)
        .map_err(|e| anyhow::anyhow!("Failed to serialize inner payload: {}", e))?;
    let sign_content = format!(
        "{}:{}:{}",
        sealed_content.sender, sealed_content.timestamp, payload_str
    );
    crate::crypto::pgp::PgpSigner::verify_detached(
        &sender_pgp_pubkey,
        sign_content.as_bytes(),
        &sealed_content.signature,
    )?;
    tracing::info!("Sealed sender signature verified for {}", real_sender);

    // Build handler used by all dispatch branches
    let mls_client = state.get_mls_client().await
        .ok_or_else(|| anyhow::anyhow!("MLS client not initialized"))?;
    let mixnet_service = state.get_mixnet_service().await
        .ok_or_else(|| anyhow::anyhow!("Mixnet not connected"))?;
    let handler = DirectMessageHandlerBuilder::new()
        .mls_client(mls_client)
        .mixnet_service(mixnet_service)
        .pgp_keys(pgp_secret_key, pgp_passphrase)
        .current_user(current_user.username.clone())
        .db(state.db.clone())
        .build()?;

    // Dispatch on inner_action (carried inside the sealed payload, hidden from server).
    // Default (missing/unknown) is a regular DM application message.
    let inner_action = sealed_content.payload
        .get("inner_action")
        .and_then(|v| v.as_str())
        .unwrap_or("send");

    match inner_action {
        "p2pWelcome" => {
            handle_sealed_welcome(
                emitter,
                state,
                &handler,
                &real_sender,
                &sender_pubkey_armored,
                &sealed_content.payload,
            ).await?;
        }
        "p2pWelcomeAck" => {
            handle_sealed_welcome_ack(
                emitter,
                &handler,
                state,
                &real_sender,
                &sealed_content.payload,
            ).await?;
        }
        _ => {
            handle_sealed_application_message(
                emitter,
                state,
                &handler,
                &real_sender,
                &sealed_content.payload,
                incoming,
            ).await?;
        }
    }

    Ok(())
}

/// Process an unsealed p2pWelcome. Mirrors the former cleartext p2pWelcome
/// handler but reads sender from the sealed envelope rather than the outer one.
async fn handle_sealed_welcome(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    handler: &crate::core::message_handler::DirectMessageHandler,
    sender: &str,
    sender_pubkey_armored: &str,
    payload: &serde_json::Value,
) -> anyhow::Result<()> {
    tracing::info!("Received sealed p2pWelcome from {}", sender);

    let current_user = state.get_current_user().await
        .ok_or_else(|| anyhow::anyhow!("No user logged in"))?;

    // Skip if we already have a completed conversation with this user
    if handler.conversation_exists(sender).await {
        tracing::info!("Conversation already exists with {}, skipping duplicate p2pWelcome", sender);
        return Ok(());
    }

    let is_known_contact: bool = {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COUNT(*) FROM contacts WHERE owner_username = ? AND username = ?"
        )
        .bind(&current_user.username)
        .bind(sender)
        .fetch_optional(&state.db)
        .await?;
        row.map(|(c,)| c > 0).unwrap_or(false)
    };

    let welcome_message = payload
        .get("welcomeMessage")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing welcomeMessage in payload"))?;

    let conversation_id = payload
        .get("groupId")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if is_known_contact {
        handler.process_incoming_message(sender, welcome_message, MlsMessageType::Welcome).await?;
        handler.send_welcome_ack(sender, conversation_id, true).await?;

        drain_pending_messages(handler, &state.db, sender).await;

        tracing::info!("Joined conversation with known contact {} and sent p2pWelcomeAck", sender);
    } else {
        // Unknown sender — cache their verified pubkey and store as contact request.
        // Signature was already verified against the server-fetched key, so we can
        // trust sender identity when the user accepts the request.
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO query_cache (username, public_key) VALUES (?, ?)"
        )
        .bind(sender)
        .bind(sender_pubkey_armored)
        .execute(&state.db)
        .await;

        let welcome_payload_json = serde_json::to_string(payload).unwrap_or_default();
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO contact_requests (from_username, received_at, status, welcome_payload)
            VALUES (?, datetime('now'), 'pending', ?)
            "#,
        )
        .bind(sender)
        .bind(&welcome_payload_json)
        .execute(&state.db)
        .await?;

        emitter.contact_request_received(sender.to_string());
        tracing::info!("Stored p2pWelcome from unknown sender {} as contact request", sender);
    }

    Ok(())
}

/// Process an unsealed p2pWelcomeAck.
async fn handle_sealed_welcome_ack(
    emitter: &EventEmitter,
    handler: &crate::core::message_handler::DirectMessageHandler,
    state: &Arc<AppState>,
    sender: &str,
    payload: &serde_json::Value,
) -> anyhow::Result<()> {
    tracing::info!("Received sealed p2pWelcomeAck from {}", sender);

    let accepted = payload
        .get("accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if accepted {
        handler.finalize_handshake(sender).await?;

        let conversation_id = payload
            .get("conversationId")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        drain_pending_messages(handler, &state.db, sender).await;

        emitter.emit(crate::events::AppEvent::ConversationEstablished {
            conversation_id: conversation_id.to_string(),
            peer: sender.to_string(),
        });

        tracing::info!("DM handshake finalized with {} (conversation: {})", sender, conversation_id);
    } else {
        handler.cleanup_failed_handshake(sender).await?;
        tracing::info!("DM handshake rejected by {}", sender);
    }

    Ok(())
}

/// Process a sealed MLS application message (regular DM).
async fn handle_sealed_application_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    handler: &crate::core::message_handler::DirectMessageHandler,
    real_sender: &str,
    payload: &serde_json::Value,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let mls_message_b64 = payload
        .get("mls_message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing mls_message in sealed content payload"))?;

    match handler.process_incoming_message(real_sender, mls_message_b64, MlsMessageType::Application).await {
        Ok(Some(content)) => {
            tracing::info!("Decrypted sealed-sender message from {}", real_sender);

            let conversation_id = handler.get_conversation_id(real_sender);
            let message = MessageDTO {
                id: uuid::Uuid::new_v4().to_string(),
                sender: real_sender.to_string(),
                content,
                timestamp: incoming.ts.to_rfc3339(),
                status: MessageStatus::Delivered,
                is_own: false,
                is_read: false,
            };

            Db::save_message(&state.db, &conversation_id, &message).await?;
            emitter.message_received(message, conversation_id);
        }
        Ok(None) => {
            tracing::debug!("Processed non-application sealed MLS message from {}", real_sender);
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("epoch") || error_msg.contains("Epoch") {
                tracing::info!("Sealed message from {} has epoch mismatch, buffering", real_sender);

                let conversation_id = handler.get_conversation_id(real_sender);
                let buffered = BufferedMessage {
                    id: 0,
                    conversation_id: conversation_id.clone(),
                    sender: real_sender.to_string(),
                    mls_message_b64: mls_message_b64.to_string(),
                    received_at: incoming.ts.to_rfc3339(),
                    retry_count: 0,
                    processed: false,
                    failed: false,
                    error_message: Some(error_msg),
                };

                Db::buffer_message(&state.db, &buffered).await?;
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Handle handshake messages for P2P discovery
async fn handle_handshake_message(
    _emitter: &EventEmitter,
    _state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    tracing::info!("Received handshake message from {}", incoming.envelope.sender);
    // Handshake handling can be extended as needed
    Ok(())
}

/// Handle group server response messages
async fn handle_group_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let action = incoming.envelope.action.as_str();
    let payload = &incoming.envelope.payload;

    match action {
        "fetchGroupResponse" => {
            tracing::info!("Received group fetch response");

            // Extract the server address from the sender field
            let server_address = &incoming.envelope.sender;

            // Extract messages from payload
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");

            if content.starts_with("error:") {
                tracing::error!("Group fetch failed: {}", content);
                return Ok(());
            }

            // Parse the content
            if let Ok(content_json) = serde_json::from_str::<serde_json::Value>(content) {
                if let Some(messages) = content_json.get("messages").and_then(|v| v.as_array()) {
                    tracing::info!("Received {} messages from group server", messages.len());

                    // Find the maximum message ID for cursor update
                    let max_message_id = messages
                        .iter()
                        .filter_map(|msg| msg.get("id").and_then(|v| v.as_i64()))
                        .max();

                    // Update cursor if we received messages
                    if let Some(max_id) = max_message_id {
                        // Update the cursor in the database
                        if let Err(e) = sqlx::query(
                            r#"
                            INSERT OR REPLACE INTO group_cursors (server_address, last_message_id, updated_at)
                            VALUES (?, ?, datetime('now'))
                            "#,
                        )
                        .bind(server_address)
                        .bind(max_id)
                        .execute(&state.db)
                        .await
                        {
                            tracing::warn!("Failed to update group cursor: {}", e);
                        } else {
                            tracing::debug!(
                                "Updated group cursor for {} to {}",
                                server_address,
                                max_id
                            );
                        }
                    }

                    // Messages need to be decrypted with MLS - this requires group context
                    // For now, emit a raw event and let the command layer handle decryption
                    emitter.emit(AppEvent::GroupMessagesReceived {
                        count: messages.len() as u32,
                    });
                }
            }
        }

        "sendGroupResponse" => {
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("sent");
            tracing::info!("Group message send response: {}", content);
        }

        "registerResponse" => {
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            tracing::info!("Group registration response: {}", content);

            if content == "pending" {
                emitter.emit(AppEvent::GroupRegistrationPending);
            } else if content.starts_with("error:") {
                emitter.emit(AppEvent::GroupRegistrationFailed {
                    error: content.to_string(),
                });
            } else {
                emitter.emit(AppEvent::GroupRegistrationSuccess);
            }
        }

        "approveGroupResponse" => {
            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("approved");
            tracing::info!("Group approval response: {}", content);
        }

        "syncEpochResponse" => {
            tracing::info!("Received commit sync response");

            let content = payload
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");

            if content.starts_with("error:") {
                tracing::warn!("Commit sync failed: {}", content);
                return Ok(());
            }

            // Parse the sync response
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                let group_id = parsed.get("groupId").and_then(|v| v.as_str());

                // Process any buffered commits
                if let Some(commits) = parsed.get("commits").and_then(|v| v.as_array()) {
                    if commits.is_empty() {
                        tracing::debug!("No commits to process in commit sync");
                        return Ok(());
                    }

                    tracing::info!("Processing {} buffered commits for catch-up", commits.len());

                    // Get MLS client to process commits
                    let current_user = match state.get_current_user().await {
                        Some(u) => u,
                        None => {
                            tracing::warn!("Cannot process commit sync: no user logged in");
                            return Ok(());
                        }
                    };

                    let (secret_key, public_key, passphrase) = match state.get_pgp_keys().await {
                        Some(keys) => keys,
                        None => {
                            tracing::warn!("Cannot process commit sync: PGP keys not available");
                            return Ok(());
                        }
                    };

                    let mls_client = match MlsClient::new(
                        &current_user.username,
                        secret_key,
                        public_key,
                        &passphrase,
                        state.app_dir.clone(),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Cannot process commit sync: failed to create MLS client: {}", e);
                            return Ok(());
                        }
                    };

                    // Use the group_id from the response
                    let mls_group_id = match group_id {
                        Some(id) => id.to_string(),
                        None => {
                            tracing::warn!("Cannot process commit sync: no group ID in response");
                            return Ok(());
                        }
                    };

                    // Process each commit in order (ordered by sequential id from server)
                    for commit_obj in commits {
                        let commit_id = commit_obj.get("id").and_then(|v| v.as_i64());
                        let commit_epoch = commit_obj.get("epoch").and_then(|v| v.as_i64());
                        let commit_b64 = commit_obj.get("commit").and_then(|v| v.as_str());

                        if let (Some(epoch), Some(commit_data)) = (commit_epoch, commit_b64) {
                            tracing::debug!(
                                "Processing commit id={:?} epoch={} for group {}",
                                commit_id,
                                epoch,
                                mls_group_id
                            );

                            match base64::engine::general_purpose::STANDARD.decode(commit_data) {
                                Ok(commit_bytes) => {
                                    match mls_client.process_commit(&mls_group_id, &commit_bytes) {
                                        Ok(new_epoch) => {
                                            tracing::info!(
                                                "Advanced to epoch {} after processing commit (server id={:?})",
                                                new_epoch,
                                                commit_id
                                            );
                                        }
                                        Err(e) => {
                                            // This might happen if we already processed this commit
                                            tracing::debug!(
                                                "Failed to process commit id={:?} epoch={}: {} (may already be processed)",
                                                commit_id,
                                                epoch,
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to decode commit base64: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        _ => {
            tracing::debug!("Unhandled group action: {}", action);
        }
    }

    Ok(())
}

/// Handle Welcome flow messages (invites, welcomes, join requests)
///
/// Uses the shared MLS client from AppState to ensure conversation state
/// persists across messages. When a Welcome is successfully processed,
/// emits a GroupJoined event to the frontend.
async fn handle_welcome_flow_message(
    emitter: &EventEmitter,
    state: &Arc<AppState>,
    incoming: &Incoming,
) -> anyhow::Result<()> {
    let current_user = state.get_current_user().await;
    let mixnet_service = state.get_mixnet_service().await;
    let pgp_keys = state.get_pgp_keys().await;
    let mls_client = state.get_mls_client().await;

    // Create welcome flow handler with shared MLS client
    // The MLS client is obtained from AppState to ensure state persists across messages
    let mut handler = WelcomeFlowHandler::new(
        state.db.clone(),
        mixnet_service.unwrap_or_else(|| panic!("Mixnet service not available")),
        current_user.as_ref().map(|u| u.username.clone()),
        pgp_keys.as_ref().map(|(sk, _, _)| sk.clone()),
        pgp_keys.as_ref().map(|(_, pk, _)| pk.clone()),
        pgp_keys.as_ref().map(|(_, _, pp)| pp.clone()),
        mls_client, // Shared MLS client maintains conversation state
    );

    // Process the message
    let result = handler.handle_welcome_flow_message(&incoming.envelope).await?;

    // Emit events for any notifications
    for (sender, notification) in result.notifications {
        if sender == "SYSTEM" {
            emitter.emit(AppEvent::SystemNotification {
                message: notification,
            });
        }
    }

    // If a Welcome was successfully processed, emit the GroupJoined event
    if let Some(welcome_result) = result.welcome_processed {
        emitter.group_joined(
            welcome_result.group_id,
            welcome_result.mls_group_id,
            welcome_result.sender,
        );
        tracing::info!("Emitted GroupJoined event for automatic Welcome processing");
    }

    Ok(())
}

/// Handle pending message delivery (offline queue)
///
/// Drain pending messages for a peer after a handshake has been completed.
///
/// Queries all own pending messages for the conversation and sends them
/// through the now-established MLS channel. Updates status to 'sent' on success.
async fn drain_pending_messages(
    handler: &crate::core::message_handler::DirectMessageHandler,
    db: &sqlx::SqlitePool,
    peer: &str,
) {
    let conversation_id = handler.get_conversation_id(peer);
    let pending: Vec<(String, String)> = match sqlx::query_as(
        "SELECT id, content FROM messages WHERE conversation_id = ? AND status = 'pending' AND is_own = 1 ORDER BY timestamp ASC"
    )
    .bind(&conversation_id)
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("Failed to query pending messages for {}: {}", peer, e);
            return;
        }
    };

    if pending.is_empty() {
        return;
    }

    tracing::info!("Draining {} pending messages for {}", pending.len(), peer);

    for (msg_id, content) in &pending {
        match handler.send_message(peer, content).await {
            Ok(_) => {
                let _ = sqlx::query("UPDATE messages SET status = 'sent' WHERE id = ?")
                    .bind(msg_id)
                    .execute(db)
                    .await;
                tracing::debug!("Drained pending message {} to {}", msg_id, peer);
            }
            Err(e) => {
                tracing::error!("Failed to drain pending message {} to {}: {}", msg_id, peer, e);
                break; // Stop draining on first failure to preserve ordering
            }
        }
    }
}
