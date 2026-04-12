//! Invite management commands (DM contact requests + group invite denial)

use tauri::State;

use crate::core::message_handler::DirectMessageHandlerBuilder;
use crate::state::AppState;
use crate::types::ApiError;

/// Get all pending contact requests (DM invites)
#[tauri::command]
pub async fn get_contact_requests(
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let requests: Vec<(i64, String, String)> = sqlx::query_as(
        r#"
        SELECT id, from_username, received_at
        FROM contact_requests
        WHERE status = 'pending'
        ORDER BY received_at ASC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let result: Vec<serde_json::Value> = requests
        .into_iter()
        .map(|(id, from_username, received_at)| {
            serde_json::json!({
                "id": id,
                "fromUsername": from_username,
                "receivedAt": received_at,
            })
        })
        .collect();

    Ok(result)
}

/// Accept a contact request: join the MLS group from the stored Welcome and send p2pWelcomeAck.
/// Returns `{ conversationId, fromUsername }` so the frontend can create the conversation.
#[tauri::command]
pub async fn accept_contact_request(
    from_username: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, ApiError> {
    use crate::crypto::mls::MlsMessageType;

    // Fetch the stored welcome payload
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT welcome_payload FROM contact_requests WHERE from_username = ? AND status = 'pending'",
    )
    .bind(&from_username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let welcome_payload_json = match row {
        Some((payload,)) => payload,
        None => return Err(ApiError::not_found("Contact request not found or already handled")),
    };

    let welcome_payload: serde_json::Value = serde_json::from_str(&welcome_payload_json)
        .map_err(|e| ApiError::internal(format!("Invalid stored welcome payload: {}", e)))?;

    let welcome_message = welcome_payload
        .get("welcomeMessage")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("Missing welcomeMessage in stored payload"))?;

    let group_id = welcome_payload
        .get("groupId")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    tracing::info!("Accepting contact request from {}", from_username);

    // Get required state for building the handler
    let current_user = state
        .get_current_user()
        .await
        .ok_or_else(|| ApiError::unauthorized("Not logged in"))?;
    let mls_client = state
        .get_mls_client()
        .await
        .ok_or_else(|| ApiError::internal("MLS client not initialized"))?;
    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Not connected to mixnet"))?;
    let (pgp_secret_key, pgp_passphrase) = state
        .get_pgp_signing_keys()
        .await
        .ok_or_else(|| ApiError::internal("PGP keys not available"))?;

    // Fetch the sender's public key from the server (authoritative source).
    // Check query_cache first to avoid a round-trip if we already have it.
    let cached_pk: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM query_cache WHERE username = ?"
    )
    .bind(&from_username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let sender_public_key = if let Some(pk) = cached_pk.filter(|pk| !pk.is_empty()) {
        pk
    } else {
        // Query the server for the sender's public key
        let rx = state.register_pending_query(&from_username).await;
        mixnet_service
            .send_query_request(&from_username)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to query sender: {}", e)))?;

        let result = tokio::time::timeout(std::time::Duration::from_secs(15), rx).await;
        match result {
            Ok(Ok(Some(query_result))) => {
                // Cache for future use
                let _ = sqlx::query(
                    "INSERT OR REPLACE INTO query_cache (username, public_key) VALUES (?, ?)"
                )
                .bind(&from_username)
                .bind(&query_result.public_key)
                .execute(&state.db)
                .await;
                query_result.public_key
            }
            Ok(Ok(None)) => {
                return Err(ApiError::not_found("Sender not found on server"));
            }
            _ => {
                state.cancel_pending_query(&from_username).await;
                return Err(ApiError::timeout("Timed out fetching sender's public key"));
            }
        }
    };

    let handler = DirectMessageHandlerBuilder::new()
        .mls_client(mls_client)
        .mixnet_service(mixnet_service)
        .pgp_keys(pgp_secret_key, pgp_passphrase)
        .current_user(current_user.username.clone())
        .db(state.db.clone())
        .build()
        .map_err(|e| ApiError::internal(format!("Failed to build handler: {}", e)))?;

    // Join the MLS group from the stored Welcome message
    handler
        .process_incoming_message(&from_username, welcome_message, MlsMessageType::Welcome)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to join MLS group: {}", e)))?;

    // Add the user as a contact with their server-verified public key BEFORE
    // sending the ack — the sealed ack needs to look up their public key from
    // the contacts table to encrypt the envelope.
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO contacts (owner_username, username, display_name, public_key, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        "#,
    )
    .bind(&current_user.username)
    .bind(&from_username)
    .bind(&from_username)
    .bind(&sender_public_key)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Send p2pWelcomeAck so the initiator can apply the deferred commit
    handler
        .send_welcome_ack(&from_username, group_id, true)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send welcome ack: {}", e)))?;

    // Use peer username as the conversation ID (matches frontend convention)
    let conversation_id = from_username.clone();

    // Mark the request as accepted
    sqlx::query("UPDATE contact_requests SET status = 'accepted' WHERE from_username = ?")
        .bind(&from_username)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tracing::info!("Contact request from {} accepted, conversation: {}", from_username, conversation_id);

    Ok(serde_json::json!({
        "conversationId": conversation_id,
        "fromUsername": from_username,
    }))
}

/// Deny a contact request (silently ignore it)
#[tauri::command]
pub async fn deny_contact_request(
    from_username: String,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    let rows_affected = sqlx::query(
        "UPDATE contact_requests SET status = 'denied' WHERE from_username = ? AND status = 'pending'",
    )
    .bind(&from_username)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .rows_affected();

    if rows_affected == 0 {
        return Err(ApiError::not_found(
            "Contact request not found or already handled",
        ));
    }

    tracing::info!("Contact request from {} denied", from_username);

    Ok(())
}

/// Deny a group welcome/invite (mark as processed with denial)
#[tauri::command]
pub async fn deny_welcome(
    welcome_id: i64,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    crate::core::db::MlsDb::mark_welcome_failed(&state.db, welcome_id, "denied_by_user")
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    tracing::info!("Welcome {} denied by user", welcome_id);

    Ok(())
}
