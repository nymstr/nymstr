//! Authentication commands
//!
//! This module handles user registration and login flows with the Nymstr
//! discovery server, including PGP key generation and nonce-challenge authentication.

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, State};

use crate::core::message_handler::AuthenticationHandler;
use crate::core::mixnet_client::MixnetService;
use crate::crypto::mls::MlsClient;
use crate::crypto::pgp::{PgpKeyManager, PgpSigner, SecurePassphrase};
use crate::state::AppState;
use crate::types::{ApiError, InitializeResponse, UserDTO};

/// Timeout for authentication flows (30 seconds)
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// Validate username format.
///
/// Rules:
/// - 1-64 characters
/// - Alphanumeric, underscore, or hyphen only
fn validate_username(username: &str) -> Result<(), ApiError> {
    if username.is_empty() || username.len() > 64 {
        return Err(ApiError::validation("Username must be 1-64 characters"));
    }

    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::validation(
            "Username can only contain letters, numbers, underscores, and hyphens",
        ));
    }

    Ok(())
}

/// Initialize the application and check for existing users
#[tauri::command]
pub async fn initialize(state: State<'_, AppState>) -> Result<InitializeResponse, ApiError> {
    tracing::info!("Initializing application");

    // Check if we have a local user
    let username = state
        .has_local_user()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(InitializeResponse {
        has_user: username.is_some(),
        username,
    })
}

/// Register a new user
///
/// This performs the full registration flow:
/// 1. Validate username
/// 2. Generate PGP keypair
/// 3. Store encrypted keys locally
/// 4. Connect to mixnet if not connected
/// 5. Send registration request
/// 6. Handle challenge-response authentication
/// 7. Store user in database on success
#[tauri::command]
pub async fn register_user(
    app_handle: AppHandle,
    username: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<UserDTO, ApiError> {
    tracing::info!("Registering user: {}", username);

    // 1. Validate username
    validate_username(&username)?;

    // 2. Generate PGP keypair
    let secure_passphrase = SecurePassphrase::new(passphrase);

    let (secret_key, public_key) =
        PgpKeyManager::generate_keypair_secure(&username, &secure_passphrase)
            .map_err(|e| ApiError::internal(format!("Failed to generate PGP keypair: {}", e)))?;

    // Get armored public key for registration
    let public_key_armored = PgpKeyManager::public_key_armored(&public_key)
        .map_err(|e| ApiError::internal(format!("Failed to armor public key: {}", e)))?;

    // 3. Store encrypted keys locally
    let key_dir = state.get_pgp_key_dir(&username);
    std::fs::create_dir_all(&key_dir)
        .map_err(|e| ApiError::internal(format!("Failed to create key directory: {}", e)))?;

    // Save keys using PgpKeyManager (saves to storage/{username}/pgp_keys/)
    // We need to temporarily change directory or modify the save path
    // For now, we'll save directly to the app directory
    save_keys_to_app_dir(
        &key_dir,
        &username,
        &secret_key,
        &public_key,
        &secure_passphrase,
    )?;

    // Wrap keys in Arc for state storage
    let arc_secret_key = Arc::new(secret_key);
    let arc_public_key = Arc::new(public_key);
    let arc_passphrase = Arc::new(secure_passphrase);

    // 4. Check if mixnet is connected
    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Mixnet not connected. Please connect first."))?;

    // 5. Check server address
    let server_address = state
        .get_server_address()
        .await
        .ok_or_else(|| ApiError::validation("Server address not configured"))?;

    // Ensure mixnet service has server address
    mixnet_service
        .set_server_address(Some(server_address.clone()))
        .await;

    // 6. Send registration request
    mixnet_service
        .send_registration_request(&username, &public_key_armored)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send registration request: {}", e)))?;

    tracing::info!("Registration request sent for user: {}", username);

    // 7. Wait for challenge and handle response
    // Take the incoming receiver to process messages
    let mut incoming_rx = state
        .take_incoming_rx()
        .await
        .ok_or_else(|| ApiError::internal("Message receiver not available"))?;

    // Create auth handler for processing challenge
    let auth_handler = AuthenticationHandler::new(
        mixnet_service.clone(),
        arc_secret_key.clone(),
        arc_public_key.clone(),
        arc_passphrase.clone(),
    );

    // Wait for server response with timeout
    let result = tokio::time::timeout(AUTH_TIMEOUT, async {
        loop {
            match incoming_rx.recv().await {
                Some(incoming) => {
                    let env = &incoming.envelope;
                    let action = env.action.as_str();

                    match action {
                        "challenge" => {
                            // Check if this is a registration challenge
                            if let Some(context) =
                                env.payload.get("context").and_then(|v| v.as_str())
                            {
                                if context == "registration" {
                                    if let Some(nonce) =
                                        env.payload.get("nonce").and_then(|v| v.as_str())
                                    {
                                        tracing::info!("Received registration challenge");

                                        if let Err(e) = auth_handler
                                            .process_register_challenge(&username, nonce)
                                            .await
                                        {
                                            return Err(format!(
                                                "Failed to process challenge: {}",
                                                e
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        "challengeResponse" => {
                            // Check if this is a registration response
                            if let Some(context) =
                                env.payload.get("context").and_then(|v| v.as_str())
                            {
                                if context == "registration" {
                                    if let Some(result) =
                                        env.payload.get("result").and_then(|v| v.as_str())
                                    {
                                        match auth_handler
                                            .process_register_response(&username, result)
                                        {
                                            Ok(true) => {
                                                // Extract server public key from response (TOFU)
                                                let server_pk = env
                                                    .payload
                                                    .get("serverPublicKey")
                                                    .and_then(|v| v.as_str())
                                                    .map(String::from)
                                                    .or_else(|| {
                                                        // Legacy format: content may be JSON with serverPublicKey
                                                        env.payload
                                                            .get("content")
                                                            .and_then(|v| v.as_str())
                                                            .and_then(|c| {
                                                                serde_json::from_str::<
                                                                    serde_json::Value,
                                                                >(
                                                                    c
                                                                )
                                                                .ok()
                                                            })
                                                            .and_then(|p| {
                                                                p.get("serverPublicKey")?
                                                                    .as_str()
                                                                    .map(String::from)
                                                            })
                                                    });
                                                return Ok(server_pk);
                                            }
                                            Ok(false) => {
                                                return Err(format!(
                                                    "Registration failed: {}",
                                                    result
                                                ))
                                            }
                                            Err(e) => {
                                                return Err(format!(
                                                    "Error processing response: {}",
                                                    e
                                                ))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            tracing::debug!("Ignoring message with action: {}", action);
                        }
                    }
                }
                None => {
                    return Err("Message channel closed".to_string());
                }
            }
        }
    })
    .await;

    // Handle result
    let server_pk = match result {
        Ok(Ok(server_pk)) => {
            tracing::info!("Registration successful for user: {}", username);
            server_pk
        }
        Ok(Err(e)) => {
            // Put the receiver back on failure
            *state.incoming_rx.write().await = Some(incoming_rx);
            return Err(ApiError::authentication(format!(
                "Registration failed: {}",
                e
            )));
        }
        Err(_) => {
            // Put the receiver back on timeout
            *state.incoming_rx.write().await = Some(incoming_rx);
            return Err(ApiError::timeout(
                "Registration timed out waiting for server response",
            ));
        }
    };

    // Store server public key if provided (TOFU)
    if let Some(ref pk) = server_pk {
        state.store_server_public_key(pk).await;
    }

    // 8. Store user in database
    sqlx::query("INSERT INTO users (username, display_name, public_key) VALUES (?, ?, ?)")
        .bind(&username)
        .bind(&username)
        .bind(&public_key_armored)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to store user: {}", e)))?;

    // 9. Set current user and keys in state
    let user = UserDTO {
        username: username.clone(),
        display_name: username.clone(),
        public_key: public_key_armored.clone(),
        online: true,
    };

    state.set_current_user(Some(user.clone())).await;
    state
        .set_pgp_keys(arc_secret_key, arc_public_key, arc_passphrase)
        .await;

    // 10. Initialize MLS client for encrypted messaging
    if let Err(e) = state.initialize_mls_client(&user.username).await {
        tracing::warn!("Failed to initialize MLS client: {}", e);
        // Continue - MLS can be initialized later if needed
    }

    // 11. Publish initial MLS key packages (fire-and-forget)
    if let (Some(mls_client), Some((sk, _pk, pp))) =
        (state.get_mls_client().await, state.get_pgp_keys().await)
    {
        spawn_publish_key_packages(username.clone(), mls_client, sk, pp, mixnet_service);
    } else {
        tracing::warn!("Skipping key package publishing: MLS client or PGP keys not available");
    }

    // 12. Start background tasks with the message loop
    state.start_background_tasks(app_handle, incoming_rx).await;

    tracing::info!("User registered successfully: {}", username);
    Ok(user)
}

/// Ping the server to update sender_tag and provide fresh SURBs
///
/// This replaces login — single round-trip, no challenge-response:
/// 1. Load user from database
/// 2. Load PGP keys from disk
/// 3. Sign timestamp and send ping with 200 SURBs
/// 4. Wait for pong response
/// 5. Set current user and start background tasks
#[tauri::command]
pub async fn ping_server(
    app_handle: AppHandle,
    username: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<UserDTO, ApiError> {
    tracing::info!("Pinging server for user: {}", username);

    // 1. Check if user exists in database
    let result: Option<(String, String, String)> =
        sqlx::query_as("SELECT username, display_name, public_key FROM users WHERE username = ?")
            .bind(&username)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;

    let (db_username, display_name, public_key_armored) =
        result.ok_or_else(|| ApiError::not_found("User not found"))?;

    // 2. Load PGP keys from disk
    let secure_passphrase = SecurePassphrase::new(passphrase);
    let key_dir = state.get_pgp_key_dir(&username);

    let (secret_key, public_key) = load_keys_from_app_dir(&key_dir, &secure_passphrase)?;

    // Wrap keys in Arc
    let arc_secret_key = Arc::new(secret_key);
    let arc_public_key = Arc::new(public_key);
    let arc_passphrase = Arc::new(secure_passphrase);

    // Store keys in state
    state
        .set_pgp_keys(
            arc_secret_key.clone(),
            arc_public_key.clone(),
            arc_passphrase.clone(),
        )
        .await;

    // 3. Check if mixnet is connected
    let mixnet_service = state
        .get_mixnet_service()
        .await
        .ok_or_else(|| ApiError::not_connected("Mixnet not connected. Please connect first."))?;

    // 4. Check server address
    let server_address = state
        .get_server_address()
        .await
        .ok_or_else(|| ApiError::validation("Server address not configured"))?;

    mixnet_service
        .set_server_address(Some(server_address.clone()))
        .await;

    // 5. Sign timestamp and send ping
    let timestamp = chrono::Utc::now().timestamp();
    let sign_content = format!("ping:{}:{}", username, timestamp);
    let signature =
        PgpSigner::sign_detached_secure(&arc_secret_key, sign_content.as_bytes(), &arc_passphrase)
            .map_err(|e| ApiError::internal(format!("Failed to sign ping: {}", e)))?;

    mixnet_service
        .send_ping(&username, timestamp, &signature)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to send ping: {}", e)))?;

    tracing::info!("Ping sent for user: {}", username);

    // 6. Wait for pong response
    let mut incoming_rx = state
        .take_incoming_rx()
        .await
        .ok_or_else(|| ApiError::internal("Message receiver not available"))?;

    let result = tokio::time::timeout(AUTH_TIMEOUT, async {
        loop {
            match incoming_rx.recv().await {
                Some(incoming) => {
                    let env = &incoming.envelope;
                    if env.action == "pong" {
                        if let Some(status) = env.payload.get("status").and_then(|v| v.as_str()) {
                            if status == "success" {
                                // Extract server time for clock sync
                                if let Some(server_time) =
                                    env.payload.get("serverTime").and_then(|v| v.as_i64())
                                {
                                    tracing::debug!("Server time from pong: {}", server_time);
                                }
                                return Ok(());
                            } else {
                                let error = env
                                    .payload
                                    .get("error")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown error");
                                return Err(format!("Ping failed: {}", error));
                            }
                        }
                    } else {
                        tracing::debug!(
                            "Ignoring message with action: {} while waiting for pong",
                            env.action
                        );
                    }
                }
                None => {
                    return Err("Message channel closed".to_string());
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(())) => {
            tracing::info!("Pong received for user: {}", username);
        }
        Ok(Err(e)) => {
            *state.incoming_rx.write().await = Some(incoming_rx);
            state.clear_pgp_keys().await;
            return Err(ApiError::authentication(format!("Ping failed: {}", e)));
        }
        Err(_) => {
            *state.incoming_rx.write().await = Some(incoming_rx);
            state.clear_pgp_keys().await;
            return Err(ApiError::timeout("Ping timed out waiting for pong"));
        }
    };

    // Load server public key from DB (set during registration)
    state.load_server_public_key().await;

    // 7. Set current user
    let user = UserDTO {
        username: db_username.clone(),
        display_name,
        public_key: public_key_armored,
        online: true,
    };

    state.set_current_user(Some(user.clone())).await;

    // 8. Initialize MLS client for encrypted messaging
    if let Err(e) = state.initialize_mls_client(&user.username).await {
        tracing::warn!("Failed to initialize MLS client: {}", e);
    }

    // 9. Publish initial MLS key packages (fire-and-forget)
    if let (Some(mls_client), Some((sk, _pk, pp))) =
        (state.get_mls_client().await, state.get_pgp_keys().await)
    {
        spawn_publish_key_packages(user.username.clone(), mls_client, sk, pp, mixnet_service);
    } else {
        tracing::warn!("Skipping key package publishing: MLS client or PGP keys not available");
    }

    // 10. Start background tasks with the message loop
    state.start_background_tasks(app_handle, incoming_rx).await;

    tracing::info!("User session active: {}", user.username);
    Ok(user)
}

/// Logout the current user
#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), ApiError> {
    tracing::info!("Logging out user");

    // Stop background tasks first (they depend on mixnet)
    state.stop_background_tasks().await;

    // Disconnect from mixnet (this drops the channel which is now broken)
    // User will need to reconnect before logging in again
    state.clear_mixnet_service().await;
    state.set_connection_status(false, None).await;

    // Clear MLS client
    state.clear_mls_client().await;

    // Clear current user
    state.set_current_user(None).await;

    // Clear PGP keys from memory
    state.clear_pgp_keys().await;

    tracing::info!("User logged out, mixnet disconnected");
    Ok(())
}

/// Get the current logged in user
#[tauri::command]
pub async fn get_current_user(state: State<'_, AppState>) -> Result<Option<UserDTO>, ApiError> {
    Ok(state.get_current_user().await)
}

// ========== Helper Functions ==========

/// Number of MLS key packages to pre-publish after registration/login
const KEY_PACKAGE_COUNT: usize = 5;

/// Generate and publish signed MLS key packages to the server.
///
/// This is fire-and-forget: failures are logged but do not block the caller.
/// The client will replenish key packages later if some fail to publish.
fn spawn_publish_key_packages(
    username: String,
    mls_client: Arc<MlsClient>,
    secret_key: Arc<pgp::composed::SignedSecretKey>,
    passphrase: Arc<SecurePassphrase>,
    mixnet_service: Arc<MixnetService>,
) {
    tokio::spawn(async move {
        use base64::Engine;

        let mut published = 0usize;
        for i in 0..KEY_PACKAGE_COUNT {
            // Generate key package bytes from the app's MLS client
            let raw_bytes = match mls_client.generate_key_package() {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Failed to generate key package {}: {}", i, e);
                    continue;
                }
            };

            let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);

            // PGP-sign the raw key package bytes
            let pgp_signature =
                match PgpSigner::sign_detached_secure(&secret_key, &raw_bytes, &passphrase) {
                    Ok(sig) => sig,
                    Err(e) => {
                        tracing::warn!("Failed to PGP-sign key package {}: {}", i, e);
                        continue;
                    }
                };

            use pgp::types::KeyDetails;
            let pgp_fingerprint = hex::encode(secret_key.fingerprint().as_bytes());

            // Compute the envelope-level signature over the publish action content
            let sign_content = format!("publishKeyPackage:{}:{}", username, key_package_b64);
            let signature = match PgpSigner::sign_detached_secure(
                &secret_key,
                sign_content.as_bytes(),
                &passphrase,
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    tracing::warn!("Failed to sign publish action {}: {}", i, e);
                    continue;
                }
            };

            if let Err(e) = mixnet_service
                .send_publish_key_package(
                    &username,
                    &key_package_b64,
                    &pgp_signature,
                    &pgp_fingerprint,
                    &signature,
                )
                .await
            {
                tracing::warn!("Failed to publish key package {}: {}", i, e);
                continue;
            }

            published += 1;
        }

        tracing::info!(
            "Published {}/{} MLS key packages for user {}",
            published,
            KEY_PACKAGE_COUNT,
            username
        );
    });
}

/// Save PGP keys to the app data directory
fn save_keys_to_app_dir(
    key_dir: &std::path::Path,
    _username: &str,
    secret_key: &pgp::composed::SignedSecretKey,
    public_key: &pgp::composed::SignedPublicKey,
    passphrase: &SecurePassphrase,
) -> Result<(), ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    type HmacSha256 = Hmac<Sha256>;

    // Ensure directory exists with secure permissions
    fs::create_dir_all(key_dir)
        .map_err(|e| ApiError::internal(format!("Failed to create key directory: {}", e)))?;

    #[cfg(unix)]
    {
        let mut dir_perms = fs::metadata(key_dir)
            .map_err(|e| ApiError::internal(format!("Failed to read directory metadata: {}", e)))?
            .permissions();
        dir_perms.set_mode(0o700);
        fs::set_permissions(key_dir, dir_perms).map_err(|e| {
            ApiError::internal(format!("Failed to set directory permissions: {}", e))
        })?;
    }

    // Armor and save secret key
    let secret_armored = secret_key
        .to_armored_string(Default::default())
        .map_err(|e| ApiError::internal(format!("Failed to armor secret key: {}", e)))?;

    let secret_path = key_dir.join("secret.asc");

    // Compute HMAC for integrity
    let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
        .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
    mac.update(secret_armored.as_bytes());
    let secret_hmac = hex::encode(mac.finalize().into_bytes());

    fs::write(&secret_path, &secret_armored)
        .map_err(|e| ApiError::internal(format!("Failed to write secret key: {}", e)))?;
    fs::write(secret_path.with_extension("hmac"), &secret_hmac)
        .map_err(|e| ApiError::internal(format!("Failed to write secret key HMAC: {}", e)))?;

    #[cfg(unix)]
    {
        let mut secret_perms = fs::metadata(&secret_path)
            .map_err(|e| ApiError::internal(format!("Failed to read secret key metadata: {}", e)))?
            .permissions();
        secret_perms.set_mode(0o600);
        fs::set_permissions(&secret_path, secret_perms).map_err(|e| {
            ApiError::internal(format!("Failed to set secret key permissions: {}", e))
        })?;
    }

    // Armor and save public key
    let public_armored = public_key
        .to_armored_string(Default::default())
        .map_err(|e| ApiError::internal(format!("Failed to armor public key: {}", e)))?;

    let public_path = key_dir.join("public.asc");

    let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
        .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
    mac.update(public_armored.as_bytes());
    let public_hmac = hex::encode(mac.finalize().into_bytes());

    fs::write(&public_path, &public_armored)
        .map_err(|e| ApiError::internal(format!("Failed to write public key: {}", e)))?;
    fs::write(public_path.with_extension("hmac"), &public_hmac)
        .map_err(|e| ApiError::internal(format!("Failed to write public key HMAC: {}", e)))?;

    tracing::info!("Saved PGP keys to {:?}", key_dir);
    Ok(())
}

/// Load PGP keys from the app data directory
fn load_keys_from_app_dir(
    key_dir: &std::path::Path,
    passphrase: &SecurePassphrase,
) -> Result<
    (
        pgp::composed::SignedSecretKey,
        pgp::composed::SignedPublicKey,
    ),
    ApiError,
> {
    use hmac::{Hmac, Mac};
    use pgp::composed::Deserializable;
    use sha2::Sha256;
    use std::fs;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;

    let secret_path = key_dir.join("secret.asc");
    let public_path = key_dir.join("public.asc");
    let secret_hmac_path = secret_path.with_extension("hmac");
    let public_hmac_path = public_path.with_extension("hmac");

    if !secret_path.exists() || !public_path.exists() {
        return Err(ApiError::not_found("PGP keys not found"));
    }

    // Load and verify secret key
    let secret_armored = fs::read_to_string(&secret_path)
        .map_err(|e| ApiError::internal(format!("Failed to read secret key: {}", e)))?;

    if secret_hmac_path.exists() {
        let stored_hmac = fs::read_to_string(&secret_hmac_path)
            .map_err(|e| ApiError::internal(format!("Failed to read secret key HMAC: {}", e)))?;

        let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
        mac.update(secret_armored.as_bytes());
        let computed_hmac = hex::encode(mac.finalize().into_bytes());

        if !bool::from(
            stored_hmac
                .trim()
                .as_bytes()
                .ct_eq(computed_hmac.as_bytes()),
        ) {
            return Err(ApiError::authentication(
                "Secret key integrity verification failed (incorrect passphrase?)",
            ));
        }
    } else {
        tracing::warn!("No HMAC file found for secret key - skipping integrity verification");
    }

    let (secret_key, _) = pgp::composed::SignedSecretKey::from_string(&secret_armored)
        .map_err(|e| ApiError::internal(format!("Failed to parse secret key: {}", e)))?;

    // Load and verify public key
    let public_armored = fs::read_to_string(&public_path)
        .map_err(|e| ApiError::internal(format!("Failed to read public key: {}", e)))?;

    if public_hmac_path.exists() {
        let stored_hmac = fs::read_to_string(&public_hmac_path)
            .map_err(|e| ApiError::internal(format!("Failed to read public key HMAC: {}", e)))?;

        let mut mac = HmacSha256::new_from_slice(passphrase.as_str().as_bytes())
            .map_err(|e| ApiError::internal(format!("Failed to create HMAC: {}", e)))?;
        mac.update(public_armored.as_bytes());
        let computed_hmac = hex::encode(mac.finalize().into_bytes());

        if !bool::from(
            stored_hmac
                .trim()
                .as_bytes()
                .ct_eq(computed_hmac.as_bytes()),
        ) {
            return Err(ApiError::authentication(
                "Public key integrity verification failed",
            ));
        }
    }

    let (public_key, _) = pgp::composed::SignedPublicKey::from_string(&public_armored)
        .map_err(|e| ApiError::internal(format!("Failed to parse public key: {}", e)))?;

    tracing::info!("Loaded PGP keys from {:?}", key_dir);
    Ok((secret_key, public_key))
}
