use crate::db_utils::{DbUtils, QueryResult};
use nymstr_crypto::ServerKeyManager;
use crate::pending::{PendingEntry, PendingGroupData, PendingLoginData, PendingUserData};
use crate::transport::{ReplyTag, ReplySender};
use nymstr_common::rate_limiter::RateLimiter;
use nymstr_common::validation;
use nym_sdk::mixnet::{ReconstructedMessage, ReceivedReplySurbsMap};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

/// Handler for incoming mixnet messages and command processing.
pub struct MessageUtils {
    db: DbUtils,
    crypto: ServerKeyManager,
    sender: Box<dyn ReplySender>,
    client_id: String,
    pending_users: HashMap<ReplyTag, PendingEntry<PendingUserData>>,
    nonces: HashMap<ReplyTag, PendingEntry<PendingLoginData>>,
    pending_groups: HashMap<ReplyTag, PendingEntry<PendingGroupData>>,
    /// Rate limiter for authentication endpoints (registration/login)
    rate_limiter: RateLimiter,
    /// Rate limiter for send operations (message relay)
    send_rate_limiter: RateLimiter,
    /// SURB pool storage for checking recipient SURB availability before relay
    surb_storage: Option<ReceivedReplySurbsMap>,
}

impl MessageUtils {
    /// Time-to-live for pending entries in seconds (5 minutes)
    const PENDING_TTL_SECS: u64 = 300;

    /// Maximum authentication attempts per sender within the rate limit window
    const RATE_LIMIT_MAX_ATTEMPTS: usize = 10;

    /// Rate limit window in seconds (1 minute)
    const RATE_LIMIT_WINDOW_SECS: u64 = 60;

    /// Maximum send operations per sender within the rate limit window
    const SEND_RATE_LIMIT_MAX: usize = 60;

    /// Send rate limit window in seconds (1 minute)
    const SEND_RATE_LIMIT_WINDOW_SECS: u64 = 60;

    /// Create a new MessageUtils instance.
    pub fn new(
        client_id: String,
        sender: Box<dyn ReplySender>,
        db: DbUtils,
        crypto: ServerKeyManager,
        surb_storage: Option<ReceivedReplySurbsMap>,
    ) -> Self {
        MessageUtils {
            sender,
            db,
            crypto,
            client_id,
            pending_users: HashMap::new(),
            nonces: HashMap::new(),
            pending_groups: HashMap::new(),
            rate_limiter: RateLimiter::new(
                Self::RATE_LIMIT_MAX_ATTEMPTS,
                Self::RATE_LIMIT_WINDOW_SECS,
            ),
            send_rate_limiter: RateLimiter::new(
                Self::SEND_RATE_LIMIT_MAX,
                Self::SEND_RATE_LIMIT_WINDOW_SECS,
            ),
            surb_storage,
        }
    }

    /// Remove stale entries from all pending HashMaps that exceed the TTL.
    /// This prevents memory leaks from incomplete registration/login flows.
    fn cleanup_stale_entries(&mut self) {
        let now = Instant::now();
        let ttl_secs = Self::PENDING_TTL_SECS;

        let pending_users_before = self.pending_users.len();
        self.pending_users
            .retain(|_, entry| now.duration_since(entry.created_at).as_secs() < ttl_secs);
        let pending_users_removed = pending_users_before - self.pending_users.len();

        let nonces_before = self.nonces.len();
        self.nonces
            .retain(|_, entry| now.duration_since(entry.created_at).as_secs() < ttl_secs);
        let nonces_removed = nonces_before - self.nonces.len();

        let pending_groups_before = self.pending_groups.len();
        self.pending_groups
            .retain(|_, entry| now.duration_since(entry.created_at).as_secs() < ttl_secs);
        let pending_groups_removed = pending_groups_before - self.pending_groups.len();

        let total_removed = pending_users_removed + nonces_removed + pending_groups_removed;
        if total_removed > 0 {
            log::info!(
                "Cleaned up {} stale entries (pending_users: {}, nonces: {}, pending_groups: {})",
                total_removed,
                pending_users_removed,
                nonces_removed,
                pending_groups_removed
            );
        }

        // Clean up rate limiter entries with no recent attempts
        self.rate_limiter.cleanup();
        self.send_rate_limiter.cleanup();
    }

    /// Process an incoming Nym mixnet message (convenience wrapper).
    pub async fn process_received_message(&mut self, msg: ReconstructedMessage) {
        let tag = msg.sender_tag.map(ReplyTag::from);
        self.process_message(tag, msg.message).await;
    }

    /// Process an incoming message from any transport.
    pub async fn process_message(&mut self, sender_tag: Option<ReplyTag>, raw_bytes: Vec<u8>) {
        // Clean up stale pending entries on each message to prevent memory leaks
        self.cleanup_stale_entries();

        let sender_tag = if let Some(tag) = sender_tag {
            tag
        } else {
            log::warn!("Received message without sender tag, ignoring");
            return;
        };
        let raw = match String::from_utf8(raw_bytes) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Invalid UTF-8 in message: {}", e);
                return;
            }
        };
        let data: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                log::error!("processReceivedMessage - JSON decode error: {}", e);
                return;
            }
        };
        // Check if this is the new unified format (has "type" field) or old format
        if let Some(message_type) = data.get("type").and_then(Value::as_str) {
            // New unified format
            if let Some(action) = data.get("action").and_then(Value::as_str) {
                log::info!(
                    "Processing unified format - type: '{}', action: '{}' from sender_tag={:?}",
                    message_type,
                    action,
                    sender_tag
                );

                // Extract payload, sender, recipient, and signature for handlers
                let payload = data.get("payload").unwrap_or(&Value::Null);
                let sender_username = data
                    .get("sender")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let recipient_username = data.get("recipient").and_then(Value::as_str);
                let signature = data.get("signature").and_then(Value::as_str);

                match action {
                    "query" => {
                        self.handle_query_unified(payload, sender_tag, sender_username)
                            .await
                    }
                    "register" => {
                        self.handle_register_unified(payload, sender_tag, sender_username)
                            .await
                    }
                    "registrationResponse" => {
                        self.handle_registration_response_unified(payload, sender_tag, signature)
                            .await
                    }
                    "login" => {
                        self.handle_login_unified(payload, sender_tag, sender_username)
                            .await
                    }
                    "loginResponse" => {
                        self.handle_login_response_unified(payload, sender_tag, signature)
                            .await
                    }
                    "send" if message_type == "sealed" => {
                        self.handle_sealed_send(payload, sender_tag, recipient_username)
                            .await
                    }
                    "send" => {
                        self.handle_send_unified(payload, sender_tag, sender_username, recipient_username, signature)
                            .await
                    }
                    "fetchPending" => {
                        self.handle_fetch_pending_unified(payload, sender_tag, sender_username, signature)
                            .await
                    }
                    "keyPackageRequest" => {
                        self.handle_key_package_request_unified(
                            payload,
                            sender_tag,
                            sender_username,
                            recipient_username,
                        )
                        .await
                    }
                    "keyPackageResponse" => {
                        self.handle_key_package_response_unified(
                            payload,
                            sender_tag,
                            sender_username,
                            recipient_username,
                        )
                        .await
                    }
                    "groupJoinResponse" => {
                        self.handle_group_join_response_unified(
                            payload,
                            sender_tag,
                            sender_username,
                            recipient_username,
                        )
                        .await
                    }
                    "ping" => {
                        self.handle_ping_unified(payload, sender_tag, sender_username, signature)
                            .await
                    }
                    "ack" => {
                        self.handle_ack_unified(payload, sender_tag, sender_username, signature)
                            .await
                    }
                    "publishKeyPackage" => {
                        self.handle_publish_key_package(payload, sender_tag, sender_username, signature)
                            .await
                    }
                    "fetchKeyPackageChallenge" => {
                        self.handle_fetch_kp_challenge(payload, sender_tag).await
                    }
                    "fetchKeyPackage" => {
                        self.handle_fetch_key_package(payload, sender_tag).await
                    }
                    _ => log::error!("Unknown unified action: {}", action),
                }
            } else {
                log::error!("Unified format message missing 'action' field");
            }
        } else if let Some(action) = data.get("action").and_then(Value::as_str) {
            // Legacy format (for backward compatibility during migration)
            log::info!(
                "Processing legacy format action '{}' from sender_tag={:?}",
                action,
                sender_tag
            );
            match action {
                "query" => self.handle_query(&data, sender_tag).await,
                "register" => self.handle_register(&data, sender_tag).await,
                "registrationResponse" => {
                    self.handle_registration_response(&data, sender_tag).await
                }
                "login" => self.handle_login(&data, sender_tag).await,
                "loginResponse" => self.handle_login_response(&data, sender_tag).await,
                "update" => self.handle_update(&data, sender_tag).await,
                "send" => self.handle_send(&data, sender_tag).await,
                "sendGroup" => self.handle_send_group(&data, sender_tag).await,
                "createGroup" => self.handle_create_group(&data, sender_tag).await,
                "inviteGroup" => self.handle_send_invite(&data, sender_tag).await,
                "registerGroup" => self.handle_register_group(&data, sender_tag).await,
                "registerGroupResponse" => {
                    self.handle_register_group_response(&data, sender_tag).await
                }
                "queryGroups" => self.handle_query_groups(&data, sender_tag).await,
                _ => log::error!("Unknown legacy action: {}", action),
            }
        } else {
            log::error!("processReceivedMessage - missing action field");
        }
    }

    async fn handle_query(&mut self, data: &Value, sender_tag: ReplyTag) {
        // Support both "username" (legacy) and "identifier" (unified) fields
        let identifier = data
            .get("identifier")
            .or_else(|| data.get("username"))
            .and_then(Value::as_str);

        if let Some(identifier) = identifier {
            let query_result = match self.db.query_by_identifier(identifier).await {
                Ok(result) => result,
                Err(e) => {
                    log::error!(
                        "Database query failed for identifier '{}': {}",
                        identifier,
                        e
                    );
                    None
                }
            };
            match query_result {
                Some(QueryResult::User {
                    username,
                    public_key,
                    ..
                }) => {
                    let reply = json!({
                        "type": "user",
                        "username": username,
                        "publicKey": public_key
                    })
                    .to_string();
                    self.send_encapsulated_reply(&sender_tag, reply, "queryResponse", Some("query"))
                        .await;
                }
                Some(QueryResult::Group {
                    group_id,
                    name,
                    nym_address,
                    public_key,
                    description,
                }) => {
                    let reply = json!({
                        "type": "group",
                        "groupId": group_id,
                        "name": name,
                        "nymAddress": nym_address,
                        "publicKey": public_key,
                        "description": description
                    })
                    .to_string();
                    self.send_encapsulated_reply(&sender_tag, reply, "queryResponse", Some("query"))
                        .await;
                }
                None => {
                    self.send_encapsulated_reply(
                        &sender_tag,
                        "No user or group found".into(),
                        "queryResponse",
                        Some("query"),
                    )
                    .await;
                }
            }
        } else {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: missing 'username' or 'identifier' field".into(),
                "queryResponse",
                Some("query"),
            )
            .await;
        }
    }

    async fn handle_register(&mut self, data: &Value, sender_tag: ReplyTag) {
        // Rate limit check for registration attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!(
                "Rate limit exceeded for registration from sender_tag={:?}",
                sender_tag
            );
            self.send_encapsulated_reply(
                &sender_tag,
                "error: rate limit exceeded, please try again later".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        let username = data.get("username").and_then(Value::as_str);
        let public_key = data.get("publicKey").and_then(Value::as_str);
        log::debug!(
            "Registration request - username: {:?}, has_public_key: {}",
            username,
            public_key.is_some()
        );
        if username.is_none() || public_key.is_none() {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: missing username or public key".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        let username = username.unwrap();
        let pubkey = public_key.unwrap();
        if !validation::is_valid_username(username) {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: invalid username format".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        let user_exists = match self.db.get_user_by_username(username).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                log::error!("Database error checking username '{}': {}", username, e);
                self.send_encapsulated_reply(
                    &sender_tag,
                    json!({"status": "error", "error_code": "INTERNAL_ERROR", "message": "Database error"}).to_string(),
                    "challengeResponse",
                    Some("registration"),
                ).await;
                return;
            }
        };
        if user_exists {
            self.send_encapsulated_reply(
                &sender_tag,
                json!({"status": "error", "error_code": "USER_EXISTS", "message": "Username already in use"}).to_string(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        let nonce = Uuid::new_v4().to_string();
        log::debug!("Generated nonce for user '{}': {}", username, nonce);
        self.pending_users.insert(
            sender_tag.clone(),
            PendingEntry::new((username.to_string(), pubkey.to_string(), nonce.clone())),
        );
        self.send_encapsulated_reply(
            &sender_tag,
            json!({"nonce": nonce}).to_string(),
            "challenge",
            Some("registration"),
        )
        .await;
    }

    async fn handle_registration_response(&mut self, data: &Value, sender_tag: ReplyTag) {
        let signature = data.get("signature").and_then(Value::as_str);
        log::debug!(
            "Registration response - has_signature: {}",
            signature.is_some()
        );
        if signature.is_none() {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: missing signature".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        let signature = signature.unwrap();
        if let Some(entry) = self.pending_users.remove(&sender_tag) {
            let (username, pubkey, nonce) = entry.data;
            log::debug!(
                "Verifying signature for user '{}' with nonce '{}'",
                username,
                nonce
            );
            if self.crypto.verify_signature(&pubkey, &nonce, signature) {
                log::debug!("Signature verification successful for user '{}'", username);
                if self
                    .db
                    .add_user(&username, &pubkey, &sender_tag.to_string())
                    .await
                    .unwrap_or(false)
                {
                    log::info!("Registration successful for user '{}'", username);
                    self.send_encapsulated_reply(
                        &sender_tag,
                        "success".into(),
                        "challengeResponse",
                        Some("registration"),
                    )
                    .await;
                } else {
                    log::error!(
                        "Database failure during registration for user '{}'",
                        username
                    );
                    self.send_encapsulated_reply(
                        &sender_tag,
                        "error: database failure".into(),
                        "challengeResponse",
                        Some("registration"),
                    )
                    .await;
                }
            } else {
                log::warn!("Signature verification failed for user '{}'", username);
                self.send_encapsulated_reply(
                    &sender_tag,
                    "error: signature verification failed".into(),
                    "challengeResponse",
                    Some("registration"),
                )
                .await;
            }
        } else {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: no pending registration".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
        }
    }

    async fn handle_login(&mut self, data: &Value, sender_tag: ReplyTag) {
        // Rate limit check for login attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!(
                "Rate limit exceeded for login from sender_tag={:?}",
                sender_tag
            );
            self.send_encapsulated_reply(
                &sender_tag,
                "error: rate limit exceeded, please try again later".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
            return;
        }

        let username = data.get("username").and_then(Value::as_str);
        if username.is_none() {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: missing username".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
            return;
        }
        let username = username.unwrap();
        if let Some((_user, pubkey, _)) =
            self.db.get_user_by_username(username).await.unwrap_or(None)
        {
            let nonce = Uuid::new_v4().to_string();
            self.nonces.insert(
                sender_tag.clone(),
                PendingEntry::new((username.to_string(), pubkey, nonce.clone())),
            );
            self.send_encapsulated_reply(
                &sender_tag,
                json!({"nonce": nonce}).to_string(),
                "challenge",
                Some("login"),
            )
            .await;
        } else {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: user not found".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
        }
    }

    async fn handle_login_response(&mut self, data: &Value, sender_tag: ReplyTag) {
        let signature = data.get("signature").and_then(Value::as_str);
        if signature.is_none() {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: missing signature".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
            return;
        }
        let signature = signature.unwrap();
        if let Some(entry) = self.nonces.remove(&sender_tag) {
            let (username, pubkey, nonce) = entry.data;
            if self.crypto.verify_signature(&pubkey, &nonce, signature) {
                if let Some((_u, _pk, db_sender_tag)) = self
                    .db
                    .get_user_by_username(&username)
                    .await
                    .unwrap_or(None)
                {
                    if db_sender_tag != sender_tag.to_string() {
                        if let Err(e) = self
                            .db
                            .update_user_field(&username, "senderTag", &sender_tag.to_string())
                            .await
                        {
                            log::warn!("Failed to update senderTag for user {}: {}", username, e);
                        }
                    }
                }
                self.send_encapsulated_reply(
                    &sender_tag,
                    "success".into(),
                    "challengeResponse",
                    Some("login"),
                )
                .await;
            } else {
                self.send_encapsulated_reply(
                    &sender_tag,
                    "error: invalid signature".into(),
                    "challengeResponse",
                    Some("login"),
                )
                .await;
            }
        } else {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: no pending login".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
        }
    }

    /// Validates a send request and extracts content/signature.
    /// Returns (content_str, signature, parsed_content) or an error message.
    fn validate_send_request(data: &Value) -> Result<(&str, &str, Value), &'static str> {
        let content_str = data
            .get("content")
            .and_then(Value::as_str)
            .ok_or("error: missing 'content' or 'signature'")?;
        let signature = data
            .get("signature")
            .and_then(Value::as_str)
            .ok_or("error: missing 'content' or 'signature'")?;
        let content: Value =
            serde_json::from_str(content_str).map_err(|_| "error: invalid JSON in content")?;
        Ok((content_str, signature, content))
    }

    /// Extracts and validates sender/recipient usernames from content.
    fn extract_usernames(content: &Value) -> Result<(&str, &str), &'static str> {
        let sender = content
            .get("sender")
            .and_then(Value::as_str)
            .ok_or("error: missing 'sender' or 'recipient' field")?;
        let recipient = content
            .get("recipient")
            .and_then(Value::as_str)
            .ok_or("error: missing 'sender' or 'recipient' field")?;
        Ok((sender, recipient))
    }

    /// Routes a message to the recipient if they exist.
    async fn route_message_to_recipient(
        &mut self,
        sender_username: &str,
        recipient_username: &str,
        content: &Value,
        sender_tag: ReplyTag,
    ) {
        let Some((_u2, _pk2, target_sender_tag)) = self
            .db
            .get_user_by_username(recipient_username)
            .await
            .unwrap_or(None)
        else {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: recipient not found".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        };

        if let Some(tag) = ReplyTag::from_stored_string(&target_sender_tag) {
            let mut forward = json!({
                "sender": sender_username,
                "body": content.get("body").cloned().unwrap_or(Value::Null)
            });
            if let Some(spk) = content.get("senderPublicKey") {
                forward["senderPublicKey"] = spk.clone();
            }
            self.send_encapsulated_reply(&tag, forward.to_string(), "incomingMessage", Some("chat"))
                .await;
        }

        self.send_encapsulated_reply(&sender_tag, "success".into(), "sendResponse", Some("chat"))
            .await;
    }

    async fn handle_send(&mut self, data: &Value, sender_tag: ReplyTag) {
        // Validate request and parse content
        let (content_str, signature, content) = match Self::validate_send_request(data) {
            Ok(v) => v,
            Err(msg) => {
                self.send_encapsulated_reply(&sender_tag, msg.into(), "sendResponse", Some("chat"))
                    .await;
                return;
            }
        };

        // Extract sender and recipient usernames
        let (sender_username, recipient_username) = match Self::extract_usernames(&content) {
            Ok(v) => v,
            Err(msg) => {
                self.send_encapsulated_reply(&sender_tag, msg.into(), "sendResponse", Some("chat"))
                    .await;
                return;
            }
        };

        // Verify sender exists and signature is valid
        let Some((_u, pubkey, db_sender_tag)) = self
            .db
            .get_user_by_username(sender_username)
            .await
            .unwrap_or(None)
        else {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: unrecognized sender username".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        };

        if !self
            .crypto
            .verify_signature(&pubkey, content_str, signature)
        {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: invalid signature".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        }

        // Update sender tag if changed
        if db_sender_tag != sender_tag.to_string() {
            if let Err(e) = self
                .db
                .update_user_field(sender_username, "senderTag", &sender_tag.to_string())
                .await
            {
                log::warn!(
                    "Failed to update senderTag for user {}: {}",
                    sender_username,
                    e
                );
            }
        }

        // Route message to recipient
        self.route_message_to_recipient(sender_username, recipient_username, &content, sender_tag)
            .await;
    }

    async fn handle_create_group(&mut self, _data: &Value, sender_tag: ReplyTag) {
        log::warn!("handleCreateGroup - stubs not implemented");
        self.send_encapsulated_reply(
            &sender_tag,
            "error: unimplemented".into(),
            "createGroupResponse",
            None,
        )
        .await;
    }
    async fn handle_send_group(&mut self, _data: &Value, sender_tag: ReplyTag) {
        log::warn!("handleSendGroup - stubs not implemented");
        self.send_encapsulated_reply(
            &sender_tag,
            "error: unimplemented".into(),
            "sendGroupResponse",
            None,
        )
        .await;
    }
    async fn handle_send_invite(&mut self, _data: &Value, sender_tag: ReplyTag) {
        log::warn!("handleSendInvite - stubs not implemented");
        self.send_encapsulated_reply(
            &sender_tag,
            "error: unimplemented".into(),
            "inviteGroupResponse",
            None,
        )
        .await;
    }
    async fn handle_update(&mut self, _data: &Value, sender_tag: ReplyTag) {
        log::warn!("handleUpdate - stubs not implemented");
        self.send_encapsulated_reply(
            &sender_tag,
            "error: unimplemented".into(),
            "updateResponse",
            None,
        )
        .await;
    }

    // ===== GROUP SERVER REGISTRATION =====

    /// Handle a group server registration request (step 1: send challenge)
    async fn handle_register_group(&mut self, data: &Value, sender_tag: ReplyTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);
        let name = data.get("name").and_then(Value::as_str);
        let nym_address = data.get("nymAddress").and_then(Value::as_str);
        let public_key = data.get("publicKey").and_then(Value::as_str);
        let description = data.get("description").and_then(Value::as_str);
        let is_public = data
            .get("isPublic")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        log::info!(
            "Group registration request - groupId: {:?}, name: {:?}",
            group_id,
            name
        );

        // Validate required fields
        if group_id.is_none() || name.is_none() || nym_address.is_none() || public_key.is_none() {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: missing required fields (groupId, name, nymAddress, publicKey)".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        let group_id = group_id.unwrap();
        let name = name.unwrap();
        let nym_address = nym_address.unwrap();
        let public_key = public_key.unwrap();

        // Validate group_id format
        if !validation::is_valid_group_id(group_id) {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: invalid groupId format".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        // Check if group already exists
        if let Ok(Some(existing)) = self.db.get_group_by_id(group_id).await {
            // Group exists - check if this is a re-registration (same public key)
            if existing.3 == public_key {
                // Same key - allow address update, send challenge
                log::info!(
                    "Group '{}' re-registering with same key, allowing address update",
                    group_id
                );
            } else {
                self.send_encapsulated_reply(
                    &sender_tag,
                    "error: groupId already registered with different key".into(),
                    "registerGroupResponse",
                    Some("registration"),
                )
                .await;
                return;
            }
        }

        // Generate nonce for challenge
        let nonce = Uuid::new_v4().to_string();
        log::debug!("Generated nonce for group '{}': {}", group_id, nonce);

        // Store pending registration
        self.pending_groups.insert(
            sender_tag.clone(),
            PendingEntry::new(PendingGroupData {
                group_id: group_id.to_string(),
                name: name.to_string(),
                nym_address: nym_address.to_string(),
                public_key: public_key.to_string(),
                description: description.map(String::from),
                is_public,
                nonce: nonce.clone(),
            }),
        );

        // Send challenge
        self.send_encapsulated_reply(
            &sender_tag,
            json!({"nonce": nonce}).to_string(),
            "challenge",
            Some("groupRegistration"),
        )
        .await;
    }

    /// Handle group registration response (step 2: verify signature)
    async fn handle_register_group_response(
        &mut self,
        data: &Value,
        sender_tag: ReplyTag,
    ) {
        let signature = data.get("signature").and_then(Value::as_str);

        if signature.is_none() {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: missing signature".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        let signature = signature.unwrap();

        if let Some(entry) = self.pending_groups.remove(&sender_tag) {
            let pending = entry.data;
            log::debug!(
                "Verifying signature for group '{}' with nonce '{}'",
                pending.group_id,
                pending.nonce
            );

            // Verify signature over the nonce using the group's public key
            if self
                .crypto
                .verify_signature(&pending.public_key, &pending.nonce, signature)
            {
                log::debug!(
                    "Signature verification successful for group '{}'",
                    pending.group_id
                );

                // Check if updating existing or creating new
                let result = if let Ok(Some(_)) = self.db.get_group_by_id(&pending.group_id).await {
                    // Update existing group's address
                    self.db
                        .update_group_address(&pending.group_id, &pending.nym_address)
                        .await
                } else {
                    // Add new group
                    self.db
                        .add_group(
                            &pending.group_id,
                            &pending.name,
                            &pending.nym_address,
                            &pending.public_key,
                            pending.description.as_deref(),
                            pending.is_public,
                        )
                        .await
                };

                match result {
                    Ok(true) => {
                        log::info!("Group '{}' registered successfully", pending.group_id);
                        self.send_encapsulated_reply(
                            &sender_tag,
                            "success".into(),
                            "registerGroupResponse",
                            Some("registration"),
                        )
                        .await;
                    }
                    _ => {
                        log::error!(
                            "Database failure during group registration for '{}'",
                            pending.group_id
                        );
                        self.send_encapsulated_reply(
                            &sender_tag,
                            "error: database failure".into(),
                            "registerGroupResponse",
                            Some("registration"),
                        )
                        .await;
                    }
                }
            } else {
                log::warn!(
                    "Signature verification failed for group '{}'",
                    pending.group_id
                );
                self.send_encapsulated_reply(
                    &sender_tag,
                    "error: signature verification failed".into(),
                    "registerGroupResponse",
                    Some("registration"),
                )
                .await;
            }
        } else {
            self.send_encapsulated_reply(
                &sender_tag,
                "error: no pending group registration".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
        }
    }

    /// Handle query for discoverable groups
    async fn handle_query_groups(&mut self, data: &Value, sender_tag: ReplyTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);

        if let Some(gid) = group_id {
            // Query specific group
            match self.db.get_group_by_id(gid).await {
                Ok(Some((id, name, address, public_key, description, is_public))) => {
                    if is_public {
                        let reply = json!({
                            "groups": [{
                                "groupId": id,
                                "name": name,
                                "nymAddress": address,
                                "publicKey": public_key,
                                "description": description
                            }]
                        })
                        .to_string();
                        self.send_encapsulated_reply(
                            &sender_tag,
                            reply,
                            "queryGroupsResponse",
                            None,
                        )
                        .await;
                    } else {
                        self.send_encapsulated_reply(
                            &sender_tag,
                            json!({"groups": []}).to_string(),
                            "queryGroupsResponse",
                            None,
                        )
                        .await;
                    }
                }
                _ => {
                    self.send_encapsulated_reply(
                        &sender_tag,
                        json!({"groups": []}).to_string(),
                        "queryGroupsResponse",
                        None,
                    )
                    .await;
                }
            }
        } else {
            // Query all public groups
            match self.db.get_public_groups().await {
                Ok(groups) => {
                    let group_list: Vec<Value> = groups
                        .into_iter()
                        .map(|(id, name, address, public_key, description)| {
                            json!({
                                "groupId": id,
                                "name": name,
                                "nymAddress": address,
                                "publicKey": public_key,
                                "description": description
                            })
                        })
                        .collect();
                    let reply = json!({"groups": group_list}).to_string();
                    self.send_encapsulated_reply(&sender_tag, reply, "queryGroupsResponse", None)
                        .await;
                }
                Err(e) => {
                    log::error!("Failed to query groups: {}", e);
                    self.send_encapsulated_reply(
                        &sender_tag,
                        "error: database failure".into(),
                        "queryGroupsResponse",
                        None,
                    )
                    .await;
                }
            }
        }
    }

    // ===== UNIFIED FORMAT HANDLERS =====

    async fn handle_query_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        // Support both "username" (legacy) and "identifier" (unified) fields
        let identifier = payload
            .get("identifier")
            .or_else(|| payload.get("username"))
            .and_then(Value::as_str);

        if let Some(identifier) = identifier {
            let query_result = match self.db.query_by_identifier(identifier).await {
                Ok(result) => result,
                Err(e) => {
                    log::error!(
                        "Database query failed for identifier '{}': {}",
                        identifier,
                        e
                    );
                    None
                }
            };
            match query_result {
                Some(QueryResult::User {
                    username,
                    public_key,
                    ..
                }) => {
                    let response_payload = json!({
                        "type": "user",
                        "username": username,
                        "publicKey": public_key
                    });
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "queryResponse",
                        sender_username,
                    )
                    .await;
                }
                Some(QueryResult::Group {
                    group_id,
                    name,
                    nym_address,
                    public_key,
                    description,
                }) => {
                    let response_payload = json!({
                        "type": "group",
                        "groupId": group_id,
                        "name": name,
                        "nymAddress": nym_address,
                        "publicKey": public_key,
                        "description": description
                    });
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "queryResponse",
                        sender_username,
                    )
                    .await;
                }
                None => {
                    let response_payload = json!({"error": "No user or group found"});
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "queryResponse",
                        sender_username,
                    )
                    .await;
                }
            }
        } else {
            let response_payload = json!({"error": "missing 'username' or 'identifier' field"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "queryResponse",
                sender_username,
            )
            .await;
        }
    }

    async fn handle_register_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        // Rate limit check for registration attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!(
                "Rate limit exceeded for unified registration from sender_tag={:?}",
                sender_tag
            );
            let response_payload = json!({"result": "error", "context": "registration", "message": "rate limit exceeded, please try again later"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "challengeResponse",
                sender_username,
            )
            .await;
            return;
        }

        let username = payload.get("username").and_then(Value::as_str);
        let public_key = payload.get("publicKey").and_then(Value::as_str);

        if let (Some(username), Some(public_key)) = (username, public_key) {
            if !validation::is_valid_username(username) {
                let response_payload = json!({"result": "error", "context": "registration", "message": "invalid username"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "challengeResponse",
                    sender_username,
                )
                .await;
                return;
            }

            if self
                .db
                .get_user_by_username(username)
                .await
                .unwrap_or(None)
                .is_some()
            {
                let response_payload = json!({"result": "error", "context": "registration", "message": "user already exists"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "challengeResponse",
                    sender_username,
                )
                .await;
                return;
            }

            // Send challenge
            let nonce = Uuid::new_v4().to_string();
            self.pending_users.insert(
                sender_tag.clone(),
                PendingEntry::new((username.to_string(), public_key.to_string(), nonce.clone())),
            );

            let challenge_payload = json!({"nonce": nonce, "context": "registration"});
            self.send_unified_reply(&sender_tag, challenge_payload, "challenge", sender_username)
                .await;
        } else {
            let response_payload = json!({"result": "error", "context": "registration", "message": "missing username or publicKey"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "challengeResponse",
                sender_username,
            )
            .await;
        }
    }

    async fn handle_registration_response_unified(
        &mut self,
        _payload: &Value,
        sender_tag: ReplyTag,
        signature: Option<&str>,
    ) {
        if let Some(signature) = signature {
            if let Some(entry) = self.pending_users.remove(&sender_tag) {
                let (username, public_key, nonce) = entry.data;
                log::info!(
                    "Verifying registration signature for '{}' (nonce={}, sig_len={})",
                    username,
                    nonce,
                    signature.len()
                );
                let is_valid = self.crypto.verify_signature(&public_key, &nonce, signature);

                if is_valid {
                    if let Err(e) = self
                        .db
                        .add_user(&username, &public_key, &sender_tag.to_string())
                        .await
                    {
                        log::error!("Failed to register user in DB: {}", e);
                        let response_payload = json!({"result": "error", "context": "registration", "message": "database error"});
                        self.send_unified_reply(
                            &sender_tag,
                            response_payload,
                            "challengeResponse",
                            &username,
                        )
                        .await;
                    } else {
                        log::info!(
                            "Successfully registered user '{}' with sender_tag: {}",
                            username,
                            sender_tag
                        );
                        let response_payload =
                            json!({"result": "success", "context": "registration"});
                        self.send_unified_reply(
                            &sender_tag,
                            response_payload,
                            "challengeResponse",
                            &username,
                        )
                        .await;
                    }
                } else {
                    log::warn!(
                        "Registration signature verification FAILED for '{}'",
                        username
                    );
                    let response_payload = json!({"result": "error", "context": "registration", "message": "invalid signature"});
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "challengeResponse",
                        &username,
                    )
                    .await;
                }
            } else {
                log::warn!(
                    "No pending registration found for sender_tag={:?}",
                    sender_tag
                );
                let response_payload = json!({"result": "error", "context": "registration", "message": "no pending registration"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "challengeResponse",
                    "unknown",
                )
                .await;
            }
        } else {
            log::warn!("Registration response missing signature field");
            let response_payload = json!({"result": "error", "context": "registration", "message": "missing signature"});
            self.send_unified_reply(&sender_tag, response_payload, "challengeResponse", "unknown")
                .await;
        }
    }

    async fn handle_login_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
    ) {
        // Rate limit check for login attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!(
                "Rate limit exceeded for unified login from sender_tag={:?}",
                sender_tag
            );
            let response_payload = json!({"result": "error", "context": "login", "message": "rate limit exceeded, please try again later"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "challengeResponse",
                sender_username,
            )
            .await;
            return;
        }

        let username = payload.get("username").and_then(Value::as_str);
        if let Some(username) = username {
            if let Ok(Some((_, public_key, _))) = self.db.get_user_by_username(username).await {
                let nonce = Uuid::new_v4().to_string();
                self.nonces.insert(
                    sender_tag.clone(),
                    PendingEntry::new((username.to_string(), public_key, nonce.clone())),
                );

                let challenge_payload = json!({"nonce": nonce, "context": "login"});
                self.send_unified_reply(
                    &sender_tag,
                    challenge_payload,
                    "challenge",
                    sender_username,
                )
                .await;
            } else {
                let response_payload =
                    json!({"result": "error", "context": "login", "message": "user not found"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "challengeResponse",
                    sender_username,
                )
                .await;
            }
        } else {
            let response_payload =
                json!({"result": "error", "context": "login", "message": "missing username"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "challengeResponse",
                sender_username,
            )
            .await;
        }
    }

    async fn handle_login_response_unified(
        &mut self,
        _payload: &Value,
        sender_tag: ReplyTag,
        signature: Option<&str>,
    ) {
        if let Some(signature) = signature {
            if let Some(entry) = self.nonces.remove(&sender_tag) {
                let (username, public_key, nonce) = entry.data;
                let is_valid = self.crypto.verify_signature(&public_key, &nonce, signature);

                if is_valid {
                    // Update the user's senderTag since ephemeral clients change addresses each session
                    if let Err(e) = self
                        .db
                        .update_user_field(&username, "senderTag", &sender_tag.to_string())
                        .await
                    {
                        log::error!("Failed to update senderTag for user '{}': {}", username, e);
                    } else {
                        log::info!(
                            "Updated senderTag for user '{}' to: {}",
                            username,
                            sender_tag
                        );
                    }

                    let response_payload = json!({"result": "success", "context": "login"});
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "challengeResponse",
                        &username,
                    )
                    .await;
                } else {
                    let response_payload = json!({"result": "error", "context": "login", "message": "invalid signature"});
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "challengeResponse",
                        &username,
                    )
                    .await;
                }
            } else {
                let response_payload =
                    json!({"result": "error", "context": "login", "message": "no pending login"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "challengeResponse",
                    "unknown",
                )
                .await;
            }
        } else {
            let response_payload =
                json!({"result": "error", "context": "login", "message": "missing signature"});
            self.send_unified_reply(&sender_tag, response_payload, "challengeResponse", "unknown")
                .await;
        }
    }

    async fn handle_send_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        recipient_username: Option<&str>,
        signature: Option<&str>,
    ) {
        log::debug!(
            "Received unified send message from {} with payload: {}",
            sender_username,
            payload
        );

        // Rate limit check for send operations
        let rate_key = sender_tag.to_string();
        if !self.send_rate_limiter.check_and_record(&rate_key) {
            log::warn!(
                "Rate limit exceeded for send from sender_tag={:?} (user={})",
                sender_tag,
                sender_username
            );
            let response_payload = json!({"status": "error", "message": "rate limit exceeded, please try again later"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "sendResponse",
                sender_username,
            )
            .await;
            return;
        }

        // Verify sender exists and signature is valid
        let sender_data = match self.db.get_user_by_username(sender_username).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                log::warn!(
                    "Send rejected: sender {} not registered",
                    sender_username
                );
                let response_payload =
                    json!({"status": "error", "message": "sender not registered"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "sendResponse",
                    sender_username,
                )
                .await;
                return;
            }
            Err(e) => {
                log::error!("Send: database error looking up {}: {}", sender_username, e);
                let response_payload =
                    json!({"status": "error", "message": "database error"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "sendResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };

        let public_key = &sender_data.1;

        // Require and verify PGP signature over the payload
        let signature = match signature {
            Some(sig) => sig,
            None => {
                log::warn!(
                    "Send from {} rejected: missing signature",
                    sender_username
                );
                let response_payload =
                    json!({"status": "error", "message": "missing signature"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "sendResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };

        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        if !self
            .crypto
            .verify_signature(public_key, &payload_str, signature)
        {
            log::warn!(
                "Send from {} rejected: invalid signature",
                sender_username
            );
            let response_payload =
                json!({"status": "error", "message": "invalid signature"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "sendResponse",
                sender_username,
            )
            .await;
            return;
        }

        // For MLS messages, extract conversation_id and mls_message
        if let (Some(conversation_id), Some(_mls_message)) = (
            payload.get("conversation_id").and_then(Value::as_str),
            payload.get("mls_message").and_then(Value::as_str),
        ) {
            log::info!(
                "Routing MLS encrypted message from {} (conversation: {})",
                sender_username,
                conversation_id
            );

            // Use the recipient from the top-level message envelope
            let recipient = match recipient_username {
                Some(r) if !r.is_empty() => r,
                _ => {
                    log::error!("No recipient specified in message envelope for MLS send from {}", sender_username);
                    let response_payload =
                        json!({"status": "error", "message": "missing recipient field"});
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "sendResponse",
                        sender_username,
                    )
                    .await;
                    return;
                }
            };

                // Check recipient exists before persisting
                if self
                    .db
                    .get_user_by_username(recipient)
                    .await
                    .ok()
                    .flatten()
                    .is_none()
                {
                    log::info!("Recipient {} not found in database", recipient);
                    let response_payload =
                        json!({"status": "error", "message": "recipient not found"});
                    self.send_unified_reply(
                        &sender_tag,
                        response_payload,
                        "sendResponse",
                        sender_username,
                    )
                    .await;
                } else {
                    // Persist-then-relay: message is safe in DB, best-effort SURB delivery
                    match self
                        .relay_with_persistence(recipient, sender_username, payload, "send")
                        .await
                    {
                        Ok(_pending_id) => {
                            let response_payload = json!({
                                "status": "sent",
                                "recipient": recipient,
                                "message": "Message accepted for delivery"
                            });
                            self.send_unified_reply(
                                &sender_tag,
                                response_payload,
                                "sendResponse",
                                sender_username,
                            )
                            .await;
                        }
                        Err(e) => {
                            log::error!("Failed to relay message to {}: {}", recipient, e);
                            let response_payload =
                                json!({"status": "error", "message": "failed to queue message"});
                            self.send_unified_reply(
                                &sender_tag,
                                response_payload,
                                "sendResponse",
                                sender_username,
                            )
                            .await;
                        }
                    }
                }
        } else {
            let response_payload =
                json!({"status": "error", "message": "missing conversation_id or mls_message"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "sendResponse",
                sender_username,
            )
            .await;
        }
    }

    /// Handle a sealed sender message. The server treats the sealed_payload as an
    /// opaque blob — it does not verify the sender or read the contents.
    async fn handle_sealed_send(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        recipient_username: Option<&str>,
    ) {
        log::info!(
            "Received sealed send from sender_tag={:?}",
            sender_tag
        );

        // Rate limit by sender_tag (anonymous, but throttled)
        let rate_key = sender_tag.to_string();
        if !self.send_rate_limiter.check_and_record(&rate_key) {
            log::warn!(
                "Rate limit exceeded for sealed send from sender_tag={:?}",
                sender_tag
            );
            let response_payload = json!({
                "status": "error",
                "message": "rate limit exceeded, please try again later"
            });
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "sendResponse",
                "__sealed__",
            )
            .await;
            return;
        }

        // Extract the sealed_payload (opaque base64 blob)
        let sealed_payload = match payload.get("sealed_payload").and_then(Value::as_str) {
            Some(sp) => sp,
            None => {
                log::warn!("Sealed send rejected: missing sealed_payload");
                let response_payload = json!({
                    "status": "error",
                    "message": "missing sealed_payload"
                });
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "sendResponse",
                    "__sealed__",
                )
                .await;
                return;
            }
        };

        // Require a recipient
        let recipient = match recipient_username {
            Some(r) if !r.is_empty() => r,
            _ => {
                log::warn!("Sealed send rejected: missing recipient");
                let response_payload = json!({
                    "status": "error",
                    "message": "missing recipient field"
                });
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "sendResponse",
                    "__sealed__",
                )
                .await;
                return;
            }
        };

        // Verify recipient exists
        if self
            .db
            .get_user_by_username(recipient)
            .await
            .ok()
            .flatten()
            .is_none()
        {
            log::info!("Sealed send: recipient {} not found", recipient);
            let response_payload = json!({
                "status": "error",
                "message": "recipient not found"
            });
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "sendResponse",
                "__sealed__",
            )
            .await;
            return;
        }

        // Build the relay payload — just the sealed_payload, passed through as-is
        let relay_payload = json!({
            "sealed_payload": sealed_payload
        });

        // Persist-then-relay with sender as "__sealed__"
        match self
            .relay_sealed_with_persistence(recipient, &relay_payload)
            .await
        {
            Ok(_pending_id) => {
                let response_payload = json!({
                    "status": "sent",
                    "recipient": recipient,
                    "message": "Sealed message accepted for delivery"
                });
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "sendResponse",
                    "__sealed__",
                )
                .await;
            }
            Err(e) => {
                log::error!("Failed to relay sealed message to {}: {}", recipient, e);
                let response_payload = json!({
                    "status": "error",
                    "message": "failed to queue message"
                });
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "sendResponse",
                    "__sealed__",
                )
                .await;
            }
        }
    }

    async fn handle_fetch_pending_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        signature: Option<&str>,
    ) {
        log::info!("Handling fetchPending request from {}", sender_username);

        // Verify signature - user must sign "fetchPending:{username}:{timestamp}"
        let timestamp = payload
            .get("timestamp")
            .and_then(Value::as_i64)
            .unwrap_or(0);

        // Get user's public key for verification
        let user_data = match self.db.get_user_by_username(sender_username).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                log::warn!("fetchPending: user {} not found", sender_username);
                let response_payload = json!({"status": "error", "message": "user not registered"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "fetchPendingResponse",
                    sender_username,
                )
                .await;
                return;
            }
            Err(e) => {
                log::error!("fetchPending: database error: {}", e);
                let response_payload = json!({"status": "error", "message": "database error"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "fetchPendingResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };

        let public_key = &user_data.1;

        // Verify signature
        if let Some(sig) = signature {
            let message_to_verify = format!("fetchPending:{}:{}", sender_username, timestamp);
            if !self
                .crypto
                .verify_signature(public_key, &message_to_verify, sig)
            {
                log::warn!("fetchPending: invalid signature from {}", sender_username);
                let response_payload = json!({"status": "error", "message": "invalid signature"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "fetchPendingResponse",
                    sender_username,
                )
                .await;
                return;
            }
        } else {
            log::warn!("fetchPending: missing signature from {}", sender_username);
            let response_payload = json!({"status": "error", "message": "missing signature"});
            self.send_unified_reply(
                &sender_tag,
                response_payload,
                "fetchPendingResponse",
                sender_username,
            )
            .await;
            return;
        }

        // Fetch pending messages from database
        match self.db.get_pending_messages(sender_username).await {
            Ok(messages) => {
                let message_ids: Vec<String> = messages.iter().map(|(id, _, _, _, _)| id.clone()).collect();
                let message_list: Vec<Value> = messages
                    .iter()
                    .map(|(id, sender, payload_str, action, created_at)| {
                        // Parse the stored payload JSON
                        let payload_value: Value =
                            serde_json::from_str(payload_str).unwrap_or(json!({}));
                        json!({
                            "id": id,
                            "sender": sender,
                            "payload": payload_value,
                            "action": action,
                            "timestamp": created_at
                        })
                    })
                    .collect();

                let count = message_list.len();
                log::info!(
                    "fetchPending: returning {} pending messages to {}",
                    count,
                    sender_username
                );

                let response_payload = json!({
                    "status": "success",
                    "messages": message_list,
                    "count": count
                });
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "fetchPendingResponse",
                    sender_username,
                )
                .await;

                // Messages are NOT deleted here — the client will ACK them
                // after successful processing, and handle_ack_unified will
                // delete them. This prevents message loss if the SURB
                // response doesn't reach the client.
                let _ = message_ids; // suppress unused warning
            }
            Err(e) => {
                log::error!("fetchPending: failed to get messages: {}", e);
                let response_payload =
                    json!({"status": "error", "message": "failed to fetch messages"});
                self.send_unified_reply(
                    &sender_tag,
                    response_payload,
                    "fetchPendingResponse",
                    sender_username,
                )
                .await;
            }
        }

        // Probabilistically clean up expired key packages (~1 in 10 calls)
        if rand::random::<u8>() % 10 == 0 {
            match self.db.cleanup_expired_key_packages().await {
                Ok(deleted) if deleted > 0 => {
                    log::info!("Cleaned up {} expired key packages", deleted);
                }
                Err(e) => {
                    log::warn!("Failed to clean up expired key packages: {}", e);
                }
                _ => {}
            }
        }
    }

    async fn handle_key_package_request_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        recipient_username: Option<&str>,
    ) {
        log::info!("Handling key package request from {}", sender_username);

        if let Some(recipient) = recipient_username {
            match self
                .relay_with_persistence(recipient, sender_username, payload, "keyPackageRequest")
                .await
            {
                Ok(pending_id) => {
                    log::info!(
                        "Relayed key package request from {} to {} (pending_id={})",
                        sender_username,
                        recipient,
                        pending_id
                    );
                }
                Err(e) => {
                    log::error!("Failed to relay key package request to {}: {}", recipient, e);
                    let error_payload = json!({
                        "status": "error",
                        "message": format!("Failed to relay key package request: {}", e)
                    });
                    self.send_unified_reply(
                        &sender_tag,
                        error_payload,
                        "keyPackageResponse",
                        sender_username,
                    )
                    .await;
                }
            }
        } else {
            log::error!("Key package request missing recipient field");
            let error_payload = json!({
                "status": "error",
                "message": "Missing recipient field"
            });
            self.send_unified_reply(
                &sender_tag,
                error_payload,
                "keyPackageResponse",
                sender_username,
            )
            .await;
        }
    }

    async fn handle_key_package_response_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        recipient_username: Option<&str>,
    ) {
        log::info!("Handling key package response from {}", sender_username);

        if let Some(recipient) = recipient_username {
            match self
                .relay_with_persistence(recipient, sender_username, payload, "keyPackageResponse")
                .await
            {
                Ok(pending_id) => {
                    log::info!(
                        "Relayed key package response from {} to {} (pending_id={})",
                        sender_username,
                        recipient,
                        pending_id
                    );
                }
                Err(e) => {
                    log::error!(
                        "Failed to relay key package response to {}: {}",
                        recipient,
                        e
                    );
                    let error_payload = json!({
                        "status": "error",
                        "message": format!("Failed to relay key package response: {}", e)
                    });
                    self.send_unified_reply(
                        &sender_tag,
                        error_payload,
                        "keyPackageResponse",
                        sender_username,
                    )
                    .await;
                }
            }
        } else {
            log::error!("Key package response missing recipient field");
        }
    }

    async fn handle_group_join_response_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        recipient_username: Option<&str>,
    ) {
        log::info!("Handling group join response from {}", sender_username);

        if let Some(recipient) = recipient_username {
            match self
                .relay_with_persistence(recipient, sender_username, payload, "groupJoinResponse")
                .await
            {
                Ok(pending_id) => {
                    log::info!(
                        "Relayed group join response from {} to {} (pending_id={})",
                        sender_username,
                        recipient,
                        pending_id
                    );
                }
                Err(e) => {
                    log::error!(
                        "Failed to relay group join response to {}: {}",
                        recipient,
                        e
                    );
                    let error_payload = json!({
                        "status": "error",
                        "message": format!("Failed to relay group join response: {}", e)
                    });
                    self.send_unified_reply(
                        &sender_tag,
                        error_payload,
                        "groupJoinResponse",
                        sender_username,
                    )
                    .await;
                }
            }
        } else {
            log::error!("Group join response missing recipient field");
        }
    }

    /// Handle ping from client: update sender_tag and drain pending messages.
    ///
    /// Ping replaces login — single round-trip, PGP signature over "ping:{username}:{timestamp}".
    /// Server verifies signature against stored public key, updates sender_tag, and drains
    /// any pending messages via SURB delivery using the fresh SURBs from the ping.
    async fn handle_ping_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        signature: Option<&str>,
    ) {
        log::info!("Handling ping from {}", sender_username);

        // Rate limit
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!("Ping from {} rate limited", sender_username);
            let response_payload = json!({"status": "error", "error": "rate_limited"});
            self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
                .await;
            return;
        }

        // Require signature
        let signature = match signature {
            Some(sig) => sig,
            None => {
                log::warn!("Ping from {} rejected: missing signature", sender_username);
                let response_payload = json!({"status": "error", "error": "missing_signature"});
                self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
                    .await;
                return;
            }
        };

        // Extract timestamp
        let timestamp = match payload.get("timestamp").and_then(Value::as_i64) {
            Some(ts) => ts,
            None => {
                log::warn!("Ping from {} rejected: missing timestamp", sender_username);
                let response_payload = json!({"status": "error", "error": "missing_timestamp"});
                self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
                    .await;
                return;
            }
        };

        // Validate timestamp freshness (within 300 seconds)
        let now = chrono::Utc::now().timestamp();
        if (now - timestamp).unsigned_abs() > 300 {
            log::warn!(
                "Ping from {} rejected: stale timestamp (delta={}s)",
                sender_username,
                now - timestamp
            );
            let response_payload = json!({"status": "error", "error": "stale_timestamp"});
            self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
                .await;
            return;
        }

        // Look up user and verify signature
        let (public_key, _old_sender_tag) = match self.db.get_user_by_username(sender_username).await {
            Ok(Some((_username, public_key, old_tag))) => (public_key, old_tag),
            Ok(None) => {
                log::warn!("Ping from {} rejected: user not found", sender_username);
                let response_payload = json!({"status": "error", "error": "user_not_found"});
                self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
                    .await;
                return;
            }
            Err(e) => {
                log::error!("Ping from {} rejected: DB error: {}", sender_username, e);
                let response_payload = json!({"status": "error", "error": "internal_error"});
                self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
                    .await;
                return;
            }
        };

        // Verify PGP signature over "ping:{username}:{timestamp}"
        let sign_content = format!("ping:{}:{}", sender_username, timestamp);
        if !self.crypto.verify_signature(&public_key, &sign_content, signature) {
            log::warn!("Ping from {} rejected: invalid signature", sender_username);
            let response_payload = json!({"status": "error", "error": "invalid_signature"});
            self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
                .await;
            return;
        }

        // Update sender_tag in DB
        if let Err(e) = self
            .db
            .update_user_field(sender_username, "senderTag", &sender_tag.to_string())
            .await
        {
            log::error!("Failed to update sender_tag for {}: {}", sender_username, e);
        }

        log::info!(
            "Ping from {} verified, sender_tag updated to {}",
            sender_username,
            sender_tag
        );

        // Reply pong
        let server_time = chrono::Utc::now().timestamp();
        let response_payload = json!({
            "status": "success",
            "serverTime": server_time
        });
        self.send_unified_reply(&sender_tag, response_payload, "pong", sender_username)
            .await;

        // Drain pending messages for this user
        match self.db.get_pending_messages(sender_username).await {
            Ok(pending_messages) => {
                if pending_messages.is_empty() {
                    return;
                }
                log::info!(
                    "Draining {} pending messages for {}",
                    pending_messages.len(),
                    sender_username
                );
                let mut delivered_ids = Vec::new();
                for (id, msg_sender, payload_str, action, _created_at) in &pending_messages {
                    if let Ok(msg_payload) = serde_json::from_str::<Value>(payload_str) {
                        self.send_unified_message(
                            &sender_tag,
                            msg_payload,
                            action,
                            sender_username,
                            msg_sender,
                        )
                        .await;
                        delivered_ids.push(id.clone());
                    }
                }
                // Delete delivered pending messages
                if !delivered_ids.is_empty() {
                    if let Err(e) = self
                        .db
                        .delete_pending_messages_for_recipient(sender_username, &delivered_ids)
                        .await
                    {
                        log::error!("Failed to delete drained pending messages: {}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to fetch pending messages for {}: {}", sender_username, e);
            }
        }
    }

    /// Handle ACK from client: delete the acknowledged pending messages.
    ///
    /// Clients send ACKs after processing messages (both SURB-delivered and fetchPending).
    /// Requires PGP signature verification to prevent unauthorized message deletion.
    async fn handle_ack_unified(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        signature: Option<&str>,
    ) {
        let pending_ids: Vec<String> = match payload.get("pendingIds").and_then(|v| v.as_array()) {
            Some(arr) => arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
            None => {
                log::warn!("ACK from {} missing pendingIds array", sender_username);
                return;
            }
        };

        if pending_ids.is_empty() {
            return;
        }

        // Verify the sender's PGP signature
        let signature = match signature {
            Some(sig) => sig,
            None => {
                log::warn!("ACK from {} rejected: missing signature", sender_username);
                let response_payload = json!({"status": "error", "message": "missing signature"});
                self.send_unified_reply(&sender_tag, response_payload, "ackResponse", sender_username)
                    .await;
                return;
            }
        };

        let timestamp = match payload.get("timestamp").and_then(Value::as_i64) {
            Some(ts) => ts,
            None => {
                log::warn!("ACK from {} rejected: missing timestamp", sender_username);
                let response_payload = json!({"status": "error", "message": "missing timestamp"});
                self.send_unified_reply(&sender_tag, response_payload, "ackResponse", sender_username)
                    .await;
                return;
            }
        };

        // Validate timestamp freshness (within 300 seconds)
        let now = chrono::Utc::now().timestamp();
        if (now - timestamp).unsigned_abs() > 300 {
            log::warn!(
                "ACK from {} rejected: stale timestamp (delta={}s)",
                sender_username,
                now - timestamp
            );
            let response_payload = json!({"status": "error", "message": "stale timestamp"});
            self.send_unified_reply(&sender_tag, response_payload, "ackResponse", sender_username)
                .await;
            return;
        }

        // Look up the user's public key
        let user_data = match self.db.get_user_by_username(sender_username).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                log::warn!("ACK from {} rejected: user not found", sender_username);
                let response_payload = json!({"status": "error", "message": "user not registered"});
                self.send_unified_reply(&sender_tag, response_payload, "ackResponse", sender_username)
                    .await;
                return;
            }
            Err(e) => {
                log::error!("ACK: database error looking up {}: {}", sender_username, e);
                return;
            }
        };

        let public_key = &user_data.1;

        // Verify signature over "ack:{username}:{timestamp}:{pendingIds_joined}"
        let ids_joined = pending_ids.join(",");
        let message_to_verify = format!("ack:{}:{}:{}", sender_username, timestamp, ids_joined);
        if !self
            .crypto
            .verify_signature(public_key, &message_to_verify, signature)
        {
            log::warn!(
                "ACK from {} rejected: invalid signature",
                sender_username
            );
            let response_payload = json!({"status": "error", "message": "invalid signature"});
            self.send_unified_reply(&sender_tag, response_payload, "ackResponse", sender_username)
                .await;
            return;
        }

        log::info!(
            "Processing ACK from {} for {} pending message(s): {:?}",
            sender_username,
            pending_ids.len(),
            pending_ids
        );

        match self
            .db
            .delete_pending_messages_for_recipient(sender_username, &pending_ids)
            .await
        {
            Ok(deleted) => {
                log::debug!(
                    "ACK: deleted {} of {} pending messages for {}",
                    deleted,
                    pending_ids.len(),
                    sender_username
                );
            }
            Err(e) => {
                log::error!(
                    "ACK: failed to delete pending messages for {}: {}",
                    sender_username,
                    e
                );
            }
        }
    }

    async fn get_user_sender_tag(&self, username: &str) -> Option<ReplyTag> {
        if let Ok(Some((_username, _public_key, target_sender_tag))) =
            self.db.get_user_by_username(username).await
        {
            return ReplyTag::from_stored_string(&target_sender_tag);
        }
        None
    }

    /// Send a unified format reply
    async fn send_unified_reply(
        &self,
        recipient: &ReplyTag,
        payload: Value,
        action: &str,
        recipient_username: &str,
    ) {
        log::info!(
            "Sending unified reply action '{}' to sender_tag={:?}",
            action,
            recipient
        );

        // Create unified format response
        let message = json!({
            "type": "response",
            "action": action,
            "sender": "server",
            "recipient": recipient_username,
            "payload": payload,
            "signature": "server_signature",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "serverTime": chrono::Utc::now().timestamp()
        });

        // Sign the payload
        let payload_str = serde_json::to_string(&payload).unwrap_or_default();
        if let Ok(signature) = self.crypto.sign_message(&self.client_id, &payload_str) {
            let mut signed_message = message;
            signed_message["signature"] = json!(signature);

            let msg_str = signed_message.to_string();
            if let Err(e) = self.sender.send_reply(recipient, msg_str).await {
                log::warn!("Failed to send unified reply: {}", e);
            }
        } else {
            log::error!("Failed to sign unified reply message");
        }
    }

    /// Send a unified format message (type: "message")
    async fn send_unified_message(
        &self,
        recipient: &ReplyTag,
        payload: Value,
        action: &str,
        recipient_username: &str,
        sender_username: &str,
    ) {
        log::info!(
            "Sending unified message action '{}' to sender_tag={:?}",
            action,
            recipient
        );

        // Create unified format message (type: "message" for forwarded messages)
        let message = json!({
            "type": "message",
            "action": action,
            "sender": sender_username,
            "recipient": recipient_username,
            "payload": payload,
            "signature": "server_signature",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "serverTime": chrono::Utc::now().timestamp()
        });

        // Sign the payload
        let payload_str = serde_json::to_string(&payload).unwrap_or_default();
        if let Ok(signature) = self.crypto.sign_message(&self.client_id, &payload_str) {
            let mut signed_message = message;
            signed_message["signature"] = json!(signature);

            let msg_str = signed_message.to_string();
            if let Err(e) = self.sender.send_reply(recipient, msg_str).await {
                log::warn!("Failed to send unified message: {}", e);
            }
        } else {
            log::error!("Failed to sign unified message");
        }
    }

    /// Persist a message to the pending queue, then attempt best-effort SURB delivery.
    ///
    /// Returns the pending message ID. If the recipient is online, the message is also
    /// sent immediately via SURB with a `pendingId` field injected into the payload so
    /// the client can ACK it. If the recipient is offline, the message stays in the DB
    /// for `fetchPending` to pick up later.
    /// Check if a recipient has SURBs available for delivery.
    fn has_surbs_for_tag(&self, tag: &ReplyTag) -> bool {
        if let Some(ref storage) = self.surb_storage {
            if let ReplyTag::Nym(nym_tag) = tag {
                let count = storage.available_surbs(nym_tag);
                log::debug!("SURB count for {}: {}", tag, count);
                return count > 0;
            }
        }
        // No surb_storage (stdio mode) or non-Nym tag — assume delivery works
        true
    }

    async fn relay_with_persistence(
        &mut self,
        recipient: &str,
        sender: &str,
        payload: &Value,
        action: &str,
    ) -> Result<String, String> {
        // Check if recipient has a sender_tag and SURBs available
        if let Some(recipient_tag) = self.get_user_sender_tag(recipient).await {
            if self.has_surbs_for_tag(&recipient_tag) {
                // SURBs available — deliver via SURB, no persistence needed
                self.send_unified_message(
                    &recipient_tag,
                    payload.clone(),
                    action,
                    recipient,
                    sender,
                )
                .await;

                log::info!(
                    "SURB delivery (action={}) from {} to {}",
                    action, sender, recipient
                );

                return Ok("surb_delivered".to_string());
            }

            log::info!(
                "SURBs exhausted for {}, persisting message (action={})",
                recipient, action
            );
        } else {
            log::info!(
                "No sender_tag for {}, persisting message (action={})",
                recipient, action
            );
        }

        // No sender_tag or SURBs exhausted — persist for drain-on-ping
        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        let pending_id = self
            .db
            .queue_pending_message(recipient, sender, &payload_str, action)
            .await
            .map_err(|e| format!("Failed to queue pending message: {}", e))?;

        log::info!(
            "Persisted pending message {} (action={}) from {} to {}",
            pending_id, action, sender, recipient
        );

        Ok(pending_id)
    }

    /// Persist a sealed sender message and attempt best-effort delivery.
    ///
    /// Similar to `relay_with_persistence` but uses type="sealed" in the
    /// outgoing message envelope so the client knows it is a sealed sender message.
    async fn relay_sealed_with_persistence(
        &mut self,
        recipient: &str,
        payload: &Value,
    ) -> Result<String, String> {
        let sender = "__sealed__";
        let action = "send";

        // Check if recipient has a sender_tag and SURBs available
        if let Some(recipient_tag) = self.get_user_sender_tag(recipient).await {
            if self.has_surbs_for_tag(&recipient_tag) {
                // SURBs available — deliver sealed message via SURB, no persistence
                let message = json!({
                    "type": "sealed",
                    "action": "send",
                    "sender": "__sealed__",
                    "recipient": recipient,
                    "payload": payload,
                    "signature": "server_signature",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "serverTime": chrono::Utc::now().timestamp()
                });

                let sig_payload_str = serde_json::to_string(payload).unwrap_or_default();
                if let Ok(signature) = self.crypto.sign_message(&self.client_id, &sig_payload_str) {
                    let mut signed_message = message;
                    signed_message["signature"] = json!(signature);

                    let msg_str = signed_message.to_string();
                    if let Err(e) = self.sender.send_reply(&recipient_tag, msg_str).await {
                        log::warn!("Failed to send sealed message to {}: {}", recipient, e);
                    }
                } else {
                    log::error!("Failed to sign sealed relay message");
                }

                log::info!("SURB delivery (sealed) to {}", recipient);
                return Ok("surb_delivered".to_string());
            }

            log::info!("SURBs exhausted for {}, persisting sealed message", recipient);
        } else {
            log::info!("No sender_tag for {}, persisting sealed message", recipient);
        }

        // No sender_tag or SURBs exhausted — persist for drain-on-ping
        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        let pending_id = self
            .db
            .queue_pending_message(recipient, sender, &payload_str, action)
            .await
            .map_err(|e| format!("Failed to queue sealed pending message: {}", e))?;

        log::info!("Persisted sealed pending message {} to {}", pending_id, recipient);
        Ok(pending_id)
    }

    /// Sign and send a JSON reply via the configured transport.
    async fn send_encapsulated_reply(
        &self,
        recipient: &ReplyTag,
        content: String,
        action: &str,
        context: Option<&str>,
    ) {
        log::info!(
            "Sending action '{}' to sender_tag={:?}, context={:?}",
            action,
            recipient,
            context
        );
        let mut payload = json!({"action": action, "content": content, "serverTime": chrono::Utc::now().timestamp()});
        if let Some(ctx) = context {
            payload["context"] = json!(ctx);
        }
        let to_sign = payload["content"].as_str().unwrap_or_default().to_string();
        if let Ok(signature) = self.crypto.sign_message(&self.client_id, &to_sign) {
            payload["signature"] = json!(signature);
            let msg = payload.to_string();
            if let Err(e) = self.sender.send_reply(recipient, msg).await {
                log::warn!("Failed to send encapsulated reply: {}", e);
            }
        } else {
            log::error!("sendEncapsulatedReply - failed to sign message");
        }
    }
    // ===== KEY PACKAGE MANAGEMENT =====

    async fn handle_publish_key_package(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
        sender_username: &str,
        signature: Option<&str>,
    ) {
        log::info!("Handling publishKeyPackage from {}", sender_username);

        // Verify sender exists
        let user_data = match self.db.get_user_by_username(sender_username).await {
            Ok(Some(data)) => data,
            Ok(None) => {
                log::warn!("publishKeyPackage: user {} not found", sender_username);
                self.send_unified_reply(
                    &sender_tag,
                    json!({"status": "error", "message": "user not registered"}),
                    "publishKeyPackageResponse",
                    sender_username,
                )
                .await;
                return;
            }
            Err(e) => {
                log::error!("publishKeyPackage: database error: {}", e);
                self.send_unified_reply(
                    &sender_tag,
                    json!({"status": "error", "message": "database error"}),
                    "publishKeyPackageResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };

        // Verify signature over "publishKeyPackage:{username}:{keyPackage_b64}" per protocol
        let public_key = &user_data.1;
        if let Some(sig) = signature {
            let key_package_b64 = payload.get("keyPackage").and_then(Value::as_str).unwrap_or("");
            let sign_content = format!("publishKeyPackage:{}:{}", sender_username, key_package_b64);
            if !self.crypto.verify_signature(public_key, &sign_content, sig) {
                log::warn!("publishKeyPackage: invalid signature from {}", sender_username);
                self.send_unified_reply(
                    &sender_tag,
                    json!({"status": "error", "message": "invalid signature"}),
                    "publishKeyPackageResponse",
                    sender_username,
                )
                .await;
                return;
            }
        } else {
            log::warn!("publishKeyPackage: missing signature from {}", sender_username);
            self.send_unified_reply(
                &sender_tag,
                json!({"status": "error", "message": "missing signature"}),
                "publishKeyPackageResponse",
                sender_username,
            )
            .await;
            return;
        }

        // Extract required fields
        let key_package = match payload.get("keyPackage").and_then(Value::as_str) {
            Some(v) => v,
            None => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"status": "error", "message": "missing keyPackage"}),
                    "publishKeyPackageResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let pgp_signature = match payload.get("pgpSignature").and_then(Value::as_str) {
            Some(v) => v,
            None => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"status": "error", "message": "missing pgpSignature"}),
                    "publishKeyPackageResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };
        let pgp_fingerprint = match payload.get("pgpFingerprint").and_then(Value::as_str) {
            Some(v) => v,
            None => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"status": "error", "message": "missing pgpFingerprint"}),
                    "publishKeyPackageResponse",
                    sender_username,
                )
                .await;
                return;
            }
        };

        // Store the key package
        if let Err(e) = self
            .db
            .store_key_package(sender_username, key_package, pgp_signature, pgp_fingerprint)
            .await
        {
            log::error!("publishKeyPackage: failed to store: {}", e);
            self.send_unified_reply(
                &sender_tag,
                json!({"status": "error", "message": "failed to store key package"}),
                "publishKeyPackageResponse",
                sender_username,
            )
            .await;
            return;
        }

        // Get updated count
        let count = self
            .db
            .count_key_packages(sender_username)
            .await
            .unwrap_or(0);

        log::info!(
            "publishKeyPackage: stored KP for {}, total count: {}",
            sender_username,
            count
        );

        self.send_unified_reply(
            &sender_tag,
            json!({"status": "success", "count": count}),
            "publishKeyPackageResponse",
            sender_username,
        )
        .await;
    }

    async fn handle_fetch_kp_challenge(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
    ) {
        let username = match payload.get("username").and_then(Value::as_str) {
            Some(v) => v,
            None => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "missing username"}),
                    "fetchKeyPackageChallengeResponse",
                    "anonymous",
                )
                .await;
                return;
            }
        };

        log::info!("Handling fetchKeyPackageChallenge for target {}", username);

        // Count available key packages
        let count = match self.db.count_key_packages(username).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("fetchKeyPackageChallenge: db error counting KPs: {}", e);
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "database error"}),
                    "fetchKeyPackageChallengeResponse",
                    "anonymous",
                )
                .await;
                return;
            }
        };

        if count == 0 {
            // Notify target that key packages are needed
            let notification = json!({"action": "keyPackageNeeded"}).to_string();
            if let Err(e) = self
                .db
                .queue_pending_message(username, "__system__", &notification, "keyPackageNeeded")
                .await
            {
                log::warn!("Failed to queue keyPackageNeeded notification for {}: {}", username, e);
            }

            self.send_unified_reply(
                &sender_tag,
                json!({"error": "no_key_packages"}),
                "fetchKeyPackageChallengeResponse",
                "anonymous",
            )
            .await;
            return;
        }

        if count == 1 {
            // Holdback: don't give out the last key package
            self.send_unified_reply(
                &sender_tag,
                json!({"error": "last_key_package"}),
                "fetchKeyPackageChallengeResponse",
                "anonymous",
            )
            .await;
            return;
        }

        // Compute difficulty: base 20, increased when KPs are scarce
        let difficulty: u32 = if count <= 3 {
            20 + (4 - count as u32) * 2
        } else {
            20
        };

        // Generate HMAC-SHA256 challenge
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let time_window = now / 300; // 5-minute windows
        let hmac_message = format!("{}{}", username, time_window);

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(self.client_id.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(hmac_message.as_bytes());
        let result = mac.finalize();
        let challenge_b64 = BASE64.encode(result.into_bytes());

        log::info!(
            "fetchKeyPackageChallenge: issuing challenge for {} with difficulty {} (count={})",
            username,
            difficulty,
            count
        );

        self.send_unified_reply(
            &sender_tag,
            json!({
                "challenge": challenge_b64,
                "difficulty": difficulty,
                "username": username
            }),
            "fetchKeyPackageChallengeResponse",
            "anonymous",
        )
        .await;
    }

    async fn handle_fetch_key_package(
        &mut self,
        payload: &Value,
        sender_tag: ReplyTag,
    ) {
        // Extract required fields
        let username = match payload.get("username").and_then(Value::as_str) {
            Some(v) => v,
            None => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "missing username"}),
                    "fetchKeyPackageResponse",
                    "anonymous",
                )
                .await;
                return;
            }
        };
        let challenge = match payload.get("challenge").and_then(Value::as_str) {
            Some(v) => v,
            None => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "missing challenge"}),
                    "fetchKeyPackageResponse",
                    "anonymous",
                )
                .await;
                return;
            }
        };
        let nonce = match payload.get("nonce").and_then(Value::as_str) {
            Some(v) => v,
            None => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "missing nonce"}),
                    "fetchKeyPackageResponse",
                    "anonymous",
                )
                .await;
                return;
            }
        };

        log::info!("Handling fetchKeyPackage for target {}", username);

        // Verify challenge: recompute HMAC for current and previous 5-min windows
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        type HmacSha256 = Hmac<Sha256>;
        let challenge_valid = [now / 300, (now / 300).saturating_sub(1)].iter().any(|&window| {
            let hmac_message = format!("{}{}", username, window);
            let mut mac = HmacSha256::new_from_slice(self.client_id.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(hmac_message.as_bytes());
            let result = mac.finalize();
            let expected = BASE64.encode(result.into_bytes());
            expected == challenge
        });

        if !challenge_valid {
            log::warn!("fetchKeyPackage: invalid challenge for {}", username);
            self.send_unified_reply(
                &sender_tag,
                json!({"error": "invalid_challenge"}),
                "fetchKeyPackageResponse",
                "anonymous",
            )
            .await;
            return;
        }

        // Determine difficulty based on current KP count
        let count = match self.db.count_key_packages(username).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("fetchKeyPackage: db error counting KPs: {}", e);
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "database error"}),
                    "fetchKeyPackageResponse",
                    "anonymous",
                )
                .await;
                return;
            }
        };

        let difficulty: u32 = if count <= 3 {
            20 + (4 - count as u32) * 2
        } else {
            20
        };

        // Verify PoW: SHA256(username || challenge || nonce) must have `difficulty` leading zero bits
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(challenge.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();

        if !has_leading_zero_bits(&hash, difficulty) {
            log::warn!(
                "fetchKeyPackage: invalid PoW for {} (required {} leading zero bits)",
                username,
                difficulty
            );
            self.send_unified_reply(
                &sender_tag,
                json!({"error": "invalid_pow", "difficulty": difficulty}),
                "fetchKeyPackageResponse",
                "anonymous",
            )
            .await;
            return;
        }

        // Consume a key package (respects holdback)
        let kp = match self.db.consume_key_package(username).await {
            Ok(Some(kp)) => kp,
            Ok(None) => {
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "no_key_packages"}),
                    "fetchKeyPackageResponse",
                    "anonymous",
                )
                .await;
                return;
            }
            Err(e) => {
                log::error!("fetchKeyPackage: db error consuming KP: {}", e);
                self.send_unified_reply(
                    &sender_tag,
                    json!({"error": "database error"}),
                    "fetchKeyPackageResponse",
                    "anonymous",
                )
                .await;
                return;
            }
        };

        let (key_package_b64, pgp_signature, pgp_fingerprint) = kp;

        // Get user's public key
        let public_key = match self.db.get_user_by_username(username).await {
            Ok(Some((_u, pk, _tag))) => pk,
            _ => String::new(),
        };

        log::info!("fetchKeyPackage: served KP for {}", username);

        self.send_unified_reply(
            &sender_tag,
            json!({
                "username": username,
                "keyPackage": key_package_b64,
                "pgpSignature": pgp_signature,
                "pgpFingerprint": pgp_fingerprint,
                "publicKey": public_key
            }),
            "fetchKeyPackageResponse",
            "anonymous",
        )
        .await;
    }
}

/// Check if a hash has the required number of leading zero bits.
fn has_leading_zero_bits(hash: &[u8], required_bits: u32) -> bool {
    let full_bytes = (required_bits / 8) as usize;
    let remaining_bits = required_bits % 8;

    for i in 0..full_bytes {
        if hash[i] != 0 {
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

// Validation tests are in nymstr-common::validation::tests
