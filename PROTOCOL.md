# Nymstr Messaging Protocol Specification

**Version**: 3.0 (pre-published key packages)  
**Date**: 2026-04-10

## 1. Transport

All messages are JSON-serialized and sent over the **Nym mixnet**. The mixnet provides network-layer anonymity (IP address hiding). Messages are routed through a central **discovery/relay server** for delivery.

Communication is **message-based** (not stream-based). Delivery is **store-and-forward**: the server persists every relayed message and the client polls for missed messages.

## 2. Message Envelope

Every message follows this structure:

```json
{
  "type": "system|message|sealed|response",
  "action": "<action_name>",
  "sender": "<username>",
  "recipient": "<username|server>",
  "payload": { },
  "signature": "<PGP detached signature>",
  "timestamp": "<RFC3339>",
  "serverTime": <unix_epoch_optional>
}
```

| Field | Required | Description |
|---|---|---|
| `type` | yes | `system` (auth/control), `message` (relayed), `sealed` (sealed sender), `response` (server reply) |
| `action` | yes | Specific action name |
| `sender` | yes* | Username of sender. `"anonymous"` for queries and KP fetches |
| `recipient` | yes | Target username or `"server"` |
| `payload` | yes | Action-specific JSON object |
| `signature` | yes* | PGP detached signature (base64 or armored). `"placeholder"` for unsigned actions |
| `timestamp` | yes | Client-side RFC3339 timestamp |
| `serverTime` | no | Unix epoch seconds, present in server responses for clock sync |

## 3. Signature Scheme

Signatures use **PGP Ed25519 detached signatures**. The server reads signatures from the **top-level `signature` field**, never from inside `payload`.

What gets signed depends on the action:

| Action | Signed Content |
|---|---|
| `registrationResponse` / `loginResponse` | The nonce string from the challenge |
| `publishKeyPackage` | `"publishKeyPackage:{username}:{keyPackage_b64}"` |
| `send` | `serde_json::to_string(&payload)` |
| `ping` | `"ping:{username}:{timestamp}"` |
| `p2pWelcome` | The welcome message bytes (base64) |
| `p2pWelcomeAck` | `"p2pWelcomeAck:{sender}:{conversationId}:{accepted}"` |

Verification: the server hashes the content with SHA-256, then verifies the PGP signature using the sender's stored public key.

## 4. Authentication

### 4.1 Registration

```
Client                          Server
  |-- register ------------------>|   (username + publicKey)
  |<-- challenge -----------------|   (nonce, context="registration")
  |-- registrationResponse ------>|   (signature over nonce)
  |<-- challengeResponse ---------|   (result="success" + serverPublicKey)
  |                               |
  |-- publishKeyPackage (×5) ---->|   (signed MLS key package bundles)
```

#### `register` (client → server)
- **type**: `system`
- **payload**: `{ "username": "<name>", "publicKey": "<armored PGP>" }`
- **signature**: `"placeholder"` (unsigned — no key registered yet)
- **server**: validates username (alphanumeric + `-_`), checks uniqueness, generates UUID nonce

#### `challenge` (server → client)
- **type**: `system`
- **payload**: `{ "nonce": "<uuid>", "context": "registration" }`

#### `registrationResponse` (client → server)
- **type**: `system`
- **payload**: `{ "context": "registration" }`
- **signature**: PGP signature over the nonce string

#### `challengeResponse` (server → client)
- **type**: `response`
- **payload**: `{ "result": "success|error", "context": "registration", "serverPublicKey": "<armored>" }`
- On success: user added to DB with public key and current sender tag. Client then publishes 5 signed key package bundles (see Section 6).

### 4.2 Ping/Pong (Session Init)

Replaces login. Single round-trip — client signs a timestamp, server verifies against stored public key.

```
Client                          Server
  |-- ping ---------------------->|   (signed timestamp, 200 SURBs)
  |<-- pong ----------------------|   (status, serverTime)
  |                               |   (+ drain any pending messages)
  |-- publishKeyPackage (×5) ---->|   (signed MLS key package bundles)
```

#### `ping` (client → server)
- **type**: `system`
- **payload**: `{ "timestamp": <unix_epoch> }`
- **signature**: PGP signature over `"ping:{username}:{timestamp}"`
- **SURBs**: Client sends 200 SURBs to fill server's SURB pool
- **server**: verifies user exists, verifies PGP signature, validates timestamp freshness (±300s), updates sender_tag, drains pending messages

#### `pong` (server → client)
- **type**: `response`
- **payload**: `{ "status": "success|error", "serverTime": <unix_epoch> }`
- On success: sender_tag updated, pending messages drained via SURB delivery

## 5. Anonymous Queries

Queries do **not** require authentication. The sender field is set to `"anonymous"`. Since the mixnet hides the requester's network identity, the server cannot determine who made the query.

#### `query` (client → server)
- **type**: `system`
- **sender**: `"anonymous"`
- **payload**: `{ "username": "<target>" }`
- **signature**: `"placeholder"` (no auth required)

#### `queryResponse` (server → client)
- **type**: `response`
- **payload**: `{ "username": "<target>", "publicKey": "<armored PGP>", "type": "user" }`
- If user not found: `{ "error": "not_found" }`

## 6. Pre-Published Key Packages

Users pre-publish signed MLS key packages to the server after registration/login. Other users fetch these to initiate conversations without requiring the target to be online.

### 6.1 Key Package Bundles

Each published bundle contains:
- `keyPackage`: Base64-encoded MLS key package bytes
- `pgpSignature`: PGP detached signature over the raw key package bytes
- `pgpFingerprint`: Hex fingerprint of the signing PGP key

The PGP signature prevents the server from substituting its own key package (MITM protection). The fetcher verifies the signature against the target's PGP public key before using it.

### 6.2 Publishing

#### `publishKeyPackage` (client → server, authenticated)
- **type**: `system`
- **payload**: `{ "keyPackage": "<base64>", "pgpSignature": "<signature>", "pgpFingerprint": "<hex>" }`
- **signature**: signs `"publishKeyPackage:{username}:{keyPackage_b64}"`
- **server**: verifies sender exists, stores in `key_packages` table
- **response**: `{ "status": "success", "count": N }`

Clients publish 5 bundles after registration/login. Bundles expire after 30 days. Clients replenish when count drops below 3.

### 6.3 Fetching (with Proof-of-Work)

Fetching key packages is **anonymous** but requires a **proof-of-work** to prevent exhaustion attacks.

#### Step 1: `fetchKeyPackageChallenge` (client → server, anonymous)
- **type**: `system`
- **sender**: `"anonymous"`
- **payload**: `{ "username": "<target>" }`
- **response**: `{ "challenge": "<base64 HMAC>", "difficulty": N, "username": "<target>" }`
- **difficulty**: base=20, increases as target's KP count decreases (+2 per KP below 3)
- **errors**: `no_key_packages` (target has 0), `last_key_package` (holdback — server never gives out the last one)

When target has 0 KPs, the server queues a `keyPackageNeeded` notification to the target's pending messages. The target's client auto-publishes fresh bundles when it receives this.

#### Step 2: Grind PoW nonce
Client computes `SHA256(target_username || challenge || nonce)` incrementing `nonce` until the hash has `difficulty` leading zero bits. At difficulty=20, this takes ~0.5s.

#### Step 3: `fetchKeyPackage` (client → server, anonymous)
- **type**: `system`
- **sender**: `"anonymous"`
- **payload**: `{ "username": "<target>", "challenge": "<base64>", "nonce": "<string>" }`
- **server**: verifies challenge HMAC (stateless, 5-minute window), verifies PoW hash, consumes one key package
- **response**: `{ "username", "keyPackage", "pgpSignature", "pgpFingerprint", "publicKey" }`
- `publicKey` is the target's armored PGP public key (from `users` table)

### 6.4 Server-Side Rules

- **Holdback**: server never gives out the last key package (ensures user is always reachable)
- **Expiry**: key packages expire after 30 days, cleaned up periodically
- **PoW challenge**: HMAC-SHA256 keyed on server's client_id, message = `username || floor(timestamp/300)`. Stateless, valid for 5 minutes.
- **Adaptive difficulty**: fewer remaining KPs → harder PoW

## 7. DM Handshake (MLS Key Exchange)

Establishing a direct message conversation requires 2 round-trips using pre-published key packages.

```
[Prior] Bob published key packages to server

Alice (initiator)               Server                    Bob (responder)
  |                               |                         |
  |-- fetchKPChallenge [anon] --->|                         |
  |<-- challenge + difficulty ----|                         |
  |   (grinds PoW ~0.5s)         |                         |
  |-- fetchKP [anon + PoW] ----->|                         |
  |<-- KP bundle + publicKey ----|                         |
  |                               |                         |
  |   (verifies PGP signature)   |                         |
  |   (creates MLS group)        |                         |
  |   (deferred commit)          |                         |
  |                               |                         |
  |-- p2pWelcome [system] ------>|-- p2pWelcome ---------->|
  |                               |                         |
  |                               |   (message request UI) |
  |                               |   (user accepts)       |
  |                               |   (joins MLS group)    |
  |                               |                         |
  |                               |<-- p2pWelcomeAck ------|
  |<-- p2pWelcomeAck -------------|                         |
  |                               |                         |
  |   (applies pending commit)   |                         |
  |========== conversation ready ===========================|
  |   Bob publishes replacement KP                         |
```

### 7.1 `p2pWelcome`
- **type**: `system` (relayed through server; server sees sender/recipient but not message content)
- **payload**: `{ "welcomeMessage": "<base64>", "groupId": "dm:alice:bob", "commitMessage": "<base64>", "ratchetTree": "<base64>" }`
- **server**: persists and relays as opaque blob
- **responder (known contact)**: auto-joins MLS group, sends ack
- **responder (unknown sender)**: stored as "message request" in UI, user must accept before joining

### 7.2 `p2pWelcomeAck`
- **type**: `system`
- **payload**: `{ "conversationId": "dm:alice:bob", "accepted": true|false }`
- **signature**: signs `"p2pWelcomeAck:{sender}:{conversationId}:{accepted}"`
- **initiator on accepted=true**: applies deferred commit, conversation ready
- **initiator on accepted=false**: cleans up pending handshake

### 7.3 Conversation IDs

Normalized as `dm:{user1}:{user2}` where users are sorted alphabetically. This ensures both sides use the same ID regardless of who initiated.

### 7.4 Pending Messages

Messages sent before the handshake completes are stored with `status = 'pending'`. After the handshake finalizes (p2pWelcomeAck received or p2pWelcome auto-joined), pending messages are drained and sent automatically.

### 7.5 KP Exhaustion Fallback

If the target has no key packages, the client stores the intent in `pending_outreach` and retries with backoff. The server notifies the target via `keyPackageNeeded`. When the target comes online and replenishes, the retry succeeds.

## 8. Sealed Sender Messages

For encrypted DMs, the sender's identity is hidden from the server using **sealed sender** encryption. The server only sees the recipient (for routing) and an opaque blob.

### 8.1 Wire Format

```json
{
  "type": "sealed",
  "action": "send",
  "recipient": "bob",
  "payload": {
    "sealed_payload": "<base64>"
  },
  "signature": "placeholder",
  "timestamp": "<RFC3339>"
}
```

No `sender` field. No verifiable signature. The server routes blindly by `recipient`.

### 8.2 Sealed Envelope Construction

The `sealed_payload` is constructed by the sender:

**Step 1**: Build the inner content:
```json
{
  "sender": "alice",
  "sender_key_fingerprint": "<hex fingerprint of alice's PGP key>",
  "payload": {
    "conversation_id": "<base64>",
    "mls_message": "<base64>"
  },
  "signature": "<PGP signature over sender:timestamp:payload_json>",
  "timestamp": <unix_epoch>
}
```

**Step 2**: Encrypt to recipient's public key:
1. Generate ephemeral X25519 keypair
2. Extract recipient's Curve25519 public key from their PGP ECDH subkey
3. Perform X25519 ECDH → shared secret
4. HKDF-SHA256(shared_secret, info="nymstr-sealed-sender-v1") → 32-byte AES key
5. Generate random 12-byte nonce
6. AES-256-GCM encrypt the serialized inner content

**Step 3**: Wire format of `sealed_payload` (binary, then base64-encoded):
```
[ephemeral_public_key: 32 bytes]
[nonce: 12 bytes]
[ciphertext + GCM tag: variable]
```

### 8.3 Unsealing (Recipient)

1. Decode `sealed_payload` from base64
2. Parse: ephemeral key (32B), nonce (12B), ciphertext (rest)
3. X25519 ECDH with own secret key + ephemeral public key → shared secret
4. HKDF-SHA256 → AES key
5. AES-256-GCM decrypt → inner content JSON
6. Verify PGP signature using `sender_key_fingerprint` (look up full key from contacts DB)
7. Check timestamp freshness (reject if > 24 hours old)
8. Process inner `payload` as a normal MLS message

### 8.4 Server Handling

The server treats sealed messages as opaque:
- Does **not** verify any signature
- Does **not** read the sender
- Looks up recipient's sender tag for routing
- Persists to pending queue with `sender = "__sealed__"`
- Rate limits by sender_tag

### 8.5 What the Server Sees

| Field | Visible to Server |
|---|---|
| Recipient username | Yes (needed for routing) |
| Sender username | No |
| Message content | No (MLS encrypted inside sealed envelope) |
| Conversation ID | No (inside sealed envelope) |
| Sender's signature | No (inside sealed envelope) |
| Message size | Yes (inherent) |
| Timing | Yes (inherent) |

## 9. Message Delivery

### 9.1 SURB-Based Delivery

The server delivers messages to clients using SURBs (Single Use Reply Blocks) — the server never learns client Nym addresses. When a message arrives for a recipient:

1. **SURBs available**: Server sends immediately via SURB (fire-and-forget)
2. **SURBs exhausted**: Message persisted to `pending_messages` table for later delivery

### 9.2 Pending Message Drain

When a client sends a `ping`, the server receives 200 fresh SURBs and drains any pending messages:
1. Fetch all pending messages for the user
2. Deliver each via SURB using fresh SURBs from the ping
3. Delete successfully sent pending messages

### 9.3 Gateway Caching (Offline Delivery)

Clients use **persistent Nym identities** (same address across sessions). Nym gateways cache messages for persistent identities when the client is offline. When the client reconnects, the gateway delivers cached messages automatically.

### 9.4 SURB Replenishment

- Client sends 200 SURBs on each ping (session init)
- The Nym SDK's transport layer automatically requests more SURBs from the client when the pool runs low (using 10 reserved SURBs)
- No application-level polling required — SURB management is handled at the transport layer

## 10. Rate Limiting

| Scope | Limit | Applies To |
|---|---|---|
| Auth | 10/60s per sender_tag | register, ping, registrationResponse |
| Send | 60/60s per sender_tag | send, sealed send, p2pWelcome, p2pWelcomeAck |
| KP Fetch | PoW required | fetchKeyPackage (adaptive difficulty, see Section 6.3) |

## 11. Database Schema

### Server (`nymstr-server`)

**users**: `username` (PK), `public_key`, `sender_tag`, `created_at`

**key_packages**: `id` (PK, auto), `username`, `key_package_b64`, `pgp_signature`, `pgp_fingerprint`, `device_id` (default "primary"), `created_at`, `expires_at` (30 days)

**pending_messages**: `id` (PK, UUID), `recipient`, `sender`, `payload` (JSON), `action`, `created_at`, `expires_at` (7 days) — fallback buffer for messages when SURB delivery fails; drained on next ping

### Client (`app/desktop`)

**conversations**: `id` (PK, `dm:user1:user2`), `mls_group_id` (base64)

**pending_handshakes**: `recipient` (PK), `mls_group_id`, `conversation_id`, `created_at`

**pending_outreach**: `recipient` (PK), `message_draft`, `created_at`, `retry_count`

**messages**: `id` (PK, UUID), `conversation_id`, `sender`, `content`, `timestamp`, `status`, `is_own`, `is_read`

**contact_requests**: `id` (PK), `from_username` (unique), `received_at`, `status`, `welcome_payload`

**contacts**: `(owner_username, username)` (PK), `display_name`, `public_key`, `last_seen`, `created_at`

**query_cache**: `username` (PK), `public_key`, `cached_at`

## 12. Security Properties

| Property | Mechanism |
|---|---|
| Network anonymity | Nym mixnet (IP hidden) |
| Sender anonymity (from server) | Sealed sender (Section 8) |
| Message confidentiality | MLS (RFC 9420) with AES-256-GCM |
| Forward secrecy | MLS epoch rotation |
| Authentication | PGP Ed25519 challenge-response |
| Key package integrity | PGP-signed bundles (Section 6.1) |
| Replay protection | Nonces (registration), timestamps (ping ±300s) |
| Anti-spam (messages) | Rate limiting by sender_tag |
| Anti-spam (KP exhaustion) | Proof-of-work with adaptive difficulty (Section 6.3) |
| KP holdback | Server never gives out the last key package |

### Metadata visible to server
- Recipient username (required for routing)
- Message size and timing
- That a user initiated a session (ping — but no periodic presence leakage)
- Who has published key packages (but not who fetches them)

### Metadata NOT visible to server
- Sender identity (sealed sender)
- Message content (MLS)
- Conversation participants (sealed envelope)
- Query targets (anonymous queries)
- Who is fetching key packages (anonymous + PoW)

### Assumptions
- **Single device per user.** The `device_id` field in `key_packages` is reserved for future multi-device support but is not implemented. Logging in from a second device overwrites the sender_tag, making the first device unable to receive messages.
- **Trust-on-first-use (TOFU) for server public key.** The server's PGP public key is received during registration and trusted without out-of-band verification.
