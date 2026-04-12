# Nymstr Frontend Wiring Spec

Target: a UI engineer who already has a v0-style React component library and
needs to connect it to the nymstr Tauri backend with 1:1 parity with the
existing desktop app.

---

## 0. Stack & conventions

- **Build**: Vite + React 19 + TypeScript, Tailwind v4 + shadcn primitives, Tauri 2.
- **Backend bridge**: `src/services/api.ts` — typed wrappers around Tauri
  `invoke()` commands. Never call `invoke` from components directly.
- **Event stream**: `src/services/events.ts` — Tauri event subscription.
  Subscribe exactly once at the app root via `useAppEvents()`.
- **State**: Zustand stores in `src/stores/`:
  `authStore`, `chatStore`, `groupStore`, `connectionStore`, `toastStore`.
- **Types**: `src/types/index.ts` is the source of truth. Do not invent a
  parallel shape for the UI — consume backend types directly and render them.
- **Toasts**: `showToast.{success,error,info,warning}(title, message?)`.
- **Auth guard**: `App.tsx` renders `<AuthView>` when `authStore.status !==
  'authenticated'`. Everything else in this spec assumes authenticated state.

## 1. App-root responsibilities (`App.tsx`)

1. `useAppEvents()` — mounts event subscriptions (messages, presence, welcomes,
   contact requests, message status, connection, group registration, system).
2. On mount: `api.initialize()` → sets auth status to `unauthenticated`.
   The auth flow itself sets `authenticated` on success.
3. When `status === 'authenticated'`: load `api.getContacts()` → map to
   `Conversation[]` and `api.getJoinedGroups()` → merge in. Hydrate
   `chatStore.conversations`.
4. Render tree:
   - `loading` / `authenticating` → spinner with progress message
   - `unauthenticated` → `<AuthView />`
   - `authenticated` → `<MessengerPage />`
   - Always: `<ToastContainer />` + `<ErrorBoundary>`.

## 2. AuthView (`components/ported/auth-view.tsx`)

### State
- `mode: 'login' | 'register'`
- `username`, `passphrase`, `confirmPassphrase`
- `isLoading`, `error`
- `currentStep`, `completedSteps` (for `<ProgressStepper>`)
- `serverAddress` (for server settings dropdown)

### Flow — Register
1. Validate inputs (non-empty username, passphrase match).
2. Step `generating_keys` → mark complete.
3. Step `connecting_mixnet` → `await api.connectToMixnet()`.
4. Step `registering` → `const user = await api.registerUser(username, passphrase)`.
5. Step `initializing_mls` → mark complete.
6. `authStore.setAuthenticated(user)`.

### Flow — Login (ping/pong, not legacy login)
1. Validate inputs.
2. Step `loading_keys` → mark complete.
3. Step `connecting_mixnet` → `await api.connectToMixnetForUser(username)`.
4. Step `authenticating` → `const user = await api.pingServer(username, passphrase)`.
5. Step `loading_conversations` → mark complete.
6. `authStore.setAuthenticated(user)`.

### Server address settings
- Load on mount: `api.getServerAddress()` → populate input + `connectionStore.setServerAddress`.
- Save: `api.setServerAddress(addr)` + update store.

### Error handling
- Catch any thrown error; show via `setError(msg)`.
- Steps remain at the step that threw, styled as error.

## 3. MessengerPage (`components/ported/messenger-page.tsx`)

Top-level authenticated layout.

### Store subscriptions
- `conversations`, `activeConversationId`, `setActiveConversation` from `chatStore`.
- `contactRequests`, `pendingWelcomes` lengths from `groupStore` for the inbox badge.
- `user` from `authStore` for the sidebar avatar.

### Sidebar (left column)
1. Header: user avatar (initials fallback), title "Messages", icon buttons:
   - **New message** → toggles `UserSearch` panel.
   - **Join group** → opens `<GroupJoinModal>`.
   - **Inbox** → toggles `MessageRequests` panel; badge = `contactRequests.length + pendingWelcomes.length`.
   - **Settings** → toggles `SettingsPanel`.
2. Search input: local filter over `conversations` by `conv.name`.
3. `<ConversationList>` fed the filtered list.

### Right column (one of)
- `<SettingsPanel onClose />`
- `<UserSearch onOpenConversation onClose />`
- `<MessageRequests onClose onOpenConversation />`
- `<ChatView conversation onBack />` when a conversation is selected
- `<EmptyChat />` otherwise

### Selection
`handleSelectConversation(id)` → `setActiveConversation(id)` (store handles
clearing unreadCount) → switch panel to `chat`.

## 4. ConversationList (`components/ported/conversation-list.tsx`)

### Props
```ts
interface Props {
  conversations: Conversation[];  // backend Conversation type
  selectedId: string | null;
  onSelect: (id: string) => void;
}
```

### Rendering rules
- Empty state when `conversations.length === 0`.
- Each row:
  - `Avatar` with `AvatarFallback` = first two letters of `conv.name`
    (group: `<Users>` icon instead).
  - Presence dot for `conv.type === 'direct'`: green if `conv.online`, grey otherwise.
  - Name = `conv.name`.
  - Timestamp = `formatDistanceToNow(new Date(conv.lastMessageTime))` when present.
  - Unread badge when `conv.unreadCount > 0`.
  - Truncated `conv.lastMessage` preview.
- Highlight row when `selectedId === conv.id`.

## 5. ChatView (`components/ported/chat-view.tsx`)

### Props
```ts
interface Props {
  conversation: Conversation;
  onBack?: () => void;  // mobile back button
}
```

### Hooks
- `useMessages(conversationId)` when `type === 'direct'` — returns
  `{ messages, sendMessage, fetchMessages }` and auto-loads 50 messages on
  mount + calls `api.markAsRead` on the latest incoming message.
- `useChatStore(s => s.messages.get(conversationId))` when `type === 'group'`
  — group messages are populated by event handlers.
- `useMessageSend(conversationId, conversation.type)` — optimistic send that
  dispatches to `api.sendMessage` or `api.sendGroupMessage`.
- `useChatStore(s => s.pendingHandshakes.has(conversationId))` — disable
  composer with "Setting up secure session..." placeholder while true.

### Header
- Back button (mobile only).
- Avatar with initials fallback (direct) or `<Users>` (group).
- Title = `conversation.name`; subtitle = online/offline or `N members`.

### Messages area
- Iterate messages in chronological order.
- Each message uses `msg.isOwn` for alignment.
- Group chats only: show sender name above non-own bubbles
  (`msg.senderDisplayName || msg.sender`).
- Status icon (own messages only):
  - `pending | encrypting` → clock
  - `sent` → single check
  - `delivered` → double check (accent color)
  - `failed` → alert icon (destructive color)
- Timestamp: `format(new Date(msg.timestamp), 'h:mm a')`.
- Auto-scroll to bottom on new messages.

### Composer
- Input (disabled while `pendingHandshake`).
- Enter (no shift) submits. Empty submissions ignored.
- On send: clear draft, call `sendMessage(content)`. Do NOT manually add to
  the store — `useMessageSend` handles the optimistic insert + status.

## 6. UserSearch (`components/ported/user-search.tsx`)

Single-username lookup, not a live search box.

### Hook
`useNewConversation()` returns `{ status, error, startConversation, reset }`.
Status machine: `idle → querying → (not_found | initiating → pending_handshake | error)`
or `idle → querying → ready` (if already have a conversation).

### Flow
1. User enters a username (strip leading `@`).
2. Submit → `await startConversation(username)`:
   - `api.queryUser(username)`; if `null` → status `not_found`.
   - `api.checkConversationExists(username)`; if true → status `ready`, return username.
   - Else: `chatStore.addPendingHandshake(username)`, `api.initiateConversation(username)`, `api.addContact(username)` → status `pending_handshake`.
3. On result: `onOpenConversation(username)`; toast "Request sent" or "Opening conversation".

### UI states
- `idle`: friendly prompt with search icon.
- `querying` / `initiating`: spinner + label.
- `not_found`: "No user found for @xyz".
- `pending_handshake`: "Request sent. Waiting for @xyz to accept."
- `error`: destructive alert with `error` text.

## 7. MessageRequests / Inbox (`components/ported/message-requests.tsx`)

Combines DM contact requests + MLS group welcomes into one list.

### Data
- On mount:
  - `api.getContactRequests()` → `groupStore.setContactRequests`.
  - `api.getPendingWelcomes()` → `groupStore.setPendingWelcomes`.
- Live updates flow in via `useAppEvents()`.

### Contact request row
- Accept: `const { conversationId } = await api.acceptContactRequest(fromUsername)`.
  - `chatStore.addConversation({ id: conversationId, type: 'direct', name: fromUsername, unreadCount: 0 })`.
  - `groupStore.removeContactRequest(request.id)`.
  - `onOpenConversation(conversationId)`.
- Decline: `api.denyContactRequest(fromUsername)` → `removeContactRequest`.

### Pending welcome row
- Show `groupName || 'Group ${groupId[:8]}'` and "Invite from @sender".
- Accept: `setProcessingWelcome(id, true)` → `api.processWelcome(id)` →
  `removePendingWelcome(id)`. Group will be added by the backend emitting
  `GroupRegistrationSuccess` or by the next `getJoinedGroups` refresh.
- Deny: `api.denyWelcome(id)` → `removePendingWelcome(id)`.
- Disable buttons while `processingWelcomes.has(id)`.

### Empty state
When both lists empty: inbox icon + "Nothing pending" + description.

## 8. SettingsPanel (`components/ported/settings-panel.tsx`)

### Data
- `user = authStore.user` (`User { username, displayName, publicKey, online }`).
- Username and public key are **read-only** — backend does not support rename.
- Public key copy: `navigator.clipboard.writeText(user.publicKey)`.

### Logout
```ts
await api.logout();       // always; ignore errors
chatStore.reset();
groupStore.reset();
authStore.logout();       // flips status to 'unauthenticated'
showToast.info('Logged out');
```

## 9. GroupJoinModal (`components/ported/group-join-modal.tsx`)

Overlay (backdrop + centered card), opened from sidebar.

### Discoverable list
- On mount: `setDiscovering(true)`, `api.discoverGroups()` →
  `groupStore.setDiscoveredGroups`, `setDiscovering(false)`.
- Refresh button repeats the call.

### Join flows
Use `useGroupJoin()` → `{ joinGroup, isJoining, isJoined, isPendingApproval }`.
Both "join by address" form and "join discovered" button call
`await joinGroup(address, name?)`. On success:
- `groupStore.addJoinedGroup` (done by hook).
- `chatStore.addConversation({ id: address, type: 'group', name, ... })` (done by hook).
- `onJoined(address)` → caller sets it as active conversation and closes modal.

Pending-approval detection: the hook catches errors containing "pending",
"approval", or "waiting" and transitions to the pending state.

## 10. Event subscriptions (`useAppEvents` — already wired)

Map of event → action. If the UI feels "stale", check these first.

| Event | Store action |
|---|---|
| `MessageReceived` | `chatStore.addMessage` + `updateConversation(lastMessage/Time)` + `incrementUnread` if not active, else `api.markAsRead` |
| `MessageSent / Delivered / Failed` | `chatStore.updateMessageStatus` + `setMessageSending(false)` |
| `MixnetConnected / Disconnected` | `connectionStore.setConnected / setDisconnected` |
| `ContactOnline` | `chatStore.updateContactOnlineStatus` |
| `ContactRequestReceived` | `groupStore.addContactRequest` + toast |
| `WelcomeReceived / GroupInviteReceived` | `groupStore.addPendingWelcome` |
| `GroupRegistrationPending / Success / Failed` | `groupStore.addPendingApproval` / `removeJoiningGroup` + toast |
| `LoginSuccess / LoginFailed / RegistrationSuccess / RegistrationFailed` | toast only; auth state is set by the auth flow itself |

## 11. Sending a message — canonical path

```
User types → Enter → useMessageSend.sendMessage(content)
  1. Build optimistic Message { id: 'temp-…', status: 'pending', isOwn: true }
  2. chatStore.addMessage(conversationId, optimistic)
  3. chatStore.setMessageSending(tempId, true)
  4. api.sendMessage(conversationId, content)   // or sendGroupMessage
  5. on success: updateMessageStatus(tempId, 'sent'); setMessageSending(false)
  6. on failure: updateMessageStatus(tempId, 'failed')
  Backend emits MessageSent/Delivered events → updateMessageStatus again as it progresses.
```

Do not manually replay the returned `Message` into the store — the events
will supply the real ID and status.

## 12. Lifecycle invariants (things that WILL break the app)

- **Keep `useAppEvents()` at the root.** It registers a single Tauri listener.
  Mounting it in a child remounts the listener on every re-render.
- **Use `chatStore.setActiveConversation(id)`**, not a local `selectedId`.
  The store clears unreadCount as a side effect.
- **Conversation IDs:**
  - Direct: the peer username.
  - Group: the group's Nym address.
  Do not derive IDs from `dm:a:b` normalized strings — the event handler
  already maps those back to the peer username.
- **Never mutate `messages: Map`** — always build a new Map and set it.
  Zustand only triggers re-renders on reference change.
- **Timestamps** from the backend are ISO strings; wrap in `new Date()`
  before passing to `date-fns`.
- **Avatars**: the backend has no avatar URLs. Use `<AvatarFallback>` with
  initials — do not add `AvatarImage` with made-up URLs.
- **Do not re-introduce a login/fetchPending/ack flow.** The protocol is
  ping/pong only (`api.pingServer`). `pending_poller` is deleted on purpose.

## 13. File map

```
src/
  App.tsx                                  // root + auth guard
  main.tsx
  services/
    api.ts                                 // Tauri command wrappers (source of truth)
    events.ts                              // Tauri event subscription
  stores/
    authStore.ts   chatStore.ts
    groupStore.ts  connectionStore.ts  toastStore.ts
  hooks/
    useAppEvents.ts      // MOUNT ONCE
    useMessages.ts       // direct conversation message lifecycle
    useMessageSend.ts    // optimistic send + status
    useNewConversation.ts// username → handshake flow
    useGroupJoin.ts      // group join flow + pending/joining state
    useToast.ts          // showToast.* helpers
  lib/
    utils.ts             // cn()
    types.ts             // zip-style types — being phased out, prefer /types
  types/index.ts         // backend-aligned types (USE THIS)
  components/
    shadcn/              // primitives: button, input, avatar, field, label, separator
    ported/              // ported v0 UI wired to backend
      auth-view.tsx
      messenger-page.tsx
      conversation-list.tsx
      chat-view.tsx
      user-search.tsx
      message-requests.tsx
      settings-panel.tsx
      group-join-modal.tsx
      empty-chat.tsx
      progress-stepper.tsx
    ui/                  // legacy — Toast + ErrorBoundary still in use
    ErrorBoundary.tsx
```

## 14. Testing checklist (must pass before calling this done)

- [ ] Fresh install → register → land in empty messenger.
- [ ] Logout → login same user (ping path) → conversations reload.
- [ ] Start new conversation with a nonexistent user → "not found".
- [ ] Start new conversation with a real user → pending_handshake → peer
      accepts → conversation becomes active and messages can be sent.
- [ ] Send a DM → appears optimistically → status transitions to delivered.
- [ ] Receive a DM while conversation inactive → unread badge increments.
- [ ] Receive a DM while conversation active → no badge, marked read in DB.
- [ ] Contact request inbox: accept → conversation appears; deny → removed.
- [ ] Join group by address → appears in sidebar with group icon.
- [ ] Send group message → delivered to other members.
- [ ] Receive MLS welcome → inbox → accept → group appears in sidebar.
- [ ] Mixnet disconnect → connection store reflects it; reconnect restores.
- [ ] Logout clears all stores (no leaked conversations after re-login).
