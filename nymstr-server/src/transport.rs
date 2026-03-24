//! Transport abstraction layer for mixnet and stdio-based communication.
//!
//! Provides a `ReplyTag` enum and `ReplySender` trait so that `MessageUtils`
//! can operate identically over the Nym mixnet or a stdio pipe (for testing).

use async_trait::async_trait;
use nym_sdk::mixnet::{AnonymousSenderTag, MixnetClientSender, MixnetMessageSender};
use serde_json::json;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// A reply destination — either a real Nym SURB tag or a stdio session ID.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ReplyTag {
    /// Real Nym mixnet anonymous sender tag (SURB-based).
    Nym(AnonymousSenderTag),
    /// Stdio session identifier (test/debug mode).
    Stdio(String),
}

impl std::fmt::Display for ReplyTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplyTag::Nym(tag) => write!(f, "{}", tag),
            ReplyTag::Stdio(id) => write!(f, "stdio:{}", id),
        }
    }
}

impl From<AnonymousSenderTag> for ReplyTag {
    fn from(tag: AnonymousSenderTag) -> Self {
        ReplyTag::Nym(tag)
    }
}

impl ReplyTag {
    /// Reconstruct a `ReplyTag` from a string previously produced by `Display`.
    /// Handles both `"stdio:xxx"` prefixed IDs and base58-encoded Nym tags.
    pub fn from_stored_string(s: &str) -> Option<Self> {
        if let Some(id) = s.strip_prefix("stdio:") {
            Some(ReplyTag::Stdio(id.to_string()))
        } else {
            AnonymousSenderTag::try_from_base58_string(s)
                .ok()
                .map(ReplyTag::Nym)
        }
    }
}

/// Trait for sending reply messages back to a client.
#[async_trait]
pub trait ReplySender: Send + Sync {
    async fn send_reply(&self, tag: &ReplyTag, message: String) -> anyhow::Result<()>;
}

/// Blanket impl: `Arc<T>` implements `ReplySender` if `T` does.
#[async_trait]
impl<T: ReplySender> ReplySender for Arc<T> {
    async fn send_reply(&self, tag: &ReplyTag, message: String) -> anyhow::Result<()> {
        (**self).send_reply(tag, message).await
    }
}

/// Wraps a real `MixnetClientSender` for production use.
pub struct NymReplySender {
    inner: MixnetClientSender,
}

impl NymReplySender {
    pub fn new(sender: MixnetClientSender) -> Self {
        Self { inner: sender }
    }
}

#[async_trait]
impl ReplySender for NymReplySender {
    async fn send_reply(&self, tag: &ReplyTag, message: String) -> anyhow::Result<()> {
        match tag {
            ReplyTag::Nym(nym_tag) => {
                self.inner.send_reply(nym_tag.clone(), message).await?;
                Ok(())
            }
            ReplyTag::Stdio(_) => {
                anyhow::bail!("Cannot send Nym reply to stdio tag")
            }
        }
    }
}

/// Captures replies in memory for in-process testing.
pub struct CapturingReplySender {
    replies: Mutex<Vec<(String, String)>>, // (tag_string, message_json)
}

impl CapturingReplySender {
    pub fn new() -> Self {
        Self {
            replies: Mutex::new(Vec::new()),
        }
    }

    /// Take all captured replies, clearing the buffer.
    pub async fn take_replies(&self) -> Vec<(String, String)> {
        let mut replies = self.replies.lock().await;
        std::mem::take(&mut *replies)
    }
}

#[async_trait]
impl ReplySender for CapturingReplySender {
    async fn send_reply(&self, tag: &ReplyTag, message: String) -> anyhow::Result<()> {
        let mut replies = self.replies.lock().await;
        replies.push((tag.to_string(), message));
        Ok(())
    }
}

/// Writes replies as newline-delimited JSON to stdout (for testing).
pub struct StdioReplySender {
    stdout: Mutex<tokio::io::Stdout>,
}

impl StdioReplySender {
    pub fn new() -> Self {
        Self {
            stdout: Mutex::new(tokio::io::stdout()),
        }
    }
}

#[async_trait]
impl ReplySender for StdioReplySender {
    async fn send_reply(&self, tag: &ReplyTag, message: String) -> anyhow::Result<()> {
        let parsed = serde_json::from_str::<serde_json::Value>(&message)
            .unwrap_or(serde_json::Value::String(message));
        let envelope = json!({
            "replyTag": tag.to_string(),
            "message": parsed
        });
        let mut out = self.stdout.lock().await;
        out.write_all(envelope.to_string().as_bytes()).await?;
        out.write_all(b"\n").await?;
        out.flush().await?;
        Ok(())
    }
}
