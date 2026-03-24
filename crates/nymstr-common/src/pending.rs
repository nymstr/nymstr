//! TTL-tracked pending entries for in-progress operations.

use std::time::Instant;

/// Generic wrapper for pending entries with TTL support.
pub struct PendingEntry<T> {
    pub data: T,
    pub created_at: Instant,
}

impl<T> PendingEntry<T> {
    pub fn new(data: T) -> Self {
        Self {
            data,
            created_at: Instant::now(),
        }
    }
}
