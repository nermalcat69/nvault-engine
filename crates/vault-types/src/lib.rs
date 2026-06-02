use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const VAULT_MAGIC: &[u8; 8] = b"VLTDB001";
pub const VAULT_VERSION: u32 = 1;
pub const DEFAULT_PAGE_SIZE: u32 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub page_size: u32,
    pub salt: [u8; 32],
}

/// Public record type returned by `Vault::get`. Payload is fully assembled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub collection: String,
    pub kind: String,
    pub metadata: Metadata,
    pub payload: Vec<u8>,
}

/// Lightweight record summary returned by `Vault::list`. No payload loaded.
#[derive(Debug, Clone)]
pub struct RecordInfo {
    pub id: Uuid,
    pub collection: String,
    pub kind: String,
    pub version: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

/// One entry in a record's version history.
#[derive(Debug, Clone)]
pub struct RecordVersion {
    pub version: u32,
    pub timestamp: u64,
    pub kind: String,
    pub metadata: Metadata,
}

/// A ranked search result returned by `Vault::search`.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub record: RecordInfo,
    /// Relevance score — higher is better. IDF-weighted sum of per-term scores.
    pub score: f32,
    /// Query terms that matched this record (after fuzzy expansion).
    pub matched_terms: Vec<String>,
}

/// Result of a vault integrity check.
#[derive(Debug)]
pub struct VerifyReport {
    pub records_checked: usize,
    pub versions_checked: usize,
    pub chunks_checked: usize,
    pub orphaned_chunks: usize,
    pub errors: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub created_at: u64,
    pub updated_at: u64,
    pub tags: Vec<String>,
}

impl Record {
    pub fn new(collection: impl Into<String>, kind: impl Into<String>, payload: Vec<u8>) -> Self {
        let now = now_unix();
        Self {
            id: Uuid::new_v4(),
            collection: collection.into(),
            kind: kind.into(),
            metadata: Metadata { created_at: now, updated_at: now, tags: Vec::new() },
            payload,
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
