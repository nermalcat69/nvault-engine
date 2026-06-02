use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const VAULT_MAGIC: &[u8; 8] = b"VLTDB001";
pub const VAULT_VERSION: u32 = 1;
pub const DEFAULT_PAGE_SIZE: u32 = 4096;

/// Fixed-size plaintext header at the start of every .vlt file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub page_size: u32,
    pub salt: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub collection: String,
    pub kind: String,
    pub metadata: Metadata,
    pub payload: Vec<u8>,
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
            metadata: Metadata {
                created_at: now,
                updated_at: now,
                tags: Vec::new(),
            },
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
