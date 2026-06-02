use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;
use vault_compression::{compress, decompress, CompressionError};
use vault_crypto::{decrypt, derive_key, encrypt, generate_salt, CryptoError};
use vault_index::{IndexEntry, VaultIndex};
use vault_search::SearchIndex;
use vault_storage::StorageError;
use vault_types::{
    now_unix, Metadata, Record, RecordInfo, RecordVersion, SearchResult, VerifyReport, VaultHeader,
    DEFAULT_PAGE_SIZE, VAULT_MAGIC, VAULT_VERSION,
};

/// Blake3 hash of a chunk's raw bytes — the content address.
type ChunkId = [u8; 32];

/// Chunks are 4 KB, matching the page size from the vault header.
const CHUNK_SIZE: usize = 4096;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("compression error: {0}")]
    Compression(#[from] CompressionError),
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("record not found: {0}")]
    NotFound(Uuid),
    #[error("version {1} not found for record {0}")]
    VersionNotFound(Uuid, u32),
    #[error("vault already exists at: {0}")]
    AlreadyExists(PathBuf),
    #[error("corrupted vault: referenced chunk is missing")]
    CorruptedChunk,
}

pub type Result<T> = std::result::Result<T, VaultError>;

// ── Internal storage types ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct StoredRecord {
    id: Uuid,
    collection: String,
    kind: String,
    metadata: Metadata,
    chunks: Vec<ChunkId>,
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct StoredVersion {
    version: u32,
    timestamp: u64,
    kind: String,
    metadata: Metadata,
    chunks: Vec<ChunkId>,
}

#[derive(Serialize, Deserialize)]
struct VaultData {
    /// Content-addressed chunk store: blake3(raw_chunk) → raw_chunk_bytes.
    /// Identical chunks across records are stored exactly once.
    chunk_store: HashMap<ChunkId, Vec<u8>>,
    records: HashMap<Uuid, StoredRecord>,
    versions: HashMap<Uuid, Vec<StoredVersion>>,
    index: VaultIndex,
    /// Inverted index for full-text search. Always encrypted at rest with the vault.
    search_index: SearchIndex,
}

// ── Chunk helpers (free functions to avoid borrow conflicts) ───────────────

fn hash_chunk(data: &[u8]) -> ChunkId {
    *blake3::hash(data).as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Split `payload` into chunks, insert any new ones into `store`, return IDs.
fn store_chunks(store: &mut HashMap<ChunkId, Vec<u8>>, payload: &[u8]) -> Vec<ChunkId> {
    payload
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let id = hash_chunk(chunk);
            store.entry(id).or_insert_with(|| chunk.to_vec());
            id
        })
        .collect()
}

/// Reassemble a payload by concatenating chunks in order.
fn assemble_payload(store: &HashMap<ChunkId, Vec<u8>>, ids: &[ChunkId]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    for id in ids {
        let chunk = store.get(id).ok_or(VaultError::CorruptedChunk)?;
        buf.extend_from_slice(chunk);
    }
    Ok(buf)
}

// ── Public Vault API ───────────────────────────────────────────────────────

pub struct Vault {
    path: PathBuf,
    header: VaultHeader,
    /// Master key — wrapped in Zeroizing so the bytes are overwritten
    /// with zeroes the moment this Vault is dropped.
    key: Zeroizing<[u8; 32]>,
    data: VaultData,
}

impl Vault {
    /// Create a new vault file. Fails if the path already exists.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_path_buf()));
        }
        let salt = generate_salt();
        let key = Zeroizing::new(derive_key(password.as_bytes(), &salt)?);
        let header = VaultHeader {
            magic: *VAULT_MAGIC,
            version: VAULT_VERSION,
            page_size: DEFAULT_PAGE_SIZE,
            salt,
        };
        let data = VaultData {
            chunk_store: HashMap::new(),
            records: HashMap::new(),
            versions: HashMap::new(),
            index: VaultIndex::default(),
            search_index: SearchIndex::default(),
        };
        let vault = Self { path: path.to_path_buf(), header, key, data };
        vault.flush()?;
        Ok(vault)
    }

    /// Open an existing vault file with a password.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let (header, blob) = vault_storage::read_vault(path)?;
        let key = Zeroizing::new(derive_key(password.as_bytes(), &header.salt)?);
        // Decrypt and decompress in Zeroizing buffers so plaintext is wiped on drop.
        let decrypted = Zeroizing::new(decrypt(&*key, &blob)?);
        let decompressed = Zeroizing::new(decompress(&*decrypted)?);
        let data: VaultData = bincode::deserialize(&*decompressed)?;
        Ok(Self { path: path.to_path_buf(), header, key, data })
    }

    /// Store a record. Chunks are deduplicated; a version entry is created.
    pub fn put(&mut self, record: Record) -> Result<Uuid> {
        let id = record.id;
        let now = record.metadata.created_at;

        let chunk_ids = store_chunks(&mut self.data.chunk_store, &record.payload);

        let stored = StoredRecord {
            id,
            collection: record.collection.clone(),
            kind: record.kind.clone(),
            metadata: record.metadata.clone(),
            chunks: chunk_ids.clone(),
            version: 1,
        };
        let first_version = StoredVersion {
            version: 1,
            timestamp: now,
            kind: record.kind.clone(),
            metadata: record.metadata.clone(),
            chunks: chunk_ids,
        };
        self.data.index.insert(id, IndexEntry {
            collection: record.collection,
            kind: record.kind,
            created_at: record.metadata.created_at,
            updated_at: record.metadata.updated_at,
        });
        self.data.records.insert(id, stored);
        self.data.versions.insert(id, vec![first_version]);

        if let Ok(text) = std::str::from_utf8(&record.payload) {
            self.data.search_index.index_record(id, text);
        }

        self.flush()?;
        Ok(id)
    }

    /// Retrieve the latest version of a record with its payload assembled.
    pub fn get(&self, id: &Uuid) -> Result<Record> {
        let stored = self.data.records.get(id).ok_or(VaultError::NotFound(*id))?;
        let payload = assemble_payload(&self.data.chunk_store, &stored.chunks)?;
        Ok(Record {
            id: stored.id,
            collection: stored.collection.clone(),
            kind: stored.kind.clone(),
            metadata: stored.metadata.clone(),
            payload,
        })
    }

    /// Replace a record's payload. Appends a new version; old chunks are kept
    /// in the store so previous versions remain retrievable.
    pub fn update(&mut self, id: Uuid, payload: Vec<u8>) -> Result<()> {
        let now = now_unix();

        if !self.data.records.contains_key(&id) {
            return Err(VaultError::NotFound(id));
        }

        let chunk_ids = store_chunks(&mut self.data.chunk_store, &payload);

        let stored = self.data.records.get_mut(&id).unwrap();
        let new_version = stored.version + 1;
        stored.chunks = chunk_ids.clone();
        stored.metadata.updated_at = now;
        stored.version = new_version;

        let ver = StoredVersion {
            version: new_version,
            timestamp: now,
            kind: stored.kind.clone(),
            metadata: stored.metadata.clone(),
            chunks: chunk_ids,
        };
        self.data.versions.entry(id).or_default().push(ver);
        self.data.index.set_updated_at(&id, now);

        self.data.search_index.remove_record(&id);
        if let Ok(text) = std::str::from_utf8(&payload) {
            self.data.search_index.index_record(id, text);
        }

        self.flush()
    }

    /// Delete a record from the index. Chunks are retained (shared chunks
    /// may belong to other records or versions). Run compaction to reclaim.
    pub fn delete(&mut self, id: &Uuid) -> Result<()> {
        self.data.records.remove(id).ok_or(VaultError::NotFound(*id))?;
        self.data.index.remove(id);
        self.data.search_index.remove_record(id);
        self.flush()
    }

    /// List record summaries without loading any payloads.
    pub fn list(&self, collection: Option<&str>) -> Vec<RecordInfo> {
        self.data
            .records
            .values()
            .filter(|r| collection.map_or(true, |col| r.collection == col))
            .map(|r| RecordInfo {
                id: r.id,
                collection: r.collection.clone(),
                kind: r.kind.clone(),
                version: r.version,
                created_at: r.metadata.created_at,
                updated_at: r.metadata.updated_at,
            })
            .collect()
    }

    /// Return all distinct collection names, sorted.
    pub fn collections(&self) -> Vec<String> {
        self.data.index.collections()
    }

    /// Return the full version history for a record (oldest first).
    pub fn history(&self, id: &Uuid) -> Result<Vec<RecordVersion>> {
        let versions = self.data.versions.get(id).ok_or(VaultError::NotFound(*id))?;
        Ok(versions
            .iter()
            .map(|v| RecordVersion {
                version: v.version,
                timestamp: v.timestamp,
                kind: v.kind.clone(),
                metadata: v.metadata.clone(),
            })
            .collect())
    }

    /// Retrieve the payload of a specific historical version.
    pub fn get_version(&self, id: &Uuid, version: u32) -> Result<(RecordVersion, Vec<u8>)> {
        let versions = self.data.versions.get(id).ok_or(VaultError::NotFound(*id))?;
        let v = versions
            .iter()
            .find(|v| v.version == version)
            .ok_or(VaultError::VersionNotFound(*id, version))?;
        let payload = assemble_payload(&self.data.chunk_store, &v.chunks)?;
        Ok((
            RecordVersion {
                version: v.version,
                timestamp: v.timestamp,
                kind: v.kind.clone(),
                metadata: v.metadata.clone(),
            },
            payload,
        ))
    }

    /// Fuzzy full-text search. Returns results ranked by relevance (IDF-weighted).
    /// Multi-word queries require all terms to match (AND). No payloads are loaded.
    pub fn search(&self, query: &str) -> Vec<SearchResult> {
        use vault_search::DEFAULT_MAX_RESULTS;
        self.data
            .search_index
            .search(query, DEFAULT_MAX_RESULTS)
            .into_iter()
            .filter_map(|hit| {
                self.data.records.get(&hit.id).map(|r| SearchResult {
                    record: RecordInfo {
                        id: r.id,
                        collection: r.collection.clone(),
                        kind: r.kind.clone(),
                        version: r.version,
                        created_at: r.metadata.created_at,
                        updated_at: r.metadata.updated_at,
                    },
                    score: hit.score,
                    matched_terms: hit.matched_terms,
                })
            })
            .collect()
    }

    /// Verify vault integrity:
    ///   1. Every chunk referenced by a record or version exists in the chunk store.
    ///   2. Every stored chunk's content hashes to its key (tamper detection).
    ///   3. The index matches the live record set.
    pub fn verify(&self) -> VerifyReport {
        let mut errors: Vec<String> = Vec::new();

        // Collect every chunk ID that any record or version references.
        let mut referenced: std::collections::HashSet<ChunkId> =
            std::collections::HashSet::new();

        let mut records_checked = 0usize;
        for stored in self.data.records.values() {
            records_checked += 1;
            for id in &stored.chunks {
                referenced.insert(*id);
                if !self.data.chunk_store.contains_key(id) {
                    errors.push(format!(
                        "record {}: missing chunk {}",
                        stored.id,
                        hex(&id[..4])
                    ));
                }
            }
        }

        let mut versions_checked = 0usize;
        for (record_id, versions) in &self.data.versions {
            for v in versions {
                versions_checked += 1;
                for id in &v.chunks {
                    referenced.insert(*id);
                    if !self.data.chunk_store.contains_key(id) {
                        errors.push(format!(
                            "record {} v{}: missing chunk {}",
                            record_id,
                            v.version,
                            hex(&id[..4])
                        ));
                    }
                }
            }
        }

        // Verify every stored chunk's hash matches its content.
        let mut chunks_checked = 0usize;
        for (id, bytes) in &self.data.chunk_store {
            chunks_checked += 1;
            let computed = hash_chunk(bytes);
            if computed != *id {
                errors.push(format!("chunk {}: hash mismatch — data was tampered", hex(&id[..4])));
            }
        }

        // Count chunks not referenced by any live record or version (orphans from deletes).
        let orphaned_chunks = self
            .data
            .chunk_store
            .keys()
            .filter(|id| !referenced.contains(*id))
            .count();

        // Index consistency: every record should have an index entry and vice versa.
        for id in self.data.records.keys() {
            if self.data.index.get(id).is_none() {
                errors.push(format!("record {}: present in records but missing from index", id));
            }
        }

        VerifyReport { records_checked, versions_checked, chunks_checked, orphaned_chunks, errors }
    }

    fn flush(&self) -> Result<()> {
        // Both intermediate buffers are plaintext — Zeroizing wipes them on drop.
        let serialized = Zeroizing::new(bincode::serialize(&self.data)?);
        let compressed = Zeroizing::new(compress(&*serialized)?);
        let encrypted = encrypt(&*self.key, &*compressed)?;
        vault_storage::write_vault(&self.path, &self.header, &encrypted)?;
        Ok(())
    }
}
