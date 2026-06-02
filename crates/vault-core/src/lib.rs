use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{decrypt, derive_key, encrypt, generate_salt, CryptoError};
use vault_index::{IndexEntry, VaultIndex};
use vault_storage::StorageError;
use vault_types::{now_unix, Record, VaultHeader, DEFAULT_PAGE_SIZE, VAULT_MAGIC, VAULT_VERSION};

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("record not found: {0}")]
    NotFound(Uuid),
    #[error("vault already exists at: {0}")]
    AlreadyExists(PathBuf),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Serialize, Deserialize)]
struct VaultData {
    records: HashMap<Uuid, Record>,
    index: VaultIndex,
}

pub struct Vault {
    path: PathBuf,
    header: VaultHeader,
    key: [u8; 32],
    data: VaultData,
}

impl Vault {
    /// Create a new vault file. Fails if the path already exists.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_path_buf()));
        }
        let salt = generate_salt();
        let key = derive_key(password.as_bytes(), &salt)?;
        let header = VaultHeader {
            magic: *VAULT_MAGIC,
            version: VAULT_VERSION,
            page_size: DEFAULT_PAGE_SIZE,
            salt,
        };
        let data = VaultData {
            records: HashMap::new(),
            index: VaultIndex::default(),
        };
        let vault = Self { path: path.to_path_buf(), header, key, data };
        vault.flush()?;
        Ok(vault)
    }

    /// Open an existing vault file with a password.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let (header, encrypted_data) = vault_storage::read_vault(path)?;
        let key = derive_key(password.as_bytes(), &header.salt)?;
        let decrypted = decrypt(&key, &encrypted_data)?;
        let data: VaultData = bincode::deserialize(&decrypted)?;
        Ok(Self { path: path.to_path_buf(), header, key, data })
    }

    /// Store a record and return its ID.
    pub fn put(&mut self, record: Record) -> Result<Uuid> {
        let id = record.id;
        let entry = IndexEntry {
            collection: record.collection.clone(),
            kind: record.kind.clone(),
            created_at: record.metadata.created_at,
            updated_at: record.metadata.updated_at,
        };
        self.data.index.insert(id, entry);
        self.data.records.insert(id, record);
        self.flush()?;
        Ok(id)
    }

    /// Retrieve a record by ID.
    pub fn get(&self, id: &Uuid) -> Result<&Record> {
        self.data.records.get(id).ok_or(VaultError::NotFound(*id))
    }

    /// Replace a record's payload and bump its updated_at timestamp.
    pub fn update(&mut self, id: Uuid, payload: Vec<u8>) -> Result<()> {
        let now = now_unix();
        let record = self.data.records.get_mut(&id).ok_or(VaultError::NotFound(id))?;
        record.payload = payload;
        record.metadata.updated_at = now;
        self.data.index.set_updated_at(&id, now);
        self.flush()
    }

    /// Delete a record by ID.
    pub fn delete(&mut self, id: &Uuid) -> Result<()> {
        self.data.records.remove(id).ok_or(VaultError::NotFound(*id))?;
        self.data.index.remove(id);
        self.flush()
    }

    /// List records, optionally filtered to a single collection.
    pub fn list(&self, collection: Option<&str>) -> Vec<(&Uuid, &Record)> {
        match collection {
            Some(col) => self
                .data
                .records
                .iter()
                .filter(|(_, r)| r.collection == col)
                .collect(),
            None => self.data.records.iter().collect(),
        }
    }

    /// Return all distinct collection names, sorted.
    pub fn collections(&self) -> Vec<String> {
        self.data.index.collections()
    }

    fn flush(&self) -> Result<()> {
        let serialized = bincode::serialize(&self.data)?;
        let encrypted = encrypt(&self.key, &serialized)?;
        vault_storage::write_vault(&self.path, &self.header, &encrypted)?;
        Ok(())
    }
}
