use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Lightweight summary of a record used for listing without decrypting payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub collection: String,
    pub kind: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Maps record IDs to their index entries. Serialized as part of the encrypted vault payload.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VaultIndex {
    entries: HashMap<Uuid, IndexEntry>,
}

impl VaultIndex {
    pub fn insert(&mut self, id: Uuid, entry: IndexEntry) {
        self.entries.insert(id, entry);
    }

    pub fn remove(&mut self, id: &Uuid) -> bool {
        self.entries.remove(id).is_some()
    }

    pub fn get(&self, id: &Uuid) -> Option<&IndexEntry> {
        self.entries.get(id)
    }

    pub fn set_updated_at(&mut self, id: &Uuid, updated_at: u64) {
        if let Some(e) = self.entries.get_mut(id) {
            e.updated_at = updated_at;
        }
    }

    pub fn list_all(&self) -> impl Iterator<Item = (&Uuid, &IndexEntry)> {
        self.entries.iter()
    }

    pub fn list_collection<'a>(
        &'a self,
        collection: &'a str,
    ) -> impl Iterator<Item = (&'a Uuid, &'a IndexEntry)> {
        self.entries
            .iter()
            .filter(move |(_, e)| e.collection == collection)
    }

    pub fn collections(&self) -> Vec<String> {
        let mut cols: Vec<String> = self
            .entries
            .values()
            .map(|e| e.collection.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        cols.sort();
        cols
    }
}
