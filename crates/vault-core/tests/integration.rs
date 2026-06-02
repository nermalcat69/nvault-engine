use std::path::PathBuf;
use vault_core::Vault;
use vault_types::Record;

fn tmp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

#[test]
fn create_open_put_get_delete() {
    let path = tmp_path("test_vault_basic.vlt");
    let _ = std::fs::remove_file(&path);

    let mut vault = Vault::create(&path, "hunter2").unwrap();
    let record = Record::new("notes", "text", b"hello vault".to_vec());
    let id = vault.put(record).unwrap();

    let vault = Vault::open(&path, "hunter2").unwrap();
    let r = vault.get(&id).unwrap();
    assert_eq!(r.payload, b"hello vault");
    assert_eq!(r.collection, "notes");
    assert_eq!(r.kind, "text");

    let mut vault = Vault::open(&path, "hunter2").unwrap();
    vault.delete(&id).unwrap();
    assert!(vault.get(&id).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_password_fails() {
    let path = tmp_path("test_vault_auth2.vlt");
    let _ = std::fs::remove_file(&path);
    Vault::create(&path, "correct").unwrap();
    assert!(Vault::open(&path, "wrong").is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn list_and_collections() {
    let path = tmp_path("test_vault_list2.vlt");
    let _ = std::fs::remove_file(&path);

    let mut vault = Vault::create(&path, "pass").unwrap();
    vault.put(Record::new("work", "text", b"task 1".to_vec())).unwrap();
    vault.put(Record::new("work", "text", b"task 2".to_vec())).unwrap();
    vault.put(Record::new("personal", "json", b"{}".to_vec())).unwrap();

    let vault = Vault::open(&path, "pass").unwrap();
    assert_eq!(vault.list(None).len(), 3);
    assert_eq!(vault.list(Some("work")).len(), 2);
    assert_eq!(vault.list(Some("personal")).len(), 1);

    let cols = vault.collections();
    assert!(cols.contains(&"work".to_string()));
    assert!(cols.contains(&"personal".to_string()));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn version_history() {
    let path = tmp_path("test_vault_versions.vlt");
    let _ = std::fs::remove_file(&path);

    let mut vault = Vault::create(&path, "pass").unwrap();
    let id = vault.put(Record::new("notes", "text", b"draft one".to_vec())).unwrap();
    vault.update(id, b"draft two".to_vec()).unwrap();
    vault.update(id, b"final".to_vec()).unwrap();

    let vault = Vault::open(&path, "pass").unwrap();

    let r = vault.get(&id).unwrap();
    assert_eq!(r.payload, b"final");

    let history = vault.history(&id).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].version, 1);
    assert_eq!(history[2].version, 3);

    let (_, payload_v1) = vault.get_version(&id, 1).unwrap();
    assert_eq!(payload_v1, b"draft one");

    let (_, payload_v2) = vault.get_version(&id, 2).unwrap();
    assert_eq!(payload_v2, b"draft two");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn chunk_deduplication() {
    let path = tmp_path("test_vault_dedup.vlt");
    let _ = std::fs::remove_file(&path);

    let mut vault = Vault::create(&path, "pass").unwrap();

    // Two records with identical content → chunks stored once.
    let same = b"identical payload".to_vec();
    vault.put(Record::new("a", "text", same.clone())).unwrap();
    vault.put(Record::new("b", "text", same)).unwrap();

    // Both records readable after reload.
    let vault = Vault::open(&path, "pass").unwrap();
    let records = vault.list(None);
    assert_eq!(records.len(), 2);
    for info in &records {
        let r = vault.get(&info.id).unwrap();
        assert_eq!(r.payload, b"identical payload");
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn large_record_spans_multiple_chunks() {
    let path = tmp_path("test_vault_large.vlt");
    let _ = std::fs::remove_file(&path);

    // 10 KB payload → 3 chunks at 4 KB each
    let payload: Vec<u8> = (0u8..=255).cycle().take(10 * 1024).collect();

    let mut vault = Vault::create(&path, "pass").unwrap();
    let id = vault.put(Record::new("files", "binary", payload.clone())).unwrap();

    let vault = Vault::open(&path, "pass").unwrap();
    let r = vault.get(&id).unwrap();
    assert_eq!(r.payload, payload);

    let _ = std::fs::remove_file(&path);
}
