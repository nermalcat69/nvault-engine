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
    let path = tmp_path("test_vault_auth.vlt");
    let _ = std::fs::remove_file(&path);
    Vault::create(&path, "correct").unwrap();
    assert!(Vault::open(&path, "wrong").is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn list_and_collections() {
    let path = tmp_path("test_vault_list.vlt");
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
fn update_record() {
    let path = tmp_path("test_vault_update.vlt");
    let _ = std::fs::remove_file(&path);

    let mut vault = Vault::create(&path, "pass").unwrap();
    let id = vault.put(Record::new("notes", "text", b"original".to_vec())).unwrap();
    vault.update(id, b"updated".to_vec()).unwrap();

    let vault = Vault::open(&path, "pass").unwrap();
    let r = vault.get(&id).unwrap();
    assert_eq!(r.payload, b"updated");

    let _ = std::fs::remove_file(&path);
}
