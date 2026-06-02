use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;
use vault_types::{VaultHeader, VAULT_MAGIC, VAULT_VERSION};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid vault file: bad magic bytes")]
    InvalidFormat,
    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u32),
}

pub type Result<T> = std::result::Result<T, StorageError>;

pub fn write_vault(path: &Path, header: &VaultHeader, encrypted_data: &[u8]) -> Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(&header.magic)?;
    file.write_all(&header.version.to_le_bytes())?;
    file.write_all(&header.page_size.to_le_bytes())?;
    file.write_all(&header.salt)?;
    file.write_all(encrypted_data)?;
    file.flush()?;
    Ok(())
}

pub fn read_vault(path: &Path) -> Result<(VaultHeader, Vec<u8>)> {
    let mut file = std::fs::File::open(path)?;

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != VAULT_MAGIC {
        return Err(StorageError::InvalidFormat);
    }

    let mut version_bytes = [0u8; 4];
    file.read_exact(&mut version_bytes)?;
    let version = u32::from_le_bytes(version_bytes);
    if version != VAULT_VERSION {
        return Err(StorageError::UnsupportedVersion(version));
    }

    let mut page_size_bytes = [0u8; 4];
    file.read_exact(&mut page_size_bytes)?;
    let page_size = u32::from_le_bytes(page_size_bytes);

    let mut salt = [0u8; 32];
    file.read_exact(&mut salt)?;

    let header = VaultHeader { magic, version, page_size, salt };

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok((header, data))
}
