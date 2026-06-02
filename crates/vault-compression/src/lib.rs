use thiserror::Error;

#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("compression failed: {0}")]
    Compress(std::io::Error),
    #[error("decompression failed: {0}")]
    Decompress(std::io::Error),
}

pub type Result<T> = std::result::Result<T, CompressionError>;

pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::bulk::compress(data, 0).map_err(CompressionError::Compress)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::bulk::decompress(data, 64 * 1024 * 1024).map_err(CompressionError::Decompress)
}
