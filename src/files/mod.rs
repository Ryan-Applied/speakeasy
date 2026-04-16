//! Files module -- chunked file transfer with integrity verification,
//! resume support, and progress tracking.

use crate::crypto::CryptoService;
use crate::models::{AttachmentRef, FileChunk, FileMetadata, FileTransfer, TransferDirection, TransferStatus};
use anyhow::{Context, Result};
use chrono::Utc;
use std::path::Path;

/// Default chunk size: 64KB raw (before encryption).
pub const DEFAULT_CHUNK_SIZE: usize = 65_536;
/// Small file threshold: files under this size are sent inline.
pub const INLINE_THRESHOLD: usize = 256 * 1024;

/// Prepare a file for transfer: read, hash, chunk, and produce metadata.
pub fn prepare_file(
    path: impl AsRef<Path>,
    sender_key: &[u8],
) -> Result<(FileMetadata, Vec<FileChunk>)> {
    let path = path.as_ref();
    let data = std::fs::read(path).context("reading file")?;
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed".into());

    prepare_file_from_bytes(&data, &filename, sender_key)
}

/// Prepare file from raw bytes.
pub fn prepare_file_from_bytes(
    data: &[u8],
    filename: &str,
    sender_key: &[u8],
) -> Result<(FileMetadata, Vec<FileChunk>)> {
    let file_hash = CryptoService::hash_fixed(data);
    let mut file_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut file_id);

    let mime_type = mime_guess(filename);
    let chunk_count = (data.len() + DEFAULT_CHUNK_SIZE - 1) / DEFAULT_CHUNK_SIZE;

    let metadata = FileMetadata {
        file_id,
        filename: filename.to_string(),
        mime_type,
        size: data.len() as u64,
        blake3_hash: file_hash.to_vec(),
        chunk_size: DEFAULT_CHUNK_SIZE as u32,
        chunk_count: chunk_count as u32,
        sender_key: sender_key.to_vec(),
        timestamp: Utc::now(),
        schema_version: 1,
    };

    let chunks: Vec<FileChunk> = data
        .chunks(DEFAULT_CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk_data)| {
            let chunk_hash = CryptoService::hash(chunk_data);
            FileChunk {
                file_id,
                chunk_index: i as u32,
                data: chunk_data.to_vec(),
                blake3_hash: chunk_hash,
            }
        })
        .collect();

    Ok((metadata, chunks))
}

/// Verify a complete file's integrity against its metadata.
pub fn verify_file(chunks: &[FileChunk], metadata: &FileMetadata) -> Result<bool> {
    // Check chunk count
    if chunks.len() != metadata.chunk_count as usize {
        return Ok(false);
    }

    // Reassemble and hash
    let mut full_data = Vec::with_capacity(metadata.size as usize);
    for (i, chunk) in chunks.iter().enumerate() {
        if chunk.chunk_index != i as u32 {
            return Ok(false);
        }
        // Verify individual chunk hash
        let expected = CryptoService::hash(&chunk.data);
        if expected != chunk.blake3_hash {
            return Ok(false);
        }
        full_data.extend_from_slice(&chunk.data);
    }

    // Verify full file hash
    let full_hash = CryptoService::hash_fixed(&full_data);
    Ok(full_hash.as_slice() == metadata.blake3_hash.as_slice())
}

/// Create an AttachmentRef from file metadata.
pub fn to_attachment_ref(meta: &FileMetadata, dht_key: Option<Vec<u8>>) -> AttachmentRef {
    AttachmentRef {
        file_id: meta.file_id,
        filename: meta.filename.clone(),
        mime_type: meta.mime_type.clone(),
        size: meta.size,
        blake3_hash: meta.blake3_hash.clone(),
        dht_record_key: dht_key,
    }
}

/// Check if a file is small enough for inline transfer.
pub fn is_inline(size: u64) -> bool {
    (size as usize) <= INLINE_THRESHOLD
}

/// Create a transfer tracker.
pub fn new_transfer(file_id: [u8; 32], direction: TransferDirection, chunk_count: u32) -> FileTransfer {
    FileTransfer {
        file_id,
        direction,
        status: TransferStatus::Queued,
        chunks_done: 0,
        chunks_total: chunk_count,
    }
}

/// Simple MIME type guessing by extension.
fn mime_guess(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "mp3" => "audio/mpeg",
        "ogg" | "opus" => "audio/opus",
        "mp4" => "video/mp4",
        "json" => "application/json",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_and_verify_file() {
        let data = vec![42u8; 200_000]; // ~200KB, 4 chunks
        let (meta, chunks) = prepare_file_from_bytes(&data, "test.bin", &[1u8; 32]).unwrap();

        assert_eq!(meta.chunk_count, 4); // ceil(200000/65536)
        assert_eq!(chunks.len(), 4);
        assert_eq!(meta.mime_type, "application/octet-stream");

        assert!(verify_file(&chunks, &meta).unwrap());
    }

    #[test]
    fn test_small_file_inline() {
        assert!(is_inline(100_000));
        assert!(!is_inline(300_000));
    }

    #[test]
    fn test_integrity_failure() {
        let data = vec![42u8; 100_000];
        let (meta, mut chunks) = prepare_file_from_bytes(&data, "test.bin", &[1u8; 32]).unwrap();

        // Corrupt a chunk
        chunks[0].data[0] = 99;
        assert!(!verify_file(&chunks, &meta).unwrap());
    }
}
