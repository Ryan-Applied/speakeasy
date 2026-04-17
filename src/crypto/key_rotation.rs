//! Key rotation for rooms -- manages symmetric key epochs so that
//! when a member is removed (or periodically), a new room key is generated
//! and older messages remain decryptable via their epoch.

use crate::crypto::CryptoService;
use crate::storage::LocalStorage;
use anyhow::Result;
use tracing::info;

/// Rotate the symmetric key for a room.
///
/// Generates a new random key, stores it as the next epoch, and returns
/// the new key and epoch number. The old key remains in storage so that
/// messages encrypted under previous epochs can still be decrypted.
///
/// `rotated_by` is the public key of the member initiating the rotation.
pub fn rotate_room_key(
    storage: &LocalStorage,
    room_id: &[u8; 32],
    rotated_by: &[u8],
) -> Result<(Vec<u8>, u32)> {
    let new_epoch = match storage.get_current_epoch(room_id)? {
        Some((current_epoch, _)) => current_epoch + 1,
        None => {
            // First rotation -- epoch 0 is the original key (should be recorded
            // before calling this, but we handle it gracefully).
            1
        }
    };

    let new_key = CryptoService::generate_room_key();

    storage.insert_key_epoch(room_id, new_epoch, &new_key, rotated_by)?;

    info!(
        "rotated room key to epoch {} for room {}",
        new_epoch,
        hex_short(room_id)
    );

    Ok((new_key, new_epoch))
}

/// Record the initial room key as epoch 0.
///
/// Should be called when creating a room or when first setting up
/// key rotation for a room that was created before key rotation existed.
pub fn record_initial_epoch(
    storage: &LocalStorage,
    room_id: &[u8; 32],
    room_key: &[u8],
    creator_key: &[u8],
) -> Result<()> {
    storage.insert_key_epoch(room_id, 0, room_key, creator_key)?;
    Ok(())
}

/// Get the decryption key for a specific epoch.
///
/// Used when receiving a message that includes an epoch field --
/// the receiver looks up the correct key for that epoch.
pub fn get_decryption_key(
    storage: &LocalStorage,
    room_id: &[u8; 32],
    epoch: u32,
) -> Result<Option<Vec<u8>>> {
    storage.get_key_for_epoch(room_id, epoch)
}

/// Get the current epoch and key for encrypting new messages.
pub fn get_current_key(
    storage: &LocalStorage,
    room_id: &[u8; 32],
) -> Result<Option<(u32, Vec<u8>)>> {
    storage.get_current_epoch(room_id)
}

fn hex_short(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_epoch_recording() {
        let db = LocalStorage::open_memory().unwrap();
        let room_id = [1u8; 32];
        let room_key = vec![42u8; 32];
        let creator = vec![10u8; 32];

        record_initial_epoch(&db, &room_id, &room_key, &creator).unwrap();

        let (epoch, key) = db.get_current_epoch(&room_id).unwrap().unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(key, room_key);
    }

    #[test]
    fn test_rotate_room_key() {
        let db = LocalStorage::open_memory().unwrap();
        let room_id = [1u8; 32];
        let original_key = vec![42u8; 32];
        let creator = vec![10u8; 32];

        // Record initial epoch
        record_initial_epoch(&db, &room_id, &original_key, &creator).unwrap();

        // Rotate
        let (new_key, new_epoch) = rotate_room_key(&db, &room_id, &creator).unwrap();
        assert_eq!(new_epoch, 1);
        assert_ne!(new_key, original_key);
        assert_eq!(new_key.len(), 32);

        // Current epoch is now 1
        let (epoch, key) = db.get_current_epoch(&room_id).unwrap().unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(key, new_key);

        // Original key still accessible at epoch 0
        let old = db.get_key_for_epoch(&room_id, 0).unwrap().unwrap();
        assert_eq!(old, original_key);
    }

    #[test]
    fn test_multi_epoch_rotation() {
        let db = LocalStorage::open_memory().unwrap();
        let room_id = [1u8; 32];
        let creator = vec![10u8; 32];

        record_initial_epoch(&db, &room_id, &vec![1u8; 32], &creator).unwrap();

        let mut keys = vec![vec![1u8; 32]];
        for _ in 0..5 {
            let (new_key, _) = rotate_room_key(&db, &room_id, &creator).unwrap();
            keys.push(new_key);
        }

        // Current epoch should be 5
        let (epoch, _) = db.get_current_epoch(&room_id).unwrap().unwrap();
        assert_eq!(epoch, 5);

        // All previous epoch keys should be retrievable
        for (i, expected_key) in keys.iter().enumerate() {
            let stored = db.get_key_for_epoch(&room_id, i as u32).unwrap().unwrap();
            assert_eq!(&stored, expected_key);
        }
    }

    #[test]
    fn test_get_decryption_key() {
        let db = LocalStorage::open_memory().unwrap();
        let room_id = [1u8; 32];
        let creator = vec![10u8; 32];
        let original_key = vec![42u8; 32];

        record_initial_epoch(&db, &room_id, &original_key, &creator).unwrap();
        let (key1, _) = rotate_room_key(&db, &room_id, &creator).unwrap();
        let (key2, _) = rotate_room_key(&db, &room_id, &creator).unwrap();

        // Get keys by epoch
        assert_eq!(get_decryption_key(&db, &room_id, 0).unwrap().unwrap(), original_key);
        assert_eq!(get_decryption_key(&db, &room_id, 1).unwrap().unwrap(), key1);
        assert_eq!(get_decryption_key(&db, &room_id, 2).unwrap().unwrap(), key2);

        // Non-existent epoch
        assert!(get_decryption_key(&db, &room_id, 99).unwrap().is_none());
    }

    #[test]
    fn test_get_current_key() {
        let db = LocalStorage::open_memory().unwrap();
        let room_id = [1u8; 32];

        // No epochs yet
        assert!(get_current_key(&db, &room_id).unwrap().is_none());

        let creator = vec![10u8; 32];
        record_initial_epoch(&db, &room_id, &vec![1u8; 32], &creator).unwrap();

        let (epoch, _key) = get_current_key(&db, &room_id).unwrap().unwrap();
        assert_eq!(epoch, 0);

        rotate_room_key(&db, &room_id, &creator).unwrap();
        let (epoch, _) = get_current_key(&db, &room_id).unwrap().unwrap();
        assert_eq!(epoch, 1);
    }
}
