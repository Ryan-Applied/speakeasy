//! Sync module -- handles catch-up after reconnect, conflict resolution,
//! and coordination between local storage and DHT state.

use crate::dht::DhtOps;
use crate::storage::LocalStorage;
use anyhow::Result;
use tracing::info;

/// Orchestrates synchronization between local state and DHT records.
pub struct SyncService<D: DhtOps> {
    dht: D,
}

impl<D: DhtOps> SyncService<D> {
    pub fn new(dht: D) -> Self {
        Self { dht }
    }

    /// Catch up on a room's message log.
    /// Fetches new subkey values from the DHT message record,
    /// compares against local sync cursors, and returns new raw
    /// message envelopes for decryption and insertion.
    pub async fn catch_up(
        &self,
        storage: &LocalStorage,
        room_id: &[u8; 32],
        dht_messages_key: &[u8],
        members: &[(Vec<u8>, u32, u32)], // (public_key, subkey_start, subkey_end)
    ) -> Result<Vec<(u32, Vec<u8>)>> {
        info!("sync catch-up for room {}", hex_short(room_id));

        self.dht.open_record(dht_messages_key).await?;

        let mut new_messages = Vec::new();

        for (member_key, sk_start, sk_end) in members {
            let cursor = storage.get_sync_cursor(room_id, member_key)?;
            let start_subkey = cursor.map(|(_, sk)| sk + 1).unwrap_or(*sk_start);

            for sk in start_subkey..=*sk_end {
                match self.dht.get_subkey(dht_messages_key, sk).await? {
                    Some(data) => {
                        new_messages.push((sk, data));
                    }
                    None => {
                        // No more data for this member's range
                        break;
                    }
                }
            }

            // Update cursor to last fetched subkey
            if let Some(&(last_sk, _)) = new_messages.last() {
                storage.update_sync_cursor(
                    room_id, member_key,
                    new_messages.len() as u64, last_sk,
                )?;
            }
        }

        self.dht.close_record(dht_messages_key).await?;

        info!("sync fetched {} new messages", new_messages.len());
        Ok(new_messages)
    }

    /// Publish a message to the DHT.
    /// Writes the encrypted envelope to the sender's next available subkey.
    pub async fn publish_message(
        &self,
        dht_messages_key: &[u8],
        subkey: u32,
        encrypted_envelope: &[u8],
    ) -> Result<()> {
        self.dht.open_record(dht_messages_key).await?;
        self.dht.set_subkey(dht_messages_key, subkey, encrypted_envelope).await?;
        self.dht.close_record(dht_messages_key).await?;
        Ok(())
    }
}

fn hex_short(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::MockDht;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_publish_and_catch_up() {
        let dht = Arc::new(MockDht::new());
        let sync = SyncService::new(dht.clone());
        let storage = LocalStorage::open_memory().unwrap();
        let room_id = [1u8; 32];

        // Create a DHT record
        let key = dht.create_record().await.unwrap();

        // Publish a message at subkey 0
        sync.publish_message(&key, 0, b"encrypted_msg_1").await.unwrap();
        sync.publish_message(&key, 1, b"encrypted_msg_2").await.unwrap();

        // Catch up
        let members = vec![(vec![2u8; 32], 0u32, 999u32)];
        let new = sync.catch_up(&storage, &room_id, &key, &members).await.unwrap();
        assert_eq!(new.len(), 2);
        assert_eq!(new[0].1, b"encrypted_msg_1");
        assert_eq!(new[1].1, b"encrypted_msg_2");
    }
}
