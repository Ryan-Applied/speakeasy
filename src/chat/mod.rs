use crate::crypto::CryptoService;
use crate::models::*;
use crate::storage::LocalStorage;
use anyhow::Result;
use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

/// Manages chat rooms and message lifecycle.
pub struct ChatService {
    storage: LocalStorage,
    // Per-room sequence counters. In production this is a HashMap<RoomId, AtomicU64>.
    // Simplified here for scaffolding.
    next_seq: AtomicU64,
}

impl ChatService {
    pub fn new(storage: LocalStorage) -> Self {
        Self {
            storage,
            next_seq: AtomicU64::new(0),
        }
    }

    /// Create a new group chat room.
    pub fn create_group_room(
        &self,
        name: &str,
        creator_public_key: &[u8],
    ) -> Result<Room> {
        let room_id = CryptoService::hash_fixed(
            &[name.as_bytes(), creator_public_key, &Utc::now().timestamp().to_le_bytes()].concat(),
        );
        let room_key = CryptoService::generate_room_key();

        let room = Room {
            room_id,
            room_type: RoomType::Group,
            name: name.to_string(),
            created_at: Utc::now(),
            creator_key: creator_public_key.to_vec(),
            room_key,
            dht_metadata_key: Vec::new(),  // set after DHT record creation
            dht_members_key: Vec::new(),
            dht_messages_key: Vec::new(),
            members: vec![RoomMember {
                public_key: creator_public_key.to_vec(),
                display_name: String::new(), // filled from identity
                role: MemberRole::Admin,
                joined_at: Utc::now(),
                subkey_start: 0,
                subkey_end: 999,
                route_data: None,
            }],
            last_sync_seq: 0,
            schema_version: 1,
        };

        self.storage.insert_room(&room)?;
        info!("created group room: {} ({})", name, hex_short(&room.room_id));
        Ok(room)
    }

    /// Create a direct 1:1 chat room.
    pub fn create_direct_room(
        &self,
        our_public_key: &[u8],
        our_secret_key: &[u8],
        their_public_key: &[u8],
    ) -> Result<Room> {
        // Deterministic room ID from sorted key pair
        let mut keys = vec![our_public_key.to_vec(), their_public_key.to_vec()];
        keys.sort();
        let room_id = CryptoService::hash_fixed(&keys.concat());

        // Derive shared room key via DH
        let room_key = CryptoService::derive_room_key_direct(our_secret_key, their_public_key)?;

        let room = Room {
            room_id,
            room_type: RoomType::Direct,
            name: String::new(),
            created_at: Utc::now(),
            creator_key: our_public_key.to_vec(),
            room_key,
            dht_metadata_key: Vec::new(),
            dht_members_key: Vec::new(),
            dht_messages_key: Vec::new(),
            members: vec![
                RoomMember {
                    public_key: our_public_key.to_vec(),
                    display_name: String::new(),
                    role: MemberRole::Member,
                    joined_at: Utc::now(),
                    subkey_start: 0,
                    subkey_end: 999,
                    route_data: None,
                },
                RoomMember {
                    public_key: their_public_key.to_vec(),
                    display_name: String::new(),
                    role: MemberRole::Member,
                    joined_at: Utc::now(),
                    subkey_start: 1000,
                    subkey_end: 1999,
                    route_data: None,
                },
            ],
            last_sync_seq: 0,
            schema_version: 1,
        };

        self.storage.insert_room(&room)?;
        info!("created direct room: {}", hex_short(&room.room_id));
        Ok(room)
    }

    /// Compose and store a new outbound text message.
    /// Returns the message ready for encryption and DHT write.
    pub fn compose_message(
        &self,
        room_id: &[u8; 32],
        sender_key: &[u8],
        content: &str,
        reply_to: Option<&str>,
    ) -> Result<Message> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let msg = Message {
            msg_id: ulid::Ulid::new().to_string(),
            room_id: *room_id,
            sender_key: sender_key.to_vec(),
            sequence: seq,
            timestamp: Utc::now(),
            content_type: ContentType::Text,
            content: content.to_string(),
            reply_to: reply_to.map(|s| s.to_string()),
            attachments: Vec::new(),
            status: MessageStatus::Pending,
            signature: Vec::new(), // filled after encryption
        };

        self.storage.insert_message(&msg)?;
        Ok(msg)
    }

    /// Process an inbound message: deduplicate, validate, store.
    pub fn receive_message(&self, msg: Message) -> Result<bool> {
        // Dedup
        if self.storage.message_exists(&msg.msg_id)? {
            warn!("duplicate message ignored: {}", &msg.msg_id[..8]);
            return Ok(false);
        }

        // TODO: verify signature via crypto module
        // TODO: check sequence ordering

        self.storage.insert_message(&msg)?;
        self.storage.update_message_status(&msg.msg_id, MessageStatus::Synced)?;
        info!("received message {} in room {}", &msg.msg_id[..8], hex_short(&msg.room_id));
        Ok(true)
    }

    /// Mark a message as sent (DHT write succeeded).
    pub fn mark_sent(&self, msg_id: &str) -> Result<()> {
        self.storage.update_message_status(msg_id, MessageStatus::Sent)
    }

    /// Mark a message as synced (confirmed by peer).
    pub fn mark_synced(&self, msg_id: &str) -> Result<()> {
        self.storage.update_message_status(msg_id, MessageStatus::Synced)
    }

    /// Mark a message as failed.
    pub fn mark_failed(&self, msg_id: &str) -> Result<()> {
        self.storage.update_message_status(msg_id, MessageStatus::Failed)
    }

    /// Get recent messages for a room.
    pub fn get_messages(
        &self,
        room_id: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<(String, String, String, String, String)>> {
        self.storage.get_messages_for_room(room_id, limit, None)
    }

    /// List all rooms.
    pub fn list_rooms(&self) -> Result<Vec<(Vec<u8>, String, String)>> {
        self.storage.list_rooms()
    }

    /// Get reference to storage (for sync module access).
    pub fn storage(&self) -> &LocalStorage {
        &self.storage
    }
}

fn hex_short(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> ChatService {
        let storage = LocalStorage::open_memory().unwrap();
        ChatService::new(storage)
    }

    #[test]
    fn test_create_group_room() {
        let svc = setup();
        let room = svc.create_group_room("test", &[1u8; 32]).unwrap();
        assert_eq!(room.room_type, RoomType::Group);
        assert_eq!(room.members.len(), 1);

        let rooms = svc.list_rooms().unwrap();
        assert_eq!(rooms.len(), 1);
    }

    #[test]
    fn test_create_direct_room() {
        let svc = setup();
        let room = svc.create_direct_room(&[1u8; 32], &[2u8; 32], &[3u8; 32]).unwrap();
        assert_eq!(room.room_type, RoomType::Direct);
        assert_eq!(room.members.len(), 2);
    }

    #[test]
    fn test_compose_and_receive_message() {
        let svc = setup();
        let room = svc.create_group_room("test", &[1u8; 32]).unwrap();

        let msg = svc.compose_message(&room.room_id, &[1u8; 32], "hello", None).unwrap();
        assert_eq!(msg.status, MessageStatus::Pending);

        // Simulate receive of same message (should dedup)
        let received = svc.receive_message(msg.clone()).unwrap();
        assert!(!received); // already exists

        // New message from another sender
        let mut msg2 = msg.clone();
        msg2.msg_id = ulid::Ulid::new().to_string();
        msg2.sender_key = vec![9u8; 32];
        let received = svc.receive_message(msg2).unwrap();
        assert!(received);

        let msgs = svc.get_messages(&room.room_id, 50).unwrap();
        assert_eq!(msgs.len(), 2);
    }
}
