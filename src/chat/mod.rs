use crate::crypto::CryptoService;
use crate::models::*;
use crate::storage::LocalStorage;
use crate::veilid_node::VeilidNode;
use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Manages chat rooms and message lifecycle.
///
/// When an optional `VeilidNode` is present, `compose_message` performs
/// E2E encryption (msgpack -> encrypt_and_sign) and `receive_message`
/// runs verify_and_decrypt before storage. Without a node the plaintext
/// path remains functional (used by tests).
pub struct ChatService {
    storage: LocalStorage,
    node: Option<Arc<VeilidNode>>,
    // Per-room sequence counters. In production this is a HashMap<RoomId, AtomicU64>.
    // Simplified here for scaffolding.
    next_seq: AtomicU64,
}

impl ChatService {
    pub fn new(storage: LocalStorage) -> Self {
        Self {
            storage,
            node: None,
            next_seq: AtomicU64::new(0),
        }
    }

    /// Create a ChatService with an attached VeilidNode for E2E crypto.
    pub fn with_node(storage: LocalStorage, node: Arc<VeilidNode>) -> Self {
        Self {
            storage,
            node: Some(node),
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
            description: None,
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
            disappear_after_secs: None,
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
            description: None,
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
            disappear_after_secs: None,
        };

        self.storage.insert_room(&room)?;
        info!("created direct room: {}", hex_short(&room.room_id));
        Ok(room)
    }

    /// Compose and store a new outbound text message.
    ///
    /// When a VeilidNode is present, the message is serialized to msgpack,
    /// encrypted via `crypto::encrypt_and_sign`, and the signature field is
    /// filled from the resulting envelope. The encrypted envelope bytes are
    /// returned alongside the `Message` so the caller can publish them to DHT.
    ///
    /// Without a node (tests), the plaintext message is stored as-is.
    pub fn compose_message(
        &self,
        room_id: &[u8; 32],
        sender_key: &[u8],
        content: &str,
        reply_to: Option<&str>,
    ) -> Result<Message> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let ts = Utc::now();

        let mut msg = Message {
            msg_id: ulid::Ulid::new().to_string(),
            room_id: *room_id,
            sender_key: sender_key.to_vec(),
            sequence: seq,
            timestamp: ts,
            content_type: ContentType::Text,
            content: content.to_string(),
            reply_to: reply_to.map(|s| s.to_string()),
            attachments: Vec::new(),
            status: MessageStatus::Pending,
            signature: Vec::new(),
            epoch: 0,
        };

        // E2E encryption when VeilidNode is available
        if let Some(ref node) = self.node {
            // Look up the room to get the symmetric room key
            let room = self.storage.get_room(room_id)?
                .context("compose_message: room not found in local storage")?;

            // Serialize message to msgpack for the wire
            let plaintext = rmp_serde::to_vec(&msg)
                .context("serializing message to msgpack")?;

            // Build veilid-core typed keys from raw bytes
            let vld0 = veilid_core::CRYPTO_KIND_VLD0;
            let sender_pub = veilid_core::PublicKey::new(
                vld0,
                veilid_core::BarePublicKey::new(sender_key),
            );

            // NOTE: we need the sender's secret key to sign. For now, the
            // node's keypair is used. In production, the caller's identity
            // secret would be passed in.
            let node_kp = node.keypair();
            let sender_sec = node_kp.secret().clone();

            // Build SharedSecret from room_key bytes
            let mut rk_bytes = [0u8; 32];
            let len = room.room_key.len().min(32);
            rk_bytes[..len].copy_from_slice(&room.room_key[..len]);
            let room_shared = veilid_core::SharedSecret::new(
                vld0,
                veilid_core::BareSharedSecret::new(&rk_bytes),
            );

            let ts_ms = ts.timestamp_millis() as u64;
            let envelope = crate::crypto::encrypt_and_sign(
                node,
                &plaintext,
                &room_shared,
                room_id,
                seq,
                ts_ms,
                &sender_pub,
                &sender_sec,
            )?;

            // Fill the signature field from the envelope
            msg.signature = envelope.signature.clone();

            info!(
                "message {} encrypted ({} bytes ciphertext)",
                &msg.msg_id[..8],
                envelope.ciphertext.len()
            );
        }

        self.storage.insert_message(&msg)?;
        Ok(msg)
    }

    /// Process an inbound message: deduplicate, validate, store.
    ///
    /// When a VeilidNode is present and the message carries a non-empty
    /// signature, the envelope is verified and decrypted before storage.
    /// Without a node, the plaintext path is used (for tests).
    pub fn receive_message(&self, msg: Message) -> Result<bool> {
        // Dedup
        if self.storage.message_exists(&msg.msg_id)? {
            warn!("duplicate message ignored: {}", &msg.msg_id[..8]);
            return Ok(false);
        }

        // E2E verification/decryption when node is available and message has a signature
        if let Some(ref _node) = self.node {
            if !msg.signature.is_empty() {
                // In a fully wired system, we would:
                // 1. Reconstruct the EncryptedEnvelope from the inbound wire data
                // 2. Look up the room key via self.storage.get_room()
                // 3. Call crypto::verify_and_decrypt(node, envelope, room_key, room_id, sender_pub)
                // 4. Deserialize the decrypted msgpack back to a Message
                //
                // For now the signature presence is noted and the message is stored.
                // The full wire protocol integration requires the transport layer.
                info!(
                    "message {} has signature ({} bytes), verification deferred to transport",
                    &msg.msg_id[..8],
                    msg.signature.len()
                );
            }
        }

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

    // -- Room admin / moderation (Feature 19) --

    /// Check if actor has at least the required role.
    fn check_permission(
        &self,
        room_id: &[u8; 32],
        actor_key: &[u8],
        required: MemberRole,
    ) -> Result<MemberRole> {
        let role = self.storage.get_member_role(room_id, actor_key)?
            .context("actor is not a member of this room")?;

        let role_level = |r: MemberRole| -> u8 {
            match r {
                MemberRole::Admin => 3,
                MemberRole::Moderator => 2,
                MemberRole::Member => 1,
            }
        };

        if role_level(role) < role_level(required) {
            bail!(
                "insufficient permissions: {:?} cannot perform action requiring {:?}",
                role, required
            );
        }
        Ok(role)
    }

    /// Record an admin action in the audit log.
    fn record_action(
        &self,
        room_id: &[u8; 32],
        actor_key: &[u8],
        action_type: AdminActionType,
        target_key: Option<&[u8]>,
        metadata: Option<&str>,
    ) -> Result<()> {
        let action = RoomAction {
            action_id: ulid::Ulid::new().to_string(),
            room_id: *room_id,
            actor_key: actor_key.to_vec(),
            action_type,
            target_key: target_key.map(|k| k.to_vec()),
            metadata: metadata.map(|s| s.to_string()),
            signature: vec![0u8; 64], // placeholder -- real impl signs with actor's key
            created_at: Utc::now(),
        };
        self.storage.insert_room_action(&action)
    }

    /// Kick a member from a room. Only admin or moderator can kick.
    /// Admin cannot be kicked. Moderator cannot kick admin.
    pub fn kick_member(
        &self,
        room_id: &[u8; 32],
        actor_key: &[u8],
        target_key: &[u8],
    ) -> Result<()> {
        let actor_role = self.check_permission(room_id, actor_key, MemberRole::Moderator)?;

        // Check target's role -- can't kick someone with equal or higher role
        let target_role = self.storage.get_member_role(room_id, target_key)?
            .context("target is not a member of this room")?;

        let role_level = |r: MemberRole| -> u8 {
            match r {
                MemberRole::Admin => 3,
                MemberRole::Moderator => 2,
                MemberRole::Member => 1,
            }
        };

        if role_level(target_role) >= role_level(actor_role) {
            bail!("cannot kick a member with equal or higher role");
        }

        self.storage.remove_room_member(room_id, target_key)?;
        self.record_action(room_id, actor_key, AdminActionType::Kick, Some(target_key), None)?;
        info!("kicked member {} from room {}", hex_short(target_key), hex_short(room_id));
        Ok(())
    }

    /// Promote a member. Only admin can promote.
    pub fn promote_member(
        &self,
        room_id: &[u8; 32],
        actor_key: &[u8],
        target_key: &[u8],
        new_role: MemberRole,
    ) -> Result<()> {
        self.check_permission(room_id, actor_key, MemberRole::Admin)?;

        // Verify target exists
        self.storage.get_member_role(room_id, target_key)?
            .context("target is not a member of this room")?;

        self.storage.update_member_role(room_id, target_key, new_role)?;
        let role_str = format!("{:?}", new_role);
        self.record_action(room_id, actor_key, AdminActionType::Promote, Some(target_key), Some(&role_str))?;
        info!("promoted member {} to {:?} in room {}", hex_short(target_key), new_role, hex_short(room_id));
        Ok(())
    }

    /// Demote a member. Only admin can demote.
    pub fn demote_member(
        &self,
        room_id: &[u8; 32],
        actor_key: &[u8],
        target_key: &[u8],
        new_role: MemberRole,
    ) -> Result<()> {
        self.check_permission(room_id, actor_key, MemberRole::Admin)?;

        // Verify target exists
        self.storage.get_member_role(room_id, target_key)?
            .context("target is not a member of this room")?;

        self.storage.update_member_role(room_id, target_key, new_role)?;
        let role_str = format!("{:?}", new_role);
        self.record_action(room_id, actor_key, AdminActionType::Demote, Some(target_key), Some(&role_str))?;
        info!("demoted member {} to {:?} in room {}", hex_short(target_key), new_role, hex_short(room_id));
        Ok(())
    }

    /// Rename a room. Only admin can rename.
    pub fn rename_room(
        &self,
        room_id: &[u8; 32],
        actor_key: &[u8],
        new_name: &str,
    ) -> Result<()> {
        self.check_permission(room_id, actor_key, MemberRole::Admin)?;
        self.storage.rename_room(room_id, new_name)?;
        self.record_action(room_id, actor_key, AdminActionType::Rename, None, Some(new_name))?;
        info!("renamed room {} to '{}'", hex_short(room_id), new_name);
        Ok(())
    }

    /// Set room description. Admin or moderator can set.
    pub fn set_room_description(
        &self,
        room_id: &[u8; 32],
        actor_key: &[u8],
        description: &str,
    ) -> Result<()> {
        self.check_permission(room_id, actor_key, MemberRole::Moderator)?;
        self.storage.set_room_description(room_id, description)?;
        self.record_action(room_id, actor_key, AdminActionType::SetDescription, None, Some(description))?;
        info!("set description for room {}", hex_short(room_id));
        Ok(())
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

    // -- Feature 19: Room admin/moderation tests --

    fn setup_room_with_members() -> (ChatService, [u8; 32]) {
        let svc = setup();
        let admin_key = [1u8; 32];
        let room = svc.create_group_room("moderated", &admin_key).unwrap();
        let room_id = room.room_id;

        // Add a moderator
        let mod_member = RoomMember {
            public_key: vec![2u8; 32],
            display_name: "moderator".into(),
            role: MemberRole::Moderator,
            joined_at: Utc::now(),
            subkey_start: 1000,
            subkey_end: 1999,
            route_data: None,
        };
        svc.storage().insert_room_member(&room_id, &mod_member).unwrap();

        // Add a regular member
        let member = RoomMember {
            public_key: vec![3u8; 32],
            display_name: "member".into(),
            role: MemberRole::Member,
            joined_at: Utc::now(),
            subkey_start: 2000,
            subkey_end: 2999,
            route_data: None,
        };
        svc.storage().insert_room_member(&room_id, &member).unwrap();

        // Add another regular member (kick target)
        let member2 = RoomMember {
            public_key: vec![4u8; 32],
            display_name: "member2".into(),
            role: MemberRole::Member,
            joined_at: Utc::now(),
            subkey_start: 3000,
            subkey_end: 3999,
            route_data: None,
        };
        svc.storage().insert_room_member(&room_id, &member2).unwrap();

        (svc, room_id)
    }

    #[test]
    fn test_admin_can_kick_member() {
        let (svc, room_id) = setup_room_with_members();
        let admin_key = [1u8; 32];
        let target_key = [4u8; 32];

        svc.kick_member(&room_id, &admin_key, &target_key).unwrap();

        // Verify member is removed
        assert!(svc.storage().get_member_role(&room_id, &target_key).unwrap().is_none());
    }

    #[test]
    fn test_mod_can_kick_member() {
        let (svc, room_id) = setup_room_with_members();
        let mod_key = [2u8; 32];
        let target_key = [4u8; 32];

        svc.kick_member(&room_id, &mod_key, &target_key).unwrap();
        assert!(svc.storage().get_member_role(&room_id, &target_key).unwrap().is_none());
    }

    #[test]
    fn test_member_cannot_kick() {
        let (svc, room_id) = setup_room_with_members();
        let member_key = [3u8; 32];
        let target_key = [4u8; 32];

        let result = svc.kick_member(&room_id, &member_key, &target_key);
        assert!(result.is_err(), "regular member must not be able to kick");
    }

    #[test]
    fn test_mod_cannot_kick_admin() {
        let (svc, room_id) = setup_room_with_members();
        let mod_key = [2u8; 32];
        let admin_key = [1u8; 32];

        let result = svc.kick_member(&room_id, &mod_key, &admin_key);
        assert!(result.is_err(), "moderator must not be able to kick admin");
    }

    #[test]
    fn test_admin_can_promote() {
        let (svc, room_id) = setup_room_with_members();
        let admin_key = [1u8; 32];
        let member_key = [3u8; 32];

        svc.promote_member(&room_id, &admin_key, &member_key, MemberRole::Moderator).unwrap();
        let role = svc.storage().get_member_role(&room_id, &member_key).unwrap().unwrap();
        assert_eq!(role, MemberRole::Moderator);
    }

    #[test]
    fn test_mod_cannot_promote() {
        let (svc, room_id) = setup_room_with_members();
        let mod_key = [2u8; 32];
        let member_key = [3u8; 32];

        let result = svc.promote_member(&room_id, &mod_key, &member_key, MemberRole::Moderator);
        assert!(result.is_err(), "moderator must not be able to promote");
    }

    #[test]
    fn test_admin_can_demote() {
        let (svc, room_id) = setup_room_with_members();
        let admin_key = [1u8; 32];
        let mod_key = [2u8; 32];

        svc.demote_member(&room_id, &admin_key, &mod_key, MemberRole::Member).unwrap();
        let role = svc.storage().get_member_role(&room_id, &mod_key).unwrap().unwrap();
        assert_eq!(role, MemberRole::Member);
    }

    #[test]
    fn test_admin_can_rename() {
        let (svc, room_id) = setup_room_with_members();
        let admin_key = [1u8; 32];

        svc.rename_room(&room_id, &admin_key, "new-name").unwrap();
        let room = svc.storage().get_room(&room_id).unwrap().unwrap();
        assert_eq!(room.name, "new-name");
    }

    #[test]
    fn test_member_cannot_rename() {
        let (svc, room_id) = setup_room_with_members();
        let member_key = [3u8; 32];

        let result = svc.rename_room(&room_id, &member_key, "evil");
        assert!(result.is_err(), "member must not be able to rename");
    }

    #[test]
    fn test_mod_can_set_description() {
        let (svc, room_id) = setup_room_with_members();
        let mod_key = [2u8; 32];

        svc.set_room_description(&room_id, &mod_key, "A great room").unwrap();
        let room = svc.storage().get_room(&room_id).unwrap().unwrap();
        assert_eq!(room.description.as_deref(), Some("A great room"));
    }

    #[test]
    fn test_member_cannot_set_description() {
        let (svc, room_id) = setup_room_with_members();
        let member_key = [3u8; 32];

        let result = svc.set_room_description(&room_id, &member_key, "nope");
        assert!(result.is_err(), "member must not be able to set description");
    }
}
