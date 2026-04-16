use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Local user identity backed by a Veilid Ed25519 keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>, // encrypted at rest
    pub display_name: String,
    pub avatar_hash: Option<Vec<u8>>,
    pub status: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Public-only view of an identity, safe to share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub public_key: Vec<u8>,
    pub display_name: String,
    pub avatar_hash: Option<Vec<u8>>,
    pub status: Option<String>,
}

// ---------------------------------------------------------------------------
// Room
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomType {
    Direct,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    pub room_id: [u8; 32],
    pub room_type: RoomType,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub creator_key: Vec<u8>,
    pub room_key: Vec<u8>,            // symmetric key for E2E
    pub dht_metadata_key: Vec<u8>,    // DHT record key for room metadata
    pub dht_members_key: Vec<u8>,     // DHT record key for member list
    pub dht_messages_key: Vec<u8>,    // DHT record key for message log
    pub members: Vec<RoomMember>,
    pub last_sync_seq: u64,
    pub schema_version: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMember {
    pub public_key: Vec<u8>,
    pub display_name: String,
    pub role: MemberRole,
    pub joined_at: DateTime<Utc>,
    pub subkey_start: u32,
    pub subkey_end: u32,
    pub route_data: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    Draft,
    Pending,
    Sent,
    Synced,
    Failed,
}

impl fmt::Display for MessageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Pending => write!(f, "pending"),
            Self::Sent => write!(f, "sent"),
            Self::Synced => write!(f, "synced"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    Text,
    Audio,
    File,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub msg_id: String,              // ULID
    pub room_id: [u8; 32],
    pub sender_key: Vec<u8>,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub content_type: ContentType,
    pub content: String,
    pub reply_to: Option<String>,    // msg_id of parent
    pub attachments: Vec<AttachmentRef>,
    pub status: MessageStatus,
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Attachments and files
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub file_id: [u8; 32],
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub blake3_hash: Vec<u8>,
    pub dht_record_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_id: [u8; 32],
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub blake3_hash: Vec<u8>,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub sender_key: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub schema_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub file_id: [u8; 32],
    pub chunk_index: u32,
    pub data: Vec<u8>,               // encrypted
    pub blake3_hash: Vec<u8>,        // hash of plaintext chunk
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferStatus {
    Queued,
    InProgress { progress_pct: u8 },
    Complete,
    Failed,
    Paused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransfer {
    pub file_id: [u8; 32],
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub chunks_done: u32,
    pub chunks_total: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    Upload,
    Download,
}

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceNote {
    pub note_id: [u8; 32],
    pub duration_ms: u32,
    pub sample_rate: u32,
    pub codec: String,               // "opus"
    pub chunk_count: u32,
    pub total_size: u64,
    pub sender_key: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioChunk {
    pub note_id: [u8; 32],
    pub chunk_index: u32,
    pub data: Vec<u8>,               // encrypted Opus frames
    pub duration_ms: u32,
}

// ---------------------------------------------------------------------------
// Invite
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteType {
    Direct = 0,
    Room = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatInvite {
    pub version: u8,
    pub invite_type: InviteType,
    pub room_id: [u8; 32],
    pub dht_record_key: Vec<u8>,
    pub bootstrap_route: Option<Vec<u8>>,
    pub room_name: Option<String>,
    pub creator_public_key: Vec<u8>,
    pub created_at: u64,             // unix timestamp
    pub expires_at: Option<u64>,
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub room_id: [u8; 32],
    pub member_cursors: Vec<MemberCursor>,
    pub last_sync_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCursor {
    pub public_key: Vec<u8>,
    pub last_seq: u64,
    pub last_subkey: u32,
}

// ---------------------------------------------------------------------------
// Crypto envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,          // 64 bytes
    pub sender_fingerprint: [u8; 8], // first 8 bytes of blake3(pubkey)
}

// ---------------------------------------------------------------------------
// Events (UI event bus)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppEvent {
    NewMessage { room_id: [u8; 32], msg_id: String },
    MessageStatusChanged { msg_id: String, status: MessageStatus },
    SyncComplete { room_id: [u8; 32] },
    PeerOnline { public_key: Vec<u8> },
    PeerOffline { public_key: Vec<u8> },
    TransferProgress { file_id: [u8; 32], progress_pct: u8 },
    InviteReceived { invite: ChatInvite },
    Error { context: String, message: String },
}
