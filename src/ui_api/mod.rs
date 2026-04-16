//! UI API module -- the boundary between the UI layer and the networking/storage core.
//!
//! All UI interactions go through this module. The UI never touches DHT, transport,
//! or crypto directly. This keeps the core testable and the UI swappable
//! (terminal -> Tauri -> mobile).

use crate::models::*;
use tokio::sync::broadcast;

/// Commands the UI can issue to the core.
pub enum Command {
    CreateRoom { name: String, room_type: RoomType },
    JoinRoom { invite_string: String },
    SendMessage { room_id: [u8; 32], content: String, reply_to: Option<String> },
    SendFile { room_id: [u8; 32], file_path: String },
    RecordVoiceNote { room_id: [u8; 32] },
    StopVoiceNote,
    ExportInvite { room_id: [u8; 32] },
    ListRooms,
    GetMessages { room_id: [u8; 32], limit: u32 },
    GetSyncStatus { room_id: [u8; 32] },
}

/// Responses to UI queries.
pub enum QueryResult {
    Rooms(Vec<(Vec<u8>, String, String)>),
    Messages(Vec<(String, String, String, String, String)>),
    Invite(String),
    InviteQr(Vec<u8>),
    SyncStatus { last_sync: String, pending_count: u32 },
    Ok,
    Error(String),
}

/// The API handle given to the UI layer.
pub struct UiApi {
    event_tx: broadcast::Sender<AppEvent>,
}

impl UiApi {
    pub fn new() -> (Self, broadcast::Receiver<AppEvent>) {
        let (tx, rx) = broadcast::channel(256);
        (Self { event_tx: tx }, rx)
    }

    /// Subscribe to events (additional subscribers beyond the first).
    pub fn subscribe(&self) -> broadcast::Receiver<AppEvent> {
        self.event_tx.subscribe()
    }

    /// Emit an event to all subscribers.
    pub fn emit(&self, event: AppEvent) {
        let _ = self.event_tx.send(event);
    }
}
