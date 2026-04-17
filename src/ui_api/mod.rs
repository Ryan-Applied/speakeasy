//! UI API module -- the boundary between the UI layer and the networking/storage core.
//!
//! All UI interactions go through this module. The UI never touches DHT, transport,
//! or crypto directly. This keeps the core testable and the UI swappable
//! (terminal -> Tauri -> mobile).

use crate::chat::ChatService;
use crate::invite::InviteService;
use crate::models::*;
use tokio::sync::broadcast;
use tracing::info;

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

/// Dispatcher processes `Command` variants by delegating to the appropriate
/// service and emitting `AppEvent`s via the `UiApi` event bus.
pub struct Dispatcher<'a> {
    pub chat: &'a ChatService,
    pub ui: &'a UiApi,
    pub identity: &'a UserIdentity,
}

impl<'a> Dispatcher<'a> {
    pub fn new(
        chat: &'a ChatService,
        ui: &'a UiApi,
        identity: &'a UserIdentity,
    ) -> Self {
        Self { chat, ui, identity }
    }

    /// Dispatch a command and return a result for the UI.
    pub fn dispatch(&self, cmd: Command) -> QueryResult {
        match cmd {
            Command::CreateRoom { name, room_type: _ } => {
                match self.chat.create_group_room(&name, &self.identity.public_key) {
                    Ok(room) => {
                        info!("dispatcher: created room '{}'", room.name);
                        self.ui.emit(AppEvent::SyncComplete { room_id: room.room_id });
                        QueryResult::Ok
                    }
                    Err(e) => {
                        self.ui.emit(AppEvent::Error {
                            context: "CreateRoom".into(),
                            message: e.to_string(),
                        });
                        QueryResult::Error(e.to_string())
                    }
                }
            }

            Command::JoinRoom { invite_string } => {
                match InviteService::decode_from_string(&invite_string) {
                    Ok(invite) => match InviteService::validate(&invite) {
                        Ok(()) => {
                            info!(
                                "dispatcher: valid invite for room '{}'",
                                invite.room_name.as_deref().unwrap_or("(unnamed)")
                            );
                            self.ui.emit(AppEvent::InviteReceived { invite });
                            QueryResult::Ok
                        }
                        Err(e) => {
                            self.ui.emit(AppEvent::Error {
                                context: "JoinRoom/validate".into(),
                                message: e.to_string(),
                            });
                            QueryResult::Error(e.to_string())
                        }
                    },
                    Err(e) => {
                        self.ui.emit(AppEvent::Error {
                            context: "JoinRoom/decode".into(),
                            message: e.to_string(),
                        });
                        QueryResult::Error(e.to_string())
                    }
                }
            }

            Command::SendMessage { room_id, content, reply_to } => {
                let reply_ref = reply_to.as_deref();
                match self.chat.compose_message(
                    &room_id,
                    &self.identity.public_key,
                    &content,
                    reply_ref,
                ) {
                    Ok(msg) => {
                        self.ui.emit(AppEvent::NewMessage {
                            room_id,
                            msg_id: msg.msg_id.clone(),
                        });
                        QueryResult::Ok
                    }
                    Err(e) => {
                        self.ui.emit(AppEvent::Error {
                            context: "SendMessage".into(),
                            message: e.to_string(),
                        });
                        QueryResult::Error(e.to_string())
                    }
                }
            }

            Command::ListRooms => {
                match self.chat.list_rooms() {
                    Ok(rooms) => QueryResult::Rooms(rooms),
                    Err(e) => {
                        self.ui.emit(AppEvent::Error {
                            context: "ListRooms".into(),
                            message: e.to_string(),
                        });
                        QueryResult::Error(e.to_string())
                    }
                }
            }

            Command::GetMessages { room_id, limit } => {
                match self.chat.get_messages(&room_id, limit) {
                    Ok(msgs) => QueryResult::Messages(msgs),
                    Err(e) => {
                        self.ui.emit(AppEvent::Error {
                            context: "GetMessages".into(),
                            message: e.to_string(),
                        });
                        QueryResult::Error(e.to_string())
                    }
                }
            }

            Command::ExportInvite { room_id } => {
                match InviteService::create_room_invite(
                    room_id,
                    Vec::new(),
                    None,
                    self.identity.public_key.clone(),
                    &self.identity.secret_key,
                    None,
                    Some(86400),
                ) {
                    Ok(invite) => match InviteService::encode_to_string(&invite) {
                        Ok(s) => QueryResult::Invite(s),
                        Err(e) => QueryResult::Error(e.to_string()),
                    },
                    Err(e) => {
                        self.ui.emit(AppEvent::Error {
                            context: "ExportInvite".into(),
                            message: e.to_string(),
                        });
                        QueryResult::Error(e.to_string())
                    }
                }
            }

            // Unhandled commands return Ok for now
            Command::SendFile { .. }
            | Command::RecordVoiceNote { .. }
            | Command::StopVoiceNote
            | Command::GetSyncStatus { .. } => {
                QueryResult::Ok
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalStorage;

    fn setup() -> (ChatService, UiApi, broadcast::Receiver<AppEvent>, UserIdentity) {
        let storage = LocalStorage::open_memory().unwrap();
        let chat = ChatService::new(storage);
        let (ui, rx) = UiApi::new();
        let identity = UserIdentity {
            public_key: vec![1u8; 32],
            secret_key: vec![2u8; 32],
            display_name: "test-user".into(),
            avatar_hash: None,
            status: None,
            created_at: chrono::Utc::now(),
        };
        (chat, ui, rx, identity)
    }

    #[test]
    fn test_dispatcher_create_room() {
        let (chat, ui, _rx, identity) = setup();
        let disp = Dispatcher::new(&chat, &ui, &identity);
        let result = disp.dispatch(Command::CreateRoom {
            name: "my-room".into(),
            room_type: RoomType::Group,
        });
        assert!(matches!(result, QueryResult::Ok));

        // Verify room was created
        let result = disp.dispatch(Command::ListRooms);
        if let QueryResult::Rooms(rooms) = result {
            assert_eq!(rooms.len(), 1);
            assert_eq!(rooms[0].1, "my-room");
        } else {
            panic!("expected QueryResult::Rooms");
        }
    }

    #[test]
    fn test_dispatcher_send_message() {
        let (chat, ui, _rx, identity) = setup();
        let disp = Dispatcher::new(&chat, &ui, &identity);

        // Create a room first
        disp.dispatch(Command::CreateRoom {
            name: "test".into(),
            room_type: RoomType::Group,
        });

        // Get the room ID
        let rooms = chat.list_rooms().unwrap();
        let mut room_id = [0u8; 32];
        room_id.copy_from_slice(&rooms[0].0[..32]);

        let result = disp.dispatch(Command::SendMessage {
            room_id,
            content: "hello world".into(),
            reply_to: None,
        });
        assert!(matches!(result, QueryResult::Ok));

        // Verify message stored
        let result = disp.dispatch(Command::GetMessages {
            room_id,
            limit: 50,
        });
        if let QueryResult::Messages(msgs) = result {
            assert_eq!(msgs.len(), 1);
        } else {
            panic!("expected QueryResult::Messages");
        }
    }

    #[test]
    fn test_dispatcher_join_room_invalid() {
        let (chat, ui, _rx, identity) = setup();
        let disp = Dispatcher::new(&chat, &ui, &identity);
        let result = disp.dispatch(Command::JoinRoom {
            invite_string: "not-a-valid-invite".into(),
        });
        assert!(matches!(result, QueryResult::Error(_)));
    }

    #[test]
    fn test_dispatcher_unhandled_returns_ok() {
        let (chat, ui, _rx, identity) = setup();
        let disp = Dispatcher::new(&chat, &ui, &identity);
        let result = disp.dispatch(Command::StopVoiceNote);
        assert!(matches!(result, QueryResult::Ok));
    }
}
