//! Terminal UI for veilid-chat using ratatui + crossterm.

use crate::chat::ChatService;
use crate::invite::InviteService;
use crate::models::UserIdentity;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::collections::HashMap;
use std::io::stdout;
use std::time::{Duration, Instant};

/// Lightweight room entry for the sidebar.
struct RoomEntry {
    id: [u8; 32],
    name: String,
    room_type: String,
    unread: u32,
    disappear_after_secs: Option<u64>,
}

/// Lightweight message entry for the message view.
struct MessageEntry {
    msg_id: String,
    sender: String,
    content: String,
    time: String,
    status: String,
    reactions: Vec<(String, u32)>,
}

/// Pane that currently has keyboard focus.
#[derive(PartialEq)]
enum Focus {
    Rooms,
    Input,
}

/// Application state driving the TUI.
pub struct App {
    rooms: Vec<RoomEntry>,
    room_state: ListState,
    messages: Vec<MessageEntry>,
    input: String,
    input_cursor: usize,
    _status_line: String,
    notification: Option<String>,
    focus: Focus,
    should_quit: bool,
    /// Typing indicators: room_id -> [(sender_fingerprint, last_typed_at)]
    typing_state: HashMap<[u8; 32], Vec<(String, Instant)>>,
    /// Flag: local user is typing (set on keypress in Input focus)
    local_typing: bool,
    // services
    chat: ChatService,
    identity: UserIdentity,
}

impl App {
    pub fn new(chat: ChatService, identity: UserIdentity) -> Self {
        let mut app = Self {
            rooms: Vec::new(),
            room_state: ListState::default(),
            messages: Vec::new(),
            input: String::new(),
            input_cursor: 0,
            _status_line: String::new(),
            notification: None,
            focus: Focus::Input,
            should_quit: false,
            typing_state: HashMap::new(),
            local_typing: false,
            chat,
            identity,
        };
        app.refresh_rooms();
        if !app.rooms.is_empty() {
            app.room_state.select(Some(0));
            app.refresh_messages();
        }
        app
    }

    fn refresh_rooms(&mut self) {
        match self.chat.list_rooms() {
            Ok(rows) => {
                self.rooms = rows
                    .into_iter()
                    .map(|(id_bytes, name, rtype)| {
                        let mut id = [0u8; 32];
                        let len = id_bytes.len().min(32);
                        id[..len].copy_from_slice(&id_bytes[..len]);

                        // Get unread count for this room
                        let unread = self.chat.storage()
                            .count_unread(&id, &self.identity.public_key)
                            .unwrap_or(0);

                        // Get disappear_after_secs
                        let disappear_after_secs = self.chat.storage()
                            .get_room(&id)
                            .ok()
                            .flatten()
                            .and_then(|r| r.disappear_after_secs);

                        RoomEntry {
                            id,
                            name,
                            room_type: rtype,
                            unread,
                            disappear_after_secs,
                        }
                    })
                    .collect();
            }
            Err(e) => {
                self.notification = Some(format!("Error listing rooms: {}", e));
            }
        }
    }

    fn refresh_messages(&mut self) {
        let idx = match self.room_state.selected() {
            Some(i) if i < self.rooms.len() => i,
            _ => return,
        };
        let room_id = self.rooms[idx].id;
        match self.chat.get_messages(&room_id, 100) {
            Ok(rows) => {
                self.messages = rows
                    .into_iter()
                    .rev() // oldest first
                    .map(|(msg_id, sender, content, ts, status)| {
                        let time = ts
                            .split('T')
                            .nth(1)
                            .unwrap_or(&ts)
                            .split('.')
                            .next()
                            .unwrap_or("")
                            .to_string();

                        // Load reactions for this message
                        let reactions = self.chat.storage()
                            .get_reactions_for_message(&msg_id)
                            .unwrap_or_default();

                        MessageEntry {
                            msg_id,
                            sender: sender[..8.min(sender.len())].to_string(),
                            content,
                            time,
                            status,
                            reactions,
                        }
                    })
                    .collect();
            }
            Err(e) => {
                self.notification = Some(format!("Error fetching messages: {}", e));
            }
        }

        // Update read receipt when viewing a room
        if let Some(last_msg) = self.messages.last() {
            let _ = self.chat.storage().update_read_receipt(
                &room_id,
                &self.identity.public_key,
                &last_msg.msg_id,
            );
        }
    }

    fn selected_room_id(&self) -> Option<[u8; 32]> {
        self.room_state
            .selected()
            .and_then(|i| self.rooms.get(i))
            .map(|r| r.id)
    }

    fn selected_room_name(&self) -> String {
        self.room_state
            .selected()
            .and_then(|i| self.rooms.get(i))
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "(none)".into())
    }

    fn selected_room_disappear(&self) -> Option<u64> {
        self.room_state
            .selected()
            .and_then(|i| self.rooms.get(i))
            .and_then(|r| r.disappear_after_secs)
    }

    fn handle_command(&mut self, line: &str) {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        match parts[0] {
            "/quit" | "/q" => self.should_quit = true,
            "/create" => {
                let name = parts.get(1).unwrap_or(&"unnamed").trim();
                match self.chat.create_group_room(name, &self.identity.public_key) {
                    Ok(room) => {
                        self.notification =
                            Some(format!("Created room: {}", room.name));
                        self.refresh_rooms();
                        // Select the new room (last in list)
                        if !self.rooms.is_empty() {
                            self.room_state.select(Some(self.rooms.len() - 1));
                            self.refresh_messages();
                        }
                    }
                    Err(e) => self.notification = Some(format!("Error: {}", e)),
                }
            }
            "/invite" => {
                if let Some(room_id) = self.selected_room_id() {
                    match InviteService::create_room_invite(
                        room_id,
                        Vec::new(),
                        Some(self.selected_room_name()),
                        self.identity.public_key.clone(),
                        &self.identity.secret_key,
                        None,
                        Some(86400),
                    ) {
                        Ok(invite) => match InviteService::encode_to_string(&invite) {
                            Ok(s) => {
                                // Post the invite as a system message in the chat so
                                // it word-wraps and can be fully selected/copied.
                                let _ = self.chat.compose_message(
                                    &room_id,
                                    &self.identity.public_key,
                                    &self.identity.secret_key,
                                    &format!("--- INVITE (share this) ---\n{}", s),
                                    None,
                                );
                                self.refresh_messages();
                                self.notification = Some("Invite posted to chat (scroll up if needed)".into());
                            }
                            Err(e) => self.notification = Some(format!("Error: {}", e)),
                        },
                        Err(e) => self.notification = Some(format!("Error: {}", e)),
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/join" => {
                let code = parts.get(1).unwrap_or(&"").trim();
                if code.is_empty() {
                    self.notification = Some("Usage: /join <invite_string>".into());
                } else {
                    match InviteService::decode_from_string(code) {
                        Ok(invite) => match InviteService::validate(&invite) {
                            Ok(()) => {
                                let room_name = invite
                                    .room_name
                                    .clone()
                                    .unwrap_or_else(|| "(unnamed)".into());
                                match self.chat.join_room_from_invite(
                                    &invite,
                                    &self.identity.public_key,
                                ) {
                                    Ok(_room) => {
                                        self.refresh_rooms();
                                        // Select the newly joined room
                                        if !self.rooms.is_empty() {
                                            self.room_state
                                                .select(Some(self.rooms.len() - 1));
                                            self.refresh_messages();
                                        }
                                        self.notification =
                                            Some(format!("Joined room: {}", room_name));
                                    }
                                    Err(e) => {
                                        self.notification =
                                            Some(format!("Join failed: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                self.notification = Some(format!("Invalid invite: {}", e))
                            }
                        },
                        Err(e) => self.notification = Some(format!("Decode error: {}", e)),
                    }
                }
            }
            "/search" => {
                let query = parts.get(1).unwrap_or(&"").trim();
                if query.is_empty() {
                    self.notification = Some("Usage: /search <query>".into());
                } else {
                    match self.chat.storage().search_messages(query, 50) {
                        Ok(results) => {
                            if results.is_empty() {
                                self.notification = Some(format!("No results for '{}'", query));
                            } else {
                                // Display results in message view by replacing messages
                                self.messages = results
                                    .into_iter()
                                    .map(|(msg_id, sender, content, ts, status)| {
                                        let time = ts
                                            .split('T')
                                            .nth(1)
                                            .unwrap_or(&ts)
                                            .split('.')
                                            .next()
                                            .unwrap_or("")
                                            .to_string();
                                        let reactions = self.chat.storage()
                                            .get_reactions_for_message(&msg_id)
                                            .unwrap_or_default();
                                        MessageEntry {
                                            msg_id,
                                            sender: sender[..8.min(sender.len())].to_string(),
                                            content,
                                            time,
                                            status,
                                            reactions,
                                        }
                                    })
                                    .collect();
                                self.notification = Some(
                                    format!("Search: {} result(s) for '{}'", self.messages.len(), query)
                                );
                            }
                        }
                        Err(e) => self.notification = Some(format!("Search error: {}", e)),
                    }
                }
            }
            "/disappear" => {
                if let Some(room_id) = self.selected_room_id() {
                    let arg = parts.get(1).unwrap_or(&"").trim();
                    if arg == "off" || arg.is_empty() {
                        match self.chat.storage().set_disappear_after(&room_id, None) {
                            Ok(()) => {
                                self.notification = Some("Disappearing messages disabled".into());
                                self.refresh_rooms();
                            }
                            Err(e) => self.notification = Some(format!("Error: {}", e)),
                        }
                    } else {
                        match arg.parse::<u64>() {
                            Ok(secs) => {
                                match self.chat.storage().set_disappear_after(&room_id, Some(secs)) {
                                    Ok(()) => {
                                        self.notification = Some(
                                            format!("Messages will disappear after {} seconds", secs)
                                        );
                                        self.refresh_rooms();
                                    }
                                    Err(e) => self.notification = Some(format!("Error: {}", e)),
                                }
                            }
                            Err(_) => {
                                self.notification = Some(
                                    "Usage: /disappear <seconds> | /disappear off".into()
                                );
                            }
                        }
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/react" => {
                let emoji = parts.get(1).unwrap_or(&"").trim();
                if emoji.is_empty() {
                    self.notification = Some("Usage: /react <emoji>".into());
                } else if let Some(last_msg) = self.messages.last() {
                    let msg_id = last_msg.msg_id.clone();
                    match self.chat.storage().add_reaction(
                        &msg_id,
                        &self.identity.public_key,
                        emoji,
                    ) {
                        Ok(()) => {
                            self.notification = Some(format!("Reacted {} to last message", emoji));
                            self.refresh_messages();
                        }
                        Err(e) => self.notification = Some(format!("Error: {}", e)),
                    }
                } else {
                    self.notification = Some("No messages to react to".into());
                }
            }
            "/send" => {
                let filepath = parts.get(1).unwrap_or(&"").trim();
                if filepath.is_empty() {
                    self.notification = Some("Usage: /send <filepath>".into());
                } else if let Some(_room_id) = self.selected_room_id() {
                    // File transfer is async; in a real implementation this would
                    // spawn a task. Here we show a placeholder notification.
                    let path = std::path::Path::new(filepath);
                    if path.exists() {
                        self.notification = Some(format!(
                            "File transfer queued: {} ({} bytes)",
                            filepath,
                            std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                        ));
                    } else {
                        self.notification = Some(format!("File not found: {}", filepath));
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/rotate" => {
                if let Some(room_id) = self.selected_room_id() {
                    match crate::crypto::key_rotation::rotate_room_key(
                        self.chat.storage(),
                        &room_id,
                        &self.identity.public_key,
                    ) {
                        Ok((_, epoch)) => {
                            self.notification = Some(format!(
                                "Room key rotated to epoch {}. Members should re-sync.",
                                epoch
                            ));
                        }
                        Err(e) => self.notification = Some(format!("Rotation error: {}", e)),
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/kick" => {
                let fp = parts.get(1).unwrap_or(&"").trim();
                if fp.is_empty() {
                    self.notification = Some("Usage: /kick <fingerprint_hex>".into());
                } else if let Some(room_id) = self.selected_room_id() {
                    match hex_decode(fp) {
                        Some(target_key) => {
                            match self.chat.kick_member(&room_id, &self.identity.public_key, &target_key) {
                                Ok(()) => {
                                    self.notification = Some(format!("Kicked {}", fp));
                                    self.refresh_rooms();
                                    self.refresh_messages();
                                }
                                Err(e) => self.notification = Some(format!("Kick error: {}", e)),
                            }
                        }
                        None => self.notification = Some("Invalid hex fingerprint".into()),
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/promote" => {
                let fp = parts.get(1).unwrap_or(&"").trim();
                if fp.is_empty() {
                    self.notification = Some("Usage: /promote <fingerprint_hex>".into());
                } else if let Some(room_id) = self.selected_room_id() {
                    match hex_decode(fp) {
                        Some(target_key) => {
                            match self.chat.promote_member(
                                &room_id, &self.identity.public_key, &target_key,
                                crate::models::MemberRole::Moderator,
                            ) {
                                Ok(()) => {
                                    self.notification = Some(format!("Promoted {} to moderator", fp));
                                }
                                Err(e) => self.notification = Some(format!("Promote error: {}", e)),
                            }
                        }
                        None => self.notification = Some("Invalid hex fingerprint".into()),
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/demote" => {
                let fp = parts.get(1).unwrap_or(&"").trim();
                if fp.is_empty() {
                    self.notification = Some("Usage: /demote <fingerprint_hex>".into());
                } else if let Some(room_id) = self.selected_room_id() {
                    match hex_decode(fp) {
                        Some(target_key) => {
                            match self.chat.demote_member(
                                &room_id, &self.identity.public_key, &target_key,
                                crate::models::MemberRole::Member,
                            ) {
                                Ok(()) => {
                                    self.notification = Some(format!("Demoted {} to member", fp));
                                }
                                Err(e) => self.notification = Some(format!("Demote error: {}", e)),
                            }
                        }
                        None => self.notification = Some("Invalid hex fingerprint".into()),
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/rename" => {
                let new_name = parts.get(1).unwrap_or(&"").trim();
                if new_name.is_empty() {
                    self.notification = Some("Usage: /rename <name>".into());
                } else if let Some(room_id) = self.selected_room_id() {
                    match self.chat.rename_room(&room_id, &self.identity.public_key, new_name) {
                        Ok(()) => {
                            self.notification = Some(format!("Room renamed to '{}'", new_name));
                            self.refresh_rooms();
                        }
                        Err(e) => self.notification = Some(format!("Rename error: {}", e)),
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/description" => {
                let desc = parts.get(1).unwrap_or(&"").trim();
                if desc.is_empty() {
                    self.notification = Some("Usage: /description <text>".into());
                } else if let Some(room_id) = self.selected_room_id() {
                    match self.chat.set_room_description(&room_id, &self.identity.public_key, desc) {
                        Ok(()) => {
                            self.notification = Some(format!("Description set: {}", desc));
                        }
                        Err(e) => self.notification = Some(format!("Description error: {}", e)),
                    }
                } else {
                    self.notification = Some("No room selected".into());
                }
            }
            "/help" | "/?" => {
                self.notification = Some(
                    "/create /invite /join /search /disappear /react /send /rotate /kick /promote /demote /rename /description /quit | Tab=pane"
                        .into(),
                );
            }
            other => {
                self.notification = Some(format!("Unknown command: {}", other));
            }
        }
    }

    fn send_message(&mut self) {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return;
        }

        if text.starts_with('/') {
            self.handle_command(&text);
            self.input.clear();
            self.input_cursor = 0;
            return;
        }

        if let Some(room_id) = self.selected_room_id() {
            match self.chat.compose_message(
                &room_id,
                &self.identity.public_key,
                &self.identity.secret_key,
                &text,
                None,
            ) {
                Ok(_msg) => {
                    self.refresh_messages();
                }
                Err(e) => {
                    self.notification = Some(format!("Send error: {}", e));
                }
            }
        } else {
            self.notification = Some("No room selected. Use /create <name>".into());
        }

        self.input.clear();
        self.input_cursor = 0;
        self.local_typing = false;
    }

    fn handle_key(&mut self, key: KeyEvent) {
        // Global shortcuts
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        match key.code {
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Input => Focus::Rooms,
                    Focus::Rooms => Focus::Input,
                };
            }
            _ => match self.focus {
                Focus::Input => self.handle_input_key(key),
                Focus::Rooms => self.handle_rooms_key(key),
            },
        }
    }

    fn handle_input_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.send_message(),
            KeyCode::Char(c) => {
                self.input.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
                self.local_typing = true;
            }
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    let prev = self.input[..self.input_cursor]
                        .chars()
                        .last()
                        .map(|c| c.len_utf8())
                        .unwrap_or(0);
                    self.input_cursor -= prev;
                    self.input.remove(self.input_cursor);
                    self.local_typing = true;
                }
            }
            KeyCode::Left => {
                if self.input_cursor > 0 {
                    let prev = self.input[..self.input_cursor]
                        .chars()
                        .last()
                        .map(|c| c.len_utf8())
                        .unwrap_or(0);
                    self.input_cursor -= prev;
                }
            }
            KeyCode::Right => {
                if self.input_cursor < self.input.len() {
                    let next = self.input[self.input_cursor..]
                        .chars()
                        .next()
                        .map(|c| c.len_utf8())
                        .unwrap_or(0);
                    self.input_cursor += next;
                }
            }
            KeyCode::Home => self.input_cursor = 0,
            KeyCode::End => self.input_cursor = self.input.len(),
            KeyCode::Esc => {
                self.notification = None;
            }
            _ => {}
        }
    }

    fn handle_rooms_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                let i = self.room_state.selected().unwrap_or(0);
                if i > 0 {
                    self.room_state.select(Some(i - 1));
                    self.refresh_messages();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = self.room_state.selected().unwrap_or(0);
                if i + 1 < self.rooms.len() {
                    self.room_state.select(Some(i + 1));
                    self.refresh_messages();
                }
            }
            KeyCode::Enter => {
                self.focus = Focus::Input;
            }
            _ => {}
        }
    }

    /// Called on each tick to clean up stale typing indicators and
    /// run background maintenance.
    fn tick(&mut self) {
        let now = Instant::now();
        let threshold = Duration::from_secs(5);

        // Clear stale typing indicators (older than 5 seconds)
        for entries in self.typing_state.values_mut() {
            entries.retain(|(_, ts)| now.duration_since(*ts) < threshold);
        }
        self.typing_state.retain(|_, v| !v.is_empty());

        // If local user was typing, the flag would be consumed by transport
        // to send a typing notification. Reset after each tick.
        self.local_typing = false;

        // Delete expired disappearing messages
        let _ = self.chat.storage().delete_expired_messages();
    }
}

// ── Rendering ──────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Main vertical layout: status | body | input | help
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Min(5),   // body
            Constraint::Length(3), // input
            Constraint::Length(1), // help / notification
        ])
        .split(size);

    draw_status_bar(f, app, chunks[0]);
    draw_body(f, app, chunks[1]);
    draw_input(f, app, chunks[2]);
    draw_help_bar(f, app, chunks[3]);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let fp = hex_short(&app.identity.public_key);
    let room_count = app.rooms.len();
    let text = format!(
        " veilid-chat v{}  |  {} room(s)  |  fp:{}  |  {}",
        env!("CARGO_PKG_VERSION"),
        room_count,
        fp,
        app.identity.display_name,
    );
    let bar = Paragraph::new(text).style(
        Style::default()
            .bg(Color::DarkGray)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(bar, area);
}

fn draw_body(f: &mut Frame, app: &mut App, area: Rect) {
    // Horizontal split: rooms sidebar | messages
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(20)])
        .split(area);

    draw_rooms(f, app, cols[0]);
    draw_messages(f, app, cols[1]);
}

fn draw_rooms(f: &mut Frame, app: &mut App, area: Rect) {
    let border_style = if app.focus == Focus::Rooms {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let items: Vec<ListItem> = app
        .rooms
        .iter()
        .map(|r| {
            let badge = if r.unread > 0 {
                format!(" ({})", r.unread)
            } else {
                String::new()
            };
            let symbol = match r.room_type.as_str() {
                "direct" => "@ ",
                _ => "# ",
            };
            let timer = if r.disappear_after_secs.is_some() {
                " [T]"
            } else {
                ""
            };
            ListItem::new(format!("{}{}{}{}", symbol, r.name, badge, timer))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(" Rooms "),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, &mut app.room_state);
}

fn draw_messages(f: &mut Frame, app: &App, area: Rect) {
    let room_name = app.selected_room_name();
    let disappear_label = match app.selected_room_disappear() {
        Some(s) => format!(" [disappear: {}s]", s),
        None => String::new(),
    };
    let title = format!(" {}{} ", room_name, disappear_label);

    let border_style = if app.focus == Focus::Input {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Build message lines
    let mut lines: Vec<Line> = Vec::new();
    for m in &app.messages {
        let status_icon = match m.status.as_str() {
            "pending" => " ...",
            "sent" => " ->",
            "synced" => " ok",
            "failed" => " !",
            _ => "",
        };

        // Timer icon for disappearing rooms
        let timer_icon = if app.selected_room_disappear().is_some() {
            " [T]"
        } else {
            ""
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", m.time),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{}: ", m.sender),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&m.content),
            Span::styled(status_icon, Style::default().fg(Color::DarkGray)),
            Span::styled(timer_icon, Style::default().fg(Color::Red)),
        ]));

        // Show reactions below the message if any
        if !m.reactions.is_empty() {
            let reaction_str: String = m.reactions
                .iter()
                .map(|(emoji, count)| {
                    if *count > 1 {
                        format!("  {} x{}", emoji, count)
                    } else {
                        format!("  {}", emoji)
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(Line::from(Span::styled(
                format!("    {}", reaction_str.trim()),
                Style::default().fg(Color::Magenta),
            )));
        }
    }

    // Typing indicators
    if let Some(room_id) = app.selected_room_id() {
        if let Some(typers) = app.typing_state.get(&room_id) {
            if !typers.is_empty() {
                let names: Vec<&str> = typers.iter().map(|(n, _)| n.as_str()).collect();
                let typing_text = if names.len() == 1 {
                    format!("{} is typing...", names[0])
                } else {
                    format!("{} are typing...", names.join(", "))
                };
                lines.push(Line::from(Span::styled(
                    typing_text,
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::ITALIC),
                )));
            }
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No messages yet. Type something below!",
            Style::default().fg(Color::DarkGray),
        )));
    }

    // Auto-scroll: show the last N lines that fit
    let inner_height = area.height.saturating_sub(2) as usize;
    let skip = if lines.len() > inner_height {
        lines.len() - inner_height
    } else {
        0
    };
    let visible_lines: Vec<Line> = lines.into_iter().skip(skip).collect();

    let messages = Paragraph::new(visible_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(messages, area);
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let focus_style = if app.focus == Focus::Input {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let input = Paragraph::new(app.input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(focus_style)
            .title(" Message "),
    );
    f.render_widget(input, area);

    // Show cursor in input
    if app.focus == Focus::Input {
        let x = area.x + 1 + app.input_cursor as u16;
        let y = area.y + 1;
        f.set_cursor_position((x, y));
    }
}

fn draw_help_bar(f: &mut Frame, app: &App, area: Rect) {
    let text = if let Some(ref note) = app.notification {
        Line::from(Span::styled(
            format!(" {} ", note),
            Style::default().fg(Color::Yellow),
        ))
    } else {
        Line::from(vec![
            Span::styled(" /create", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("/invite", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("/send", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("/rotate", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("/kick", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("/promote", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("/help", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::raw("=pane"),
        ])
    };
    let bar = Paragraph::new(text).style(Style::default().bg(Color::Black));
    f.render_widget(bar, area);
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(6).map(|b| format!("{:02x}", b)).collect()
}

/// Decode a hex string to bytes. Returns None on invalid hex.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ── Public entry point ─────────────────────────────────────────────

/// Run the terminal UI. Blocks until the user quits.
pub fn run(chat: ChatService, identity: UserIdentity) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(chat, identity);

    // Main loop
    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        // Poll for events with a 50ms tick
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }

        // Run periodic tick (typing cleanup, disappearing messages)
        app.tick();

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
