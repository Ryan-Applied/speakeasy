use crate::models::*;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use tracing::{info, warn};

/// Local SQLite storage for all persistent data.
pub struct LocalStorage {
    conn: Connection,
}

impl LocalStorage {
    /// Open an unencrypted database (for tests / non-sensitive setups).
    /// In production, prefer [`open_encrypted`] -- this path leaves the DB
    /// in plaintext on disk and SECURITY_AUDIT.md HIGH applies.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .context("opening SQLite database")?;
        let storage = Self { conn };
        storage.migrate()?;
        warn!(
            "LocalStorage opened WITHOUT SQLCipher encryption -- use \
             open_encrypted() in production"
        );
        Ok(storage)
    }

    /// Open a SQLCipher-encrypted database.
    ///
    /// `key_bytes` must be exactly 32 bytes -- a raw key derived from the
    /// user's passphrase (Argon2id) or pulled from the Veilid ProtectedStore.
    /// The key is passed to SQLCipher via `PRAGMA key = "x'...'"` (raw hex
    /// form, no KDF inside SQLCipher) so the application controls the KDF.
    ///
    /// Verification: a `SELECT count(*) FROM sqlite_master` is issued
    /// immediately after `PRAGMA key`. If the key is wrong (database already
    /// exists with a different key), SQLCipher errors here.
    pub fn open_encrypted(path: impl AsRef<Path>, key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != 32 {
            bail!(
                "open_encrypted: cipher key must be 32 bytes, got {}",
                key_bytes.len()
            );
        }
        let conn = Connection::open(path.as_ref())
            .context("opening SQLCipher database")?;

        // PRAGMA key with raw hex form so SQLCipher uses the bytes directly
        // (skips its internal PBKDF2 -- our caller is responsible for KDF).
        let hex_key: String = key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let pragma = format!("PRAGMA key = \"x'{}'\";", hex_key);
        conn.execute_batch(&pragma)
            .context("setting SQLCipher key")?;

        // Verify the key works by issuing a query that touches the encrypted
        // header. If the key is wrong, this returns SQLITE_NOTADB.
        conn.query_row(
            "SELECT count(*) FROM sqlite_master",
            [],
            |row| row.get::<_, i64>(0),
        )
        .context("SQLCipher key verification failed -- wrong key or corrupt DB")?;

        let storage = Self { conn };
        storage.migrate()?;
        info!("SQLCipher database opened (encrypted at rest)");
        Ok(storage)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .context("opening in-memory database")?;
        let storage = Self { conn };
        storage.migrate()?;
        Ok(storage)
    }

    /// Run schema migrations.
    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS rooms (
                room_id         BLOB PRIMARY KEY,
                room_type       TEXT NOT NULL,
                name            TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                creator_key     BLOB NOT NULL,
                room_key        BLOB NOT NULL,
                dht_metadata_key BLOB,
                dht_members_key  BLOB,
                dht_messages_key BLOB,
                last_sync_seq   INTEGER DEFAULT 0,
                schema_version  INTEGER DEFAULT 1,
                disappear_after_secs INTEGER,
                description     TEXT
            );

            CREATE TABLE IF NOT EXISTS room_members (
                room_id         BLOB NOT NULL,
                public_key      BLOB NOT NULL,
                display_name    TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'member',
                joined_at       TEXT NOT NULL,
                subkey_start    INTEGER NOT NULL,
                subkey_end      INTEGER NOT NULL,
                route_data      BLOB,
                PRIMARY KEY (room_id, public_key),
                FOREIGN KEY (room_id) REFERENCES rooms(room_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                msg_id          TEXT PRIMARY KEY,
                room_id         BLOB NOT NULL,
                sender_key      BLOB NOT NULL,
                sequence        INTEGER NOT NULL,
                timestamp       TEXT NOT NULL,
                content_type    TEXT NOT NULL,
                content         TEXT NOT NULL,
                reply_to        TEXT,
                status          TEXT NOT NULL DEFAULT 'pending',
                signature       BLOB NOT NULL,
                epoch           INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (room_id) REFERENCES rooms(room_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_room
                ON messages(room_id, timestamp);

            CREATE INDEX IF NOT EXISTS idx_messages_status
                ON messages(status);

            CREATE TABLE IF NOT EXISTS attachments (
                file_id         BLOB PRIMARY KEY,
                msg_id          TEXT NOT NULL,
                filename        TEXT NOT NULL,
                mime_type       TEXT NOT NULL,
                size            INTEGER NOT NULL,
                blake3_hash     BLOB NOT NULL,
                dht_record_key  BLOB,
                FOREIGN KEY (msg_id) REFERENCES messages(msg_id)
            );

            CREATE TABLE IF NOT EXISTS file_chunks (
                file_id         BLOB NOT NULL,
                chunk_index     INTEGER NOT NULL,
                data            BLOB NOT NULL,
                blake3_hash     BLOB NOT NULL,
                PRIMARY KEY (file_id, chunk_index)
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                room_id         BLOB NOT NULL,
                member_key      BLOB NOT NULL,
                last_seq        INTEGER NOT NULL DEFAULT 0,
                last_subkey     INTEGER NOT NULL DEFAULT 0,
                last_sync_time  TEXT NOT NULL,
                PRIMARY KEY (room_id, member_key)
            );

            CREATE TABLE IF NOT EXISTS invites (
                invite_id       BLOB PRIMARY KEY,
                invite_type     TEXT NOT NULL,
                room_id         BLOB,
                encoded         TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                expires_at      TEXT,
                used            INTEGER DEFAULT 0
            );

            -- Read receipts: tracks per-member last-read position in each room
            CREATE TABLE IF NOT EXISTS read_receipts (
                room_id         BLOB NOT NULL,
                member_key      BLOB NOT NULL,
                last_read_msg_id TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                PRIMARY KEY (room_id, member_key)
            );

            -- Message reactions
            CREATE TABLE IF NOT EXISTS reactions (
                msg_id          TEXT NOT NULL,
                sender_key      BLOB NOT NULL,
                emoji           TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                PRIMARY KEY (msg_id, sender_key, emoji)
            );

            -- FTS5 full-text search over messages
            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                msg_id, content, content=messages, content_rowid=rowid
            );

            -- Triggers to keep FTS index in sync with messages table
            CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(rowid, msg_id, content)
                VALUES (new.rowid, new.msg_id, new.content);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, msg_id, content)
                VALUES ('delete', old.rowid, old.msg_id, old.content);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, msg_id, content)
                VALUES ('delete', old.rowid, old.msg_id, old.content);
                INSERT INTO messages_fts(rowid, msg_id, content)
                VALUES (new.rowid, new.msg_id, new.content);
            END;

            -- File transfer tracking (Feature 17)
            CREATE TABLE IF NOT EXISTS file_transfers (
                file_id         BLOB PRIMARY KEY,
                filename        TEXT NOT NULL,
                mime_type       TEXT NOT NULL,
                total_size      INTEGER NOT NULL,
                chunk_size      INTEGER NOT NULL,
                chunk_count     INTEGER NOT NULL,
                blake3_hash     BLOB NOT NULL,
                direction       TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'queued',
                chunks_done     INTEGER DEFAULT 0,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );

            -- Key rotation epochs (Feature 18)
            CREATE TABLE IF NOT EXISTS key_epochs (
                room_id         BLOB NOT NULL,
                epoch           INTEGER NOT NULL,
                room_key        BLOB NOT NULL,
                rotated_at      TEXT NOT NULL,
                rotated_by      BLOB NOT NULL,
                PRIMARY KEY (room_id, epoch)
            );

            -- Room admin actions audit log (Feature 19)
            CREATE TABLE IF NOT EXISTS room_actions (
                action_id       TEXT PRIMARY KEY,
                room_id         BLOB NOT NULL,
                actor_key       BLOB NOT NULL,
                action_type     TEXT NOT NULL,
                target_key      BLOB,
                metadata        TEXT,
                signature       BLOB NOT NULL,
                created_at      TEXT NOT NULL
            );
        ").context("running migrations")?;

        info!("database migrations complete");
        Ok(())
    }

    // -- Room operations --

    pub fn insert_room(&self, room: &Room) -> Result<()> {
        let room_type = match room.room_type {
            RoomType::Direct => "direct",
            RoomType::Group => "group",
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO rooms
             (room_id, room_type, name, created_at, creator_key, room_key,
              dht_metadata_key, dht_members_key, dht_messages_key,
              last_sync_seq, schema_version, disappear_after_secs, description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                room.room_id.as_slice(),
                room_type,
                room.name,
                room.created_at.to_rfc3339(),
                room.creator_key,
                room.room_key,
                room.dht_metadata_key,
                room.dht_members_key,
                room.dht_messages_key,
                room.last_sync_seq,
                room.schema_version,
                room.disappear_after_secs,
                room.description,
            ],
        ).context("inserting room")?;

        // Insert members
        for m in &room.members {
            self.insert_room_member(&room.room_id, m)?;
        }

        Ok(())
    }

    pub fn insert_room_member(&self, room_id: &[u8; 32], member: &RoomMember) -> Result<()> {
        let role = match member.role {
            MemberRole::Admin => "admin",
            MemberRole::Moderator => "moderator",
            MemberRole::Member => "member",
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO room_members
             (room_id, public_key, display_name, role, joined_at,
              subkey_start, subkey_end, route_data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                room_id.as_slice(),
                member.public_key,
                member.display_name,
                role,
                member.joined_at.to_rfc3339(),
                member.subkey_start,
                member.subkey_end,
                member.route_data,
            ],
        ).context("inserting room member")?;
        Ok(())
    }

    pub fn list_rooms(&self) -> Result<Vec<(Vec<u8>, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT room_id, name, room_type FROM rooms ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("listing rooms")
    }

    // -- Message operations --

    pub fn insert_message(&self, msg: &Message) -> Result<()> {
        let ct = match msg.content_type {
            ContentType::Text => "text",
            ContentType::Audio => "audio",
            ContentType::File => "file",
            ContentType::System => "system",
        };
        self.conn.execute(
            "INSERT OR IGNORE INTO messages
             (msg_id, room_id, sender_key, sequence, timestamp,
              content_type, content, reply_to, status, signature, epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                msg.msg_id,
                msg.room_id.as_slice(),
                msg.sender_key,
                msg.sequence,
                msg.timestamp.to_rfc3339(),
                ct,
                msg.content,
                msg.reply_to,
                msg.status.to_string(),
                msg.signature,
                msg.epoch,
            ],
        ).context("inserting message")?;
        Ok(())
    }

    pub fn update_message_status(&self, msg_id: &str, status: MessageStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET status = ?1 WHERE msg_id = ?2",
            params![status.to_string(), msg_id],
        ).context("updating message status")?;
        Ok(())
    }

    pub fn get_messages_for_room(
        &self,
        room_id: &[u8; 32],
        limit: u32,
        before_timestamp: Option<&str>,
    ) -> Result<Vec<(String, String, String, String, String)>> {
        let sql = if before_timestamp.is_some() {
            "SELECT msg_id, sender_key, content, timestamp, status
             FROM messages WHERE room_id = ?1 AND timestamp < ?2
             ORDER BY timestamp DESC LIMIT ?3"
        } else {
            "SELECT msg_id, sender_key, content, timestamp, status
             FROM messages WHERE room_id = ?1
             ORDER BY timestamp DESC LIMIT ?2"
        };

        let mut stmt = self.conn.prepare(sql)?;
        let mapper = |row: &rusqlite::Row| -> rusqlite::Result<(String, String, String, String, String)> {
            Ok((
                row.get(0)?,
                row.get::<_, Vec<u8>>(1).map(|v| hex_encode(&v))?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        };
        let results: Vec<_> = if let Some(ts) = before_timestamp {
            stmt.query_map(params![room_id.as_slice(), ts, limit], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map(params![room_id.as_slice(), limit], mapper)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(results)
    }

    pub fn message_exists(&self, msg_id: &str) -> Result<bool> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE msg_id = ?1",
            params![msg_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // -- Sync state --

    pub fn update_sync_cursor(
        &self,
        room_id: &[u8; 32],
        member_key: &[u8],
        last_seq: u64,
        last_subkey: u32,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_state
             (room_id, member_key, last_seq, last_subkey, last_sync_time)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                room_id.as_slice(),
                member_key,
                last_seq,
                last_subkey,
                chrono::Utc::now().to_rfc3339(),
            ],
        ).context("updating sync cursor")?;
        Ok(())
    }

    pub fn get_sync_cursor(
        &self,
        room_id: &[u8; 32],
        member_key: &[u8],
    ) -> Result<Option<(u64, u32)>> {
        let result = self.conn.query_row(
            "SELECT last_seq, last_subkey FROM sync_state
             WHERE room_id = ?1 AND member_key = ?2",
            params![room_id.as_slice(), member_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // -- Room lookup --

    /// Retrieve a full Room by its 32-byte ID, including members.
    pub fn get_room(&self, room_id: &[u8; 32]) -> Result<Option<Room>> {
        let row = self.conn.query_row(
            "SELECT room_id, room_type, name, created_at, creator_key, room_key,
                    dht_metadata_key, dht_members_key, dht_messages_key,
                    last_sync_seq, schema_version, disappear_after_secs, description
             FROM rooms WHERE room_id = ?1",
            params![room_id.as_slice()],
            |row| {
                let rid_vec: Vec<u8> = row.get(0)?;
                let mut rid = [0u8; 32];
                let len = rid_vec.len().min(32);
                rid[..len].copy_from_slice(&rid_vec[..len]);

                let rtype_str: String = row.get(1)?;
                let rtype = if rtype_str == "direct" {
                    RoomType::Direct
                } else {
                    RoomType::Group
                };

                Ok((
                    rid,
                    rtype,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, u64>(9)?,
                    row.get::<_, u8>(10)?,
                    row.get::<_, Option<u64>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            },
        );

        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
            Ok((rid, rtype, name, created_at_str, creator_key, room_key,
                dht_metadata_key, dht_members_key, dht_messages_key,
                last_sync_seq, schema_version, disappear_after_secs, description)) =>
            {
                let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now());

                // Load members
                let mut stmt = self.conn.prepare(
                    "SELECT public_key, display_name, role, joined_at,
                            subkey_start, subkey_end, route_data
                     FROM room_members WHERE room_id = ?1"
                )?;
                let members = stmt.query_map(params![rid.as_slice()], |mrow| {
                    let role_str: String = mrow.get(2)?;
                    let role = match role_str.as_str() {
                        "admin" => MemberRole::Admin,
                        "moderator" => MemberRole::Moderator,
                        _ => MemberRole::Member,
                    };
                    let joined_str: String = mrow.get(3)?;
                    let joined = chrono::DateTime::parse_from_rfc3339(&joined_str)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now());
                    Ok(RoomMember {
                        public_key: mrow.get(0)?,
                        display_name: mrow.get(1)?,
                        role,
                        joined_at: joined,
                        subkey_start: mrow.get(4)?,
                        subkey_end: mrow.get(5)?,
                        route_data: mrow.get(6)?,
                    })
                })?.collect::<rusqlite::Result<Vec<_>>>()?;

                Ok(Some(Room {
                    room_id: rid,
                    room_type: rtype,
                    name,
                    created_at,
                    creator_key,
                    room_key,
                    dht_metadata_key,
                    dht_members_key,
                    dht_messages_key,
                    description,
                    members,
                    last_sync_seq,
                    schema_version,
                    disappear_after_secs,
                }))
            }
        }
    }

    /// Update the disappear_after_secs setting for a room.
    pub fn set_disappear_after(&self, room_id: &[u8; 32], secs: Option<u64>) -> Result<()> {
        self.conn.execute(
            "UPDATE rooms SET disappear_after_secs = ?1 WHERE room_id = ?2",
            params![secs, room_id.as_slice()],
        ).context("setting disappear_after_secs")?;
        Ok(())
    }

    /// Delete expired messages for rooms that have disappearing messages enabled.
    /// Returns the number of messages deleted.
    pub fn delete_expired_messages(&self) -> Result<usize> {
        let now = chrono::Utc::now().to_rfc3339();
        let count = self.conn.execute(
            "DELETE FROM messages WHERE room_id IN (
                SELECT room_id FROM rooms WHERE disappear_after_secs IS NOT NULL
             ) AND datetime(timestamp, '+' || (
                SELECT disappear_after_secs FROM rooms r WHERE r.room_id = messages.room_id
             ) || ' seconds') < datetime(?1)",
            params![now],
        ).context("deleting expired messages")?;
        Ok(count)
    }

    // -- Full-text search --

    /// Search messages using FTS5 full-text index.
    /// Returns (msg_id, sender_key_hex, content, timestamp, status).
    pub fn search_messages(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<Vec<(String, String, String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.msg_id, m.sender_key, m.content, m.timestamp, m.status
             FROM messages m
             JOIN messages_fts f ON m.msg_id = f.msg_id
             WHERE messages_fts MATCH ?1
             ORDER BY m.timestamp DESC
             LIMIT ?2"
        )?;
        let rows = stmt.query_map(params![query, limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1).map(|v| hex_encode(&v))?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("searching messages")
    }

    // -- Read receipts --

    /// Update or insert a read receipt for a member in a room.
    pub fn update_read_receipt(
        &self,
        room_id: &[u8; 32],
        member_key: &[u8],
        last_read_msg_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO read_receipts
             (room_id, member_key, last_read_msg_id, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                room_id.as_slice(),
                member_key,
                last_read_msg_id,
                chrono::Utc::now().to_rfc3339(),
            ],
        ).context("updating read receipt")?;
        Ok(())
    }

    /// Get all read receipts for a room.
    /// Returns (member_key_hex, last_read_msg_id, updated_at).
    pub fn get_read_receipts(
        &self,
        room_id: &[u8; 32],
    ) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_key, last_read_msg_id, updated_at
             FROM read_receipts WHERE room_id = ?1"
        )?;
        let rows = stmt.query_map(params![room_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0).map(|v| hex_encode(&v))?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("getting read receipts")
    }

    /// Count unread messages in a room for a given member.
    /// Counts messages whose timestamp is after the member's last read receipt.
    pub fn count_unread(
        &self,
        room_id: &[u8; 32],
        member_key: &[u8],
    ) -> Result<u32> {
        // Get the last read message's timestamp
        let last_read_ts: Option<String> = self.conn.query_row(
            "SELECT m.timestamp FROM read_receipts rr
             JOIN messages m ON m.msg_id = rr.last_read_msg_id
             WHERE rr.room_id = ?1 AND rr.member_key = ?2",
            params![room_id.as_slice(), member_key],
            |row| row.get(0),
        ).ok();

        let count: u32 = if let Some(ts) = last_read_ts {
            self.conn.query_row(
                "SELECT COUNT(*) FROM messages
                 WHERE room_id = ?1 AND timestamp > ?2",
                params![room_id.as_slice(), ts],
                |row| row.get(0),
            )?
        } else {
            // No read receipt means all messages are unread
            self.conn.query_row(
                "SELECT COUNT(*) FROM messages WHERE room_id = ?1",
                params![room_id.as_slice()],
                |row| row.get(0),
            )?
        };
        Ok(count)
    }

    // -- Reactions --

    /// Add a reaction to a message.
    pub fn add_reaction(
        &self,
        msg_id: &str,
        sender_key: &[u8],
        emoji: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO reactions
             (msg_id, sender_key, emoji, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                msg_id,
                sender_key,
                emoji,
                chrono::Utc::now().to_rfc3339(),
            ],
        ).context("adding reaction")?;
        Ok(())
    }

    /// Remove a reaction from a message.
    pub fn remove_reaction(
        &self,
        msg_id: &str,
        sender_key: &[u8],
        emoji: &str,
    ) -> Result<()> {
        self.conn.execute(
            "DELETE FROM reactions WHERE msg_id = ?1 AND sender_key = ?2 AND emoji = ?3",
            params![msg_id, sender_key, emoji],
        ).context("removing reaction")?;
        Ok(())
    }

    /// Get reactions for a message, grouped by emoji.
    /// Returns (emoji, count).
    pub fn get_reactions_for_message(
        &self,
        msg_id: &str,
    ) -> Result<Vec<(String, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT emoji, COUNT(*) FROM reactions
             WHERE msg_id = ?1
             GROUP BY emoji
             ORDER BY COUNT(*) DESC"
        )?;
        let rows = stmt.query_map(params![msg_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("getting reactions")
    }

    // -- File transfer operations (Feature 17) --

    /// Insert a new file transfer record.
    pub fn insert_file_transfer(
        &self,
        file_id: &[u8; 32],
        filename: &str,
        mime_type: &str,
        total_size: u64,
        chunk_size: u32,
        chunk_count: u32,
        blake3_hash: &[u8],
        direction: &str,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO file_transfers
             (file_id, filename, mime_type, total_size, chunk_size, chunk_count,
              blake3_hash, direction, status, chunks_done, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', 0, ?9, ?10)",
            params![
                file_id.as_slice(),
                filename,
                mime_type,
                total_size,
                chunk_size,
                chunk_count,
                blake3_hash,
                direction,
                now,
                now,
            ],
        ).context("inserting file transfer")?;
        Ok(())
    }

    /// Update transfer progress (chunks_done and status).
    pub fn update_transfer_progress(
        &self,
        file_id: &[u8; 32],
        chunks_done: u32,
        status: &str,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE file_transfers SET chunks_done = ?1, status = ?2, updated_at = ?3
             WHERE file_id = ?4",
            params![chunks_done, status, now, file_id.as_slice()],
        ).context("updating transfer progress")?;
        Ok(())
    }

    /// Get a file transfer record.
    pub fn get_transfer(
        &self,
        file_id: &[u8; 32],
    ) -> Result<Option<(String, String, u64, u32, u32, Vec<u8>, String, String, u32)>> {
        let result = self.conn.query_row(
            "SELECT filename, mime_type, total_size, chunk_size, chunk_count,
                    blake3_hash, direction, status, chunks_done
             FROM file_transfers WHERE file_id = ?1",
            params![file_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, u32>(8)?,
                ))
            },
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get pending chunk indices for a file transfer (chunks_done..chunk_count).
    pub fn get_pending_chunks(&self, file_id: &[u8; 32]) -> Result<Option<(u32, u32)>> {
        let result = self.conn.query_row(
            "SELECT chunks_done, chunk_count FROM file_transfers WHERE file_id = ?1",
            params![file_id.as_slice()],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // -- Key epoch operations (Feature 18) --

    /// Insert a new key epoch record.
    pub fn insert_key_epoch(
        &self,
        room_id: &[u8; 32],
        epoch: u32,
        room_key: &[u8],
        rotated_by: &[u8],
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO key_epochs
             (room_id, epoch, room_key, rotated_at, rotated_by)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![room_id.as_slice(), epoch, room_key, now, rotated_by],
        ).context("inserting key epoch")?;
        Ok(())
    }

    /// Get the current (highest) epoch for a room.
    pub fn get_current_epoch(&self, room_id: &[u8; 32]) -> Result<Option<(u32, Vec<u8>)>> {
        let result = self.conn.query_row(
            "SELECT epoch, room_key FROM key_epochs
             WHERE room_id = ?1 ORDER BY epoch DESC LIMIT 1",
            params![room_id.as_slice()],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the key for a specific epoch.
    pub fn get_key_for_epoch(
        &self,
        room_id: &[u8; 32],
        epoch: u32,
    ) -> Result<Option<Vec<u8>>> {
        let result = self.conn.query_row(
            "SELECT room_key FROM key_epochs
             WHERE room_id = ?1 AND epoch = ?2",
            params![room_id.as_slice(), epoch],
            |row| row.get::<_, Vec<u8>>(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // -- Room admin actions (Feature 19) --

    /// Insert a room action audit record.
    pub fn insert_room_action(
        &self,
        action: &RoomAction,
    ) -> Result<()> {
        let action_type = action.action_type.to_string();
        self.conn.execute(
            "INSERT INTO room_actions
             (action_id, room_id, actor_key, action_type, target_key,
              metadata, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                action.action_id,
                action.room_id.as_slice(),
                action.actor_key,
                action_type,
                action.target_key,
                action.metadata,
                action.signature,
                action.created_at.to_rfc3339(),
            ],
        ).context("inserting room action")?;
        Ok(())
    }

    /// Get the role of a member in a room.
    pub fn get_member_role(
        &self,
        room_id: &[u8; 32],
        member_key: &[u8],
    ) -> Result<Option<MemberRole>> {
        let result = self.conn.query_row(
            "SELECT role FROM room_members WHERE room_id = ?1 AND public_key = ?2",
            params![room_id.as_slice(), member_key],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(role_str) => {
                let role = match role_str.as_str() {
                    "admin" => MemberRole::Admin,
                    "moderator" => MemberRole::Moderator,
                    _ => MemberRole::Member,
                };
                Ok(Some(role))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a member from a room.
    pub fn remove_room_member(
        &self,
        room_id: &[u8; 32],
        member_key: &[u8],
    ) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM room_members WHERE room_id = ?1 AND public_key = ?2",
            params![room_id.as_slice(), member_key],
        ).context("removing room member")?;
        Ok(count > 0)
    }

    /// Update a member's role.
    pub fn update_member_role(
        &self,
        room_id: &[u8; 32],
        member_key: &[u8],
        new_role: MemberRole,
    ) -> Result<()> {
        let role = match new_role {
            MemberRole::Admin => "admin",
            MemberRole::Moderator => "moderator",
            MemberRole::Member => "member",
        };
        self.conn.execute(
            "UPDATE room_members SET role = ?1 WHERE room_id = ?2 AND public_key = ?3",
            params![role, room_id.as_slice(), member_key],
        ).context("updating member role")?;
        Ok(())
    }

    /// Rename a room.
    pub fn rename_room(&self, room_id: &[u8; 32], new_name: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE rooms SET name = ?1 WHERE room_id = ?2",
            params![new_name, room_id.as_slice()],
        ).context("renaming room")?;
        Ok(())
    }

    /// Set a room's description.
    pub fn set_room_description(&self, room_id: &[u8; 32], description: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE rooms SET description = ?1 WHERE room_id = ?2",
            params![description, room_id.as_slice()],
        ).context("setting room description")?;
        Ok(())
    }

    // -- Message deletion --

    /// Delete a message by ID. Returns true if a row was deleted.
    pub fn delete_message(&self, msg_id: &str) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM messages WHERE msg_id = ?1",
            params![msg_id],
        ).context("deleting message")?;
        Ok(count > 0)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_room() -> Room {
        Room {
            room_id: [1u8; 32],
            room_type: RoomType::Group,
            name: "test room".into(),
            created_at: Utc::now(),
            creator_key: vec![2u8; 32],
            room_key: vec![3u8; 32],
            dht_metadata_key: vec![4u8; 36],
            dht_members_key: vec![5u8; 36],
            dht_messages_key: vec![6u8; 36],
            description: None,
            members: vec![RoomMember {
                public_key: vec![2u8; 32],
                display_name: "alice".into(),
                role: MemberRole::Admin,
                joined_at: Utc::now(),
                subkey_start: 0,
                subkey_end: 999,
                route_data: None,
            }],
            last_sync_seq: 0,
            schema_version: 1,
            disappear_after_secs: None,
        }
    }

    fn make_message(room_id: [u8; 32]) -> Message {
        Message {
            msg_id: ulid::Ulid::new().to_string(),
            room_id,
            sender_key: vec![2u8; 32],
            sequence: 1,
            timestamp: Utc::now(),
            content_type: ContentType::Text,
            content: "hello".into(),
            reply_to: None,
            attachments: vec![],
            status: MessageStatus::Pending,
            signature: vec![0u8; 64],
            epoch: 0,
        }
    }

    #[test]
    fn test_room_crud() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let rooms = db.list_rooms().unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].1, "test room");
    }

    #[test]
    fn test_message_crud() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let msg = make_message(room.room_id);
        let msg_id = msg.msg_id.clone();
        db.insert_message(&msg).unwrap();

        assert!(db.message_exists(&msg_id).unwrap());

        let msgs = db.get_messages_for_room(&room.room_id, 50, None).unwrap();
        assert_eq!(msgs.len(), 1);

        db.update_message_status(&msg_id, MessageStatus::Sent).unwrap();
    }

    #[test]
    fn test_message_dedup() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let msg = make_message(room.room_id);
        db.insert_message(&msg).unwrap();
        db.insert_message(&msg).unwrap(); // duplicate -- should be ignored

        let msgs = db.get_messages_for_room(&room.room_id, 50, None).unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn test_sync_cursor() {
        let db = LocalStorage::open_memory().unwrap();
        let room_id = [1u8; 32];
        let member_key = vec![2u8; 32];

        assert!(db.get_sync_cursor(&room_id, &member_key).unwrap().is_none());

        db.update_sync_cursor(&room_id, &member_key, 42, 5).unwrap();
        let (seq, sk) = db.get_sync_cursor(&room_id, &member_key).unwrap().unwrap();
        assert_eq!(seq, 42);
        assert_eq!(sk, 5);
    }

    #[test]
    fn test_sqlcipher_roundtrip_and_wrong_key_rejected() {
        use tempfile::TempDir;
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("encrypted.db");
        let key = [9u8; 32];

        // Open with key, write a row.
        {
            let db = LocalStorage::open_encrypted(&db_path, &key).unwrap();
            let room = make_room();
            db.insert_room(&room).unwrap();
        }

        // Reopen with the same key -- read the row.
        {
            let db = LocalStorage::open_encrypted(&db_path, &key).unwrap();
            let rooms = db.list_rooms().unwrap();
            assert_eq!(rooms.len(), 1);
        }

        // Reopen with a wrong key -- must fail at verification.
        let wrong = [0u8; 32];
        let res = LocalStorage::open_encrypted(&db_path, &wrong);
        assert!(res.is_err(), "wrong cipher key must fail verification");
    }

    #[test]
    fn test_sqlcipher_rejects_short_key() {
        use tempfile::TempDir;
        let tmp = TempDir::new().unwrap();
        let res = LocalStorage::open_encrypted(tmp.path().join("x.db"), &[0u8; 16]);
        assert!(res.is_err(), "short key must be rejected");
    }

    #[test]
    fn test_get_room() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let loaded = db.get_room(&room.room_id).unwrap().expect("room should exist");
        assert_eq!(loaded.name, "test room");
        assert_eq!(loaded.room_type, RoomType::Group);
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].display_name, "alice");

        // Non-existent room
        let missing = db.get_room(&[99u8; 32]).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_fts_search() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let mut msg1 = make_message(room.room_id);
        msg1.content = "the quick brown fox jumps over the lazy dog".into();
        db.insert_message(&msg1).unwrap();

        let mut msg2 = make_message(room.room_id);
        msg2.content = "hello world".into();
        db.insert_message(&msg2).unwrap();

        // Search for "fox"
        let results = db.search_messages("fox", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].2.contains("fox"));

        // Search for "hello"
        let results = db.search_messages("hello", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].2.contains("hello"));

        // Search for non-existent term
        let results = db.search_messages("xyz_no_match", 10).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_read_receipts() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let msg = make_message(room.room_id);
        let msg_id = msg.msg_id.clone();
        db.insert_message(&msg).unwrap();

        let member_key = vec![2u8; 32];
        db.update_read_receipt(&room.room_id, &member_key, &msg_id).unwrap();

        let receipts = db.get_read_receipts(&room.room_id).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].1, msg_id);
    }

    #[test]
    fn test_unread_count() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let member_key = vec![2u8; 32];

        // No messages, no receipts -> 0 unread
        let count = db.count_unread(&room.room_id, &member_key).unwrap();
        assert_eq!(count, 0);

        // Insert 2 messages
        let msg1 = make_message(room.room_id);
        let msg1_id = msg1.msg_id.clone();
        db.insert_message(&msg1).unwrap();

        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));

        let msg2 = make_message(room.room_id);
        db.insert_message(&msg2).unwrap();

        // No read receipt -> all unread
        let count = db.count_unread(&room.room_id, &member_key).unwrap();
        assert_eq!(count, 2);

        // Read the first message -> 1 unread
        db.update_read_receipt(&room.room_id, &member_key, &msg1_id).unwrap();
        let count = db.count_unread(&room.room_id, &member_key).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_reactions() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let msg = make_message(room.room_id);
        let msg_id = msg.msg_id.clone();
        db.insert_message(&msg).unwrap();

        let sender1 = vec![1u8; 32];
        let sender2 = vec![2u8; 32];

        // Add reactions
        db.add_reaction(&msg_id, &sender1, "thumbsup").unwrap();
        db.add_reaction(&msg_id, &sender2, "thumbsup").unwrap();
        db.add_reaction(&msg_id, &sender1, "heart").unwrap();

        // Duplicate should be ignored (OR IGNORE)
        db.add_reaction(&msg_id, &sender1, "thumbsup").unwrap();

        let reactions = db.get_reactions_for_message(&msg_id).unwrap();
        assert_eq!(reactions.len(), 2);
        // thumbsup should have count 2 (sorted by count DESC)
        assert_eq!(reactions[0].0, "thumbsup");
        assert_eq!(reactions[0].1, 2);
        assert_eq!(reactions[1].0, "heart");
        assert_eq!(reactions[1].1, 1);

        // Remove one reaction
        db.remove_reaction(&msg_id, &sender1, "thumbsup").unwrap();
        let reactions = db.get_reactions_for_message(&msg_id).unwrap();
        assert_eq!(reactions.iter().find(|(e, _)| e == "thumbsup").unwrap().1, 1);
    }

    #[test]
    fn test_disappearing_messages() {
        let db = LocalStorage::open_memory().unwrap();
        let mut room = make_room();
        room.disappear_after_secs = Some(1); // 1 second
        db.insert_room(&room).unwrap();

        // Set disappear setting via update method too
        db.set_disappear_after(&room.room_id, Some(1)).unwrap();

        let loaded = db.get_room(&room.room_id).unwrap().unwrap();
        assert_eq!(loaded.disappear_after_secs, Some(1));

        // Turn off
        db.set_disappear_after(&room.room_id, None).unwrap();
        let loaded = db.get_room(&room.room_id).unwrap().unwrap();
        assert_eq!(loaded.disappear_after_secs, None);
    }

    #[test]
    fn test_delete_message() {
        let db = LocalStorage::open_memory().unwrap();
        let room = make_room();
        db.insert_room(&room).unwrap();

        let msg = make_message(room.room_id);
        let msg_id = msg.msg_id.clone();
        db.insert_message(&msg).unwrap();

        assert!(db.message_exists(&msg_id).unwrap());
        assert!(db.delete_message(&msg_id).unwrap());
        assert!(!db.message_exists(&msg_id).unwrap());
        // Double delete returns false
        assert!(!db.delete_message(&msg_id).unwrap());
    }
}
