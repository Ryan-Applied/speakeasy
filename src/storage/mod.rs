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
                schema_version  INTEGER DEFAULT 1
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
              last_sync_seq, schema_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
              content_type, content, reply_to, status, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
}
