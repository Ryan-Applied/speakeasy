# Veilid Chat -- Architecture and Technical Design

## 1. System overview

A decentralized peer-to-peer chat application built on the Veilid network.
No central servers for signaling, discovery, or message persistence.
All coordination happens through Veilid's DHT, private routes, and app calls.

```
+--------------------------------------------------+
|                   Tauri Shell                     |
|  (desktop GUI -- React/Svelte frontend later)    |
+--------------------------------------------------+
|                   ui_api                          |
|  (command interface, event bus, state queries)    |
+--------------------------------------------------+
|     chat     |   audio   |   files   |   invite  |
|  (rooms,     | (voice    | (chunked  | (QR gen,  |
|   messages,  |  notes,   |  transfer,|  encode,  |
|   timelines) |  stream)  |  resume)  |  decode)  |
+--------------------------------------------------+
|          sync          |        storage           |
|  (conflict resolution, | (local SQLite,           |
|   merge, catch-up)     |  cache, index)           |
+--------------------------------------------------+
|          dht           |       transport          |
|  (record management,   | (app calls, routes,      |
|   schemas, GC)         |  connection mgmt)        |
+--------------------------------------------------+
|         crypto         |       identity           |
|  (E2E encrypt/decrypt, | (keypair gen, profile,   |
|   sign/verify, KDF)    |  secure storage)         |
+--------------------------------------------------+
|              veilid-core (native API)             |
+--------------------------------------------------+
```

### Key design decisions

- Local-first: all data written locally before network sync
- Eventual consistency: CRDT-inspired append-only logs for chat
- Encrypted at rest and in transit: room keys for group, pairwise for 1:1
- Voice notes as primary audio; live audio is experimental/Phase 2
- DHT for coordination metadata; app calls for real-time message relay
- SQLite for local persistence; DHT records for shared state pointers


## 2. Module breakdown

### identity
- Ed25519 keypair generation via veilid-core
- Local secure storage (OS keychain or encrypted file)
- Profile: display_name, avatar_hash, public_key, status, created_at
- Identity export/import for device migration

### crypto
- Room key derivation: X25519 DH for 1:1, shared symmetric key for groups
- Message encryption: XChaCha20-Poly1305 (via veilid-core primitives)
- Message signing: Ed25519 per-message signatures
- Envelope format: nonce || ciphertext || signature || sender_key_fingerprint
- Key rotation hooks (Phase 2)

### dht
- Thin wrapper around veilid_api::RoutingContext
- Record creation, open, close, get, set, watch, inspect
- Schema management: DFLT(1) for single-writer, SMPL for multi-writer
- Subkey allocation strategy for append-only logs
- Record lifecycle: create -> open -> use -> close -> GC
- Content-addressed blob storage: hash -> DHT key mapping

### transport
- App call send/receive via private routes
- Route management: create, maintain, refresh
- Connection state tracking per peer
- Message framing: length-prefixed protobuf or msgpack
- Retry with exponential backoff
- Bandwidth estimation (simple moving average of RTT/throughput)

### storage
- Local SQLite database via rusqlite
- Tables: identities, rooms, messages, attachments, audio_chunks,
  file_chunks, peers, sync_state, invites
- Write-ahead for outbound messages (pending -> sent -> synced)
- Full-text search index on message content (Phase 2)
- Cache eviction policy for large media

### chat
- Room model: room_id, room_type (Direct/Group), name, created_at,
  members, room_key, dht_record_key, last_sync_seq
- Message model: msg_id (ULID), room_id, sender, timestamp, content,
  reply_to, status, signature, sequence_number
- Append-only log per room stored as DHT subkeys
- Sequence numbers for ordering within a sender's stream
- Vector clock or Lamport timestamps for cross-sender ordering
- Deduplication by msg_id
- Delivery states: Draft -> Pending -> Sent -> Synced -> Failed

### audio
- Voice note recording: Opus codec at 16kbps mono
- Chunk size: 4KB-8KB encrypted chunks
- Metadata: duration, sample_rate, codec, chunk_count, total_size
- Stored as file attachment type with audio/* MIME
- Live audio (Phase 2): 20ms Opus frames, 1.5KB chunks, jitter buffer,
  DTX (discontinuous transmission) for silence suppression

### files
- Chunked file transfer: 64KB raw chunks -> encrypted -> DHT or app call
- File metadata: filename, mime_type, size, blake3_hash, chunk_count,
  sender, timestamp
- Chunk integrity: blake3 per-chunk hash
- Resume: track which chunks delivered, re-request missing
- Small files (<256KB): inline via app call
- Large files: DHT-backed chunk storage with metadata record

### invite
- Invite payload (msgpack-encoded):
  ```
  {
    version: u8,
    invite_type: "direct" | "room",
    room_id: [u8; 32],          // or empty for direct
    dht_record_key: TypedKey,   // room metadata record
    bootstrap_route: Option<Vec<u8>>,  // creator's route
    room_name: Option<String>,
    creator_public_key: PublicKey,
    created_at: u64,            // unix timestamp
    expires_at: Option<u64>,
    signature: Signature,       // signs all above fields
  }
  ```
- Encoding: base64url for string, raw bytes for QR
- QR: generated via qrcode crate, rendered as SVG or PNG
- Validation: check signature, check expiry, check version

### qr
- QR generation: qrcode crate -> SVG string or PNG bytes
- QR scanning: Phase 2 (camera input via Tauri plugin or nokhwa)
- For MVP: paste-based import of base64url invite string

### sync
- Per-room sync state: last_known_seq per member, last_sync_time
- Catch-up protocol:
  1. Open room DHT record
  2. Inspect subkeys for new writes
  3. Fetch new subkey values
  4. Decrypt, validate, deduplicate
  5. Merge into local timeline
  6. Update sync state
- Conflict resolution: accept all valid messages, order by (timestamp, sender, msg_id)
- Consistency model: causal consistency within a sender, eventual across senders

### ui_api
- Command/query interface (no direct network access from UI)
- Commands: send_message, create_room, join_room, record_voice_note, send_file, etc.
- Queries: list_rooms, get_messages, get_room_info, get_sync_status, etc.
- Event bus: new_message, sync_complete, peer_status_change, transfer_progress, etc.
- Tauri command handlers map directly to these


## 3. DHT schema design

### Room metadata record (DFLT schema, single owner = room creator)
Subkey 0: Room info
```json
{
  "room_id": "base64(32 bytes)",
  "room_type": "direct|group",
  "name": "encrypted(room_name)",
  "created_at": 1712000000,
  "creator_key": "base64(public_key)",
  "member_count": 3,
  "schema_version": 1
}
```

### Room member list record (SMPL schema, multi-writer)
Each member writes their own subkey (subkey index = member slot).
```json
{
  "public_key": "base64(pk)",
  "display_name": "encrypted(name)",
  "joined_at": 1712000000,
  "role": "admin|member",
  "route_data": "base64(serialized_route)"  // for direct contact
}
```

### Message log record (SMPL schema, multi-writer)
Each sender gets a subkey range. Subkey allocation:
- Member 0: subkeys 0-999
- Member 1: subkeys 1000-1999
- etc.

Each subkey value is an encrypted message envelope:
```
nonce(24) || ciphertext(variable) || signature(64) || sender_fingerprint(8)
```

Decrypted payload:
```json
{
  "msg_id": "01HYX...(ULID)",
  "seq": 42,
  "timestamp": 1712000000000,
  "content_type": "text|audio|file|system",
  "content": "Hello world",
  "reply_to": null,
  "attachments": []
}
```

### File chunk record (DFLT schema, single writer = uploader)
Subkey 0: File metadata
```json
{
  "file_id": "base64(32 bytes)",
  "filename": "photo.jpg",
  "mime_type": "image/jpeg",
  "size": 524288,
  "blake3_hash": "base64(32 bytes)",
  "chunk_size": 65536,
  "chunk_count": 8,
  "schema_version": 1
}
```
Subkeys 1-N: encrypted file chunks

### String storage record (DFLT schema)
Simple key-value store on DHT for lightweight payloads.
Subkey 0: metadata (owner, created_at, content_type)
Subkey 1: encrypted string payload

### Record lifecycle
- Created when room is created or file upload starts
- Watched by participants for change notifications
- GC candidates: files older than retention period, rooms with no activity


## 4. Invite encoding format

### Wire format (msgpack)
```
Field               Type        Bytes (approx)
version             u8          1
invite_type         u8          1  (0=direct, 1=room)
room_id             [u8;32]     32
dht_record_key      [u8;36]     36 (typed key)
bootstrap_route     Option<Vec> 0-256
room_name           Option<Str> 0-64
creator_public_key  [u8;32]     32
created_at          u64         8
expires_at          Option<u64> 0-8
signature           [u8;64]     64
```

Total: ~240-500 bytes depending on optional fields.

### String encoding
Base64url(msgpack(invite_payload))
Prefix: `vc1:` (veilid-chat version 1)
Example: `vc1:rO0ABXNyADFjb20uZXhhbXBsZS...`

### QR encoding
Same base64url string rendered as QR code.
At ~400 bytes, fits comfortably in a QR Version 10 (~652 alphanumeric chars).


## 5. Text chat protocol

### Send message flow
1. User composes message in UI
2. ui_api::send_message(room_id, content, reply_to)
3. chat module creates Message with ULID, seq, timestamp
4. crypto module encrypts with room key, signs with sender key
5. storage module writes to local DB (status=Pending)
6. dht module writes encrypted envelope to sender's subkey range
7. transport module sends app_call notification to online peers
8. On DHT write success: status -> Sent
9. On peer acknowledgement or next sync: status -> Synced
10. On failure after retries: status -> Failed, queued for retry

### Receive message flow
1. DHT watch fires or app_call notification arrives
2. sync module fetches new subkey values from room's message log
3. crypto module decrypts and verifies signature
4. chat module deduplicates by msg_id
5. chat module inserts into local timeline (ordered by timestamp, seq)
6. storage module persists to local DB
7. ui_api fires new_message event to UI


## 6. Audio transport design

### Voice notes (MVP)
- Record using cpal crate for audio capture
- Encode with opus via audiopus crate (16kbps, mono, 16kHz)
- Target: 2KB/second of audio
- Chunk into 4KB encrypted blocks (2s of audio per chunk)
- Store as file attachment: content_type="audio/opus"
- Send via same file transfer path (inline for short notes, chunked for longer)
- Playback: decode Opus, play via cpal

### Live audio (Phase 2 -- experimental)
- 20ms Opus frames at 16kbps = ~40 bytes/frame
- Bundle 5 frames per packet = ~200 bytes + overhead = ~250 bytes
- Send via app_call (low latency path)
- 50 packets/second target = ~12.5 KB/s
- Jitter buffer: 60-100ms (3-5 packets)
- DTX: suppress silence packets
- Quality monitoring: track RTT, loss rate
- Auto-fallback to voice notes when loss > 10% or RTT > 500ms

### Feasibility assessment
Veilid's app_call path is designed for small payloads with moderate latency.
Expected RTT: 100-500ms depending on routing.
For voice chat this means noticeable delay but usable for push-to-talk.
Full-duplex conversation will feel laggy. Voice notes are the pragmatic default.


## 7. File transfer design

### Small files (<256KB)
- Encrypt entire file
- Send via single app_call message
- Recipient stores locally
- Confirm receipt via app_call response

### Large files (>256KB)
- Split into 64KB chunks
- Encrypt each chunk with room key + chunk nonce
- Create file metadata DHT record
- Write chunks to subkeys 1-N
- Send file metadata reference in chat message
- Recipient fetches metadata, then chunks
- Verify each chunk hash, verify total file hash
- Support resume: track received chunks, re-fetch missing

### Transfer states
Queued -> Uploading(progress) -> Complete -> Failed(retryable)
Downloading: Pending -> Downloading(progress) -> Verifying -> Complete -> Failed


## 8. Sync and conflict resolution

### Model
Each room has an append-only log. Each sender owns a subkey range.
There are no true write conflicts because each sender writes to their own subkeys.
Cross-sender ordering uses (timestamp, sender_key, msg_id) as sort key.

### Catch-up flow
1. On app start or network reconnect, iterate rooms
2. For each room, inspect DHT message log record
3. Compare subkey sequence numbers against local sync state
4. Fetch all new subkeys
5. Decrypt, validate, deduplicate, merge into local timeline
6. Update sync cursors

### Consistency guarantees
- Within a sender: strict ordering by sequence number
- Across senders: eventual consistency, ordered by Lamport-style timestamps
- No global total order (acceptable for chat)
- Duplicate messages rejected by msg_id
- Late-arriving messages inserted in correct position by timestamp


## 9. Security model

### Threat model

| Threat                    | Mitigation                                    |
|---------------------------|-----------------------------------------------|
| Message interception      | E2E encryption (XChaCha20-Poly1305)           |
| Message forgery           | Ed25519 signatures per message                |
| Replay attacks            | ULID msg_id + sequence numbers + dedup        |
| DHT observation           | Encrypted payloads, minimal public metadata    |
| Metadata leakage          | Private routes, encrypted room names           |
| Invite tampering          | Signed invites, schema version check           |
| Unauthorized room join    | Room key required, invite-gated distribution   |
| Stale state poisoning     | Signature verification, timestamp validation   |
| Eclipse/routing attacks   | Veilid's built-in Kademlia protections         |
| Key compromise            | Key rotation support (Phase 2)                 |
| Local device compromise   | OS keychain / encrypted local storage          |

### Cryptographic envelope
```
+---------+------------------+-----------+--------------------+
| Nonce   | Ciphertext       | Signature | Sender Fingerprint |
| 24 bytes| variable         | 64 bytes  | 8 bytes            |
+---------+------------------+-----------+--------------------+
```

- Nonce: random per message
- Ciphertext: XChaCha20-Poly1305(room_key, nonce, plaintext)
- Signature: Ed25519(sender_secret, nonce || ciphertext)
- Fingerprint: first 8 bytes of blake3(sender_public_key)


## 10. Phased roadmap

### MVP (Phase 1)
- [x] Identity generation and secure local storage
- [x] Room creation (direct and group)
- [x] Text messaging with E2E encryption
- [x] DHT-backed message persistence
- [x] Invite generation (string format)
- [x] Invite import and room join
- [x] QR code export of invites
- [x] Local SQLite cache
- [x] Sync catch-up on reconnect
- [x] Voice note record/send/play
- [x] Small file transfer
- [x] Delivery status tracking
- [x] Terminal UI prototype

### Phase 2
- [ ] Live low-bitrate audio (experimental)
- [ ] Large file chunked transfer with resume
- [ ] QR camera scanning (Tauri + nokhwa)
- [ ] Tauri desktop GUI
- [ ] Key rotation
- [ ] Room admin/moderation
- [ ] Message search
- [ ] Attachment previews
- [ ] Read receipts
- [ ] Typing indicators

### Phase 3
- [ ] Mobile (Android/iOS via Tauri mobile or native)
- [ ] Multi-device sync
- [ ] Disappearing messages
- [ ] Message reactions
- [ ] Rich media embeds
- [ ] Plugin system
