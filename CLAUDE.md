# CLAUDE.md — Project intelligence for veilid-chat (speakeasy)

## What this project is

Decentralized, end-to-end encrypted peer-to-peer chat over the Veilid network.
No servers, no accounts — cryptographic identity + DHT coordination + onion-routed transport.
Binary crate, Rust 2021 edition, MSRV 1.75, licensed MIT OR Apache-2.0.

## Build & test

```sh
cargo build                              # debug build (~74MB)
cargo build --release                    # release build (~17MB, thin LTO)
cargo test                               # 30 tests, all must pass
cargo build --release --features audio-codec  # with Opus (needs cmake)
```

### Critical dependency constraints (DO NOT change without testing)

- `veilid-core = "=0.5.3"` — exact pin; 0.5.2 has upstream compile rot
- `socket2 = "0.5"` and `attohttpc = "0.24"` — pin to avoid transitive semver drift against veilid-core
- `rusqlite = "0.38"` with `bundled-sqlcipher-vendored-openssl` — must match veilid-core's transitive libsqlite3-sys
- `audiopus` + `cpal` are behind the `audio-codec` feature flag (requires cmake + C toolchain)
- Release profile uses `lto = "thin"` + `codegen-units = 4` — full LTO OOMs on <4GB machines

### Running

```sh
VEILID_CHAT_DATA=./data ./target/release/veilid-chat          # basic
VEILID_CHAT_DB_KEY=$(openssl rand -hex 32) ./target/release/veilid-chat  # encrypted DB
RUST_LOG=debug ./target/release/veilid-chat                    # verbose logging
```

Logs go to `$VEILID_CHAT_DATA/veilid-chat.log`, not to the terminal (TUI owns stdout).

## Architecture — module map

```
src/main.rs           entry point: starts VeilidNode, identity, storage, TUI
src/tui/              ratatui terminal interface (rooms, messages, input, commands)
src/veilid_node/      SOLE integration point with veilid-core — no other module imports veilid-core
src/crypto/           hardened AEAD envelope (verify-before-decrypt) + CryptoService facade
src/identity/         Ed25519 keypair lifecycle + Veilid ProtectedStore for secrets
src/storage/          SQLCipher-backed local persistence (rusqlite 0.38)
src/chat/             room + message management, delivery status tracking
src/dht/              DhtOps trait + VeilidDht (production) + MockDht (test) + Arc<T> delegation
src/transport/        app_call/app_message abstraction (skeleton — not yet wired)
src/sync/             DHT catch-up, generic over DhtOps
src/invite/           Ed25519-signed invite creation/validation + QR generation
src/files/            chunked file transfer with BLAKE3 integrity
src/audio/            voice note builder (Opus behind feature flag)
src/qr/               re-export of invite::QrService
src/ui_api/           command/event bus between UI and core (skeleton)
src/models/           shared domain types (Room, Message, ChatInvite, EncryptedEnvelope, etc.)
```

### Key architectural rule

**All veilid-core interaction flows through `src/veilid_node/mod.rs`.** No other module should import `veilid_core` directly. This is the abstraction boundary.

Exception: `src/crypto/mod.rs` imports `veilid_core::CRYPTO_KIND_VLD0` and a few types for the envelope functions that take `&VeilidNode`.

## veilid-core 0.5.3 API — things that are NOT obvious

The API differs significantly from documentation and examples written for older versions:

- **Config**: `VeilidConfig::new(name, org, qualifier, Some(storage_dir), Some(config_dir))` — NOT `VeilidConfigInner`
- **Crypto guard**: `api.crypto()?.get(CRYPTO_KIND_VLD0)?` returns `CryptoSystemGuard<'_>` — **cannot be stored in a struct** (lifetime bound to temporary). Must be obtained fresh per operation.
- **Key byte access**: `public_key.ref_value().bytes()` — NOT `.bytes` field. Returns `bytes::Bytes`.
- **Key construction**: `PublicKey::new(CRYPTO_KIND_VLD0, BarePublicKey::new(&[u8]))` — types include `BarePublicKey`, `BareSecretKey`, `BareSignature`, `BareSharedSecret`, `BareMemberId`
- **Nonce**: plain byte-array type (NOT CryptoTyped) — `.bytes()` works directly, `Nonce::new(&[u8])` or `Nonce::from(vec)`
- **DHT**: `create_dht_record(CRYPTO_KIND_VLD0, schema, None)` takes 3 args; `set_dht_value` takes `Option<SetDHTValueOptions>` not bare writer; `watch_dht_values` returns `bool`
- **SMPL members**: `DHTSchemaSMPLMember.m_key` is `BareMemberId`, NOT `PublicKey`
- **DHTSchema constructors**: `DHTSchema::dflt(1)?` and `DHTSchema::smpl(0, members)?` return `VeilidAPIResult`
- **Private routes**: `api.new_private_route()` returns `RouteBlob { route_id, blob }` struct
- **ProtectedStore**: methods are **SYNC** (not async) — `save_user_secret_string`, `load_user_secret_string`
- **RouteId**: NOT Copy — must clone
- **Nested runtime**: veilid-core internally creates/blocks on a tokio runtime. `api_startup` and `api.attach()` must be called from a thread with NO existing tokio context. Current solution: `std::thread::spawn` + `futures::executor::block_on` + oneshot channel back.

## Cryptographic invariants — MUST preserve when editing

1. **Verify-before-decrypt** — `verify_and_decrypt` runs Ed25519 verify BEFORE AEAD decryption. Reordering enables padding oracles.
2. **AAD room_id check** — `verify_and_decrypt` rejects envelopes whose AAD room_id != expected. This is the cross-room replay defence.
3. **Canonical AAD layout** — `room_id(32) || seq(8 LE) || ts(8 LE) || sender_key(32)` = 80 bytes. Both sender and receiver must use identical layout.
4. **Envelope wire format** — `sig(64) || nonce(24) || aad_len(4 LE) || aad || ciphertext`. Parsed by `EncryptedEnvelope::from_bytes`.
5. **256 KiB plaintext cap** — `MAX_PAYLOAD_SIZE` in `crypto/mod.rs`. Large files go through the `files/` chunking path.
6. **No custom crypto** — all primitives via `VeilidNode` (which wraps `veilid_core::CryptoSystem` VLD0) or `ed25519-dalek`/`x25519-dalek` (same algorithms). Never add raw `ring`/`aes-gcm`/etc.

## Security decisions — context for reviewers

- Identity secret keys go to Veilid `ProtectedStore` (OS keychain / Argon2id encrypted). NEVER written to the on-disk profile. Test `test_no_plaintext_secret_on_disk` enforces this.
- SQLite encrypted via SQLCipher when `VEILID_CHAT_DB_KEY` env var is set. Without it, a `WARN` is logged. `open_encrypted()` issues `PRAGMA key` with raw hex bytes (no internal PBKDF2).
- Invite signatures use real Ed25519 (`ed25519-dalek`), NOT the old blake3 MAC placeholder. Tests cover tampered and wrong-signer rejection.
- Safety routes default to 2 hops (`SafetySpec.hop_count = 2`), `Stability::Reliable`, `Sequencing::PreferOrdered`. `always_use_insecure_storage = false`.

## Design documents

- `ARCHITECTURE.md` — authoritative 10-section design doc (modules, DHT schema, invite format, chat protocol, audio, files, sync, threat model, roadmap). Check before designing anything new.
- `SECURITY_AUDIT.md` — dated 2026-04-16; CRITICAL/HIGH/MEDIUM/LOW findings against the original scaffold + section 4 remediation plan. Most items from section 4 are now implemented.
- `progress.md` — working-memory state file recording what's been done, open questions, and next actions. Read first when resuming work.
- `resources.md` — Rust/Veilid learning methodology and reference links.

## Rust & Veilid reference (for LLM context)

### Core Rust concepts needed

- **Ownership + borrowing** — The Rust Book chapters 4-10. Critical for understanding why `CryptoSystemGuard` can't be stored (lifetime-bound to temporary).
- **Async/await** — Async Rust Book chapters 1-4. Veilid is async-heavy (tokio). The nested-runtime issue with veilid-core is a key gotcha.
- **Error handling** — `anyhow::Result` for application code, `thiserror` for typed errors in library modules.
- **Traits** — `DhtOps` trait pattern allows MockDht for tests and VeilidDht for production.

### Veilid concepts needed

- **DHT** (Distributed Hash Table) — Kademlia-style. Records have schemas (DFLT for single-writer, SMPL for multi-writer). Each record has subkeys (0..N). See Veilid Developer Book "Core Concepts".
- **Private routes** — receiver privacy. A node publishes a route blob (not its IP). Senders import the blob to reach the node. See `VeilidNode::allocate_private_route`.
- **Safety routes** — sender privacy. Messages traverse multiple relay hops before reaching the DHT or target. Configured via `SafetySelection::Safe(SafetySpec { hop_count: 2, ... })`.
- **App calls** — `app_call` (request/response, max 32KB) and `app_message` (fire-and-forget). Used for real-time message relay between peers.
- **RoutingContext** — the handle through which all DHT and app_call operations flow. Created from `VeilidAPI::routing_context()` with safety routing configuration.
- **ProtectedStore** — OS keychain or Argon2id-encrypted storage for secrets. Used for identity keys.
- **TableStore** — encrypted key-value persistence. Available but not yet used in this project.

### VLD0 cryptographic suite

| Primitive | Algorithm | Crate |
|-----------|-----------|-------|
| Key exchange | X25519 (Curve25519 ECDH) | x25519-dalek / veilid-core |
| Encryption | XChaCha20-Poly1305 (AEAD) | veilid-core |
| Signing | Ed25519 | ed25519-dalek / veilid-core |
| Hashing | BLAKE3 | blake3 |
| KDF | Argon2id | argon2 / veilid-core |

These are the same primitives used by Signal, WireGuard, and age.

### Essential crates in this project

| Crate | Purpose |
|-------|---------|
| `veilid-core` 0.5.3 | Veilid network + crypto primitives |
| `tokio` | Async runtime |
| `ed25519-dalek` | Ed25519 signing (identity, invites) |
| `x25519-dalek` | X25519 DH (1:1 room key derivation) |
| `blake3` | Content hashing, fingerprints, KDF |
| `rusqlite` | SQLCipher-backed local storage |
| `ratatui` + `crossterm` | Terminal UI |
| `serde` + `rmp-serde` | MessagePack serialization |
| `anyhow` + `thiserror` | Error handling |
| `tracing` | Structured logging |
| `qrcode` + `image` | QR code generation |
| `ulid` | Time-sortable message IDs |
| `zeroize` | Secret material cleanup |

### Quick reference — common Veilid patterns

| Task | How |
|------|-----|
| Start a node | `VeilidNode::start(config)` — runs api_startup on clean thread |
| Generate keypair | `node.generate_keypair()` returns `KeyPair` with `.key()` and `.secret()` |
| Create DHT record | `node.create_dht_record_default()` (DFLT) or `node.create_dht_record_smpl(n, subkeys)` |
| Read DHT value | `node.get_dht_value(record_key, subkey, force_refresh)` |
| Write DHT value | `node.set_dht_value(record_key, subkey, data, writer)` |
| Watch for changes | `node.watch_dht_record(record_key, subkeys)` |
| Allocate private route | `node.allocate_private_route()` returns `(RouteId, Vec<u8>)` |
| Send app call | `node.app_call(target, message)` — max 32KB |
| Encrypt message | `crypto::encrypt_and_sign(node, plaintext, room_key, room_id, seq, ts, pk, sk)` |
| Decrypt message | `crypto::verify_and_decrypt(node, envelope, room_key, expected_room_id, sender_pk)` |
| Hash content | `CryptoService::hash_fixed(data)` returns `[u8; 32]` |
| Derive 1:1 room key | `CryptoService::derive_room_key_direct(our_sk, their_pk)` |

## Remaining work

1. **Transport module** — implement against VeilidNode's `app_call`/`app_message` (currently skeleton)
2. **UI dispatcher** in `ui_api` — handle `Command` enum -> service calls (currently event bus only)
3. **End-to-end crypto wiring** — compose -> encrypt_and_sign -> DHT write -> sync fetch -> verify_and_decrypt -> receive
4. **Argon2id passphrase** -> cipher key derivation (currently hex env var)
5. **Phase 2 features** from ARCHITECTURE.md section 10 (Tauri GUI, key rotation, live audio, etc.)

## CI/CD

GitHub Actions workflow at `.github/workflows/build.yml`:
- Builds for Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64
- Triggers on `v*` tags (creates GitHub Release with binaries + SHA256 checksums)
- Also supports manual `workflow_dispatch`
