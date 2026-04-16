# progress.md — veilid-chat knowledge state

Updated: 2026-04-16 (post-hardening session)

## Build status

**Clean build. 30 tests, all green.**

- `cargo check` passes with zero errors, zero warnings.
- `cargo test` passes 30/30.
- veilid-core pinned to `=0.5.3` with transitive dep pins (socket2, attohttpc)
  to avoid upstream semver drift.
- `audiopus`/`cpal` gated behind `audio-codec` feature (requires cmake).
- `rusqlite 0.38` unified with veilid-core's transitive `libsqlite3-sys`.

## What was done (priority 1-5 from resources.md methodology)

### #1 Restore build — CryptoService facade
- Added `CryptoService` struct in `crypto/mod.rs` with static methods:
  `hash_fixed`, `hash`, `generate_room_key`, `derive_room_key_direct`.
- `derive_room_key_direct` uses x25519-dalek (same X25519 as VLD0) + BLAKE3 KDF.
- Call sites in `chat/`, `files/`, `audio/`, `invite/` updated. Unused imports removed.

### #2 Identity — real Ed25519 + ProtectedStore-aware
- `identity/mod.rs` fully rewritten. Uses `ed25519-dalek::SigningKey` for real
  Ed25519 (public IS derived from secret — passes roundtrip sign/verify test).
- Secret NEVER written to disk profile. On-disk `DiskProfile` only contains
  public material + `secret_in_protected_store` flag.
- When `VeilidNode` wired via `.with_protected_store(node)`, secret goes to
  Veilid ProtectedStore (OS keychain / Argon2id encrypted).
- Without ProtectedStore: secret is in-memory only, lost on restart, loud warning.
- Test `test_no_plaintext_secret_on_disk` verifies no secret bytes on disk.

### #3 SQLCipher — PRAGMA key
- `LocalStorage::open_encrypted(path, &[u8; 32])` added. Issues `PRAGMA key`
  with raw hex form (no internal PBKDF2). Verification query runs immediately.
- `open()` (unencrypted) logs a warning.
- `open_memory()` unchanged (for tests).
- Test `test_sqlcipher_roundtrip_and_wrong_key_rejected` verifies encryption
  and wrong-key rejection.

### #4 main.rs — VeilidNode wired
- `main.rs` starts `VeilidNode::start(config)`, wraps in `Arc`.
- Identity gets `.with_protected_store(node.clone())`.
- `VeilidDht` production impl of `DhtOps` created, backed by `VeilidNode`.
- `SyncService` wired with `VeilidDht`.
- Database encryption via `VEILID_CHAT_DB_KEY` env var (hex, 32 bytes);
  falls back to unencrypted with warning.
- Graceful shutdown sequence: drop services, unwrap Arc, shutdown node.

### #5 Invite — real Ed25519 sign + verify
- `sign_invite` uses `ed25519_dalek::SigningKey::sign` (replaces blake3 MAC).
- `validate` uses `ed25519_dalek::VerifyingKey::verify` against `creator_public_key`.
- Tests generate real keypairs. New tests: `test_validate_rejects_tampered_invite`,
  `test_validate_rejects_wrong_signer`.

## veilid_node/mod.rs — rewritten against real veilid-core 0.5.3 API

Key differences from original scaffold:
- Config: `VeilidConfig::new(name, org, qualifier, Some(storage), Some(config))`
- Crypto: `CryptoSystemGuard<'_>` obtained fresh per call (can't store — lifetime)
- Key types: `PublicKey.ref_value().bytes()` for extraction, `BareX::new(&[u8])` for construction
- DHT: `create_dht_record(CRYPTO_KIND_VLD0, schema, None)` — 3 args
- SMPL members: `BareMemberId` not `PublicKey`
- set_dht_value: `Option<SetDHTValueOptions>` not bare writer
- watch_dht_values: returns `bool` not `Timestamp`
- new_private_route: returns `RouteBlob` struct
- protected_store: SYNC methods (not async)

## Module map (current state)

| Module | Status | Notes |
|--------|--------|-------|
| `models/` | ✅ | Clean domain types |
| `veilid_node/` | ✅ hardened | Real veilid-core 0.5.3 API |
| `crypto/` | ✅ hardened | AEAD + Ed25519 + AAD + CryptoService facade |
| `identity/` | ✅ hardened | Real Ed25519, ProtectedStore, no plaintext secret |
| `storage/` | ✅ hardened | SQLCipher-ready via `open_encrypted()` |
| `chat/` | ✅ | Works with CryptoService facade |
| `invite/` | ✅ hardened | Real Ed25519 sign + verify |
| `files/` | ✅ | Works with CryptoService facade |
| `audio/` | ✅ | Placeholder pass-through (codec behind feature) |
| `qr/` | ✅ | Thin re-export |
| `dht/` | ✅ | `VeilidDht` (production) + `MockDht` (test) + `Arc<T>` delegation |
| `transport/` | ⚠️ skeleton | `Transport` trait + `OfflineTransport` only |
| `sync/` | ✅ | Generic over DhtOps, tested with MockDht via Arc |
| `ui_api/` | ⚠️ skeleton | Event bus only, no dispatcher |
| `main.rs` | ✅ | Wires VeilidNode, identity, storage, DhtOps, sync |

## Remaining work

1. Transport module: implement against VeilidNode's `app_call`/`app_message`
2. UI dispatcher in `ui_api` to handle `Command` → service calls
3. Terminal UI (ratatui)
4. Wire crypto envelope path end-to-end: compose → encrypt_and_sign → DHT write → sync fetch → verify_and_decrypt → receive
5. Argon2id passphrase → cipher key derivation (instead of hex env var)
6. Phase 2 features from ARCHITECTURE.md §10
