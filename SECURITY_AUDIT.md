# Security Audit and Hardening Report
## Veilid-Chat Codebase Review

### Classification: CONFIDENTIAL
### Date: 16 April 2026
### Auditor: Security Engineering

---

## 1. Critical findings in current scaffold

### CRITICAL: Placeholder crypto (crypto/mod.rs)

The entire cryptographic layer uses blake3 XOR stream as a substitute for
XChaCha20-Poly1305. This provides ZERO confidentiality and ZERO authentication.

- `placeholder_encrypt()`: XOR with blake3-derived stream. Trivially reversible,
  no authentication tag, malleable ciphertext.
- `placeholder_sign()`: blake3 MAC, not Ed25519. No non-repudiation, not
  verifiable without the secret key (MAC not signature).
- `placeholder_verify()`: Returns true for any 64-byte input. No verification.

**Impact**: Total compromise of all message confidentiality and integrity.
**Fix**: Replace with veilid_core::CryptoSystem (XChaCha20-Poly1305 + Ed25519).

### CRITICAL: Identity key storage (identity/mod.rs)

Secret keys are stored in plaintext msgpack on disk.

- Line: `fs::write(self.identity_path(), &data)` -- raw bytes, no encryption.
- Comment says "TODO: encrypt secret_key field before writing to disk".
- `always_use_insecure_storage: true` in the veilid config examples.

**Impact**: Any local file read leaks the identity private key.
**Fix**: Use Veilid's ProtectedStore with password protection, or encrypt with
Argon2-derived key from user passphrase.

### HIGH: No nonce uniqueness enforcement (crypto/mod.rs)

Nonces are generated randomly (`rand::thread_rng().fill_bytes(&mut nonce)`).
For XChaCha20-Poly1305, random 24-byte nonces are safe (birthday bound at
2^96 messages), but the code has no counter-based fallback and no nonce
tracking for replay detection.

**Impact**: Theoretically safe with random nonces at scale, but no defence
against nonce reuse if the CSPRNG fails.
**Fix**: Use veilid_core's nonce generation (which uses OS CSPRNG). Add
monotonic sequence number as nonce component for defence in depth.

### HIGH: No message authentication on transport (transport/mod.rs)

The transport layer sends raw bytes with no framing, no authentication, and
no replay protection at the transport level (relying entirely on app-level
crypto which is currently broken).

**Impact**: Message injection, replay, and man-in-the-middle at transport level.
**Fix**: Veilid's app_call/app_message are already encrypted at the routing
level. Add application-layer envelope verification as defence in depth.

### HIGH: SQLite not encrypted at rest (storage/mod.rs)

Local database stores all messages, room keys, sync state in plaintext SQLite.

**Impact**: Local device compromise exposes all historical messages and keys.
**Fix**: Use SQLCipher (rusqlite with `bundled-sqlcipher` feature) or encrypt
at the application layer before SQLite insertion.

### MEDIUM: Invite signature not verified (invite/mod.rs)

`validate()` checks signature length (64 bytes) but does not actually verify
the Ed25519 signature against the creator's public key.

**Impact**: Forged invites accepted without verification.
**Fix**: Implement proper Ed25519 verify via veilid_core.

### MEDIUM: No rate limiting on DHT operations (dht/mod.rs)

No backpressure, no rate limiting, no circuit breaker on DHT reads/writes.

**Impact**: Accidental or malicious flooding of DHT operations.
**Fix**: Add tokio::time::sleep-based rate limiter and concurrent operation cap.

### MEDIUM: No secure memory handling

Secret keys and room keys are stored in standard `Vec<u8>` which can be
swapped to disk, left in core dumps, and not zeroed on drop.

**Impact**: Key material persists in memory after use.
**Fix**: Use `zeroize` crate on all secret material. Consider `secrecy` crate.

### LOW: No timestamp validation on messages

Messages are accepted with any timestamp. No check against local clock or
acceptable window.

**Impact**: Timestamp manipulation for message ordering attacks.
**Fix**: Reject messages with timestamps more than 5 minutes in the future
or configurable staleness threshold in the past for new messages.

### LOW: ULID generation uses thread_rng

ULIDs contain a timestamp and random component. The random component uses
`thread_rng()` which is a CSPRNG (ChaCha20Rng) in the `rand` crate, so
this is acceptable but should be documented.

---

## 2. Veilid crypto primitives (VLD0 suite)

Veilid's built-in cryptosystem (VLD0) provides:

| Primitive | Algorithm | Notes |
|-----------|-----------|-------|
| Key exchange | X25519 | Curve25519 ECDH |
| Encryption | XChaCha20-Poly1305 | AEAD, 24-byte nonce |
| Signing | Ed25519 | 64-byte signatures |
| Hashing | BLAKE3 | 32-byte digests |
| Password KDF | Argon2id | GPU/ASIC resistant |

These are the same primitives used by Signal, WireGuard, and age.
This is a strong suite suitable for classified-adjacent applications.

The VLD0 suite is accessed via `veilid_core::CryptoSystem`:
- `generate_keypair()` -> (PublicKey, SecretKey)
- `sign(key, data)` -> Signature
- `verify(key, data, signature)` -> bool
- `encrypt_aead(key, nonce, body, associated_data)` -> Vec<u8>
- `decrypt_aead(key, nonce, body, associated_data)` -> Vec<u8>
- `compute_dh(key, other_key)` -> SharedSecret
- `generate_shared_secret(key, other_key, domain)` -> SharedSecret
- `random_nonce()` -> Nonce
- `generate_hash(data)` -> TypedHash

The ProtectedStore provides encrypted-at-rest key storage using the OS
keychain or Argon2id-derived encryption.

The TableStore provides encrypted key-value persistence.

---

## 3. Hardening requirements for GOV/MIL posture

### 3.1 Cryptographic requirements

- [ ] All encryption via veilid_core::CryptoSystem (no custom crypto)
- [ ] All signing via veilid_core Ed25519
- [ ] All key exchange via veilid_core X25519
- [ ] All hashing via veilid_core BLAKE3
- [ ] No plaintext secret material in memory longer than necessary
- [ ] zeroize all secret buffers on drop
- [ ] Encrypted local storage (ProtectedStore for keys, TableStore for data)
- [ ] No `always_use_insecure_storage` in any configuration
- [ ] Nonce uniqueness: sequence counter XOR random for belt-and-suspenders
- [ ] Message authentication: verify signatures before any processing
- [ ] Replay protection: reject duplicate msg_ids and old sequence numbers

### 3.2 Transport requirements

- [ ] All DHT operations via safety-routed RoutingContext (sender privacy)
- [ ] All direct messages via private routes (receiver privacy)
- [ ] Double-privacy: safety route + private route for maximum anonymity
- [ ] No raw NodeId exposure in any user-facing data
- [ ] Configurable hop count (default 2+ for high-security)
- [ ] Route rotation on configurable interval
- [ ] Connection state monitoring with automatic route refresh

### 3.3 Data at rest requirements

- [ ] SQLite encrypted via SQLCipher or application-layer encryption
- [ ] Identity keys in Veilid ProtectedStore (password-protected)
- [ ] Room keys in Veilid TableStore (encrypted)
- [ ] No plaintext PII in any log output
- [ ] Configurable message retention with secure deletion
- [ ] Core dump protection (disable core dumps, mlock sensitive pages)

### 3.4 Metadata minimization

- [ ] Room names encrypted in DHT records
- [ ] Member lists encrypted in DHT records
- [ ] No cleartext metadata in invite strings beyond version byte
- [ ] Timestamps use relative offsets, not absolute UTC where possible
- [ ] File metadata (filename, mime) encrypted alongside content
- [ ] No user-agent or version strings in transport headers

### 3.5 Operational security

- [ ] Panic handler that does not dump state
- [ ] Structured logging with configurable redaction
- [ ] No debug builds in distribution
- [ ] Signed release binaries
- [ ] Dependency audit (cargo-audit, cargo-deny)
- [ ] Fuzzing targets for all parsers (invite, message, envelope)

---

## 4. Hardened architecture changes

### 4.1 New module: veilid_node

Wraps all veilid_core interaction. Single point of contact between
our application and the Veilid network. Manages:
- Node lifecycle (startup, attach, detach, shutdown)
- RoutingContext creation with safety route configuration
- Private route allocation and rotation
- Update callback dispatch
- CryptoSystem access

### 4.2 Crypto module rewrite

Remove all placeholder functions. The new crypto module:
- Holds a reference to veilid_core::CryptoSystem
- Provides typed wrappers that enforce correct usage
- Implements zeroize on all secret types
- Provides the EncryptedEnvelope format using real AEAD
- Provides AAD (additional authenticated data) binding:
  room_id + sequence + timestamp in AAD prevents cross-room replay

### 4.3 Identity module rewrite

- Use Veilid's ProtectedStore for key storage
- Password-protect identity with Argon2id (via Veilid)
- Store profile data in Veilid's TableStore
- Export identity backup as encrypted blob

### 4.4 Storage module rewrite

- Use Veilid's TableStore instead of raw SQLite for sensitive data
- Keep SQLite for message cache only (encrypted at application layer)
- All values encrypted before insertion
- Secure deletion: overwrite before delete

### 4.5 DHT module rewrite

- Implement against real RoutingContext
- Safety routing enforced on all operations
- Rate limiting: max 10 DHT ops/second, configurable
- Watch management with automatic re-registration
- Subkey allocation with overflow protection

### 4.6 Transport module rewrite

- app_call for request/response (e.g., file chunk request)
- app_message for fire-and-forget (e.g., new message notification)
- Private route allocation per room
- Route health monitoring and rotation
- Bandwidth tracking for audio quality decisions
