# veilid-chat

Decentralized, end-to-end encrypted peer-to-peer chat built on the [Veilid](https://veilid.com) network. No servers. No accounts. No metadata leakage. Just cryptography and a distributed hash table.

```
┌────────────┬──────────────────────────────────────────┐
│  Rooms     │  # general                               │
│            │                                          │
│ > general  │  [14:32] a1b2c3d4: Hello from veilid!   │
│   random   │  [14:33] e5f6a7b8: Hey there            │
│            │                                          │
├────────────┴──────────────────────────────────────────┤
│  Message: _                                           │
├───────────────────────────────────────────────────────┤
│ /create <name>  /invite  /join <code>  /quit  Tab     │
└───────────────────────────────────────────────────────┘
```

## What is this?

veilid-chat is a terminal-based chat application where:

- **Every message is end-to-end encrypted** before it leaves your device
- **There are no servers** -- peers find each other through Veilid's distributed hash table (DHT)
- **Your identity is a cryptographic keypair**, not an email or phone number
- **Messages persist on the DHT**, so offline peers catch up automatically when they reconnect
- **Traffic is onion-routed** through multiple hops for sender and receiver privacy

Think of it as what you'd get if Signal and BitTorrent had a baby that was raised by Tor.

## Features

### Current (Phase 1 -- MVP)

- **Identity** -- Ed25519 keypair generation; secrets stored in OS keychain via Veilid ProtectedStore (never plaintext on disk)
- **Rooms** -- create group rooms or direct 1:1 chats; each room gets its own symmetric encryption key
- **Messaging** -- compose, send, receive with delivery status tracking (pending/sent/synced/failed)
- **End-to-end encryption** -- every message wrapped in an authenticated encrypted envelope (see Cryptography below)
- **Invite system** -- generate portable invite strings (`vc1:...`) or QR codes; Ed25519-signed to prevent tampering
- **File transfer** -- chunked file transfer with BLAKE3 integrity verification per chunk and per file
- **Voice notes** -- record, chunk, and send Opus-encoded audio (codec requires `audio-codec` feature flag)
- **Sync** -- automatic catch-up on reconnect; append-only per-sender message logs on the DHT
- **Encrypted storage** -- local SQLite database via SQLCipher (AES-256); cipher key from environment or Argon2id passphrase
- **Terminal UI** -- ratatui-based TUI with room sidebar, message view, input bar, and slash commands
- **Deduplication** -- ULID-based message IDs prevent duplicate delivery

### Planned (Phase 2)

- Live low-bitrate audio (push-to-talk over Veilid app_call)
- Large file chunked transfer with resume
- Tauri desktop GUI (React/Svelte frontend)
- Key rotation
- Room admin and moderation
- Full-text message search
- Read receipts and typing indicators

### Planned (Phase 3)

- Mobile (Android/iOS via Tauri mobile)
- Multi-device sync
- Disappearing messages
- Message reactions
- Plugin system

## Cryptography

veilid-chat uses the **VLD0 cryptographic suite** from veilid-core -- the same primitives used by Signal, WireGuard, and age:

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key exchange | **X25519** (Curve25519 ECDH) | Derive shared secrets for 1:1 room keys |
| Encryption | **XChaCha20-Poly1305** (AEAD) | Message confidentiality + integrity |
| Signing | **Ed25519** | Per-message signatures, invite signing |
| Hashing | **BLAKE3** | Content addressing, file integrity, key fingerprints |
| KDF | **Argon2id** | Passphrase-to-key derivation (GPU/ASIC resistant) |
| Local DB | **SQLCipher** (AES-256-CBC) | Encrypted-at-rest local message cache |

### Message envelope format

Every message is wrapped in a signed, authenticated envelope:

```
sig(64) || nonce(24) || aad_len(4) || aad(80) || ciphertext(variable)
```

- **Signature** (Ed25519) covers everything after it -- verified BEFORE any decryption
- **AAD** (Additional Authenticated Data) = `room_id(32) || sequence(8) || timestamp(8) || sender_key(32)` -- binds ciphertext to its context, preventing cross-room replay attacks
- **Ciphertext** includes a 16-byte Poly1305 authentication tag

### Threat model

| Threat | Mitigation |
|--------|------------|
| Message interception | E2E encryption (XChaCha20-Poly1305) |
| Message forgery | Ed25519 signatures per message |
| Replay attacks | ULID msg_id + sequence numbers + deduplication |
| Cross-room replay | AAD binds ciphertext to room_id + sender + sequence |
| DHT observation | All payloads encrypted; minimal public metadata |
| Metadata leakage | Private routes (receiver privacy) + safety routes (sender privacy) |
| Invite tampering | Ed25519-signed invites with version + expiry checks |
| Unauthorized room join | Room key required; distributed only via signed invites |
| Local device compromise | OS keychain (ProtectedStore) + SQLCipher encryption |
| Network-level surveillance | Onion-routed via Veilid safety routes (configurable hop count, default 2) |

## Network overlay

veilid-chat runs on the **Veilid network**, a peer-to-peer overlay with:

- **Kademlia-style DHT** for decentralized key-value storage and peer discovery
- **Private routes** for receiver anonymity (peers publish route blobs, not IP addresses)
- **Safety routes** for sender anonymity (messages traverse multiple relay hops before reaching the DHT or target)
- **App calls** (`app_call` / `app_message`) for real-time request/response and fire-and-forget messaging between peers
- **No central servers** -- bootstrap nodes help initial peer discovery, then the network is self-sustaining
- **No IP exposure** -- with safety routes enabled (default), your IP is never revealed to your chat partners

The default configuration uses **2-hop safety routes** with `Stability::Reliable` and `Sequencing::PreferOrdered`.

## Architecture

```
Terminal UI (ratatui)
    |
    v
chat / audio / files / invite   <-- feature modules
    |
    v
sync / storage                  <-- persistence + catch-up
    |
    v
dht / transport                 <-- network abstraction
    |
    v
crypto / identity               <-- E2E envelope + keypair management
    |
    v
veilid_node                     <-- single integration point with veilid-core
    |
    v
veilid-core (VLD0 suite)        <-- Veilid network + crypto primitives
```

All veilid-core interaction flows through `src/veilid_node/mod.rs`. No other module imports veilid-core directly.

## Installation

### Prerequisites (all platforms)

- **Rust 1.75+** -- install via [rustup](https://rustup.rs):
  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Git** -- to clone the repository
- **A C compiler** -- needed by some native dependencies (OpenSSL for SQLCipher, etc.)

### macOS

```sh
# Install Xcode command line tools (provides clang)
xcode-select --install

# Clone and build
git clone https://github.com/anthropics/veilid-chat.git
cd veilid-chat
cargo build --release

# Run
./target/release/veilid-chat
```

Optional -- for voice note support (requires cmake):
```sh
brew install cmake
cargo build --release --features audio-codec
```

### Linux (Debian/Ubuntu)

```sh
# Install build dependencies
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/anthropics/veilid-chat.git
cd veilid-chat
cargo build --release

# Run
./target/release/veilid-chat
```

Optional -- for voice note support:
```sh
sudo apt install -y cmake libasound2-dev
cargo build --release --features audio-codec
```

### Linux (Fedora/RHEL)

```sh
# Install build dependencies
sudo dnf install -y gcc gcc-c++ openssl-devel pkgconfig

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/anthropics/veilid-chat.git
cd veilid-chat
cargo build --release

# Run
./target/release/veilid-chat
```

Optional -- for voice note support:
```sh
sudo dnf install -y cmake alsa-lib-devel
cargo build --release --features audio-codec
```

### Linux (Arch)

```sh
sudo pacman -S base-devel openssl pkgconf rust
git clone https://github.com/anthropics/veilid-chat.git
cd veilid-chat
cargo build --release
./target/release/veilid-chat
```

Optional -- for voice note support:
```sh
sudo pacman -S cmake alsa-lib
cargo build --release --features audio-codec
```

### Windows

```powershell
# Install Rust via rustup (download from https://rustup.rs)
# During install, choose "Desktop development with C++" workload
# or install Visual Studio Build Tools separately

# Clone and build
git clone https://github.com/anthropics/veilid-chat.git
cd veilid-chat
cargo build --release

# Run
.\target\release\veilid-chat.exe
```

If you see OpenSSL errors, install it via [vcpkg](https://vcpkg.io):
```powershell
git clone https://github.com/microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat
.\vcpkg\vcpkg install openssl:x64-windows-static
$env:OPENSSL_DIR = "$(Get-Location)\vcpkg\installed\x64-windows-static"
cargo build --release
```

Optional -- for voice note support (requires CMake from https://cmake.org/download/):
```powershell
cargo build --release --features audio-codec
```

### NixOS

```sh
nix-shell -p rustup openssl pkg-config gcc
rustup default stable
git clone https://github.com/anthropics/veilid-chat.git
cd veilid-chat
cargo build --release
./target/release/veilid-chat
```

## Usage

### First run

```sh
# Basic run (stores data in ~/.local/share/veilid-chat)
./target/release/veilid-chat

# Custom data directory
VEILID_CHAT_DATA=./my-data ./target/release/veilid-chat

# With encrypted local database (recommended)
VEILID_CHAT_DB_KEY=$(openssl rand -hex 32) ./target/release/veilid-chat
```

On first launch, veilid-chat will:
1. Start a Veilid node and attach to the network
2. Generate a new Ed25519 identity keypair
3. Store the secret in the Veilid ProtectedStore (OS keychain)
4. Open (or create) the local SQLite database
5. Launch the terminal UI

### TUI controls

| Key | Action |
|-----|--------|
| Type + **Enter** | Send a message to the current room |
| **Tab** | Switch focus between Rooms sidebar and message input |
| **Up/Down** or **j/k** | Navigate rooms (when sidebar focused) |
| **Enter** (in sidebar) | Select room and switch to input |
| **Esc** | Clear notification bar |
| **Ctrl+C** | Quit |

### Slash commands

| Command | Description |
|---------|-------------|
| `/create <name>` | Create a new group room |
| `/invite` | Generate an invite string for the current room |
| `/join <vc1:...>` | Validate and import a room invite |
| `/help` | Show available commands |
| `/quit` | Exit veilid-chat |

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VEILID_CHAT_DATA` | Data directory path | `~/.local/share/veilid-chat` |
| `VEILID_CHAT_DB_KEY` | 32-byte hex key for SQLCipher encryption | (unencrypted with warning) |
| `RUST_LOG` | Log level filter (`trace`, `debug`, `info`, `warn`, `error`) | `info` |

Logs are written to `$VEILID_CHAT_DATA/veilid-chat.log` (not to the terminal).

## Project structure

```
src/
  main.rs           -- entry point: starts node, identity, storage, launches TUI
  lib.rs            -- module exports
  tui/mod.rs        -- ratatui terminal interface
  veilid_node/      -- single veilid-core integration point
  crypto/           -- hardened AEAD envelope + CryptoService facade (BLAKE3, X25519)
  identity/         -- Ed25519 keypair lifecycle + ProtectedStore
  storage/          -- SQLCipher-backed local persistence
  chat/             -- room + message management
  dht/              -- DhtOps trait + VeilidDht (production) + MockDht (test)
  transport/        -- app_call/app_message abstraction (skeleton)
  sync/             -- DHT catch-up and conflict resolution
  invite/           -- Ed25519-signed invite creation, encoding, validation, QR generation
  files/            -- chunked file transfer with BLAKE3 integrity
  audio/            -- voice note builder (Opus encoding behind feature flag)
  qr/               -- QR code generation re-export
  ui_api/           -- command/event bus between UI and core
  models/           -- shared domain types (Room, Message, Invite, etc.)
```

## Running tests

```sh
cargo test
```

30 tests covering cryptographic operations, identity lifecycle, storage CRUD, message deduplication, invite sign/verify/tamper-detection, file integrity, sync catch-up, and SQLCipher key rejection.

## Tech stack

| Component | Technology |
|-----------|------------|
| Language | Rust (2021 edition, MSRV 1.75) |
| Network overlay | [Veilid](https://veilid.com) 0.5.3 |
| Async runtime | [Tokio](https://tokio.rs) |
| Terminal UI | [ratatui](https://ratatui.rs) 0.29 + [crossterm](https://docs.rs/crossterm) 0.28 |
| Local database | [SQLCipher](https://www.zetetic.net/sqlcipher/) via [rusqlite](https://docs.rs/rusqlite) 0.38 |
| Serialization | [MessagePack](https://msgpack.org) (rmp-serde) + serde_json + base64 |
| Crypto (Veilid) | XChaCha20-Poly1305, Ed25519, X25519, BLAKE3, Argon2id |
| Crypto (standalone) | [ed25519-dalek](https://docs.rs/ed25519-dalek), [x25519-dalek](https://docs.rs/x25519-dalek), [blake3](https://docs.rs/blake3) |
| QR codes | [qrcode](https://docs.rs/qrcode) (SVG + PNG) |
| Audio codec | [Opus](https://opus-codec.org/) via audiopus (optional) |
| IDs | [ULID](https://github.com/ulid/spec) (time-sortable unique identifiers) |

## How it works (in 30 seconds)

1. You start veilid-chat. It generates an **Ed25519 identity** and joins the **Veilid peer-to-peer network**.
2. You **create a room**. A random 256-bit symmetric key is generated for it, and three DHT records are allocated (metadata, members, message log).
3. You **generate an invite** -- a signed, base64url-encoded blob containing the room key material and the DHT record pointers.
4. Your friend **imports the invite**. Their node opens the same DHT records and can now read and write messages.
5. When you **send a message**, it's encrypted with XChaCha20-Poly1305 using the room key, signed with your Ed25519 key, and written to your subkey range in the DHT message log.
6. Your friend's node **watches the DHT record** for changes. When new subkeys appear, it fetches them, **verifies the signature first** (before any decryption), then decrypts and displays the message.
7. All network traffic is **onion-routed** through Veilid safety routes -- neither you nor your friend reveal your IP addresses to each other or to DHT nodes.

## License

MIT OR Apache-2.0
