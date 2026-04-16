# Resources for Deep Understanding of Rust & Veilid

This document is intended for an LLM (or a human) to systematically learn and build applications with Rust and the Veilid framework.

## 🦀 Rust – Core Learning Resources

| Resource | URL / Access | Purpose |
|----------|--------------|---------|
| **The Rust Book** (official) | https://doc.rust-lang.org/book/ | Primary language fundamentals, ownership, borrowing, lifetimes, structs, enums, error handling, testing. |
| **Rust by Example** | https://doc.rust-lang.org/rust-by-example/ | Learn via runnable code snippets. |
| **Rust Standard Library API docs** | https://doc.rust-lang.org/std/ | Detailed reference for `std::`, collections, I/O, concurrency primitives. |
| **Async Rust Book** | https://rust-lang.github.io/async-book/ | Essential for Veilid – covers `Future`, `async`/`await`, executors, `tokio`, `async-std`. |
| **Rust Cookbook** | https://rust-lang-nursery.github.io/rust-cookbook/ | Practical solutions for common tasks (file I/O, JSON, HTTP, etc.). |
| **`rustup doc`** (local) | Run `rustup doc` in terminal | Offline, searchable access to all Rust documentation. |
| **crates.io** | https://crates.io | Registry of Rust libraries – check dependencies, versions, popularity. |
| **docs.rs** | https://docs.rs | Automatically generated documentation for any crate. |

## 🌐 Veilid – Framework & Protocol

| Resource | URL / Access | Purpose |
|----------|--------------|---------|
| **Veilid Official Website** | https://veilid.com | High-level architecture: DHT, RPC protocol, cryptography, security model. See “How it works”. |
| **Veilid Developer Book** | https://veilid.gitlab.io/developer-book/ | In-depth guide: building apps, using the API, key concepts (routes, keys, DHT operations). |
| **Veilid API Docs (Rust)** | https://docs.rs/veilid-core | Core Rust crate documentation – `VeilidAPI`, `RoutingContext`, `SafeKey`, etc. |
| **Veilid GitLab Repository** | https://gitlab.com/veilid/veilid | Full source code. Start with `README.md`, `INSTALL.md`, `DEVELOPMENT.md`. Sub-crates: `veilid-core`, `veilid-tools`, `veilid-cli`. |
| **Veilid Python bindings** | https://pypi.org/project/veilid/ | For prototyping or cross-checking behavior. |
| **Veilid Flutter/Dart package** | https://pub.dev/packages/veilid | Mobile / cross-platform reference. |
| **DEF CON 31 Talk (video)** | Search: “Veilid DEF CON 31” | Design rationale, use cases, deep dive from creators. |
| **Mozilla Public License 2.0** | https://mozilla.org/MPL/2.0/ | Understand licensing if modifying or distributing. |

## 🛠️ Essential Rust Crates for Veilid Development

These often appear in Veilid-based apps. Understand them as needed:

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime – Veilid uses tokio. |
| `serde` / `serde_json` | Serialization for DHT data, RPC messages. |
| `anyhow` / `thiserror` | Error handling ergonomics. |
| `tracing` | Logging and diagnostics (Veilid uses `tracing` heavily). |
| `bytes` | Efficient buffer handling for network I/O. |
| `blake3` / `x25519-dalek` | Hashing and cryptography (Veilid uses BLAKE3 and X25519). |

---

# LLM Workflow & Methodology for Building Knowledge While Building an App

Use the following iterative methodology. Each phase builds on the previous one. The LLM should simulate a “learn‑by‑building” loop.

## Phase 0 – Environment Setup (one time)

- Ensure Rust is installed (`rustup`, latest stable).
- Create a new binary crate: `cargo new my_veilid_app && cd my_veilid_app`.
- Add `veilid-core` and `tokio` to `Cargo.toml`.
- Verify a minimal async `main` runs (`tokio::main`).

## Phase 1 – Systematic Knowledge Ingestion

**Do not skip.** The LLM should read (or simulate reading) in this order:

1. **Rust Book**, chapters 1–10 (ownership, structs, enums, error handling, generics, traits).
2. **Async Rust Book**, chapters 1–4 (why async, `Future`, `async`/`await`, pinning).
3. **Veilid Developer Book**, sections “Core Concepts” and “Your First Veilid App”.
4. **Veilid API Docs** for `veilid_core::VeilidAPI` – focus on `new()`, `attach()`, `detach()`, `call()`.
5. **Veilid GitLab `DEVELOPMENT.md`** – understand how to run a local test network.

**Output after Phase 1:** A short summary (2–3 paragraphs) explaining:
- Ownership and async in Rust.
- How Veilid nodes discover each other and route messages via the DHT.
- The role of `RoutingContext`.

## Phase 2 – Build a Minimal “Echo” Example

Goal: Verify that the LLM can translate documentation into working code.

- Implement a Veilid node that:
  - Attaches to the local network (or test network).
  - Subscribes to a given `Route` (e.g., a key derived from a fixed string).
  - When it receives a message, it sends back a “pong” to the sender’s `Route`.

**Learning actions:**
- Identify the correct `veilid-core` functions for subscribing and sending.
- Handle errors using `anyhow::Result`.
- Use `tracing` to log events.

**Output:** A working `main.rs` that compiles and can be tested with two nodes.

## Phase 3 – Build a Small Realistic Feature

Pick one minimal application feature, e.g.:

> **A distributed key‑value store with time‑to‑live (TTL)**
> - Store a value at a DHT key (signed by the node).
> - Retrieve the value from another node.
> - After TTL, the value is automatically removed.

**Workflow steps for the LLM:**

1. **Decompose** the feature into sub‑problems:
   - DHT key derivation (`blake3` of user‑provided name).
   - Signing value with a `SafeKey` (from Veilid).
   - `call()` DHT `SET` and `GET` operations.
   - Parsing TTL from metadata.
2. **Search** `docs.rs/veilid-core` for DHT operation functions (look for `dht_get`, `dht_set`).
3. **Read** the source of Veilid’s `veilid-tools` crate for examples.
4. **Implement incrementally** – first `SET`, then `GET`, then TTL.
5. **Test** by running two terminal nodes (or use `cargo test` with an in‑memory test network).

**Output:** A working module with documentation comments and unit tests.

## Phase 4 – Error‑Driven Deepening

During implementation, the LLM will encounter errors (borrow checker, async lifetimes, Veilid API misuses). For each error:

- **Stop** and locate the exact Rust / Veilid documentation section that explains the correct pattern.
- **Write a short note** (as a comment in the code or a separate `NOTES.md`) explaining the error and why the fix works.
- **Add a regression test** if applicable.

This builds a context‑aware memory of pitfalls.

## Phase 5 – Iterative Refactoring with Reference Checking

After the feature works:

- **Re‑read** the relevant chapters of the Veilid Developer Book and Rust Book.
- **Identify** at least two improvements (e.g., better error handling, less cloning, more efficient async channels).
- **Refactor** and verify with existing tests.

**Key principle:** Never assume the AI’s internal knowledge is correct – always cross‑check with the provided `resources.md` links, especially `docs.rs` and the official books.

## Phase 6 – Scaling to a Full Application

Now apply the same methodology to your target app (e.g., chat, file sharing, collaborative editor). For each new component:

1. **Resource lookup** – find relevant examples or API docs.
2. **Implement a minimal version** (end‑to‑end, even if incomplete).
3. **Test with actual Veilid nodes** (use `veilid-server` in test mode).
4. **Document decisions** (why a particular DHT schema, key rotation strategy, etc.).
5. **Review against security / privacy** implications (Veilid’s design).

## LLM‑Specific Meta‑Workflow

To make this methodology work for an LLM (which has a limited context window and no persistent memory across sessions):

- **Maintain a “state file”** – e.g., `progress.md` that records:
  - Which resources have been read.
  - Current code file contents.
  - Open questions / errors.
  - Next action.
- **Use retrieval‑augmented generation (RAG)** – before answering a coding question, explicitly run a “search” over the `resources.md` links using a tool or simulated lookup.
- **Break large tasks** into “one function per turn” to avoid context overflow.
- **Always quote the source** – when suggesting an API call, include a link to the exact `docs.rs` section or book chapter.

---

## Quick Reference: Common Veilid Patterns

| Task | Resource to consult |
|------|---------------------|
| Attach to network | `VeilidAPI::new()` + `api.attach()` – see Dev Book “Initialization” |
| Derive DHT key from string | `blake3::hash()` + `Key::from_bytes()` – check `veilid_core::Key` docs |
| Sign a value | `SafeKey::sign()` – see API docs on `SafeKey` |
| Store on DHT | `RoutingContext::dht_set()` – search `veilid-core` for `dht_set` |
| Subscribe to messages | `RoutingContext::subscribe()` – Dev Book “Subscriptions” |
| Run a local test network | `DEVELOPMENT.md` in GitLab – use `veilid-server --testnet` |

