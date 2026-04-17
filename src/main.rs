use anyhow::Result;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use veilid_chat::chat::ChatService;
use veilid_chat::dht::VeilidDht;
use veilid_chat::identity::IdentityManager;
use veilid_chat::storage::LocalStorage;

use veilid_chat::veilid_node::{NodeConfig, VeilidNode};

#[tokio::main]
async fn main() -> Result<()> {
    // Log to file so it doesn't clobber the TUI.
    let log_dir = dirs_data_dir();
    std::fs::create_dir_all(&log_dir)?;
    let log_file = std::fs::File::create(log_dir.join("veilid-chat.log"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(log_file)
        .with_ansi(false)
        .init();

    info!("veilid-chat v{}", env!("CARGO_PKG_VERSION"));

    // Determine data directory
    let data_dir = dirs_data_dir();
    std::fs::create_dir_all(&data_dir)?;
    info!("data directory: {}", data_dir.display());

    // ── Start Veilid node ────────────────────────────────────────
    let storage_dir = data_dir.join("veilid");
    std::fs::create_dir_all(&storage_dir)?;

    let node_config = NodeConfig {
        storage_dir: storage_dir.to_string_lossy().to_string(),
        config_dir: storage_dir.to_string_lossy().to_string(),
        ..Default::default()
    };

    let node = Arc::new(VeilidNode::start(node_config).await?);
    info!("veilid node started");

    // ── Initialize identity (with ProtectedStore) ────────────────
    let mut identity_mgr =
        IdentityManager::new(&data_dir).with_protected_store(node.clone());

    if identity_mgr.load().await?.is_none() {
        identity_mgr.create("veilid-user").await?;
    }
    let identity = identity_mgr.current().unwrap().clone();
    info!("identity: {}", identity.display_name);

    // ── Initialize local storage ─────────────────────────────────
    let db_path = data_dir.join("veilid-chat.db");
    let storage = if let Ok(hex_key) = std::env::var("VEILID_CHAT_DB_KEY") {
        let key_bytes = hex_decode(&hex_key)?;
        LocalStorage::open_encrypted(&db_path, &key_bytes)?
    } else {
        // Passphrase-based KDF path: check for salt file.
        // NOTE: passphrase prompt happens BEFORE entering raw mode for TUI.
        let salt_path = data_dir.join("db.salt");
        if salt_path.exists() {
            // Existing salt -- prompt for passphrase
            eprint!("Enter database passphrase: ");
            let mut passphrase = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut passphrase)?;
            let passphrase = passphrase.trim_end();
            let salt_bytes = std::fs::read(&salt_path)?;
            if salt_bytes.len() != 16 {
                anyhow::bail!("salt file is corrupted (expected 16 bytes, got {})", salt_bytes.len());
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&salt_bytes);
            let key = veilid_chat::crypto::CryptoService::derive_db_key(passphrase, &salt)?;
            LocalStorage::open_encrypted(&db_path, &key)?
        } else if !db_path.exists() {
            // No salt file and no existing DB -- generate salt, prompt for new passphrase
            use rand::RngCore;
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            std::fs::write(&salt_path, &salt)?;
            info!("generated new DB salt at {}", salt_path.display());

            eprint!("Set database passphrase (or press Enter for unencrypted): ");
            let mut passphrase = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut passphrase)?;
            let passphrase = passphrase.trim_end();

            if passphrase.is_empty() {
                // User chose no passphrase -- remove salt, open unencrypted
                let _ = std::fs::remove_file(&salt_path);
                LocalStorage::open(&db_path)?
            } else {
                let key = veilid_chat::crypto::CryptoService::derive_db_key(passphrase, &salt)?;
                LocalStorage::open_encrypted(&db_path, &key)?
            }
        } else {
            // Existing DB but no salt file -- open unencrypted (legacy)
            LocalStorage::open(&db_path)?
        }
    };

    // ── Wire up services ─────────────────────────────────────────
    let _dht = VeilidDht::new(node.clone());
    let chat = ChatService::with_node(storage, node.clone());

    // ── Launch the terminal UI ───────────────────────────────────
    info!("launching TUI");
    veilid_chat::tui::run(chat, identity)?;
    info!("TUI exited");

    // ── Shutdown ─────────────────────────────────────────────────
    match Arc::try_unwrap(node) {
        Ok(n) => n.shutdown().await?,
        Err(_) => info!("skipping graceful shutdown: other references still held"),
    }

    Ok(())
}

fn dirs_data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("VEILID_CHAT_DATA") {
        std::path::PathBuf::from(dir)
    } else if let Some(dir) = dirs::data_local_dir() {
        dir.join("veilid-chat")
    } else {
        std::path::PathBuf::from("./data")
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        anyhow::bail!("hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("hex decode: {}", e))
        })
        .collect()
}

mod dirs {
    pub fn data_local_dir() -> Option<std::path::PathBuf> {
        std::env::var("HOME")
            .ok()
            .map(|h| std::path::PathBuf::from(h).join(".local").join("share"))
    }
}
