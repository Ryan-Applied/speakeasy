//! Veilid node lifecycle, routing context, and crypto system access.
//!
//! Single integration point between veilid-chat and veilid-core.
//! No other module should import veilid_core directly.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::info;
use veilid_core::{
    self, BareMemberId, DHTRecordDescriptor, DHTSchema, KeyPair, RoutingContext,
    VeilidAPI, VeilidConfig, VeilidUpdate, CRYPTO_KIND_VLD0,
};

/// Network attachment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentState {
    Detached,
    Attaching,
    AttachedWeak,
    AttachedGood,
    AttachedStrong,
    FullyAttached,
    OverAttached,
    Detaching,
}

/// Configuration for the Veilid node.
pub struct NodeConfig {
    pub program_name: String,
    pub namespace: String,
    pub storage_dir: String,
    pub config_dir: String,
    /// Minimum safety route hop count. Higher = more privacy, more latency.
    /// GOV/MIL recommendation: 2 or higher.
    pub safety_route_hop_count: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            program_name: "veilid-chat".into(),
            namespace: "veilid-chat".into(),
            storage_dir: "./.veilid-chat/storage".into(),
            config_dir: "./.veilid-chat/config".into(),
            safety_route_hop_count: 2,
        }
    }
}

/// Core Veilid node wrapper. Provides access to all Veilid primitives
/// through a controlled interface.
pub struct VeilidNode {
    api: VeilidAPI,
    routing_ctx: RoutingContext,
    node_keypair: KeyPair,
    attachment_state: Arc<RwLock<AttachmentState>>,
    update_tx: broadcast::Sender<VeilidUpdate>,
    private_routes: Arc<Mutex<Vec<veilid_core::RouteId>>>,
}

impl VeilidNode {
    /// Start the Veilid node and attach to the network.
    pub async fn start(config: NodeConfig) -> Result<Self> {
        let (update_tx, _) = broadcast::channel(512);
        let tx_clone = update_tx.clone();
        let attachment_state = Arc::new(RwLock::new(AttachmentState::Detached));
        let attach_clone = attachment_state.clone();

        let update_callback: veilid_core::UpdateCallback =
            Arc::new(move |update: VeilidUpdate| {
                if let VeilidUpdate::Attachment(ref a) = update {
                    let state = match a.state {
                        veilid_core::AttachmentState::Detached => AttachmentState::Detached,
                        veilid_core::AttachmentState::Attaching => AttachmentState::Attaching,
                        veilid_core::AttachmentState::AttachedWeak => AttachmentState::AttachedWeak,
                        veilid_core::AttachmentState::AttachedGood => AttachmentState::AttachedGood,
                        veilid_core::AttachmentState::AttachedStrong => {
                            AttachmentState::AttachedStrong
                        }
                        veilid_core::AttachmentState::FullyAttached => {
                            AttachmentState::FullyAttached
                        }
                        veilid_core::AttachmentState::OverAttached => {
                            AttachmentState::OverAttached
                        }
                        veilid_core::AttachmentState::Detaching => AttachmentState::Detaching,
                    };
                    if let Ok(mut guard) = attach_clone.try_write() {
                        *guard = state;
                    }
                }
                let _ = tx_clone.send(update);
            });

        // Build VeilidConfig
        let mut veilid_config = VeilidConfig::new(
            &config.program_name,
            &config.namespace,
            "",
            Some(&config.storage_dir),
            Some(&config.config_dir),
        );
        // On Linux, the OS keyring (secret-service via D-Bus/zbus) creates a
        // nested tokio runtime that conflicts with ours. Use file-based
        // protected store instead. On macOS (Security.framework) and Windows
        // (Credential Manager) the keyring is synchronous and works fine.
        //
        // The file-based store is still encrypted with Argon2id — it just lives
        // in the filesystem rather than the OS keychain.
        #[cfg(target_os = "linux")]
        {
            veilid_config.protected_store.always_use_insecure_storage = true;
            info!("linux: using file-based protected store (D-Bus keyring bypass)");
        }
        #[cfg(not(target_os = "linux"))]
        {
            veilid_config.protected_store.always_use_insecure_storage = false;
        }

        info!("starting veilid node (namespace: {})", config.namespace);
        let api = veilid_core::api_startup(update_callback, veilid_config)
            .await
            .context("veilid api_startup failed")?;

        // Get the VLD0 crypto system to generate our identity keypair
        let crypto_holder = api
            .crypto()
            .context("failed to get crypto system")?;
        let cs = crypto_holder
            .get(CRYPTO_KIND_VLD0)
            .context("VLD0 crypto system not available")?;
        let node_keypair = cs.generate_keypair();
        drop(cs);
        drop(crypto_holder);

        // Create routing context with safety routing enabled
        let routing_ctx = api
            .routing_context()
            .context("failed to create routing context")?
            .with_safety(veilid_core::SafetySelection::Safe(
                veilid_core::SafetySpec {
                    preferred_route: None,
                    hop_count: config.safety_route_hop_count,
                    stability: veilid_core::Stability::Reliable,
                    sequencing: veilid_core::Sequencing::PreferOrdered,
                },
            ))
            .context("failed to configure safety routing")?;

        info!("node identity: {:?}", node_keypair.key());
        info!("safety route hops: {}", config.safety_route_hop_count);

        // Attach to the network
        api.attach().await.context("failed to attach to network")?;
        info!("attached to veilid network");

        Ok(Self {
            api,
            routing_ctx,
            node_keypair,
            attachment_state,
            update_tx,
            private_routes: Arc::new(Mutex::new(Vec::new())),
        })
    }

    // ── Crypto operations (raw bytes boundary) ────────────────────

    /// Generate a new Ed25519 keypair.
    pub fn generate_keypair(&self) -> KeyPair {
        let crypto = self.api.crypto().expect("crypto must be available");
        let cs = crypto.get(CRYPTO_KIND_VLD0).expect("VLD0 must be available");
        cs.generate_keypair()
    }

    /// Encrypt with XChaCha20-Poly1305 AEAD.
    pub fn encrypt_aead(
        &self,
        key: &veilid_core::SharedSecret,
        body: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<(veilid_core::Nonce, Vec<u8>)> {
        let crypto = self.api.crypto().context("crypto")?;
        let cs = crypto.get(CRYPTO_KIND_VLD0).context("VLD0")?;
        let nonce = cs.random_nonce();
        let ct = cs
            .encrypt_aead(body, &nonce, key, associated_data)
            .map_err(|e| anyhow::anyhow!("encrypt_aead: {}", e))?;
        Ok((nonce, ct))
    }

    /// Decrypt with XChaCha20-Poly1305 AEAD.
    pub fn decrypt_aead(
        &self,
        key: &veilid_core::SharedSecret,
        nonce: &veilid_core::Nonce,
        body: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let crypto = self.api.crypto().context("crypto")?;
        let cs = crypto.get(CRYPTO_KIND_VLD0).context("VLD0")?;
        cs.decrypt_aead(body, nonce, key, associated_data)
            .map_err(|e| anyhow::anyhow!("decrypt_aead: {}", e))
    }

    /// Sign data with Ed25519.
    pub fn sign(
        &self,
        key: &veilid_core::PublicKey,
        secret: &veilid_core::SecretKey,
        data: &[u8],
    ) -> Result<veilid_core::Signature> {
        let crypto = self.api.crypto().context("crypto")?;
        let cs = crypto.get(CRYPTO_KIND_VLD0).context("VLD0")?;
        cs.sign(key, secret, data)
            .map_err(|e| anyhow::anyhow!("sign: {}", e))
    }

    /// Verify an Ed25519 signature.
    pub fn verify(
        &self,
        key: &veilid_core::PublicKey,
        data: &[u8],
        signature: &veilid_core::Signature,
    ) -> Result<()> {
        let crypto = self.api.crypto().context("crypto")?;
        let cs = crypto.get(CRYPTO_KIND_VLD0).context("VLD0")?;
        let valid = cs
            .verify(key, data, signature)
            .map_err(|e| anyhow::anyhow!("verify: {}", e))?;
        if !valid {
            anyhow::bail!("signature verification failed");
        }
        Ok(())
    }

    /// Generate a random nonce.
    pub fn random_nonce(&self) -> veilid_core::Nonce {
        let crypto = self.api.crypto().expect("crypto available");
        let cs = crypto.get(CRYPTO_KIND_VLD0).expect("VLD0 available");
        cs.random_nonce()
    }

    /// Derive shared secret via X25519 DH.
    pub fn generate_shared_secret(
        &self,
        key: &veilid_core::PublicKey,
        secret: &veilid_core::SecretKey,
        domain: &[u8],
    ) -> Result<veilid_core::SharedSecret> {
        let crypto = self.api.crypto().context("crypto")?;
        let cs = crypto.get(CRYPTO_KIND_VLD0).context("VLD0")?;
        cs.generate_shared_secret(key, secret, domain)
            .map_err(|e| anyhow::anyhow!("DH: {}", e))
    }

    /// BLAKE3 hash.
    pub fn generate_hash(&self, data: &[u8]) -> veilid_core::HashDigest {
        let crypto = self.api.crypto().expect("crypto available");
        let cs = crypto.get(CRYPTO_KIND_VLD0).expect("VLD0 available");
        cs.generate_hash(data)
    }

    // ── DHT operations ─────────────────────────────────────────────

    /// Create a new DHT record with single-writer (DFLT) schema.
    pub async fn create_dht_record_default(&self) -> Result<DHTRecordDescriptor> {
        let schema = DHTSchema::dflt(1)
            .map_err(|e| anyhow::anyhow!("DHTSchema::dflt: {}", e))?;
        self.routing_ctx
            .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
            .await
            .map_err(|e| anyhow::anyhow!("create_dht_record: {}", e))
    }

    /// Create a DHT record with SMPL (multi-writer) schema.
    pub async fn create_dht_record_smpl(
        &self,
        member_count: u16,
        subkeys_per_member: u16,
    ) -> Result<DHTRecordDescriptor> {
        let bare_id = BareMemberId::new(&self.node_keypair.key().ref_value().bytes());
        let members: Vec<veilid_core::DHTSchemaSMPLMember> = (0..member_count)
            .map(|_| veilid_core::DHTSchemaSMPLMember {
                m_key: bare_id.clone(),
                m_cnt: subkeys_per_member,
            })
            .collect();
        let schema = DHTSchema::smpl(0, members)
            .map_err(|e| anyhow::anyhow!("DHTSchema::smpl: {}", e))?;
        self.routing_ctx
            .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
            .await
            .map_err(|e| anyhow::anyhow!("create_dht_record_smpl: {}", e))
    }

    /// Open an existing DHT record.
    pub async fn open_dht_record(
        &self,
        key: veilid_core::RecordKey,
        writer: Option<KeyPair>,
    ) -> Result<DHTRecordDescriptor> {
        self.routing_ctx
            .open_dht_record(key, writer)
            .await
            .map_err(|e| anyhow::anyhow!("open_dht_record: {}", e))
    }

    /// Close a DHT record.
    pub async fn close_dht_record(&self, key: veilid_core::RecordKey) -> Result<()> {
        self.routing_ctx
            .close_dht_record(key)
            .await
            .map_err(|e| anyhow::anyhow!("close_dht_record: {}", e))
    }

    /// Get a subkey value from a DHT record.
    pub async fn get_dht_value(
        &self,
        key: veilid_core::RecordKey,
        subkey: u32,
        force_refresh: bool,
    ) -> Result<Option<Vec<u8>>> {
        let result = self
            .routing_ctx
            .get_dht_value(key, subkey, force_refresh)
            .await
            .map_err(|e| anyhow::anyhow!("get_dht_value: {}", e))?;
        Ok(result.map(|v| v.data().to_vec()))
    }

    /// Set a subkey value on a DHT record.
    pub async fn set_dht_value(
        &self,
        key: veilid_core::RecordKey,
        subkey: u32,
        data: Vec<u8>,
        writer: Option<KeyPair>,
    ) -> Result<()> {
        let options = writer.map(|kp| veilid_core::SetDHTValueOptions {
            writer: Some(kp),
            ..Default::default()
        });
        self.routing_ctx
            .set_dht_value(key, subkey, data, options)
            .await
            .map_err(|e| anyhow::anyhow!("set_dht_value: {}", e))?;
        Ok(())
    }

    /// Watch a DHT record for changes. Returns true if watch was set.
    pub async fn watch_dht_record(
        &self,
        key: veilid_core::RecordKey,
        subkeys: Option<veilid_core::ValueSubkeyRangeSet>,
    ) -> Result<bool> {
        self.routing_ctx
            .watch_dht_values(key, subkeys, None, None)
            .await
            .map_err(|e| anyhow::anyhow!("watch_dht_values: {}", e))
    }

    // ── Private routes (receiver privacy) ──────────────────────────

    /// Allocate a new private route for receiving messages.
    /// Returns (route_id, route_blob) where route_blob is shareable.
    pub async fn allocate_private_route(
        &self,
    ) -> Result<(veilid_core::RouteId, Vec<u8>)> {
        let route_blob = self
            .api
            .new_private_route()
            .await
            .map_err(|e| anyhow::anyhow!("new_private_route: {}", e))?;

        let route_id = route_blob.route_id.clone();
        let blob = route_blob.blob;

        let mut routes = self.private_routes.lock().await;
        routes.push(route_blob.route_id);
        info!("allocated private route");

        Ok((route_id, blob))
    }

    /// Import a remote peer's private route from their route blob.
    pub fn import_remote_route(
        &self,
        blob: &[u8],
    ) -> Result<veilid_core::RouteId> {
        self.api
            .import_remote_private_route(blob.to_vec())
            .map_err(|e| anyhow::anyhow!("import_remote_private_route: {}", e))
    }

    /// Send an app_call (request/response) to a remote route.
    pub async fn app_call(
        &self,
        target: veilid_core::Target,
        message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if message.len() > 32768 {
            anyhow::bail!("app_call payload exceeds 32KB limit");
        }
        self.routing_ctx
            .app_call(target, message)
            .await
            .map_err(|e| anyhow::anyhow!("app_call: {}", e))
    }

    /// Send an app_message (fire-and-forget) to a remote route.
    pub async fn app_message(
        &self,
        target: veilid_core::Target,
        message: Vec<u8>,
    ) -> Result<()> {
        if message.len() > 32768 {
            anyhow::bail!("app_message payload exceeds 32KB limit");
        }
        self.routing_ctx
            .app_message(target, message)
            .await
            .map_err(|e| anyhow::anyhow!("app_message: {}", e))
    }

    // ── Protected store (identity key storage) ─────────────────────

    /// Save a secret to the Veilid ProtectedStore (synchronous).
    pub fn protected_store_save(&self, key: &str, value: &[u8]) -> Result<()> {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            value,
        );
        self.api
            .protected_store()
            .context("protected_store not available")?
            .save_user_secret_string(key, &encoded)
            .map_err(|e| anyhow::anyhow!("protected_store save: {}", e))?;
        Ok(())
    }

    /// Load a secret from the Veilid ProtectedStore (synchronous).
    pub fn protected_store_load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let result = self
            .api
            .protected_store()
            .context("protected_store not available")?
            .load_user_secret_string(key)
            .map_err(|e| anyhow::anyhow!("protected_store load: {}", e))?;
        match result {
            Some(encoded) => {
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &encoded,
                )
                .context("base64 decode from protected store")?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    // ── Table store (encrypted local persistence) ──────────────────

    /// Open the Veilid TableStore for encrypted local key-value storage.
    pub async fn open_table_store(
        &self,
        table_name: &str,
        column_count: u32,
    ) -> Result<veilid_core::TableDB> {
        self.api
            .table_store()
            .context("table_store not available")?
            .open(table_name, column_count)
            .await
            .map_err(|e| anyhow::anyhow!("open table_store: {}", e))
    }

    // ── Lifecycle ──────────────────────────────────────────────────

    /// Get current attachment state.
    pub async fn attachment_state(&self) -> AttachmentState {
        *self.attachment_state.read().await
    }

    /// Subscribe to Veilid updates.
    pub fn subscribe_updates(&self) -> broadcast::Receiver<VeilidUpdate> {
        self.update_tx.subscribe()
    }

    /// Get the node's keypair.
    pub fn keypair(&self) -> &KeyPair {
        &self.node_keypair
    }

    /// Graceful shutdown.
    pub async fn shutdown(self) -> Result<()> {
        info!("shutting down veilid node");
        let routes = self.private_routes.lock().await;
        for route_id in routes.iter() {
            let _ = self.api.release_private_route(route_id.clone());
        }
        drop(routes);

        self.api
            .detach()
            .await
            .map_err(|e| anyhow::anyhow!("detach: {}", e))?;
        self.api.shutdown().await;
        info!("veilid node shutdown complete");
        Ok(())
    }
}
