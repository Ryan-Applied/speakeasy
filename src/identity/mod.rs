//! Identity management for veilid-chat.
//!
//! Hardening status (vs SECURITY_AUDIT.md):
//! - CRITICAL #1 (placeholder keypair): FIXED. Uses real Ed25519 via
//!   `ed25519-dalek` so the public key is derived from the secret.
//! - CRITICAL #2 (plaintext secret on disk): FIXED when a `VeilidNode`
//!   is wired in via [`IdentityManager::with_protected_store`]. The
//!   secret then lives in Veilid's ProtectedStore (OS keychain / Argon2id
//!   encrypted store) and is never written to the identity file.
//!   When no node is provided, a loud warning is logged and the secret
//!   is omitted from the on-disk profile -- callers must re-derive or
//!   re-create the identity. There is NO plaintext-fallback path.

use crate::models::{PeerIdentity, UserIdentity};
use crate::veilid_node::VeilidNode;
use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tracing::{info, warn};
use zeroize::Zeroize;

/// Storage key under which the Ed25519 secret is filed in Veilid's
/// ProtectedStore. Versioned so we can rotate later.
const PROTECTED_STORE_SECRET_KEY: &str = "veilid-chat:identity:secret:v1";

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("identity file not found at {0}")]
    NotFound(PathBuf),
    #[error("identity file corrupted")]
    Corrupted,
    #[error("failed to generate keypair: {0}")]
    KeygenFailed(String),
    #[error("secret key not available -- ProtectedStore not wired or empty")]
    SecretUnavailable,
    #[error("storage error: {0}")]
    Storage(#[from] anyhow::Error),
}

/// On-disk profile (no secret material). The secret lives in ProtectedStore.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DiskProfile {
    public_key: Vec<u8>,
    display_name: String,
    avatar_hash: Option<Vec<u8>>,
    status: Option<String>,
    created_at: chrono::DateTime<Utc>,
    /// True if the secret is in ProtectedStore. False means the identity
    /// is observation-only (no signing key locally).
    secret_in_protected_store: bool,
}

/// Manages local user identity lifecycle.
pub struct IdentityManager {
    data_dir: PathBuf,
    identity: Option<UserIdentity>,
    /// Optional Veilid node handle. When set, secrets are persisted via
    /// the ProtectedStore; otherwise the secret never touches disk and
    /// callers must keep it in memory only for the session.
    node: Option<Arc<VeilidNode>>,
}

impl IdentityManager {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            data_dir: data_dir.as_ref().to_path_buf(),
            identity: None,
            node: None,
        }
    }

    /// Wire the Veilid node so secrets persist via ProtectedStore.
    /// Call this BEFORE create()/load() when secret persistence is desired.
    pub fn with_protected_store(mut self, node: Arc<VeilidNode>) -> Self {
        self.node = Some(node);
        self
    }

    /// Load existing identity from disk (and ProtectedStore for the secret,
    /// if a node is wired). Returns None when no profile exists yet.
    pub async fn load(&mut self) -> Result<Option<&UserIdentity>> {
        let path = self.identity_path();
        if !path.exists() {
            info!("no existing identity found at {}", path.display());
            return Ok(None);
        }

        let data = fs::read(&path).await.context("reading identity file")?;
        let profile: DiskProfile = rmp_serde::from_slice(&data)
            .map_err(|_| IdentityError::Corrupted)?;

        // Recover the secret.
        let secret_key = if profile.secret_in_protected_store {
            let node = self
                .node
                .as_ref()
                .context("identity profile expects ProtectedStore but no Veilid node is wired")?;
            node.protected_store_load(PROTECTED_STORE_SECRET_KEY)?
                .ok_or(IdentityError::SecretUnavailable)?
        } else {
            warn!(
                "loaded identity {} has no secret available -- signing operations will fail",
                hex_short(&profile.public_key)
            );
            Vec::new()
        };

        let identity = UserIdentity {
            public_key: profile.public_key,
            secret_key,
            display_name: profile.display_name,
            avatar_hash: profile.avatar_hash,
            status: profile.status,
            created_at: profile.created_at,
        };

        info!(
            "loaded identity: {} (key: {})",
            identity.display_name,
            hex_short(&identity.public_key)
        );
        self.identity = Some(identity);
        Ok(self.identity.as_ref())
    }

    /// Generate a NEW Ed25519 identity. When a VeilidNode is available, uses
    /// veilid-core's crypto system so the keypair is compatible with node.sign().
    /// Falls back to ed25519-dalek for standalone/test use.
    pub async fn create(&mut self, display_name: &str) -> Result<&UserIdentity> {
        info!("generating new Ed25519 identity for '{}'", display_name);

        let (public_key, mut secret_seed): (Vec<u8>, [u8; 32]) =
            if let Some(ref node) = self.node {
                // Use veilid-core's crypto so keypair is compatible with node.sign()
                let kp = node.generate_keypair();
                let pk = kp.key().ref_value().bytes().to_vec();
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&kp.secret().ref_value().bytes());
                info!("identity keypair generated via veilid-core");
                (pk, sk)
            } else {
                // Standalone: ed25519-dalek (for tests without a VeilidNode)
                let signing_key = SigningKey::generate(&mut OsRng);
                let pk = signing_key.verifying_key().to_bytes().to_vec();
                let sk = signing_key.to_bytes();
                (pk, sk)
            };

        // Persist secret (if ProtectedStore wired) BEFORE writing the disk
        // profile -- if ProtectedStore save fails we don't want a profile
        // pointing to a secret that isn't there.
        let secret_in_ps = if let Some(node) = self.node.clone() {
            node.protected_store_save(PROTECTED_STORE_SECRET_KEY, &secret_seed)
                .context("saving identity secret to ProtectedStore")?;
            true
        } else {
            warn!(
                "no Veilid ProtectedStore wired -- identity secret will be \
                 in-memory only for this session and lost on restart"
            );
            false
        };

        // Write the disk profile (no secret).
        let profile = DiskProfile {
            public_key: public_key.clone(),
            display_name: display_name.to_string(),
            avatar_hash: None,
            status: None,
            created_at: Utc::now(),
            secret_in_protected_store: secret_in_ps,
        };
        self.write_profile(&profile).await?;

        let identity = UserIdentity {
            public_key,
            secret_key: secret_seed.to_vec(),
            display_name: display_name.to_string(),
            avatar_hash: None,
            status: None,
            created_at: profile.created_at,
        };
        // Zero the local copy of the seed -- the only remaining reference
        // is inside `identity.secret_key` which lives until IdentityManager
        // is dropped.
        secret_seed.zeroize();

        self.identity = Some(identity);
        Ok(self.identity.as_ref().unwrap())
    }

    /// Get the current identity, if loaded.
    pub fn current(&self) -> Option<&UserIdentity> {
        self.identity.as_ref()
    }

    /// Get the public-only view suitable for sharing.
    pub fn public_identity(&self) -> Option<PeerIdentity> {
        self.identity.as_ref().map(|id| PeerIdentity {
            public_key: id.public_key.clone(),
            display_name: id.display_name.clone(),
            avatar_hash: id.avatar_hash.clone(),
            status: id.status.clone(),
        })
    }

    /// Update the display name and rewrite the disk profile.
    pub async fn set_display_name(&mut self, name: &str) -> Result<()> {
        let profile = {
            let has_node = self.node.is_some();
            if let Some(ref mut id) = self.identity {
                id.display_name = name.to_string();
                Some(Self::profile_from(id, has_node))
            } else {
                None
            }
        };
        if let Some(p) = profile {
            self.write_profile(&p).await?;
        }
        Ok(())
    }

    /// Update the status message and rewrite the disk profile.
    pub async fn set_status(&mut self, status: Option<&str>) -> Result<()> {
        let profile = {
            let has_node = self.node.is_some();
            if let Some(ref mut id) = self.identity {
                id.status = status.map(|s| s.to_string());
                Some(Self::profile_from(id, has_node))
            } else {
                None
            }
        };
        if let Some(p) = profile {
            self.write_profile(&p).await?;
        }
        Ok(())
    }

    /// Compute the 8-byte fingerprint for this identity.
    pub fn fingerprint(&self) -> Option<[u8; 8]> {
        self.identity.as_ref().map(|id| {
            let hash = blake3::hash(&id.public_key);
            let mut fp = [0u8; 8];
            fp.copy_from_slice(&hash.as_bytes()[..8]);
            fp
        })
    }

    // -- Private helpers --

    fn identity_path(&self) -> PathBuf {
        self.data_dir.join("identity.bin")
    }

    fn profile_from(id: &UserIdentity, secret_in_ps: bool) -> DiskProfile {
        DiskProfile {
            public_key: id.public_key.clone(),
            display_name: id.display_name.clone(),
            avatar_hash: id.avatar_hash.clone(),
            status: id.status.clone(),
            created_at: id.created_at,
            secret_in_protected_store: secret_in_ps,
        }
    }

    async fn write_profile(&self, profile: &DiskProfile) -> Result<()> {
        fs::create_dir_all(&self.data_dir)
            .await
            .context("creating data directory")?;

        let data = rmp_serde::to_vec(profile).context("serializing identity profile")?;
        fs::write(self.identity_path(), &data)
            .await
            .context("writing identity profile")?;

        info!("identity profile saved to {}", self.identity_path().display());
        Ok(())
    }
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Signature, Verifier};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_create_identity_uses_real_ed25519() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = IdentityManager::new(tmp.path());

        let id = mgr.create("alice").await.unwrap();
        assert_eq!(id.display_name, "alice");
        assert_eq!(id.public_key.len(), 32);
        assert_eq!(id.secret_key.len(), 32);

        // Ed25519 invariant: signing with the secret produces a signature
        // that verifies under the derived public key. The pre-audit
        // placeholder failed this because public was a fresh random buffer.
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&id.secret_key);
        let sk = SigningKey::from_bytes(&seed);
        let derived_pk = sk.verifying_key().to_bytes();
        assert_eq!(derived_pk.as_slice(), id.public_key.as_slice(),
            "public key MUST be derived from secret per Ed25519");

        let sig: Signature = sk.sign(b"test");
        let vk = sk.verifying_key();
        assert!(vk.verify(b"test", &sig).is_ok());
    }

    #[tokio::test]
    async fn test_load_without_protected_store_returns_no_secret() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = IdentityManager::new(tmp.path());
        mgr.create("alice").await.unwrap();

        // Reload without ProtectedStore: profile is on disk, secret is gone.
        let mut mgr2 = IdentityManager::new(tmp.path());
        let loaded = mgr2.load().await.unwrap().expect("profile should load");
        assert_eq!(loaded.display_name, "alice");
        assert!(
            loaded.secret_key.is_empty(),
            "secret must NOT be on disk without ProtectedStore"
        );
    }

    #[tokio::test]
    async fn test_no_plaintext_secret_on_disk() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = IdentityManager::new(tmp.path());
        let id = mgr.create("alice").await.unwrap();
        let secret_copy = id.secret_key.clone();

        // Read the raw identity file and prove the secret bytes are absent.
        let raw = std::fs::read(tmp.path().join("identity.bin")).unwrap();
        let needle = secret_copy.as_slice();
        assert!(
            raw.windows(needle.len()).all(|w| w != needle),
            "secret bytes leaked to disk"
        );
    }

    #[tokio::test]
    async fn test_fingerprint() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = IdentityManager::new(tmp.path());
        mgr.create("bob").await.unwrap();
        let fp = mgr.fingerprint().unwrap();
        assert_eq!(fp.len(), 8);
    }
}
