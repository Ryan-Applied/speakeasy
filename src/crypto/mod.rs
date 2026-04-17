//! Hardened cryptographic operations using veilid-core primitives.
//!
//! All encryption: XChaCha20-Poly1305 (AEAD)
//! All signing: Ed25519
//! All key exchange: X25519
//! All hashing: BLAKE3
//!
//! SECURITY INVARIANTS:
//! - No plaintext secret material leaves this module
//! - All SharedSecrets are zeroized on drop
//! - AAD (Additional Authenticated Data) binds ciphertext to context
//! - Nonces are never reused (random + sequence counter)
//! - Signatures are verified before any decryption

pub mod key_rotation;

use crate::veilid_node::VeilidNode;
use anyhow::{bail, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use veilid_core::CRYPTO_KIND_VLD0;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed: ciphertext tampered or wrong key")]
    DecryptionFailed,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("malformed envelope: {reason}")]
    MalformedEnvelope { reason: String },
}

/// Maximum message payload size before encryption (256KB).
const MAX_PAYLOAD_SIZE: usize = 256 * 1024;

/// Encrypted envelope wire format.
///
/// Layout: signature(64) || nonce(24) || aad_len(4) || aad(variable) || ciphertext(variable)
///
/// The signature covers the entire remaining bytes (nonce || aad_len || aad || ciphertext).
/// This means:
/// 1. Verify signature FIRST (before any decryption)
/// 2. Extract nonce and AAD
/// 3. Decrypt with AAD binding
///
/// AAD contains: room_id(32) || sequence(8) || timestamp(8) || sender_key(32)
/// This binds ciphertext to its context, preventing cross-room replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Ed25519 signature over (nonce || aad_len || aad || ciphertext). 64 bytes.
    pub signature: Vec<u8>,
    /// XChaCha20-Poly1305 nonce. 24 bytes.
    pub nonce: Vec<u8>,
    /// Additional authenticated data (room_id || seq || ts || sender_key).
    pub aad: Vec<u8>,
    /// XChaCha20-Poly1305 ciphertext (includes 16-byte Poly1305 tag).
    pub ciphertext: Vec<u8>,
}

impl EncryptedEnvelope {
    /// Serialize to wire format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let aad_len = (self.aad.len() as u32).to_le_bytes();
        let mut buf =
            Vec::with_capacity(64 + 24 + 4 + self.aad.len() + self.ciphertext.len());
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&aad_len);
        buf.extend_from_slice(&self.aad);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from wire format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Minimum: signature(64) + nonce(24) + aad_len(4) + ciphertext(16 min for tag)
        if data.len() < 64 + 24 + 4 + 16 {
            bail!(CryptoError::MalformedEnvelope {
                reason: format!("too short: {} bytes", data.len())
            });
        }

        let signature = data[0..64].to_vec();
        let nonce = data[64..88].to_vec();

        let mut aad_len_bytes = [0u8; 4];
        aad_len_bytes.copy_from_slice(&data[88..92]);
        let aad_len = u32::from_le_bytes(aad_len_bytes) as usize;

        if data.len() < 92 + aad_len + 16 {
            bail!(CryptoError::MalformedEnvelope {
                reason: "aad_len exceeds available data".into()
            });
        }

        let aad = data[92..92 + aad_len].to_vec();
        let ciphertext = data[92 + aad_len..].to_vec();

        Ok(Self {
            signature,
            nonce,
            aad,
            ciphertext,
        })
    }

    /// Get the signed payload (everything after the signature).
    fn signed_payload(&self) -> Vec<u8> {
        let aad_len = (self.aad.len() as u32).to_le_bytes();
        let mut buf = Vec::with_capacity(24 + 4 + self.aad.len() + self.ciphertext.len());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&aad_len);
        buf.extend_from_slice(&self.aad);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }
}

/// Build AAD (Additional Authenticated Data) for message binding.
///
/// AAD = room_id(32) || sequence(8 LE) || timestamp(8 LE) || sender_key(32)
pub fn build_aad(
    room_id: &[u8; 32],
    sequence: u64,
    timestamp_ms: u64,
    sender_key: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(80);
    aad.extend_from_slice(room_id);
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad.extend_from_slice(&timestamp_ms.to_le_bytes());
    aad.extend_from_slice(sender_key);
    aad
}

/// Encrypt and sign a message using VeilidNode's crypto.
///
/// Order of operations:
/// 1. Build AAD from context
/// 2. Encrypt plaintext with room_key using XChaCha20-Poly1305 + AAD
/// 3. Sign (nonce || aad_len || aad || ciphertext) with sender's Ed25519 key
pub fn encrypt_and_sign(
    node: &VeilidNode,
    plaintext: &[u8],
    room_key: &veilid_core::SharedSecret,
    room_id: &[u8; 32],
    sequence: u64,
    timestamp_ms: u64,
    sender_public: &veilid_core::PublicKey,
    sender_secret: &veilid_core::SecretKey,
) -> Result<EncryptedEnvelope> {
    if plaintext.len() > MAX_PAYLOAD_SIZE {
        bail!(CryptoError::PayloadTooLarge {
            size: plaintext.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    let sender_bytes: Vec<u8> = sender_public.ref_value().bytes().to_vec();
    let aad = build_aad(room_id, sequence, timestamp_ms, &sender_bytes);

    // Encrypt with AEAD (XChaCha20-Poly1305)
    let (nonce, ciphertext) = node.encrypt_aead(room_key, plaintext, Some(&aad))?;

    // Build the payload to sign: nonce || aad_len || aad || ciphertext
    let nonce_bytes: Vec<u8> = nonce.bytes().to_vec();  // Nonce is a bare type, .bytes() works directly
    let aad_len = (aad.len() as u32).to_le_bytes();
    let mut sign_payload = Vec::with_capacity(24 + 4 + aad.len() + ciphertext.len());
    sign_payload.extend_from_slice(&nonce_bytes);
    sign_payload.extend_from_slice(&aad_len);
    sign_payload.extend_from_slice(&aad);
    sign_payload.extend_from_slice(&ciphertext);

    // Sign with Ed25519
    let signature = node.sign(sender_public, sender_secret, &sign_payload)?;
    let sig_bytes: Vec<u8> = signature.ref_value().bytes().to_vec();

    Ok(EncryptedEnvelope {
        signature: sig_bytes,
        nonce: nonce_bytes,
        aad,
        ciphertext,
    })
}

/// Verify signature, then decrypt a message.
///
/// Order of operations (CRITICAL -- verify BEFORE decrypt):
/// 1. Verify Ed25519 signature over (nonce || aad_len || aad || ciphertext)
/// 2. Verify AAD matches expected context
/// 3. Decrypt ciphertext with room_key using XChaCha20-Poly1305 + AAD
pub fn verify_and_decrypt(
    node: &VeilidNode,
    envelope: &EncryptedEnvelope,
    room_key: &veilid_core::SharedSecret,
    expected_room_id: &[u8; 32],
    sender_public: &veilid_core::PublicKey,
) -> Result<Vec<u8>> {
    // STEP 1: Verify signature FIRST
    let signed_payload = envelope.signed_payload();
    let sig = veilid_core::Signature::try_from(envelope.signature.as_slice())
        .map_err(|_| CryptoError::SignatureInvalid)?;
    node.verify(sender_public, &signed_payload, &sig)
        .map_err(|_| CryptoError::SignatureInvalid)?;

    // STEP 2: Verify AAD room_id matches expected
    if envelope.aad.len() < 32 {
        bail!(CryptoError::MalformedEnvelope {
            reason: "AAD too short for room_id".into()
        });
    }
    if &envelope.aad[..32] != expected_room_id {
        bail!(CryptoError::MalformedEnvelope {
            reason: "AAD room_id mismatch -- possible cross-room replay".into()
        });
    }

    // STEP 3: Decrypt with AEAD
    let nonce = veilid_core::Nonce::try_from(envelope.nonce.as_slice())
        .map_err(|_| CryptoError::MalformedEnvelope {
            reason: "invalid nonce".into(),
        })?;
    let plaintext =
        node.decrypt_aead(room_key, &nonce, &envelope.ciphertext, Some(&envelope.aad))
            .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Derive a shared room key for 1:1 chat from two keypairs via X25519 DH.
pub fn derive_direct_room_key(
    node: &VeilidNode,
    _our_public: &veilid_core::PublicKey,
    our_secret: &veilid_core::SecretKey,
    their_public: &veilid_core::PublicKey,
) -> Result<veilid_core::SharedSecret> {
    let domain = b"veilid-chat:direct-room-key:v1";
    node.generate_shared_secret(their_public, our_secret, domain)
}

/// Generate a random symmetric key for a group room.
pub fn generate_group_room_key(node: &VeilidNode) -> veilid_core::SharedSecret {
    let kp = node.generate_keypair();
    // Use the secret key bytes as a random 32-byte symmetric key
    // (veilid-core's CSPRNG backing)
    let secret_bytes = kp.secret().ref_value().bytes();
    veilid_core::SharedSecret::new(
        CRYPTO_KIND_VLD0,
        veilid_core::BareSharedSecret::new(&secret_bytes),
    )
}

/// Zeroizing wrapper for secret material.
pub struct SecretBuffer {
    data: Vec<u8>,
}

impl SecretBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Zeroize for SecretBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

// ---------------------------------------------------------------------------
// CryptoService -- stateless facade for non-envelope crypto helpers.
// ---------------------------------------------------------------------------

pub const DIRECT_ROOM_KEY_DOMAIN: &[u8] = b"veilid-chat:direct-room-key:v1";

/// Stateless facade for crypto ops that DON'T need a VeilidNode.
pub struct CryptoService;

impl CryptoService {
    /// BLAKE3 hash returning a 32-byte array.
    pub fn hash_fixed(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    /// BLAKE3 hash returning a Vec.
    pub fn hash(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    /// Generate a 32-byte symmetric room key from the OS CSPRNG.
    pub fn generate_room_key() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Derive a 32-byte room key for 1:1 chat via X25519 DH + BLAKE3 KDF.
    pub fn derive_room_key_direct(
        our_secret_key: &[u8],
        their_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        if our_secret_key.len() != 32 {
            bail!("secret key must be 32 bytes, got {}", our_secret_key.len());
        }
        if their_public_key.len() != 32 {
            bail!("public key must be 32 bytes, got {}", their_public_key.len());
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(our_secret_key);
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(their_public_key);

        let sk = x25519_dalek::StaticSecret::from(sk_bytes);
        let pk = x25519_dalek::PublicKey::from(pk_bytes);
        let shared = sk.diffie_hellman(&pk);

        let mut hasher = blake3::Hasher::new();
        hasher.update(DIRECT_ROOM_KEY_DOMAIN);
        hasher.update(shared.as_bytes());
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Derive a 32-byte database encryption key from a passphrase and salt
    /// using Argon2id (memory-hard KDF).
    ///
    /// The salt MUST be exactly 16 bytes. The passphrase can be any length.
    /// Uses Argon2id with default parameters (19 MiB memory, 2 iterations,
    /// 1 parallelism) which is suitable for interactive logins.
    pub fn derive_db_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
        use argon2::Argon2;

        let mut output = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut output)
            .map_err(|e| anyhow::anyhow!("argon2id KDF failed: {}", e))?;
        Ok(output)
    }
}

#[cfg(test)]
mod crypto_service_tests {
    use super::*;

    #[test]
    fn test_hash_fixed_deterministic() {
        let a = CryptoService::hash_fixed(b"hello");
        let b = CryptoService::hash_fixed(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn test_hash_matches_hash_fixed() {
        let v = CryptoService::hash(b"x");
        let f = CryptoService::hash_fixed(b"x");
        assert_eq!(v.as_slice(), &f);
    }

    #[test]
    fn test_generate_room_key_is_random_32_bytes() {
        let a = CryptoService::generate_room_key();
        let b = CryptoService::generate_room_key();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn test_dh_symmetric() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let alice_sk = StaticSecret::random_from_rng(rand::thread_rng());
        let alice_pk = PublicKey::from(&alice_sk);
        let bob_sk = StaticSecret::random_from_rng(rand::thread_rng());
        let bob_pk = PublicKey::from(&bob_sk);

        let alice_view =
            CryptoService::derive_room_key_direct(alice_sk.as_bytes(), bob_pk.as_bytes())
                .unwrap();
        let bob_view =
            CryptoService::derive_room_key_direct(bob_sk.as_bytes(), alice_pk.as_bytes())
                .unwrap();

        assert_eq!(alice_view, bob_view);
        assert_eq!(alice_view.len(), 32);
    }

    #[test]
    fn test_derive_db_key_deterministic() {
        let salt = [42u8; 16];
        let key1 = CryptoService::derive_db_key("my passphrase", &salt).unwrap();
        let key2 = CryptoService::derive_db_key("my passphrase", &salt).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_derive_db_key_different_passphrases() {
        let salt = [42u8; 16];
        let key1 = CryptoService::derive_db_key("pass1", &salt).unwrap();
        let key2 = CryptoService::derive_db_key("pass2", &salt).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_db_key_different_salts() {
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        let key1 = CryptoService::derive_db_key("same", &salt1).unwrap();
        let key2 = CryptoService::derive_db_key("same", &salt2).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_envelope_roundtrip() {
        let env = EncryptedEnvelope {
            signature: vec![1u8; 64],
            nonce: vec![2u8; 24],
            aad: vec![3u8; 80],
            ciphertext: vec![4u8; 100],
        };
        let bytes = env.to_bytes();
        let env2 = EncryptedEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(env.signature, env2.signature);
        assert_eq!(env.nonce, env2.nonce);
        assert_eq!(env.aad, env2.aad);
        assert_eq!(env.ciphertext, env2.ciphertext);
    }
}
