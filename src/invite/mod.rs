use crate::models::{ChatInvite, InviteType};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

const INVITE_PREFIX: &str = "vc1:";
const CURRENT_VERSION: u8 = 1;

#[derive(Error, Debug)]
pub enum InviteError {
    #[error("invalid invite prefix")]
    InvalidPrefix,
    #[error("unsupported invite version: {0}")]
    UnsupportedVersion(u8),
    #[error("invite has expired")]
    Expired,
    #[error("invite signature invalid")]
    SignatureInvalid,
    #[error("decode error: {0}")]
    DecodeError(String),
}

/// Create, encode, decode, and validate chat invites.
pub struct InviteService;

impl InviteService {
    /// Create an invite for a room.
    pub fn create_room_invite(
        room_id: [u8; 32],
        dht_record_key: Vec<u8>,
        room_name: Option<String>,
        creator_public_key: Vec<u8>,
        creator_secret_key: &[u8],
        bootstrap_route: Option<Vec<u8>>,
        expires_in_secs: Option<u64>,
    ) -> Result<ChatInvite> {
        let now = chrono::Utc::now().timestamp() as u64;
        let expires_at = expires_in_secs.map(|s| now + s);

        let mut invite = ChatInvite {
            version: CURRENT_VERSION,
            invite_type: InviteType::Room,
            room_id,
            dht_record_key,
            bootstrap_route,
            room_name,
            creator_public_key: creator_public_key.clone(),
            created_at: now,
            expires_at,
            signature: Vec::new(), // filled below
        };

        invite.signature = Self::sign_invite(&invite, creator_secret_key)?;
        Ok(invite)
    }

    /// Create a direct 1:1 contact invite.
    pub fn create_direct_invite(
        creator_public_key: Vec<u8>,
        creator_secret_key: &[u8],
        bootstrap_route: Option<Vec<u8>>,
        expires_in_secs: Option<u64>,
    ) -> Result<ChatInvite> {
        let now = chrono::Utc::now().timestamp() as u64;

        let mut invite = ChatInvite {
            version: CURRENT_VERSION,
            invite_type: InviteType::Direct,
            room_id: [0u8; 32],
            dht_record_key: Vec::new(),
            bootstrap_route,
            room_name: None,
            creator_public_key: creator_public_key.clone(),
            created_at: now,
            expires_at: expires_in_secs.map(|s| now + s),
            signature: Vec::new(),
        };

        invite.signature = Self::sign_invite(&invite, creator_secret_key)?;
        Ok(invite)
    }

    /// Encode an invite as a portable string: `vc1:<base64url>`
    pub fn encode_to_string(invite: &ChatInvite) -> Result<String> {
        let bytes = rmp_serde::to_vec(invite)
            .context("serializing invite")?;
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        Ok(format!("{}{}", INVITE_PREFIX, encoded))
    }

    /// Decode an invite from a string.
    pub fn decode_from_string(s: &str) -> Result<ChatInvite> {
        let s = s.trim();
        if !s.starts_with(INVITE_PREFIX) {
            bail!(InviteError::InvalidPrefix);
        }
        let encoded = &s[INVITE_PREFIX.len()..];
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| InviteError::DecodeError(e.to_string()))?;
        let invite: ChatInvite = rmp_serde::from_slice(&bytes)
            .map_err(|e| InviteError::DecodeError(e.to_string()))?;

        if invite.version != CURRENT_VERSION {
            bail!(InviteError::UnsupportedVersion(invite.version));
        }

        Ok(invite)
    }

    /// Encode an invite as raw bytes (for QR code).
    pub fn encode_to_bytes(invite: &ChatInvite) -> Result<Vec<u8>> {
        rmp_serde::to_vec(invite).context("serializing invite")
    }

    /// Validate an invite: check version, check expiry, verify Ed25519
    /// signature against `creator_public_key`. Audit MEDIUM finding fix.
    pub fn validate(invite: &ChatInvite) -> Result<()> {
        // Check version
        if invite.version != CURRENT_VERSION {
            bail!(InviteError::UnsupportedVersion(invite.version));
        }

        // Check expiry
        if let Some(expires) = invite.expires_at {
            let now = chrono::Utc::now().timestamp() as u64;
            if now > expires {
                bail!(InviteError::Expired);
            }
        }

        // Verify Ed25519 signature over canonical signable bytes.
        if invite.signature.len() != 64 {
            bail!(InviteError::SignatureInvalid);
        }
        if invite.creator_public_key.len() != 32 {
            bail!(InviteError::SignatureInvalid);
        }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&invite.creator_public_key);
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| InviteError::SignatureInvalid)?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&invite.signature);
        let signature = DalekSignature::from_bytes(&sig_bytes);

        let signable = Self::signable_bytes(invite)?;
        verifying_key
            .verify(&signable, &signature)
            .map_err(|_| InviteError::SignatureInvalid)?;

        Ok(())
    }

    // -- Private helpers --

    /// Compute the bytes that get signed (all fields except the signature itself).
    fn signable_bytes(invite: &ChatInvite) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.push(invite.version);
        buf.push(invite.invite_type as u8);
        buf.extend_from_slice(&invite.room_id);
        buf.extend_from_slice(&invite.dht_record_key);
        if let Some(ref route) = invite.bootstrap_route {
            buf.extend_from_slice(route);
        }
        if let Some(ref name) = invite.room_name {
            buf.extend_from_slice(name.as_bytes());
        }
        buf.extend_from_slice(&invite.creator_public_key);
        buf.extend_from_slice(&invite.created_at.to_le_bytes());
        if let Some(exp) = invite.expires_at {
            buf.extend_from_slice(&exp.to_le_bytes());
        }
        Ok(buf)
    }

    /// Sign with Ed25519 over canonical signable bytes. Replaces the
    /// pre-audit blake3-MAC placeholder.
    fn sign_invite(invite: &ChatInvite, secret_key: &[u8]) -> Result<Vec<u8>> {
        if secret_key.len() != 32 {
            bail!(
                "sign_invite: ed25519 secret seed must be 32 bytes, got {}",
                secret_key.len()
            );
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(secret_key);
        let signing_key = SigningKey::from_bytes(&seed);

        let signable = Self::signable_bytes(invite)?;
        let signature: DalekSignature = signing_key.sign(&signable);
        Ok(signature.to_bytes().to_vec())
    }
}

/// QR code generation for invites.
pub struct QrService;

impl QrService {
    /// Generate a QR code as SVG string from an invite.
    pub fn generate_svg(invite: &ChatInvite) -> Result<String> {
        let invite_string = InviteService::encode_to_string(invite)?;
        let code = qrcode::QrCode::new(invite_string.as_bytes())
            .context("generating QR code")?;
        let svg = code.render::<qrcode::render::svg::Color>()
            .min_dimensions(256, 256)
            .quiet_zone(true)
            .build();
        Ok(svg)
    }

    /// Generate a QR code as PNG bytes from an invite.
    pub fn generate_png(invite: &ChatInvite, size: u32) -> Result<Vec<u8>> {
        let invite_string = InviteService::encode_to_string(invite)?;
        let code = qrcode::QrCode::new(invite_string.as_bytes())
            .context("generating QR code")?;

        let image = code.render::<image::Luma<u8>>()
            .min_dimensions(size, size)
            .quiet_zone(true)
            .build();

        let mut png_bytes = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut png_bytes);
        image::DynamicImage::ImageLuma8(image)
            .write_to(&mut cursor, image::ImageFormat::Png)
            .context("encoding PNG")?;

        Ok(png_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Generate a real Ed25519 keypair so verify() actually has a chance.
    fn test_keys() -> (Vec<u8>, Vec<u8>) {
        let signing = SigningKey::generate(&mut OsRng);
        let pk = signing.verifying_key().to_bytes().to_vec();
        let sk = signing.to_bytes().to_vec();
        (pk, sk)
    }

    #[test]
    fn test_create_room_invite() {
        let (pk, sk) = test_keys();
        let invite = InviteService::create_room_invite(
            [42u8; 32], vec![3u8; 36], Some("test room".into()),
            pk, &sk, None, Some(3600),
        ).unwrap();

        assert_eq!(invite.version, 1);
        assert_eq!(invite.invite_type, InviteType::Room);
        assert_eq!(invite.signature.len(), 64);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let (pk, sk) = test_keys();
        let invite = InviteService::create_room_invite(
            [42u8; 32], vec![3u8; 36], Some("test".into()),
            pk, &sk, None, None,
        ).unwrap();

        let encoded = InviteService::encode_to_string(&invite).unwrap();
        assert!(encoded.starts_with("vc1:"));

        let decoded = InviteService::decode_from_string(&encoded).unwrap();
        assert_eq!(decoded.room_id, invite.room_id);
        assert_eq!(decoded.room_name, invite.room_name);
    }

    #[test]
    fn test_validate_invite() {
        let (pk, sk) = test_keys();
        let invite = InviteService::create_room_invite(
            [42u8; 32], vec![3u8; 36], None, pk, &sk, None, Some(3600),
        ).unwrap();
        InviteService::validate(&invite).unwrap();
    }

    #[test]
    fn test_validate_rejects_tampered_invite() {
        let (pk, sk) = test_keys();
        let mut invite = InviteService::create_room_invite(
            [42u8; 32], vec![3u8; 36], Some("orig".into()),
            pk, &sk, None, Some(3600),
        ).unwrap();
        // Tamper with the room name AFTER signing.
        invite.room_name = Some("evil".into());
        let err = InviteService::validate(&invite);
        assert!(err.is_err(), "tampered invite must fail signature check");
    }

    #[test]
    fn test_validate_rejects_wrong_signer() {
        let (pk, sk) = test_keys();
        let (other_pk, _) = test_keys();
        let mut invite = InviteService::create_room_invite(
            [42u8; 32], vec![3u8; 36], None, pk, &sk, None, Some(3600),
        ).unwrap();
        // Swap the public key to someone else's. Signature was made with `sk`
        // whose public is `pk`, so verifying against `other_pk` must fail.
        invite.creator_public_key = other_pk;
        let err = InviteService::validate(&invite);
        assert!(err.is_err(), "wrong signer must fail signature check");
    }

    #[test]
    fn test_qr_svg_generation() {
        let (pk, sk) = test_keys();
        let invite = InviteService::create_direct_invite(pk, &sk, None, None).unwrap();
        let svg = QrService::generate_svg(&invite).unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }
}
