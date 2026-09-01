//! Canonical additional authenticated data for object AEAD and DEK wrap.
//!
//! Encoding is length-prefixed big-endian binary so AAD is unique for a given
//! field set (JSON is not). Tampering any bound field must fail open.

use shelf_core::{AeadAlgorithm, ContentKind, DOMAIN_OBJECT, DeviceId, EpochId, ObjectId};

use crate::wrap::DOMAIN_DEK_WRAP;

/// Stable one-byte algorithm tag for AAD. Wire serde names are not used here
/// so a rename cannot silently change the authenticated encoding.
pub(crate) fn algorithm_tag(algorithm: AeadAlgorithm) -> u8 {
    match algorithm {
        AeadAlgorithm::XChaCha20Poly1305 => 0,
        AeadAlgorithm::Aes256Gcm => 1,
    }
}

/// AAD for object-payload XChaCha20-Poly1305.
///
/// v1 layout:
/// `domain_len || domain || version_be || object_id || epoch_be || alg_tag
///  || kind_len || kind || origin`
///
/// v2 layout (kind/origin live inside the AEAD plaintext):
/// `domain_len || domain || version_be || object_id || epoch_be || alg_tag`
pub(crate) fn object_aad(
    version: u16,
    object_id: ObjectId,
    epoch: EpochId,
    algorithm: AeadAlgorithm,
    content_kind: Option<ContentKind>,
    origin: Option<DeviceId>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    push_label(&mut buf, DOMAIN_OBJECT);
    buf.extend_from_slice(&version.to_be_bytes());
    buf.extend_from_slice(object_id.as_bytes());
    buf.extend_from_slice(&epoch.as_u64().to_be_bytes());
    buf.push(algorithm_tag(algorithm));
    if version < 2 {
        let kind = content_kind.expect("v1 AAD requires content kind");
        let origin = origin.expect("v1 AAD requires origin");
        push_label(&mut buf, kind.as_wire_str());
        buf.extend_from_slice(origin.as_bytes());
    }
    buf
}

/// AAD for software DEK wrap under an epoch key.
///
/// Binds wrap domain, wrap version, object id, and epoch so a wrapped DEK
/// cannot be spliced onto a different object or epoch.
pub(crate) fn wrap_aad(
    version: u16,
    object_id: ObjectId,
    epoch: EpochId,
    algorithm: AeadAlgorithm,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    push_label(&mut buf, DOMAIN_DEK_WRAP);
    buf.extend_from_slice(&version.to_be_bytes());
    buf.extend_from_slice(object_id.as_bytes());
    buf.extend_from_slice(&epoch.as_u64().to_be_bytes());
    buf.push(algorithm_tag(algorithm));
    buf
}

fn push_label(buf: &mut Vec<u8>, label: &str) {
    let bytes = label.as_bytes();
    let len = u8::try_from(bytes.len()).expect("AAD label exceeds 255 bytes");
    buf.push(len);
    buf.extend_from_slice(bytes);
}
