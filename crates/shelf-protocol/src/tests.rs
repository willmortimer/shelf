//! Protocol tests required by T2.

use shelf_core::{AeadAlgorithm, ContentKind, Dek, DeviceId, EpochId, ObjectId};

use crate::{ENVELOPE_VERSION, EpochKey, ProtocolError, WRAP_VERSION, open, seal};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn seal_fixture(plaintext: &[u8]) -> (crate::EncryptedObject, EpochKey) {
    let epoch_key = EpochKey::new();
    let object_id = ObjectId::new();
    let epoch = EpochId::new(7);
    let kind = ContentKind::Text;
    let origin = DeviceId::new();
    let envelope = seal(plaintext, object_id, epoch, &epoch_key, kind, origin).unwrap();
    (envelope, epoch_key)
}

#[test]
fn seal_then_open_recovers_plaintext() {
    let plaintext = b"shelf-object-plaintext";
    let (envelope, epoch_key) = seal_fixture(plaintext);
    let opened = open(&envelope, &epoch_key).unwrap();
    assert_eq!(opened.plaintext, plaintext);
    assert_eq!(envelope.version, ENVELOPE_VERSION);
    assert_eq!(envelope.wrapped_dek.version, WRAP_VERSION);
    assert_eq!(envelope.algorithm, AeadAlgorithm::XChaCha20Poly1305);
    assert_eq!(envelope.nonce.len(), 24);
    assert!(envelope.content_kind.is_none());
    assert!(envelope.origin.is_none());
}

#[test]
fn envelope_json_uses_base64_not_byte_array() {
    let (envelope, epoch_key) = seal_fixture(b"secret");
    let json = serde_json::to_string(&envelope).unwrap();
    assert!(!json.contains("[53,"), "{json}");
    assert!(json.contains(r#""ciphertext":""#), "{json}");
    assert!(open(&envelope, &epoch_key).unwrap().expires_at.is_some());
}

#[test]
fn empty_plaintext_round_trips() {
    let (envelope, epoch_key) = seal_fixture(b"");
    let opened = open(&envelope, &epoch_key).unwrap();
    assert_eq!(opened.plaintext, b"");
    assert!(!envelope.ciphertext.is_empty());
}

#[test]
fn wrong_epoch_key_fails_open() {
    let (envelope, _epoch_key) = seal_fixture(b"secret");
    let other = EpochKey::new();
    let err = open(&envelope, &other).unwrap_err();
    assert_eq!(err, ProtocolError::WrapFailure);
}

#[test]
fn tampered_ciphertext_fails_hash() {
    let (mut envelope, epoch_key) = seal_fixture(b"secret");
    envelope.ciphertext[0] ^= 0x01;
    let err = open(&envelope, &epoch_key).unwrap_err();
    assert_eq!(err, ProtocolError::HashMismatch);
}

#[test]
fn tampered_ciphertext_with_recomputed_hash_fails_aead() {
    let (mut envelope, epoch_key) = seal_fixture(b"secret");
    envelope.ciphertext[0] ^= 0x01;
    envelope.ciphertext_hash = crate::Hash::of_ciphertext(&envelope.ciphertext);
    let err = open(&envelope, &epoch_key).unwrap_err();
    assert_eq!(err, ProtocolError::AeadFailure);
}

#[test]
fn tampered_object_id_fails_open() {
    let (mut envelope, epoch_key) = seal_fixture(b"secret");
    envelope.object_id = ObjectId::new();
    let err = open(&envelope, &epoch_key).unwrap_err();
    assert_eq!(err, ProtocolError::WrapFailure);
}

#[test]
fn v2_json_omits_kind_origin_and_name() {
    let (envelope, epoch_key) = seal_fixture(b"secret-note");
    let json = serde_json::to_string(&envelope).unwrap();
    assert!(!json.contains("content_kind"), "{json}");
    assert!(!json.contains("\"origin\""), "{json}");
    assert!(!json.contains("secret-note"), "{json}");
    assert_eq!(
        open(&envelope, &epoch_key).unwrap().content_kind,
        ContentKind::Text
    );
}

#[test]
fn ciphertext_hash_is_blake3_of_ciphertext_not_plaintext() {
    let plaintext = b"not-the-ciphertext";
    let (envelope, _epoch_key) = seal_fixture(plaintext);
    let of_ct = blake3::hash(&envelope.ciphertext);
    let of_pt = blake3::hash(plaintext);
    assert_eq!(envelope.ciphertext_hash.as_bytes(), of_ct.as_bytes());
    assert_ne!(envelope.ciphertext_hash.as_bytes(), of_pt.as_bytes());
}

#[test]
fn epoch_key_and_dek_debug_do_not_leak_hex() {
    let epoch_key = EpochKey::new();
    let dek = Dek::new();
    for (label, debug, display, bytes) in [
        (
            "EpochKey",
            format!("{epoch_key:?}"),
            format!("{epoch_key}"),
            epoch_key.as_bytes().as_slice(),
        ),
        (
            "Dek",
            format!("{dek:?}"),
            format!("{dek}"),
            dek.as_bytes().as_slice(),
        ),
    ] {
        let hex = hex(bytes);
        assert!(
            !debug.to_lowercase().contains(&hex),
            "{label} Debug leaked hex"
        );
        assert!(
            !display.to_lowercase().contains(&hex),
            "{label} Display leaked hex"
        );
        assert!(
            debug.contains("REDACTED"),
            "{label} Debug should be redacted, got {debug}"
        );
    }
}

#[test]
fn unsupported_version_returns_typed_error() {
    let (mut envelope, epoch_key) = seal_fixture(b"secret");
    envelope.version = 99;
    let err = open(&envelope, &epoch_key).unwrap_err();
    assert_eq!(err, ProtocolError::UnsupportedVersion { version: 99 });
}

#[test]
fn aes256gcm_payload_returns_typed_error() {
    let (mut envelope, epoch_key) = seal_fixture(b"secret");
    envelope.algorithm = AeadAlgorithm::Aes256Gcm;
    let err = open(&envelope, &epoch_key).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::UnsupportedAlgorithm {
            algorithm: AeadAlgorithm::Aes256Gcm,
        }
    );
}

#[test]
fn aes256gcm_wrap_returns_typed_error() {
    let (mut envelope, epoch_key) = seal_fixture(b"secret");
    envelope.wrapped_dek.algorithm = AeadAlgorithm::Aes256Gcm;
    let err = open(&envelope, &epoch_key).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::UnsupportedAlgorithm {
            algorithm: AeadAlgorithm::Aes256Gcm,
        }
    );
}

#[test]
fn invalid_nonce_length_returns_typed_error() {
    let (mut envelope, epoch_key) = seal_fixture(b"secret");
    envelope.nonce = vec![0u8; 12];
    let err = open(&envelope, &epoch_key).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::InvalidNonceLength {
            expected: 24,
            actual: 12,
        }
    );
}
