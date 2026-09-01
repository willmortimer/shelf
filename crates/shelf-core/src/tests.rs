//! Cross-module tests required by T1.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::Timestamp;
use crate::blob::DEFAULT_CHUNK_SIZE;
use crate::crdt::ScratchPad;
use crate::crypto::{Dek, all_domain_labels};
use crate::enrollment::{EnrollmentError, EnrollmentEvent, EnrollmentState};
use crate::identity::DeviceId;
use crate::model::{ContentKind, ContentRef, Label, ObjectId, ShelfItem};
use crate::retention::{ExpireObject, Retention, RetentionPolicy};

#[test]
fn object_id_random_and_keyed_not_raw_blake3() {
    let a = ObjectId::new();
    let b = ObjectId::new();
    assert_ne!(a, b);

    let plaintext = b"from_plaintext_style";
    let key_a = [0x10u8; 32];
    let key_b = [0x20u8; 32];
    let id_a = ObjectId::from_keyed_plaintext(&key_a, plaintext);
    let id_b = ObjectId::from_keyed_plaintext(&key_b, plaintext);
    assert_ne!(id_a, id_b);
    assert_ne!(id_a.as_bytes(), blake3::hash(plaintext).as_bytes());
    assert_ne!(id_b.as_bytes(), blake3::hash(plaintext).as_bytes());
}

#[test]
fn shelf_item_metadata_does_not_change_content_or_id() {
    let content = ContentRef::from_bytes(b"immutable-payload");
    let mut item = ShelfItem::new(content, ContentKind::Text, DeviceId::new(), false);
    let id = item.id();
    let bytes = item.content().as_bytes().to_vec();

    item.set_pinned(true);
    item.set_archived(true);
    item.labels_mut().insert(Label::new("keep"));
    item.set_expires_at(None);

    assert_eq!(item.id(), id);
    assert_eq!(item.content().as_bytes(), bytes.as_slice());
    assert!(item.pinned());
    assert!(item.archived());
    assert!(item.labels().contains(&Label::new("keep")));
}

#[test]
fn content_kind_serde_round_trip() {
    let kinds = [
        ContentKind::Text,
        ContentKind::Markdown,
        ContentKind::Url,
        ContentKind::Image,
        ContentKind::File,
        ContentKind::Json,
        ContentKind::OpaqueBytes,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ContentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
        assert_eq!(json, format!("\"{}\"", kind.as_wire_str()));
    }
    assert_eq!(
        serde_json::to_string(&ContentKind::OpaqueBytes).unwrap(),
        "\"opaque-bytes\""
    );
}

#[test]
fn retention_defaults_match_docs() {
    let created = Timestamp::from_millis(0);
    assert_eq!(
        Retention::normal(created).expires_at(),
        Some(created.saturating_add(Duration::from_secs(7 * 24 * 60 * 60)))
    );
    assert_eq!(
        Retention::ephemeral(created).expires_at(),
        Some(created.saturating_add(Duration::from_secs(60 * 60)))
    );
    assert_eq!(Retention::pinned(created).expires_at(), None);
    assert_eq!(
        Retention::for_policy(RetentionPolicy::Normal, created).policy(),
        RetentionPolicy::Normal
    );
}

#[test]
fn enrollment_rejects_uninitialized_to_member() {
    let err = EnrollmentState::Uninitialized
        .transition(EnrollmentEvent::ValidateGrant)
        .unwrap_err();
    assert!(matches!(
        err,
        EnrollmentError::InvalidTransition {
            from: EnrollmentState::Uninitialized,
            event: EnrollmentEvent::ValidateGrant,
        }
    ));
}

#[test]
fn domain_labels_unique_and_specified() {
    let labels = all_domain_labels();
    assert_eq!(
        labels,
        [
            "shelf/object/v1",
            "shelf/chunk/v1",
            "shelf/metadata/v1",
            "shelf/enrollment/v1",
            "shelf/membership/v1",
            "shelf/search/v1",
        ]
    );
    let set: BTreeSet<_> = labels.into_iter().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn yrs_replicas_merge() {
    let mut a = ScratchPad::new("Scratch");
    let mut b = ScratchPad::new("Scratch");
    a.insert_text("from-a");
    b.apply_update(&a.encode_update()).unwrap();
    assert_eq!(a.text(), b.text());

    let mut c = ScratchPad::new("Scratch");
    let mut d = ScratchPad::new("Scratch");
    c.insert_text("left");
    d.insert_text("right");
    c.apply_update(&d.encode_update()).unwrap();
    d.apply_update(&c.encode_update()).unwrap();
    assert_eq!(c.text(), d.text());
}

#[test]
fn dek_debug_does_not_leak_key_hex() {
    let mut key = [0u8; 32];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = [0xde, 0xad, 0xbe, 0xef][i % 4];
    }
    let dek = Dek::from_bytes(key);
    let hex = crate::hexutil::encode(dek.as_bytes());
    let debug = format!("{dek:?}");
    assert!(!debug.contains(&hex));
    assert!(!debug.contains("deadbeef"));
    assert_eq!(dek.as_bytes().len(), 32);
}

#[test]
fn expire_object_fields() {
    let object_id = ObjectId::from_bytes([9; 32]);
    let effective_at = Timestamp::from_millis(1234);
    let op = ExpireObject {
        object_id,
        effective_at,
    };
    assert_eq!(op.object_id, object_id);
    assert_eq!(op.effective_at, effective_at);
}

#[test]
fn file_manifest_chunk_size_constant() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 4 * 1024 * 1024);
}
