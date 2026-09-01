//! Integration: Client <-> shelfd over a tempdir Unix socket.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shelf_core::{ContentKind, ObjectId};
use shelfd::{Client, ClientError, GetTarget, MemoryStore, serve};

static SOCK_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_socket_path() -> PathBuf {
    let seq = SOCK_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sf{}-{seq}.sock", std::process::id()))
}

async fn wait_for_client(path: &std::path::Path) -> Client {
    let mut last = None;
    for _ in 0..200 {
        match Client::connect(path).await {
            Ok(client) => return client,
            Err(err) => last = Some(err),
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("daemon did not accept connections: {last:?}");
}

#[tokio::test]
async fn put_ls_latest_get_round_trip() {
    let sock = temp_socket_path();
    let _ = std::fs::remove_file(&sock);
    let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));

    let client = wait_for_client(&sock).await;
    let secret = b"integration-plaintext-payload";
    let put = client
        .put(secret, ContentKind::Text, Some("note.txt"))
        .await
        .unwrap();
    assert_ne!(put.id, ObjectId::from_bytes([0; 32]));

    let items = client.ls().await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, put.id);
    assert_eq!(items[0].kind, ContentKind::Text);
    assert!(!items[0].pinned);
    let ls_json = serde_json::to_string(&items).unwrap();
    assert!(
        !ls_json.contains("integration-plaintext-payload"),
        "ls must not include raw plaintext"
    );
    assert!(!ls_json.contains("bytes"));

    let latest = client.latest().await.unwrap();
    assert_eq!(latest.id, put.id);
    assert_eq!(latest.kind, ContentKind::Text);
    assert_eq!(latest.bytes, secret);

    let by_id = client.get(GetTarget::Id { id: put.id }).await.unwrap();
    assert_eq!(by_id.bytes, secret);
    let by_index = client.get(GetTarget::Index { index: 1 }).await.unwrap();
    assert_eq!(by_index.bytes, secret);

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test]
async fn get_missing_id_is_typed_not_found() {
    let sock = temp_socket_path();
    let _ = std::fs::remove_file(&sock);
    let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
    let client = wait_for_client(&sock).await;

    let err = client
        .get(GetTarget::Id {
            id: ObjectId::from_bytes([0xee; 32]),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, ClientError::NotFound(_)),
        "expected NotFound, got {err:?}"
    );

    let empty_latest = client.latest().await.unwrap_err();
    assert!(matches!(empty_latest, ClientError::NotFound(_)));

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test]
async fn two_puts_latest_is_newest_and_ls_order() {
    let sock = temp_socket_path();
    let _ = std::fs::remove_file(&sock);
    let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
    let client = wait_for_client(&sock).await;

    client.put(b"alpha", ContentKind::Text, None).await.unwrap();
    let second = client.put(b"beta", ContentKind::Json, None).await.unwrap();

    let latest = client.latest().await.unwrap();
    assert_eq!(latest.id, second.id);
    assert_eq!(latest.bytes, b"beta");
    assert_eq!(latest.kind, ContentKind::Json);

    let items = client.ls().await.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].id, second.id);

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test]
async fn pin_then_ls_and_rm_then_not_found() {
    let sock = temp_socket_path();
    let _ = std::fs::remove_file(&sock);
    let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
    let client = wait_for_client(&sock).await;

    let put = client
        .put(b"pin-me", ContentKind::Text, None)
        .await
        .unwrap();
    client.pin(GetTarget::Index { index: 1 }).await.unwrap();
    let items = client.ls().await.unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].pinned);
    assert_eq!(items[0].id, put.id);

    client.rm(GetTarget::Id { id: put.id }).await.unwrap();
    let err = client.get(GetTarget::Id { id: put.id }).await.unwrap_err();
    assert!(matches!(err, ClientError::NotFound(_)));

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test]
async fn scratch_round_trip() {
    let sock = temp_socket_path();
    let _ = std::fs::remove_file(&sock);
    let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
    let client = wait_for_client(&sock).await;

    let text = client.scratch_append("Scratch", "hello ").await.unwrap();
    assert_eq!(text, "hello ");
    let again = client.scratch_get("Scratch").await.unwrap();
    assert_eq!(again, "hello ");

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_file(&sock);
}
