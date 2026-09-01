//! Offline file enrollment: `.shelfjoin` / `.shelfgrant`.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use shelf_core::enrollment::{
    DeviceCapabilities, ENROLLMENT_PROTOCOL_VERSION, EncryptedVaultKeyEnvelope, EnrollmentRequest,
    MailboxBinding, MemberRole, MembershipCertificate, MembershipGrant, MembershipSnapshot,
    RoutingBinding, SignatureBytes, TransportHint, VaultRoot,
};
use shelf_core::{
    DOMAIN_ENROLL_GENESIS, DOMAIN_ENROLL_SAS, DOMAIN_ENROLL_WRAP, HybridKemPublicKey, Timestamp,
    Transcript,
};
use shelf_protocol::{sas_display, unwrap_epoch_key, wrap_epoch_key};

use shelf_store::SqliteStore;

use crate::DeviceKeystore;
use crate::KeystoreError;
use crate::vault::Vault;

/// On-disk enrollment request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShelfJoin {
    /// Format version.
    pub version: u16,
    /// Signed enrollment request.
    pub request: EnrollmentRequest,
}

/// On-disk membership grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShelfGrant {
    /// Format version.
    pub version: u16,
    /// Grant body.
    pub grant: MembershipGrant,
}

/// Ensure this vault has a VaultRoot and a root-signed self-certificate.
pub fn ensure_local_root(vault: &mut Vault) -> Result<VaultRoot, KeystoreError> {
    if let Some(root) = vault
        .store
        .vault_root()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
    {
        return Ok(root);
    }
    let id = vault.keys.public_identity();
    let root = VaultRoot {
        vault_id: vault.store.vault_id(),
        root_signing_pubkey: id.signing_pubkey,
        generation: 1,
    };
    vault
        .store
        .save_vault_root(&root)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let request_hash = genesis_request_hash(&root, id.device_id);
    let cert = sign_certificate(
        &vault.keys,
        &root,
        MembershipCertificate {
            vault_id: root.vault_id,
            device_id: id.device_id,
            signing_pubkey: id.signing_pubkey,
            kem_pubkey: HybridKemPublicKey::new(id.x25519_pubkey, id.ml_kem_pubkey.clone()),
            role: MemberRole::Authority,
            capabilities: DeviceCapabilities {
                can_approve_enrollment: true,
                can_issue_grants: true,
                platform: None,
            },
            serial: 1,
            epoch: vault.store.epoch(),
            issuer: id.device_id,
            issuer_signing_pubkey: id.signing_pubkey,
            issued_at: Timestamp::now(),
            expires_at: None,
            request_hash,
            issuer_signature: SignatureBytes::from_bytes([0; 64]),
        },
    )?;
    vault
        .store
        .put_member(&cert)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let snapshot = sign_snapshot(&vault.keys, &vault.store, &root, vec![cert], 1, None, None)?;
    vault
        .store
        .save_membership_snapshot(&snapshot)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    Ok(root)
}

/// Export a `.shelfjoin` from a joining vault.
///
/// Empty `hints` are filled from local Tailscale self-IPs / MagicDNS and an
/// optional `lan_address` in the vault home `config.toml`.
pub fn export_join(
    vault: &Vault,
    hints: Vec<TransportHint>,
) -> Result<(ShelfJoin, String), KeystoreError> {
    export_join_store(&vault.keys, &vault.store, hints)
}

/// Export a `.shelfjoin` from an already-open store and keystore.
pub fn export_join_store(
    keys: &DeviceKeystore,
    store: &SqliteStore,
    mut hints: Vec<TransportHint>,
) -> Result<(ShelfJoin, String), KeystoreError> {
    if hints.is_empty() {
        hints = collect_local_transport_hints(keys.home());
    }
    let id = keys.public_identity();
    let nonce: [u8; 32] = rand::random();
    let expires_at =
        Timestamp::from_millis(Timestamp::now().as_millis().saturating_add(86_400_000));
    let mut req = EnrollmentRequest {
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        device_id: id.device_id,
        device_name: id.device_name.clone().unwrap_or_default(),
        signing_pubkey: id.signing_pubkey,
        kem_pubkey: HybridKemPublicKey::new(id.x25519_pubkey, id.ml_kem_pubkey.clone()),
        ephemeral_pubkey: id.x25519_pubkey,
        transport_hints: hints,
        capabilities: DeviceCapabilities::default(),
        nonce,
        expires_at,
        mailbox_id: store
            .mailbox_id()
            .map_err(|e| KeystoreError::Identity(e.to_string()))?,
        mailbox_write_cap: store
            .mailbox_write_cap()
            .map_err(|e| KeystoreError::Identity(e.to_string()))?,
        self_signature: SignatureBytes::from_bytes([0; 64]),
    };
    let body = req.transcript();
    req.self_signature = SignatureBytes::from_bytes(keys.sign(body.as_bytes()));
    store
        .save_pending_request_hash(&body.hash())
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let join = ShelfJoin {
        version: 1,
        request: req,
    };
    let sas = sas_display(body.as_bytes());
    Ok((join, sas))
}

/// Approve a join request using the vault root device.
pub fn approve_join(
    vault: &Vault,
    join: &ShelfJoin,
) -> Result<(ShelfGrant, String), KeystoreError> {
    approve_join_store(&vault.keys, &vault.store, join)
}

/// Approve a join request using an already-open store and keystore.
pub fn approve_join_store(
    keys: &DeviceKeystore,
    store: &SqliteStore,
    join: &ShelfJoin,
) -> Result<(ShelfGrant, String), KeystoreError> {
    verify_join(join)?;
    let root = store
        .vault_root()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .ok_or_else(|| KeystoreError::Signature("vault has no root".into()))?;
    let issuer_id = keys.public_identity();
    if issuer_id.signing_pubkey != root.root_signing_pubkey {
        return Err(KeystoreError::Signature(
            "only the vault root device may issue grants".into(),
        ));
    }
    let request_hash = join.request.transcript().hash();
    let approver_nonce: [u8; 32] = rand::random();
    let mut cert = MembershipCertificate {
        vault_id: root.vault_id,
        device_id: join.request.device_id,
        signing_pubkey: join.request.signing_pubkey,
        kem_pubkey: join.request.kem_pubkey.clone(),
        role: MemberRole::Member,
        capabilities: join.request.capabilities.clone(),
        serial: next_serial(store)?,
        epoch: store.epoch(),
        issuer: issuer_id.device_id,
        issuer_signing_pubkey: issuer_id.signing_pubkey,
        issued_at: Timestamp::now(),
        expires_at: None,
        request_hash,
        issuer_signature: SignatureBytes::from_bytes([0; 64]),
    };
    cert = sign_certificate(keys, &root, cert)?;
    store
        .put_member(&cert)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let members = store
        .members()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let generation = store
        .membership_snapshot()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .map(|s| s.generation.saturating_add(1))
        .unwrap_or(2);
    let snapshot = sign_snapshot(keys, store, &root, members, generation, Some(join), None)?;
    store
        .save_membership_snapshot(&snapshot)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let wrap_aad = wrap_aad(&root, &cert, request_hash);
    let wrap = wrap_epoch_key(
        store.epoch_key().as_bytes(),
        &join.request.kem_pubkey,
        &wrap_aad,
    )
    .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let envelope_bytes =
        serde_json::to_vec(&wrap).map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let grant = MembershipGrant {
        vault_root: root,
        request_hash,
        approver_nonce,
        certificate: cert,
        key_envelope: EncryptedVaultKeyEnvelope::from_bytes(envelope_bytes),
        snapshot,
    };
    let sas = grant_sas(&grant)?;
    Ok((ShelfGrant { version: 1, grant }, sas))
}

/// Two-way SAS for a grant (joiner and approver must display the same phrase).
pub fn grant_sas(grant: &MembershipGrant) -> Result<String, KeystoreError> {
    Ok(sas_display(&sas_transcript(grant)?))
}

/// Import a grant after the caller has confirmed [`grant_sas`].
pub fn import_grant(
    vault: &mut Vault,
    grant: &ShelfGrant,
    expected_sas: &str,
) -> Result<(), KeystoreError> {
    import_grant_store(&vault.keys, &mut vault.store, grant, expected_sas)
}

/// Import a grant into an already-open store and keystore.
pub fn import_grant_store(
    keys: &DeviceKeystore,
    store: &mut SqliteStore,
    grant: &ShelfGrant,
    expected_sas: &str,
) -> Result<(), KeystoreError> {
    let actual = grant_sas(&grant.grant)?;
    if !sas_eq(expected_sas, &actual) {
        return Err(KeystoreError::Signature(
            "SAS does not match --expect-sas / confirmation".into(),
        ));
    }
    verify_grant(keys, store, grant)?;
    let wrap: shelf_protocol::HybridEpochWrap =
        serde_json::from_slice(grant.grant.key_envelope.as_bytes())
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let wrap_aad = wrap_aad(
        &grant.grant.vault_root,
        &grant.grant.certificate,
        grant.grant.request_hash,
    );
    let epoch = unwrap_epoch_key(
        &wrap,
        keys.x25519_secret(),
        keys.ml_kem_decapsulation_key(),
        &wrap_aad,
    )
    .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let wrapped = keys.wrap_secret(&epoch)?;
    store
        .save_vault_root(&grant.grant.vault_root)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    for cert in &grant.grant.snapshot.certificates {
        store
            .put_member(cert)
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    }
    store
        .adopt_membership(
            shelf_protocol::EpochKey::from_bytes(epoch),
            grant.grant.certificate.epoch,
            grant.grant.certificate.vault_id,
        )
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    store
        .save_wrapped_epoch_key(&wrapped)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    store
        .save_membership_snapshot(&grant.grant.snapshot)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    store
        .clear_pending_request_hash()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    Ok(())
}

fn wrap_aad(root: &VaultRoot, cert: &MembershipCertificate, request_hash: [u8; 32]) -> Vec<u8> {
    let mut t = Transcript::new(DOMAIN_ENROLL_WRAP);
    t.push_u16(ENROLLMENT_PROTOCOL_VERSION);
    t.push_fixed(root.transcript().as_bytes());
    t.push_u64(cert.epoch.as_u64());
    t.push_fixed(cert.device_id.as_bytes());
    t.push_fixed(cert.signing_pubkey.as_bytes());
    t.push_fixed(cert.kem_pubkey.x25519.as_bytes());
    t.push_bytes(cert.kem_pubkey.ml_kem_768.as_bytes());
    t.push_fixed(&request_hash);
    t.push_fixed(cert.issuer.as_bytes());
    t.push_fixed(&cert.transcript().hash());
    t.as_bytes().to_vec()
}

fn sas_transcript(grant: &MembershipGrant) -> Result<Vec<u8>, KeystoreError> {
    let mut t = Transcript::new(DOMAIN_ENROLL_SAS);
    t.push_fixed(&grant.request_hash);
    t.push_fixed(grant.vault_root.transcript().as_bytes());
    t.push_fixed(grant.certificate.issuer.as_bytes());
    t.push_fixed(&grant.certificate.transcript().hash());
    t.push_bytes(grant.key_envelope.as_bytes());
    t.push_fixed(grant.snapshot.transcript().as_bytes());
    t.push_fixed(&grant.approver_nonce);
    Ok(t.as_bytes().to_vec())
}

fn genesis_request_hash(root: &VaultRoot, device_id: shelf_core::DeviceId) -> [u8; 32] {
    let mut t = Transcript::new(DOMAIN_ENROLL_GENESIS);
    t.push_fixed(root.transcript().as_bytes());
    t.push_fixed(device_id.as_bytes());
    t.hash()
}

fn next_serial(store: &SqliteStore) -> Result<u64, KeystoreError> {
    let members = store
        .members()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    Ok(members
        .iter()
        .map(|c| c.serial)
        .max()
        .unwrap_or(0)
        .saturating_add(1))
}

pub(crate) fn sign_snapshot(
    keys: &DeviceKeystore,
    store: &SqliteStore,
    root: &VaultRoot,
    certificates: Vec<MembershipCertificate>,
    generation: u64,
    join: Option<&ShelfJoin>,
    exclude: Option<shelf_core::DeviceId>,
) -> Result<MembershipSnapshot, KeystoreError> {
    let mut mailbox_bindings = store
        .membership_snapshot()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .map(|s| s.mailbox_bindings)
        .unwrap_or_default();
    mailbox_bindings.extend(mailbox_bindings_local(keys, store)?);
    if let Some(join) = join
        && !join.request.mailbox_id.is_empty()
    {
        mailbox_bindings.push(MailboxBinding {
            device_id: join.request.device_id,
            mailbox_id: join.request.mailbox_id.clone(),
            write_cap: join.request.mailbox_write_cap.clone(),
        });
    }
    mailbox_bindings.sort_by(|a, b| a.device_id.as_bytes().cmp(b.device_id.as_bytes()));
    mailbox_bindings.dedup_by(|a, b| a.device_id == b.device_id);
    if let Some(id) = exclude {
        mailbox_bindings.retain(|b| b.device_id != id);
    }
    let mut routing_hints = store
        .membership_snapshot()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .map(|s| s.routing_hints)
        .unwrap_or_default();
    routing_hints.extend(routing_hints_local(keys));
    if let Some(join) = join
        && !join.request.transport_hints.is_empty()
    {
        routing_hints.push(RoutingBinding {
            device_id: join.request.device_id,
            hints: join.request.transport_hints.clone(),
        });
    }
    routing_hints.sort_by(|a, b| a.device_id.as_bytes().cmp(b.device_id.as_bytes()));
    routing_hints.dedup_by(|a, b| a.device_id == b.device_id);
    if let Some(id) = exclude {
        routing_hints.retain(|b| b.device_id != id);
    }
    let mut snapshot = MembershipSnapshot {
        vault_root: root.clone(),
        generation,
        epoch: store.epoch(),
        certificates,
        mailbox_bindings,
        routing_hints,
        snapshot_signature: SignatureBytes::from_bytes([0; 64]),
    };
    let body = snapshot.transcript();
    snapshot.snapshot_signature = SignatureBytes::from_bytes(keys.sign(body.as_bytes()));
    Ok(snapshot)
}

fn routing_hints_local(keys: &DeviceKeystore) -> Vec<RoutingBinding> {
    let hints = collect_local_transport_hints(keys.home());
    if hints.is_empty() {
        return Vec::new();
    }
    vec![RoutingBinding {
        device_id: keys.public_identity().device_id,
        hints,
    }]
}

fn collect_local_transport_hints(home: &std::path::Path) -> Vec<TransportHint> {
    let mut hints = tailscale_self_hints();
    if let Some(lan) = lan_hint_from_home(home) {
        hints.push(lan);
    }
    hints
}

/// Best-effort: host `tailscale status --json` Self IPs and MagicDNS.
fn tailscale_self_hints() -> Vec<TransportHint> {
    let output = std::process::Command::new("tailscale")
        .arg("status")
        .arg("--json")
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    tailscale_self_hints_from_json(&output.stdout)
}

fn tailscale_self_hints_from_json(bytes: &[u8]) -> Vec<TransportHint> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let Some(self_node) = v.get("Self") else {
        return Vec::new();
    };
    let mut hints = Vec::new();
    if let Some(dns) = self_node.get("DNSName").and_then(serde_json::Value::as_str) {
        let dns = dns.trim_end_matches('.');
        if !dns.is_empty() {
            hints.push(TransportHint::Tailscale {
                address: dns.to_owned(),
            });
        }
    }
    if let Some(ips) = self_node
        .get("TailscaleIPs")
        .and_then(serde_json::Value::as_array)
    {
        for ip in ips.iter().filter_map(serde_json::Value::as_str) {
            if !ip.is_empty() {
                hints.push(TransportHint::Tailscale {
                    address: ip.to_owned(),
                });
            }
        }
    }
    hints
}

fn lan_hint_from_home(home: &std::path::Path) -> Option<TransportHint> {
    let text = std::fs::read_to_string(home.join("config.toml")).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() != "lan_address" {
            continue;
        }
        let val = v.trim().trim_matches('"');
        if !val.is_empty() {
            return Some(TransportHint::Lan {
                address: val.to_owned(),
            });
        }
    }
    None
}

fn mailbox_bindings_local(
    keys: &DeviceKeystore,
    store: &SqliteStore,
) -> Result<Vec<MailboxBinding>, KeystoreError> {
    let mid = store
        .mailbox_id()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let write = store
        .mailbox_write_cap()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    Ok(vec![MailboxBinding {
        device_id: keys.public_identity().device_id,
        mailbox_id: mid,
        write_cap: write,
    }])
}

fn sign_certificate(
    keys: &DeviceKeystore,
    root: &VaultRoot,
    mut cert: MembershipCertificate,
) -> Result<MembershipCertificate, KeystoreError> {
    if keys.public_identity().signing_pubkey != root.root_signing_pubkey {
        return Err(KeystoreError::Signature(
            "cannot sign a certificate without the vault root key".into(),
        ));
    }
    let body = cert.transcript();
    cert.issuer_signature = SignatureBytes::from_bytes(keys.sign(body.as_bytes()));
    Ok(cert)
}

fn verify_join(join: &ShelfJoin) -> Result<(), KeystoreError> {
    if join.request.expires_at.as_millis() < Timestamp::now().as_millis() {
        return Err(KeystoreError::Signature(
            "enrollment request expired".into(),
        ));
    }
    verify_ed25519(
        &join.request.signing_pubkey,
        join.request.transcript().as_bytes(),
        &join.request.self_signature,
    )
}

fn verify_grant(
    keys: &DeviceKeystore,
    store: &SqliteStore,
    grant: &ShelfGrant,
) -> Result<(), KeystoreError> {
    let cert = &grant.grant.certificate;
    let local = keys.public_identity();
    if cert.device_id != local.device_id {
        return Err(KeystoreError::Signature(
            "grant is not for this device".into(),
        ));
    }
    if cert.signing_pubkey != local.signing_pubkey {
        return Err(KeystoreError::Signature(
            "grant signing key does not match this device".into(),
        ));
    }
    let pending = store
        .pending_request_hash()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .ok_or_else(|| {
            KeystoreError::Signature("no pending enrollment request on this device".into())
        })?;
    if pending != grant.grant.request_hash || pending != cert.request_hash {
        return Err(KeystoreError::Signature(
            "grant is not bound to this device's enrollment request".into(),
        ));
    }
    let root = &grant.grant.vault_root;
    if cert.vault_id != root.vault_id {
        return Err(KeystoreError::Signature(
            "certificate vault_id != vault root".into(),
        ));
    }
    // Trust anchor: verify under the root key, not cert.issuer_signing_pubkey.
    verify_ed25519(
        &root.root_signing_pubkey,
        cert.transcript().as_bytes(),
        &cert.issuer_signature,
    )?;
    let snap = &grant.grant.snapshot;
    if snap.vault_root != *root {
        return Err(KeystoreError::Signature("snapshot root mismatch".into()));
    }
    verify_ed25519(
        &root.root_signing_pubkey,
        snap.transcript().as_bytes(),
        &snap.snapshot_signature,
    )?;
    if !snap
        .certificates
        .iter()
        .any(|c| c.device_id == cert.device_id && c.signing_pubkey == cert.signing_pubkey)
    {
        return Err(KeystoreError::Signature(
            "joiner certificate missing from membership snapshot".into(),
        ));
    }
    if !snap
        .certificates
        .iter()
        .any(|c| c.signing_pubkey == root.root_signing_pubkey && c.device_id == cert.issuer)
    {
        return Err(KeystoreError::Signature(
            "approver certificate missing from membership snapshot".into(),
        ));
    }
    Ok(())
}

fn verify_ed25519(
    pk: &shelf_core::SigningPublicKey,
    msg: &[u8],
    sig: &SignatureBytes,
) -> Result<(), KeystoreError> {
    let vk = VerifyingKey::try_from(*pk)
        .map_err(|_| KeystoreError::Signature("invalid verifying key".into()))?;
    let signature = Signature::from_bytes(sig.as_bytes());
    vk.verify_strict(msg, &signature)
        .map_err(|_| KeystoreError::Signature("invalid signature".into()))
}

fn sas_eq(expected: &str, actual: &str) -> bool {
    let norm = |s: &str| {
        s.split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join(" ")
    };
    let a = norm(expected);
    let b = norm(actual);
    a == b && a.split_whitespace().count() == 6
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_or_create_vault;

    #[test]
    fn tailscale_self_json_becomes_hints() {
        let json = br#"{
            "Self": {
                "Online": true,
                "DNSName": "phone.tailnet.ts.net.",
                "TailscaleIPs": ["100.64.0.9", "fd7a:115c:a1e0::9"]
            },
            "Peer": {}
        }"#;
        let hints = tailscale_self_hints_from_json(json);
        assert!(hints.contains(&TransportHint::Tailscale {
            address: "phone.tailnet.ts.net".into(),
        }));
        assert!(hints.contains(&TransportHint::Tailscale {
            address: "100.64.0.9".into(),
        }));
        assert!(hints.contains(&TransportHint::Tailscale {
            address: "fd7a:115c:a1e0::9".into(),
        }));
    }

    #[test]
    fn lan_address_from_config_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "lan_address = \"192.0.2.10:18732\"\n",
        )
        .unwrap();
        assert_eq!(
            lan_hint_from_home(dir.path()),
            Some(TransportHint::Lan {
                address: "192.0.2.10:18732".into(),
            })
        );
    }

    #[test]
    fn snapshot_copies_join_hints_and_verify() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let member = open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let mut joiner = open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let hints = vec![TransportHint::Tailscale {
            address: "100.64.1.10".into(),
        }];
        let (join, _) = export_join(&joiner, hints.clone()).unwrap();
        assert_eq!(join.request.transport_hints, hints);
        let (grant, sas) = approve_join(&member, &join).unwrap();
        let snap = &grant.grant.snapshot;
        let root = &grant.grant.vault_root;
        assert!(snap.verify(root));
        assert!(
            snap.routing_hints
                .iter()
                .any(|b| { b.device_id == join.request.device_id && b.hints == hints }),
            "join transport hints must land on the snapshot"
        );
        let json = serde_json::to_vec(snap).unwrap();
        let back: MembershipSnapshot = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, *snap);
        assert!(back.verify(root));
        let mut tampered = snap.clone();
        tampered.routing_hints.clear();
        assert!(!tampered.verify(root));
        import_grant(&mut joiner, &grant, &sas).unwrap();
        let stored = joiner.store.membership_snapshot().unwrap().unwrap();
        assert!(stored.verify(&grant.grant.vault_root));
    }
}
