//! Offline file enrollment: `.shelfjoin` / `.shelfgrant`.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use shelf_core::enrollment::{
    DeviceCapabilities, ENROLLMENT_PROTOCOL_VERSION, EncryptedVaultKeyEnvelope, EnrollmentRequest,
    MemberRole, MembershipCertificate, MembershipGrant, MembershipSnapshot, SignatureBytes,
    TransportHint, VaultRoot,
};
use shelf_core::{
    DOMAIN_ENROLL_GENESIS, DOMAIN_ENROLL_SAS, DOMAIN_ENROLL_WRAP, HybridKemPublicKey, Timestamp,
    Transcript,
};
use shelf_protocol::{sas_display, unwrap_epoch_key, wrap_epoch_key};

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
        vault,
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
    Ok(root)
}

/// Export a `.shelfjoin` from a joining vault.
pub fn export_join(
    vault: &Vault,
    hints: Vec<TransportHint>,
) -> Result<(ShelfJoin, String), KeystoreError> {
    let id = vault.keys.public_identity();
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
        self_signature: SignatureBytes::from_bytes([0; 64]),
    };
    let body = req.transcript();
    req.self_signature = SignatureBytes::from_bytes(vault.keys.sign(body.as_bytes()));
    vault
        .store
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
    verify_join(join)?;
    let root = vault
        .store
        .vault_root()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .ok_or_else(|| KeystoreError::Signature("vault has no root".into()))?;
    let issuer_id = vault.keys.public_identity();
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
        serial: 2,
        epoch: vault.store.epoch(),
        issuer: issuer_id.device_id,
        issuer_signing_pubkey: issuer_id.signing_pubkey,
        issued_at: Timestamp::now(),
        expires_at: None,
        request_hash,
        issuer_signature: SignatureBytes::from_bytes([0; 64]),
    };
    cert = sign_certificate(vault, &root, cert)?;
    vault
        .store
        .put_member(&cert)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let mut members = vault
        .store
        .members()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    if !members.iter().any(|c| c.device_id == cert.device_id) {
        members.push(cert.clone());
    }
    let mut snapshot = MembershipSnapshot {
        vault_root: root.clone(),
        generation: root.generation,
        epoch: vault.store.epoch(),
        certificates: members,
        snapshot_signature: SignatureBytes::from_bytes([0; 64]),
    };
    let snap_body = snapshot.transcript();
    snapshot.snapshot_signature = SignatureBytes::from_bytes(vault.keys.sign(snap_body.as_bytes()));
    let wrap_aad = wrap_aad(&root, &cert, request_hash);
    let wrap = wrap_epoch_key(
        vault.store.epoch_key().as_bytes(),
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
    let actual = grant_sas(&grant.grant)?;
    if !sas_eq(expected_sas, &actual) {
        return Err(KeystoreError::Signature(
            "SAS does not match --expect-sas / confirmation".into(),
        ));
    }
    verify_grant(vault, grant)?;
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
        vault.keys.x25519_secret(),
        vault.keys.ml_kem_decapsulation_key(),
        &wrap_aad,
    )
    .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let wrapped = vault.keys.wrap_secret(&epoch)?;
    vault
        .store
        .save_vault_root(&grant.grant.vault_root)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    for cert in &grant.grant.snapshot.certificates {
        vault
            .store
            .put_member(cert)
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    }
    vault
        .store
        .adopt_membership(
            shelf_protocol::EpochKey::from_bytes(epoch),
            grant.grant.certificate.epoch,
            grant.grant.certificate.vault_id,
        )
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    vault
        .store
        .save_wrapped_epoch_key(&wrapped)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    vault
        .store
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

fn sign_certificate(
    vault: &Vault,
    root: &VaultRoot,
    mut cert: MembershipCertificate,
) -> Result<MembershipCertificate, KeystoreError> {
    if vault.keys.public_identity().signing_pubkey != root.root_signing_pubkey {
        return Err(KeystoreError::Signature(
            "cannot sign a certificate without the vault root key".into(),
        ));
    }
    let body = cert.transcript();
    cert.issuer_signature = SignatureBytes::from_bytes(vault.keys.sign(body.as_bytes()));
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

fn verify_grant(vault: &Vault, grant: &ShelfGrant) -> Result<(), KeystoreError> {
    let cert = &grant.grant.certificate;
    let local = vault.keys.public_identity();
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
    let pending = vault
        .store
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
