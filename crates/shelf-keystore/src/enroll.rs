//! Offline file enrollment: `.shelfjoin` / `.shelfgrant`.

use serde::{Deserialize, Serialize};
use shelf_core::enrollment::{
    DeviceCapabilities, ENROLLMENT_PROTOCOL_VERSION, EncryptedMembershipState,
    EncryptedVaultKeyEnvelope, EnrollmentRequest, MemberRole, MembershipCertificate,
    MembershipGrant, SignatureBytes, TransportHint,
};
use shelf_core::{HybridKemPublicKey, Timestamp};
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

/// Export a `.shelfjoin` from a joining vault (identity exists, not yet a member of another vault).
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
    let body = serde_json::to_vec(&req).map_err(|e| KeystoreError::Identity(e.to_string()))?;
    req.self_signature = SignatureBytes::from_bytes(vault.keys.sign(&body));
    let join = ShelfJoin {
        version: 1,
        request: req,
    };
    let transcript =
        serde_json::to_vec(&join).map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let sas = sas_display(&transcript);
    Ok((join, sas))
}

/// Approve a join request using an existing member vault.
pub fn approve_join(
    vault: &Vault,
    join: &ShelfJoin,
) -> Result<(ShelfGrant, String), KeystoreError> {
    let sas =
        sas_display(&serde_json::to_vec(join).map_err(|e| KeystoreError::Identity(e.to_string()))?);
    let wrap = wrap_epoch_key(vault.store.epoch_key().as_bytes(), &join.request.kem_pubkey)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let envelope_bytes =
        serde_json::to_vec(&wrap).map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let mut cert = MembershipCertificate {
        vault_id: vault.store.vault_id(),
        device_id: join.request.device_id,
        signing_pubkey: join.request.signing_pubkey,
        kem_pubkey: join.request.kem_pubkey.clone(),
        role: MemberRole::Member,
        capabilities: join.request.capabilities.clone(),
        serial: 1,
        epoch: vault.store.epoch(),
        issuer: vault.keys.public_identity().device_id,
        issued_at: Timestamp::now(),
        expires_at: None,
        issuer_signature: SignatureBytes::from_bytes([0; 64]),
    };
    let cert_body =
        serde_json::to_vec(&cert).map_err(|e| KeystoreError::Identity(e.to_string()))?;
    cert.issuer_signature = SignatureBytes::from_bytes(vault.keys.sign(&cert_body));
    vault
        .store
        .put_member(&cert)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let grant = MembershipGrant {
        certificate: cert,
        key_envelope: EncryptedVaultKeyEnvelope::from_bytes(envelope_bytes),
        membership_snapshot: EncryptedMembershipState::from_bytes(Vec::new()),
    };
    Ok((ShelfGrant { version: 1, grant }, sas))
}

/// Import a grant into the joining vault, replacing the local epoch key.
pub fn import_grant(vault: &mut Vault, grant: &ShelfGrant) -> Result<(), KeystoreError> {
    let wrap: shelf_protocol::HybridEpochWrap =
        serde_json::from_slice(grant.grant.key_envelope.as_bytes())
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let epoch = unwrap_epoch_key(
        &wrap,
        vault.keys.x25519_secret(),
        vault.keys.ml_kem_decapsulation_key(),
    )
    .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let wrapped = vault.keys.wrap_secret(&epoch)?;
    vault
        .store
        .save_wrapped_epoch_key(&wrapped)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    vault
        .store
        .put_member(&grant.grant.certificate)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    vault
        .store
        .adopt_epoch_key(shelf_protocol::EpochKey::from_bytes(epoch));
    Ok(())
}
