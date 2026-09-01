//! Enrollment request, grant, and state machine.
//!
//! Enrollment is transport-independent and never requires the mailbox.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::EpochId;
use crate::identity::{DeviceId, HybridKemPublicKey, SigningPublicKey, VaultId, X25519PublicKey};
use crate::model::Timestamp;

/// Current enrollment protocol version carried on requests.
pub const ENROLLMENT_PROTOCOL_VERSION: u16 = 1;

/// Ed25519 signature bytes (64).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureBytes(#[serde(with = "crate::hexutil::hex64")] [u8; 64]);

impl SignatureBytes {
    /// Wrap 64 raw signature bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SignatureBytes")
            .field(&format_args!("{}", crate::hexutil::encode(&self.0)))
            .finish()
    }
}

/// How a joining device can be reached. Hints are not a trust signal.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum TransportHint {
    /// LAN socket address (host:port).
    Lan {
        /// Address string, e.g. `192.0.2.10:1234`.
        address: String,
    },
    /// Tailscale MagicDNS or 100.x address.
    Tailscale {
        /// Address string.
        address: String,
    },
    /// One-time rendezvous token for an out-of-band channel.
    RendezvousToken {
        /// Opaque token. Not a vault secret.
        token: String,
    },
}

/// Device-advertised capabilities used during approval and grants.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    /// Whether this device may approve enrollment of others.
    pub can_approve_enrollment: bool,
    /// Whether this device may issue membership grants.
    pub can_issue_grants: bool,
    /// Optional platform label (e.g. `Linux/x86_64`) for the approval UI.
    pub platform: Option<String>,
}

/// Role bound into a membership certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberRole {
    /// Ordinary vault member.
    Member,
    /// Device that may issue further grants according to vault policy.
    Authority,
}

/// Signed enrollment request (CSR analogue). Not secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// Protocol version.
    pub protocol_version: u16,
    /// Joining device id.
    pub device_id: DeviceId,
    /// Human-readable device name.
    pub device_name: String,
    /// Long-term signing public key.
    pub signing_pubkey: SigningPublicKey,
    /// Hybrid KEM public key the grant envelope is sealed to.
    pub kem_pubkey: HybridKemPublicKey,
    /// Ephemeral public key bound into the SAS fingerprint.
    pub ephemeral_pubkey: X25519PublicKey,
    /// Optional connectivity hints.
    pub transport_hints: Vec<TransportHint>,
    /// Advertised capabilities.
    pub capabilities: DeviceCapabilities,
    /// Fresh request nonce.
    #[serde(with = "crate::hexutil")]
    pub nonce: [u8; 32],
    /// Request expiry.
    pub expires_at: Timestamp,
    /// Signature over the request transcript by `signing_pubkey`.
    pub self_signature: SignatureBytes,
}

impl EnrollmentRequest {
    /// Binary transcript with `self_signature` omitted.
    #[must_use]
    pub fn transcript(&self) -> crate::transcript::Transcript {
        let mut t = crate::transcript::Transcript::new(crate::transcript::DOMAIN_ENROLL_REQUEST);
        t.push_u16(self.protocol_version);
        t.push_fixed(self.device_id.as_bytes());
        t.push_bytes(self.device_name.as_bytes());
        t.push_fixed(self.signing_pubkey.as_bytes());
        t.push_fixed(self.kem_pubkey.x25519.as_bytes());
        t.push_bytes(self.kem_pubkey.ml_kem_768.as_bytes());
        t.push_fixed(self.ephemeral_pubkey.as_bytes());
        t.push_u16(u16::try_from(self.transport_hints.len()).unwrap_or(u16::MAX));
        for hint in &self.transport_hints {
            match hint {
                TransportHint::Lan { address } => {
                    t.push_u8(1);
                    t.push_bytes(address.as_bytes());
                }
                TransportHint::Tailscale { address } => {
                    t.push_u8(2);
                    t.push_bytes(address.as_bytes());
                }
                TransportHint::RendezvousToken { token } => {
                    t.push_u8(3);
                    t.push_bytes(token.as_bytes());
                }
            }
        }
        t.push_u8(u8::from(self.capabilities.can_approve_enrollment));
        t.push_u8(u8::from(self.capabilities.can_issue_grants));
        t.push_bytes(
            self.capabilities
                .platform
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        t.push_fixed(&self.nonce);
        t.push_u64(self.expires_at.as_millis());
        t
    }
}

/// Opaque ciphertext wrapping vault key material to the joining device's hybrid KEM.
///
/// This is not a mailbox object; it travels with the grant on any transport.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EncryptedVaultKeyEnvelope(Vec<u8>);

impl EncryptedVaultKeyEnvelope {
    /// Wrap ciphertext bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the ciphertext.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EncryptedVaultKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedVaultKeyEnvelope")
            .field("len", &self.0.len())
            .finish()
    }
}

/// First-device vault authority. Grants are verified against this key, never
/// against a public key chosen inside the certificate being verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRoot {
    /// Vault this root governs.
    pub vault_id: VaultId,
    /// Root signing public key (v1: the first device's signing key).
    pub root_signing_pubkey: SigningPublicKey,
    /// Root generation (starts at 1).
    pub generation: u64,
}

impl VaultRoot {
    /// Binary transcript of the root (no signature; the root is the trust anchor).
    #[must_use]
    pub fn transcript(&self) -> crate::transcript::Transcript {
        let mut t = crate::transcript::Transcript::new("shelf/vault-root/v1");
        t.push_fixed(self.vault_id.as_bytes());
        t.push_fixed(self.root_signing_pubkey.as_bytes());
        t.push_u64(self.generation);
        t
    }

    /// Short hex fingerprint for CLI display (first 8 bytes of the transcript hash).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::hexutil::encode(&self.transcript().hash()[..8])
    }
}

/// Thin membership view shipped with a grant, signed by [`VaultRoot`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    /// Vault root this snapshot is bound to.
    pub vault_root: VaultRoot,
    /// Membership generation.
    pub generation: u64,
    /// Current vault epoch.
    pub epoch: EpochId,
    /// Valid member certificates (root device + joiner at minimum).
    pub certificates: Vec<MembershipCertificate>,
    /// Root signature over [`Self::transcript`].
    pub snapshot_signature: SignatureBytes,
}

impl MembershipSnapshot {
    /// Binary transcript with `snapshot_signature` omitted.
    #[must_use]
    pub fn transcript(&self) -> crate::transcript::Transcript {
        let mut t = crate::transcript::Transcript::new(crate::transcript::DOMAIN_ENROLL_SNAPSHOT);
        t.push_fixed(self.vault_root.transcript().as_bytes());
        t.push_u64(self.generation);
        t.push_u64(self.epoch.as_u64());
        t.push_u16(u16::try_from(self.certificates.len()).unwrap_or(u16::MAX));
        let mut certs = self.certificates.clone();
        certs.sort_by(|a, b| a.device_id.as_bytes().cmp(b.device_id.as_bytes()));
        for cert in &certs {
            t.push_bytes(cert.transcript().as_bytes());
        }
        t
    }
}

/// Opaque encrypted snapshot of membership state bundled with a grant.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EncryptedMembershipState(Vec<u8>);

impl EncryptedMembershipState {
    /// Wrap ciphertext bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the ciphertext.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EncryptedMembershipState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMembershipState")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Membership certificate bindings listed in the enrollment design.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCertificate {
    /// Vault this certificate admits the device into.
    pub vault_id: VaultId,
    /// Admitted device.
    pub device_id: DeviceId,
    /// Device signing key bound by the certificate.
    pub signing_pubkey: SigningPublicKey,
    /// Device hybrid KEM key bound by the certificate.
    pub kem_pubkey: HybridKemPublicKey,
    /// Role in the vault.
    pub role: MemberRole,
    /// Capability bits/flags.
    pub capabilities: DeviceCapabilities,
    /// Certificate serial.
    pub serial: u64,
    /// Vault epoch at issue.
    pub epoch: EpochId,
    /// Issuing device identity (informational; verification uses [`VaultRoot`]).
    pub issuer: DeviceId,
    /// Issuer signing public key (informational; not a trust anchor).
    pub issuer_signing_pubkey: SigningPublicKey,
    /// Issue time.
    pub issued_at: Timestamp,
    /// Optional certificate expiration.
    pub expires_at: Option<Timestamp>,
    /// Hash of the enrollment request this certificate answers.
    #[serde(with = "crate::hexutil")]
    pub request_hash: [u8; 32],
    /// Issuer signature over the bindings.
    pub issuer_signature: SignatureBytes,
}

impl MembershipCertificate {
    /// Binary transcript with `issuer_signature` omitted.
    #[must_use]
    pub fn transcript(&self) -> crate::transcript::Transcript {
        let mut t = crate::transcript::Transcript::new(crate::transcript::DOMAIN_ENROLL_CERT);
        t.push_fixed(self.vault_id.as_bytes());
        t.push_fixed(self.device_id.as_bytes());
        t.push_fixed(self.signing_pubkey.as_bytes());
        t.push_fixed(self.kem_pubkey.x25519.as_bytes());
        t.push_bytes(self.kem_pubkey.ml_kem_768.as_bytes());
        t.push_u8(match self.role {
            MemberRole::Member => 0,
            MemberRole::Authority => 1,
        });
        t.push_u8(u8::from(self.capabilities.can_approve_enrollment));
        t.push_u8(u8::from(self.capabilities.can_issue_grants));
        t.push_bytes(
            self.capabilities
                .platform
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        t.push_u64(self.serial);
        t.push_u64(self.epoch.as_u64());
        t.push_fixed(self.issuer.as_bytes());
        t.push_fixed(self.issuer_signing_pubkey.as_bytes());
        t.push_u64(self.issued_at.as_millis());
        t.push_u8(u8::from(self.expires_at.is_some()));
        if let Some(exp) = self.expires_at {
            t.push_u64(exp.as_millis());
        }
        t.push_fixed(&self.request_hash);
        t
    }
}

/// Grant delivered to a joining device after approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipGrant {
    /// Vault root used to authenticate this grant.
    pub vault_root: VaultRoot,
    /// Hash of the enrollment request this grant answers.
    #[serde(with = "crate::hexutil")]
    pub request_hash: [u8; 32],
    /// Approver nonce bound into the two-way SAS.
    #[serde(with = "crate::hexutil")]
    pub approver_nonce: [u8; 32],
    /// Signed membership certificate.
    pub certificate: MembershipCertificate,
    /// Vault key material sealed to the joiner.
    pub key_envelope: EncryptedVaultKeyEnvelope,
    /// Root-signed membership snapshot.
    pub snapshot: MembershipSnapshot,
}

/// Enrollment state machine (docs/ENROLLMENT.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnrollmentState {
    /// No local identity yet.
    Uninitialized,
    /// Device identity exists; no outstanding request.
    IdentityReady,
    /// Joining device is waiting with a live request.
    EnrollmentPending,
    /// Trusted member has a verified request awaiting user approval.
    ApprovalPending,
    /// Approver has issued a grant; joiner has not finished import.
    GrantIssued,
    /// Device holds a validated certificate and vault keys.
    Member,
}

/// Events that drive [`EnrollmentState::transition`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EnrollmentEvent {
    /// `shelf init` / first-launch identity generation.
    Init,
    /// Joining device created an enrollment request.
    CreateRequest,
    /// Trusted member received and verified a request.
    VerifiedRequest,
    /// User approved the pending request.
    Approve,
    /// Joiner validated the certificate and decrypted the envelope.
    ValidateGrant,
    /// Failure path: return to [`EnrollmentState::IdentityReady`] when allowed.
    Fail,
}

/// Illegal enrollment state-machine step.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum EnrollmentError {
    /// The `(state, event)` pair is not a permitted edge.
    #[error("invalid enrollment transition from {from:?} via {event:?}")]
    InvalidTransition {
        /// State before the event.
        from: EnrollmentState,
        /// Event that was rejected.
        event: EnrollmentEvent,
    },
}

impl EnrollmentState {
    /// Apply an event, returning the next state or a typed error.
    ///
    /// Allowed forward edges:
    /// `Uninitialized --Init--> IdentityReady --CreateRequest--> EnrollmentPending
    /// --VerifiedRequest--> ApprovalPending --Approve--> GrantIssued
    /// --ValidateGrant--> Member`.
    ///
    /// `Fail` from pending states returns to `IdentityReady`.
    pub fn transition(self, event: EnrollmentEvent) -> Result<Self, EnrollmentError> {
        let next = match self {
            Self::Uninitialized => match event {
                EnrollmentEvent::Init => Some(Self::IdentityReady),
                EnrollmentEvent::CreateRequest
                | EnrollmentEvent::VerifiedRequest
                | EnrollmentEvent::Approve
                | EnrollmentEvent::ValidateGrant
                | EnrollmentEvent::Fail => None,
            },
            Self::IdentityReady => match event {
                EnrollmentEvent::CreateRequest => Some(Self::EnrollmentPending),
                EnrollmentEvent::Init
                | EnrollmentEvent::VerifiedRequest
                | EnrollmentEvent::Approve
                | EnrollmentEvent::ValidateGrant
                | EnrollmentEvent::Fail => None,
            },
            Self::EnrollmentPending => match event {
                EnrollmentEvent::VerifiedRequest => Some(Self::ApprovalPending),
                EnrollmentEvent::Fail => Some(Self::IdentityReady),
                EnrollmentEvent::Init
                | EnrollmentEvent::CreateRequest
                | EnrollmentEvent::Approve
                | EnrollmentEvent::ValidateGrant => None,
            },
            Self::ApprovalPending => match event {
                EnrollmentEvent::Approve => Some(Self::GrantIssued),
                EnrollmentEvent::Fail => Some(Self::IdentityReady),
                EnrollmentEvent::Init
                | EnrollmentEvent::CreateRequest
                | EnrollmentEvent::VerifiedRequest
                | EnrollmentEvent::ValidateGrant => None,
            },
            Self::GrantIssued => match event {
                EnrollmentEvent::ValidateGrant => Some(Self::Member),
                EnrollmentEvent::Fail => Some(Self::IdentityReady),
                EnrollmentEvent::Init
                | EnrollmentEvent::CreateRequest
                | EnrollmentEvent::VerifiedRequest
                | EnrollmentEvent::Approve => None,
            },
            Self::Member => match event {
                EnrollmentEvent::Init
                | EnrollmentEvent::CreateRequest
                | EnrollmentEvent::VerifiedRequest
                | EnrollmentEvent::Approve
                | EnrollmentEvent::ValidateGrant
                | EnrollmentEvent::Fail => None,
            },
        };
        next.ok_or(EnrollmentError::InvalidTransition { from: self, event })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{DeviceId, ML_KEM_768_PUBLIC_KEY_LEN, MlKem768PublicKey};

    fn all_events() -> [EnrollmentEvent; 6] {
        [
            EnrollmentEvent::Init,
            EnrollmentEvent::CreateRequest,
            EnrollmentEvent::VerifiedRequest,
            EnrollmentEvent::Approve,
            EnrollmentEvent::ValidateGrant,
            EnrollmentEvent::Fail,
        ]
    }

    fn all_states() -> [EnrollmentState; 6] {
        [
            EnrollmentState::Uninitialized,
            EnrollmentState::IdentityReady,
            EnrollmentState::EnrollmentPending,
            EnrollmentState::ApprovalPending,
            EnrollmentState::GrantIssued,
            EnrollmentState::Member,
        ]
    }

    #[test]
    fn happy_path_reaches_member() {
        let mut state = EnrollmentState::Uninitialized;
        state = state.transition(EnrollmentEvent::Init).unwrap();
        state = state.transition(EnrollmentEvent::CreateRequest).unwrap();
        state = state.transition(EnrollmentEvent::VerifiedRequest).unwrap();
        state = state.transition(EnrollmentEvent::Approve).unwrap();
        state = state.transition(EnrollmentEvent::ValidateGrant).unwrap();
        assert_eq!(state, EnrollmentState::Member);
    }

    #[test]
    fn uninitialized_to_member_is_rejected() {
        let err = EnrollmentState::Uninitialized
            .transition(EnrollmentEvent::ValidateGrant)
            .unwrap_err();
        assert_eq!(
            err,
            EnrollmentError::InvalidTransition {
                from: EnrollmentState::Uninitialized,
                event: EnrollmentEvent::ValidateGrant,
            }
        );
    }

    #[test]
    fn fail_returns_to_identity_ready_from_pending() {
        let pending = EnrollmentState::EnrollmentPending
            .transition(EnrollmentEvent::Fail)
            .unwrap();
        assert_eq!(pending, EnrollmentState::IdentityReady);
        let approval = EnrollmentState::ApprovalPending
            .transition(EnrollmentEvent::Fail)
            .unwrap();
        assert_eq!(approval, EnrollmentState::IdentityReady);
        let grant = EnrollmentState::GrantIssued
            .transition(EnrollmentEvent::Fail)
            .unwrap();
        assert_eq!(grant, EnrollmentState::IdentityReady);
    }

    #[test]
    fn illegal_transitions_table() {
        let allowed = [
            (EnrollmentState::Uninitialized, EnrollmentEvent::Init),
            (
                EnrollmentState::IdentityReady,
                EnrollmentEvent::CreateRequest,
            ),
            (
                EnrollmentState::EnrollmentPending,
                EnrollmentEvent::VerifiedRequest,
            ),
            (EnrollmentState::EnrollmentPending, EnrollmentEvent::Fail),
            (EnrollmentState::ApprovalPending, EnrollmentEvent::Approve),
            (EnrollmentState::ApprovalPending, EnrollmentEvent::Fail),
            (EnrollmentState::GrantIssued, EnrollmentEvent::ValidateGrant),
            (EnrollmentState::GrantIssued, EnrollmentEvent::Fail),
        ];
        for state in all_states() {
            for event in all_events() {
                let result = state.transition(event);
                if allowed.contains(&(state, event)) {
                    assert!(result.is_ok(), "{state:?} + {event:?} should succeed");
                } else {
                    let err = result.expect_err("illegal edge");
                    assert_eq!(
                        err,
                        EnrollmentError::InvalidTransition { from: state, event }
                    );
                }
            }
        }
    }

    #[test]
    fn envelope_is_opaque_bytes() {
        let env = EncryptedVaultKeyEnvelope::from_bytes(vec![0xab, 0xcd]);
        assert_eq!(env.as_bytes(), &[0xab, 0xcd]);
        let _ = DeviceId::new();
        let _ = MlKem768PublicKey::from_bytes(vec![0x11; ML_KEM_768_PUBLIC_KEY_LEN]).unwrap();
    }
}
