# Shelf Enrollment

## Principle

Enrollment is independent of the mailbox and independent of any specific transport.

The mailbox must never be required to establish trust.

Shelf separates:

```text
Identity       Who is this cryptographic device?
Membership     Is this device part of my Shelf vault?
Connectivity   How can two devices exchange enrollment bytes?
```

## Device initialization

On first launch:

```bash
shelf init
```

or the equivalent GUI action generates a new device identity locally.

Custody is fail-closed: platform store or `--passphrase`. Use `--allow-file-key` only when you accept a 0600 `wrap.key`. iOS never uses file wrap.

Conceptual state:

```text
DeviceIdentity
├── DeviceId
├── signing public key
├── X25519 public key
├── ML-KEM-768 public key
├── private material protected by platform keystore
└── optional transport hints
```

Private key material never leaves the device during normal enrollment.

## Enrollment request

The joining device creates an `EnrollmentRequest`.

```rust
struct EnrollmentRequest {
    protocol_version: u16,
    device_id: DeviceId,
    device_name: String,
    signing_pubkey: SigningPublicKey,
    kem_pubkey: HybridKemPublicKey,
    ephemeral_pubkey: EphemeralPublicKey,
    transport_hints: Vec<TransportHint>,
    capabilities: DeviceCapabilities,
    nonce: [u8; 32],
    expires_at: Timestamp,
    self_signature: Signature,
}
```

The request is not secret. It is a signed request analogous to a CSR.

It may travel through:

- Tailscale,
- LAN,
- QR code,
- `.shelfjoin` file,
- USB drive,
- AirDrop or equivalent,
- copy/paste,
- another messaging channel.

Security does not depend on the confidentiality of the request.

## Human-verifiable fingerprint

Both devices derive a short authentication string from the enrollment transcript, e.g. six human-readable words.

```text
anchor marble cactus
falcon velvet lunar
```

The fingerprint should bind:

- request hash,
- vault root,
- issuer identity,
- grant hash (certificate + envelope + snapshot),
- approver nonce.

The joining device must confirm the **grant SAS** (two-way). Offline CLI:

```bash
shelf enroll import foo.shelfgrant --expect-sas "velvet luna cactus marble"
```

or, on a TTY, confirm the printed SAS matches the trusted device. Import verifies
the certificate and snapshot under [`VaultRoot`], not a public key chosen inside
the grant. The first device is the vault root (its signing key). Only that device
may issue grants in this version.

## Membership grant

## Approval

A trusted existing Shelf device receives the request and displays:

```text
Add device?

Name: optiprox3
Platform: Linux/x86_64
Transport: Tailscale direct
Fingerprint:
anchor marble cactus falcon velvet lunar
```

Approval may require Touch ID, Windows Hello, Kage approval, TPM-backed PIN/user presence, or another configured high-value authorization method.

## Membership grant

The approving device creates:

```rust
struct MembershipGrant {
    vault_root: VaultRoot,
    request_hash: EnrollmentRequestHash,
    approver_nonce: [u8; 32],
    certificate: MembershipCertificate,
    key_envelope: EncryptedVaultKeyEnvelope,
    snapshot: MembershipSnapshot,
}
```

`VaultRoot` is created at `shelf init` on the first device. A membership certificate
never establishes the key used to authenticate itself. Signatures use
length-prefixed binary transcripts, not JSON. The hybrid wrap AAD binds the
request hash, vault root, joiner keys, and certificate hash.

The membership certificate binds:

```text
vault ID
device ID
device signing key
device hybrid KEM key
role/capabilities
serial/epoch
issuer identity
issue time
expiration if used
```

The grant is signed by an already authorized Shelf device/root authority according to the vault policy.

The vault key material is encrypted specifically to the joining device's hybrid KEM public key.

An interceptor therefore gains no vault secret from the grant.

## Normal nearby enrollment

Preferred UX:

```text
New device
  ↓
show QR enrollment request
  ↓
Trusted phone/Mac scans QR
  ↓
compare fingerprint
  ↓
user approves with biometric/Kage
  ↓
devices exchange membership grant directly
```

The QR should contain an enrollment request plus transport hints, not sensitive vault secrets.

Possible transport hints:

```text
LAN address
Tailscale address
one-time rendezvous token
```

## Tailscale enrollment

When both devices are on the same tailnet, the joining daemon can advertise a pending request.

Example:

```bash
$ shelf enroll
Waiting for approval...

Device: optiprox3
Fingerprint: anchor marble cactus falcon velvet lunar
```

Trusted device:

```bash
$ shelf devices pending
ID      DEVICE      PATH
3c87    optiprox3   tailscale/direct

$ shelf devices approve 3c87
```

Tailscale device identity is useful context but is not sufficient authorization.

## LAN enrollment

A joining device may advertise a minimal enrollment service via mDNS/DNS-SD.

Example:

```text
_shelf-enroll._udp.local
```

The LAN is treated as hostile.

Discovery provides only a route to the joining device. The enrollment protocol itself authenticates cryptographic keys and the human-verifiable fingerprint.

## Offline file enrollment

Shelf supports a two-file offline flow:

```text
.shelfjoin
.shelfgrant
```

Joining machine:

```bash
shelf enroll export --out optiprox3.shelfjoin
```

Trusted machine:

```bash
shelf enroll approve --join optiprox3.shelfjoin --out optiprox3.shelfgrant
```

Joining machine:

```bash
shelf enroll import --grant optiprox3.shelfgrant
```

When `shelfd` is running on the same `--home` / `--socket`, `shelf enroll`
goes through local IPC against the daemon's open vault. When the daemon is
down, the CLI opens `state.db` directly. Requests and grants are
Ed25519-signed; a tampered `.shelfjoin` is rejected. Import persists the
grant's vault id and epoch, not only the wrapped epoch key.

This works without Tailscale, LAN, a mailbox, or simultaneous connectivity.

## Offline QR enrollment

An optional air-gapped flow may support animated/multi-frame QR transfer.

```text
request QR frames
   ↓
trusted device scans
   ↓
approval
   ↓
grant QR frames
   ↓
joining device scans
```

This is useful for constrained or air-gapped environments but should not be the normal path.

## Enrollment state machine

Conceptually:

```text
UNINITIALIZED
    │
    ├── init
    ▼
IDENTITY_READY
    │
    ├── create request
    ▼
ENROLLMENT_PENDING
    │
    ├── verified request received by trusted member
    ▼
APPROVAL_PENDING
    │
    ├── user approves
    ▼
GRANT_ISSUED
    │
    ├── joining device validates certificate + decrypts envelope
    ▼
MEMBER
```

Failure paths return to `IDENTITY_READY` or keep the current pending request until expiry.

## Revocation

Removing a device:

1. emits a signed revocation operation,
2. advances membership state,
3. creates a new vault epoch secret,
4. distributes the new epoch only to remaining authorized members.

The removed device retains whatever old data it previously possessed but cannot decrypt objects created under the new epoch.

## Recovery and the last device

A mailbox cannot recover a lost vault because it has no keys.

Users create an explicit recovery artifact with a strong passphrase:

```bash
shelf recovery export --out vault.shelfrecovery
shelf recovery apply --from vault.shelfrecovery --allow-file-key
```

The bundle (`shelf/recovery/v1`) wraps the vault root identity, current epoch key, membership snapshot, and sealed objects. Apply restores that `VaultRoot` onto an empty `--home` so the recovered device can decrypt and issue v1 root-only grants. The bundle passphrase is a hidden TTY prompt or `SHELF_RECOVERY_PASSPHRASE` (never argv, never logged). Export can go through `shelfd` when it is up; apply is always CLI-direct against `--home`.

Recovery is a separate trust path and should never silently weaken normal device enrollment. Kage-managed recovery keys are out of scope for this version.

## Config/state placement

Enrollment state that is not secret lives beneath:

```text
~/.shelf/
```

Examples:

```text
~/.shelf/enrollment/
~/.shelf/export/
~/.shelf/state.db
```

Long-term private key material should instead be held or wrapped by:

- Secure Enclave/Keychain,
- Windows TPM/CNG,
- Linux TPM2,
- Kage,
- passphrase-encrypted fallback if no hardware-backed provider exists.
