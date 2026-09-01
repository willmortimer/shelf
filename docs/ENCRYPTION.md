# Shelf Encryption Design

## Goals

The encryption subsystem must provide:

- application-layer E2EE independent of transport,
- secure encrypted persistence,
- post-quantum protection for long-lived key exchange where practical,
- device revocation through epoch rotation,
- per-object cryptographic erasure,
- zero-knowledge mailbox compatibility,
- resumable encrypted chunked file transfer.

## Device identity keys

Each device generates its own key material.

Conceptually:

```text
DeviceIdentity
├── signing key
├── classical KEM/ECDH key
├── post-quantum KEM key
└── hardware wrapping/binding handle
```

Preferred hybrid KEM profile:

```text
X25519 + ML-KEM-768
```

The exact wire construction must be selected from a well-reviewed library/provider rather than improvised.

## Wrap-key custody

The 32-byte device wrap key protects identity secrets and the vault epoch key. Create order is fail-closed:

1. `--passphrase` → Argon2id (salt in `wrap.salt`)
2. Platform store: macOS Keychain (`security` CLI), iOS Keychain (`security-framework`), Linux Secret Service (`secret-tool`), Windows DPAPI (`wrap.dpapi`)
3. `--allow-file-key` → `~/.shelf/wrap.key` created with mode 0600 (unsafe hatch)
4. Otherwise init fails. iOS never uses file wrap (`allow_file_key` stays false; Keychain or a passphrase only).

Existing vaults that already have `wrap.key` still load it. Headless installs work with a platform store or a passphrase; Kage is not required.

Windows DPAPI is the TPM-adjacent path when the OS binds the user logon to a TPM. There is no separate PKCS#11 / `tpm2-tss` provider yet.

## Vault epochs

A Shelf vault has a current epoch secret.

```text
VaultEpochKey[17]
VaultEpochKey[18]
...
```

Membership changes that remove a device are a root-only `EpochTransition`: the origin must be the vault root signing key. The transition includes a new epoch, a root-signed membership snapshot, and a hybrid wrap of the new epoch key for every remaining device. Receivers unwrap their envelope, install the new epoch, retain previous epoch keys, and drop the revoked member. Each replica keeps a local keyring of historical epoch keys, stored as wrap-key ciphertext in `state.db` (`epoch_wraps`), so objects sealed under older epochs still open after rotation.

## Object keys

Each object receives an independent random 256-bit data-encryption key (DEK).

```text
object plaintext
      │
      ▼
random DEK
      │
      ▼
AEAD encryption
      │
      ▼
object ciphertext
```

The DEK is wrapped under a vault/epoch-derived key-encryption mechanism.

```text
DEK
 ↓
KeyEnvelope(epoch=N, object=ID)
```

This is preferred over deterministic object-key derivation because deleting the wrapped DEK enables stronger cryptographic-erasure semantics.

## AEAD

A suitable initial AEAD profile is:

```text
XChaCha20-Poly1305
```

with a fresh random nonce per encryption.

AES-256-GCM is also acceptable when a provider/platform benefits substantially from hardware acceleration, provided nonce safety is rigorously enforced.

The implementation should define algorithm identifiers/versioning in every envelope to permit future migration.

## Domain separation

All derived keys must use explicit domain separation.

Example logical labels:

```text
shelf/object/v1
shelf/chunk/v1
shelf/metadata/v1
shelf/enrollment/v1
shelf/membership/v1
shelf/search/v1
shelf/recovery/v1
```

Do not reuse raw root material across different cryptographic purposes.

## Object envelope

Conceptual structure:

```rust
struct EncryptedObject {
    version: u16,
    object_id: ObjectId,
    epoch: EpochId,
    algorithm: AeadAlgorithm,
    nonce: Vec<u8>,
    wrapped_dek: KeyEnvelope,
    ciphertext: Vec<u8>,
    ciphertext_hash: Hash,
}
```

Authenticated associated data for v3 binds object ID, protocol version, and epoch. Content class, origin, name, created time, retention policy, and `expires_at` live inside the AEAD plaintext so mailbox JSON cannot leak them. Honest replicas independently apply the same expiry. Nonce and ciphertext are Base64 on the JSON wire (not JSON number arrays). Replica operation signatures use a canonical binary transcript (`shelf/op/v1`), not JSON serialization.

## Object IDs and deduplication

Avoid publishing raw hashes of plaintext.

Acceptable strategies:

1. random opaque object IDs, simplest and strongest privacy;
2. keyed BLAKE3 IDs using a vault-specific index key;
3. ciphertext-addressing where operationally useful.

For Shelf's transient design, random opaque IDs are a very reasonable default. Chunk-level vault-private deduplication may later use keyed BLAKE3.

## File chunks

Large files are encrypted chunk-by-chunk.

```text
FileManifest
├── object metadata
├── logical filename
├── MIME type
├── total size
└── encrypted chunk references[]
```

Each chunk has:

```text
opaque chunk ID
parent object ID
parent expiry
independent nonce
independent AEAD ciphertext
integrity hash of ciphertext
```

Replicas that have a file manifest but not its chunks emit a signed `NeedChunks` op; holders reply with the matching `Chunk` envelopes. GC deletes chunks when the parent is tombstoned or expired.

Chunk keys may either:

- be independent random DEKs wrapped by the manifest/object key, or
- be derived from a random per-file root key using a domain-separated KDF and chunk index.

A random per-file root with derived per-chunk keys is probably the best balance between erasure, compact manifests, and efficient transfer.

## Search indexes

Plaintext full-text indexes must not be written unencrypted outside protected local storage.

Possible strategies:

- decrypt into an in-memory search index at runtime,
- maintain an encrypted local search database,
- index only non-secret operational metadata,
- later implement keyed token indexes if truly needed.

For v1, prefer simple local decrypted-in-memory search over complicated searchable-encryption schemes.

## Hardware-backed storage

Hardware-backed keys should wrap or directly own the device's long-term identity/root secrets.

Logical model:

```text
Secure Enclave / TPM / Kage
        │
        ▼
Device wrapping key
        │
        ▼
encrypted device secret material
        │
        ▼
~/.shelf/state.db or key envelope file
```

The file system may contain encrypted key blobs that are useless without the TPM/Secure Enclave/Kage-controlled wrapping key.

On iOS, wrap-key custody is a Keychain generic password (`service` `shelf.wrap-key`, `account` derived from the app home the same way as macOS) via the `security-framework` crate (MIT/Apache-2.0, Apple-only target dependency). The item is hardware-encrypted with Secure Enclave–bound class keys when the device has a Secure Enclave. iOS still never writes `wrap.key`. macOS continues to use the `security` CLI, not `security-framework`.

## Headless fallback

For systems without appropriate hardware-backed custody, Shelf may use a passphrase-protected software key store in `~/.shelf/`.

Requirements:

- Argon2id or equivalently strong memory-hard password KDF,
- random salt,
- configurable resource parameters,
- locked-down filesystem permissions,
- clear indication that hardware-backed protection is unavailable.

No unencrypted private key files.

## Recovery

Recovery material is a separate explicitly generated artifact, never an automatic plaintext backup of device private keys.

v1 bundle (`shelf/recovery/v1`, file extension `.shelfrecovery`):

```text
RecoveryRoot (vault root identity secrets
              + current epoch key
              + membership snapshot
              + sealed object envelopes)
   ↓
Argon2id (salt in the bundle) → wrap key
   ↓
XChaCha20-Poly1305, AAD = transcript(shelf/recovery/v1, version, vault_id)
```

CLI:

```bash
shelf recovery export --out vault.shelfrecovery
shelf recovery apply --from vault.shelfrecovery
```

The bundle passphrase is a hidden TTY prompt when stdin is a TTY, otherwise `SHELF_RECOVERY_PASSPHRASE` (not argv). It is not the vault wrap-key passphrase. Apply targets an empty `--home` and is always CLI-direct so a running daemon of another vault cannot receive the bundle. Export uses local IPC when `shelfd` is up.

Apply restores the existing `VaultRoot` (decrypt + v1 root-only grants). A mailbox cannot recover a vault. Recovery is versioned; Kage-managed recovery keys are out of scope for v1.

## Forward secrecy considerations

Normal peer sessions use rustls (`shelf/1`) with a membership hello bound to the TLS exporter so compromise of a long-term identity key does not automatically expose all previously captured online traffic.

Persistent object confidentiality is protected separately by object DEKs and epoch key envelopes.

## Algorithm agility

Every cryptographic wire/storage structure must contain version and algorithm identifiers.

Shelf must support migration by decrypting old material and rewrapping/re-encrypting it under newer profiles without changing the logical object identity where possible.
