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

## Vault epochs

A Shelf vault has a current epoch secret.

```text
VaultEpochKey[17]
VaultEpochKey[18]
...
```

Membership changes that remove a device cause a new epoch to be generated and distributed only to currently authorized devices.

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

Authenticated associated data should bind security-relevant metadata such as:

- object ID,
- protocol version,
- epoch ID,
- content class,
- origin device identity where required.

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
independent nonce
independent AEAD ciphertext
integrity hash of ciphertext
```

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

Recovery material should be a separate explicitly generated artifact, never an automatic plaintext backup of device private keys.

Possible model:

```text
RecoveryRoot
   ↓
wrap current vault bootstrap/recovery secret
   ↓
passphrase-encrypted recovery bundle
```

Recovery should be versioned and rotatable.

## Forward secrecy considerations

Normal peer sessions should use ephemeral session keys so compromise of a long-term identity key does not automatically expose all previously captured online traffic.

Persistent object confidentiality is protected separately by object DEKs and epoch key envelopes.

## Algorithm agility

Every cryptographic wire/storage structure must contain version and algorithm identifiers.

Shelf must support migration by decrypting old material and rewrapping/re-encrypting it under newer profiles without changing the logical object identity where possible.
