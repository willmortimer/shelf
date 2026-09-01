# Shelf Security Model

## Security objective

Shelf is designed so that ordinary operation does not expose plaintext data to untrusted storage or untrusted network infrastructure.

There is no supported plaintext synchronization mode.

There is no supported plaintext persistent-object mode.

## Threat model

Shelf should protect confidentiality and integrity when an attacker can:

- capture LAN traffic,
- operate a malicious Wi-Fi network,
- capture traffic traversing an application relay,
- dump the Shelf mailbox database,
- copy an object-store bucket,
- obtain a backup of `~/.shelf/`,
- scrape a VPS filesystem,
- compromise the Shelf mailbox software,
- impersonate arbitrary unauthenticated network peers,
- later gain substantially stronger cryptanalytic capabilities.

Shelf should also limit damage from:

- accidental local database disclosure,
- stale offline replicas,
- compromised routing/control infrastructure,
- device revocation events.

## Explicit non-goals

Shelf cannot guarantee that an already-authorized endpoint forgets plaintext it previously received.

Once a trusted device has decrypted an object, a malicious or compromised endpoint can retain or export it.

Shelf can guarantee protocol-level deletion behavior for honest replicas, but it cannot revoke information already learned by a malicious endpoint.

Shelf also cannot keep plaintext secret from the target application after a user intentionally places content onto the system clipboard or opens it.

## Layered security

Shelf uses defense in depth:

```text
hardware-backed device identity
        +
Shelf application-layer E2EE
        +
Tailscale/WireGuard when available
        +
encrypted local persistence
        +
zero-knowledge optional relay
```

Tailscale is treated as a private routing fabric, not as the sole cryptographic boundary.

## Device trust

Each device owns a unique identity.

A Shelf vault stores membership as signed device certificates and revocation/epoch state.

A Tailscale node being present on the user's tailnet does not automatically make it a Shelf member.

## Key custody

Preferred key custody:

```text
macOS/iOS    Secure Enclave / Keychain
Windows      TPM-backed CNG provider / Windows Hello policy
Linux        TPM2 where available
Headless     TPM2 or Kage provider
Fallback     passphrase-protected recovery material
```

Exportable raw private identity keys should not be written to `~/.shelf/` when a platform keystore can hold or wrap them.

Current wrap-key providers (identity secrets stay wrapped under the wrap key):

```text
macOS     Keychain generic password (`shelf.wrap-key`)
Linux     Secret Service via `secret-tool`
Windows   DPAPI blob `wrap.dpapi` (TPM-backed when the OS is)
Passphrase Argon2id
File      `wrap.key` mode 0600 only with `--allow-file-key` (never on iOS)
```

`$SHELF_HOME`, `$HOME/.shelf`, or `%USERPROFILE%\.shelf` is required. There is no `./.shelf` CWD fallback. Home directories are created mode 0700.

## User presence

Normal synchronization should not require biometric approval for every operation.

Suggested model:

```text
normal unlocked device
    → routine sync allowed

sensitive lifecycle operation
    → require user presence where available
```

Lifecycle operations that may require Touch ID, Windows Hello, Kage approval, or equivalent:

- adding a device,
- removing/revoking a device,
- exporting recovery material,
- rotating vault roots,
- changing high-value security policy,
- decrypting explicitly protected items.

## Protected objects

Shelf may optionally support a stronger per-object class:

```text
Normal
Protected
Ephemeral
```

Protected objects may require user presence before their object key is unwrapped locally.

## Post-quantum posture

Shelf should protect long-lived key material and durable encrypted data against harvest-now-decrypt-later threats.

Preferred enrollment/key-wrap design:

```text
X25519 + ML-KEM-768 hybrid
```

The application should use mature provider implementations and avoid implementing standardized primitives itself.

Operational signatures may initially remain conventional where that substantially simplifies implementation and performance, while identity/root events can migrate toward hybrid authentication as ecosystem support matures.

## Revocation

Device removal rotates the vault epoch.

Example:

```text
epoch 17
  Mac
  PC
  Phone

remove PC

epoch 18
  Mac
  Phone
```

The removed PC may still possess old epoch material and previously decrypted content. It does not receive epoch 18 secrets and cannot decrypt newly created data. Honest replicas keep wrapped historical epoch keys locally so objects sealed under epoch 17 still open after rotation.

## Tailnet compromise resistance

If Tailscale is used, Shelf still validates Shelf membership certificates independently.

Where available, Tailnet Lock can provide an additional layer by preventing arbitrary unauthorized node insertion into the tailnet, but Shelf must not rely on it for vault authorization.

## Metadata minimization

The mailbox should see as little as possible:

```text
opaque mailbox identifier
opaque object identifier
ciphertext size
ciphertext
TTL
acknowledgement state
```

Avoid exposing:

- plaintext filenames (not stored in SQLite `objects.name`; v3 envelopes keep names inside AEAD),
- note titles,
- content hashes of plaintext,
- labels,
- human-readable device names unless necessary,
- object previews.

Scratch pad ids are derived with a vault-keyed BLAKE3 index key, not `VaultId || name`.

Peer TLS uses rustls/ring today (not PQ). Object encryption and enrollment wraps remain X25519 + ML-KEM-768. That is acceptable for transient sessions; the durable-data PQ layer is the one that matters.

`shelfd` unlocks a passphrase vault with `--passphrase-fd` or `SHELF_PASSPHRASE` (never a passphrase argv).

## Plaintext hashing

Do not expose a public deterministic hash such as:

```text
BLAKE3(plaintext)
```

as a public object ID because this permits known-plaintext probing.

If plaintext-based deduplication is used, use a vault-keyed construction such as keyed BLAKE3, or address encrypted content instead.

## Expiration and cryptographic erasure

Shelf uses random per-object data-encryption keys (DEKs).

Expiration deletes:

- ciphertext,
- the wrapped DEK,
- previews,
- plaintext caches,
- search artifacts.

Destroying the only remaining wrapped DEK provides useful cryptographic-erasure semantics for honest replicas.

## Anti-resurrection

Deletion/expiration must be represented by signed replicated operations.

Tombstones persist much longer than the original content and are eventually compacted behind a monotonic global/local garbage-collection watermark.

This prevents a stale replica from reintroducing an expired secret after weeks or months offline.

## Security invariants

1. A mailbox breach never reveals Shelf plaintext or vault keys.
2. A LAN attacker cannot enroll a device merely by discovering `shelfd`.
3. Tailscale membership alone never grants Shelf access.
4. Every joining device proves possession of its private key material.
5. Enrollment grants are bound to the joining device's public keys.
6. Expiration state cannot be silently rolled back by an old honest replica.
7. `~/.shelf/` may contain sensitive ciphertext and metadata but should not contain unprotected raw private identity keys when hardware-backed custody exists.
