# Shelf Architecture

## High-level topology

```text
                         optional
                    ┌─────────────────┐
                    │ shelf-mailbox   │
                    │ ciphertext only │
                    └────────┬────────┘
                             │
                   opaque encrypted envelopes
                             │
 ┌───────────────────────────┼───────────────────────────┐
 │                           │                           │
 ▼                           ▼                           ▼
macOS                       Windows                     Linux
shelfd                      shelfd                      shelfd
 │                           │                           │
 ├── encrypted store         ├── encrypted store         ├── encrypted store
 ├── CRDT replica            ├── CRDT replica            ├── CRDT replica
 ├── chunk cache             ├── chunk cache             ├── chunk cache
 ├── Tailscale/LAN peers ────┼───────────────────────────┤
 │                           │                           │
 ├── shelf CLI               ├── shelf CLI               ├── shelf CLI
 └── Slint GUI               └── Slint GUI               └── Slint/TUI optional

                             │
                             ▼
                            iOS
                    Rust core + native shell
                    Share Sheet / App Intents
```

## Process model

### Desktop and server platforms

A per-user `shelfd` owns:

- local identity provider access,
- encrypted state,
- replication,
- peer sessions,
- chunk transfer,
- retention/GC,
- CRDT merge,
- transport selection.

Clients connect locally using:

- Unix domain sockets on macOS/Linux,
- named pipes or local IPC on Windows.

Clients include:

- `shelf` CLI,
- Slint desktop GUI,
- shell adapters,
- clipboard adapters,
- optional TUI.

### iOS

Because iOS does not allow a permanent arbitrary user daemon, the same core libraries should be embedded directly in the app and extension/App Intent targets where feasible. Replication is opportunistic and triggered by foreground/background opportunities permitted by the platform.

## Crate structure

```text
crates/
├── shelf-core/
│   ├── model/
│   ├── identity/
│   ├── enrollment/
│   ├── crypto/
│   ├── crdt/
│   ├── sync/
│   ├── retention/
│   └── blob/
│
├── shelf-store/
│   └── sqlite/
│
├── shelf-transport/
│   ├── tailscale/
│   ├── lan/
│   └── mailbox/
│
├── shelf-keystore/
│   ├── apple/
│   ├── windows/
│   ├── linux/
│   └── kage/
│
├── shelf-protocol/
└── shelf-client/
```

Applications:

```text
apps/
├── shelfd/
├── shelf-cli/
├── shelf-desktop/
└── shelf-ios/
```

Service:

```text
services/
└── shelf-mailbox/
```

## Dependency rules

```text
shelf-desktop ─┐
shelf-cli ─────┼──> shelf-client ──> shelfd
shell adapters ┘

shelfd
 ├── shelf-core
 ├── shelf-store
 ├── shelf-transport
 └── shelf-keystore
```

Important invariant:

```text
shelf-core MUST NOT depend on shelf-mailbox.
```

The mailbox is only one transport implementation.

## Identity, membership, connectivity

Shelf separates:

```text
Identity       Who is this device?
Membership     Is this device trusted by this Shelf vault?
Connectivity   How can bytes reach that device?
```

Tailscale may aid connectivity and provide useful identity context, but Shelf membership is authorized by Shelf's own signed membership graph.

## Transport abstraction

```rust
trait PeerTransport {
    async fn discover(&self) -> Vec<Peer>;
    async fn connect(&self, peer: PeerId) -> Result<Connection>;
}
```

Implementations may include:

```text
TailscaleTransport
LanTransport
MailboxTransport
```

Enrollment is not implemented inside any transport.

## Tailscale transport

Tailscale is the preferred default because it provides private addressing, NAT traversal, direct paths, and relay fallback.

Shelf should use the host's normal Tailscale installation and local APIs/status information rather than embedding a Go `tsnet` runtime into the Rust core.

Peer sessions are newline-delimited JSON `ReplicaFrame` values (objects, signed pins, signed tombstones) over TCP on `peer_port` (default 18733). Peer IPs come from `tailscale status --json`. Put/pin/rm notify the replica immediately (push-on-put); a 30s idle tick is only a backstop. Frames are accepted only when the origin is a membership-table device and the Ed25519 signature verifies.

Shelf may inspect whether a peer path is direct or relayed to make bandwidth decisions, but Shelf E2EE is identical in either case.

## LAN transport

LAN discovery may use mDNS/DNS-SD, for example:

```text
_shelf._udp.local
_shelf-enroll._udp.local
```

Discovery reveals only minimal routing/version metadata.

Discovery does not confer trust. An attacker on the LAN may discover a daemon but cannot become a Shelf member without an authenticated enrollment grant.

## Mailbox transport

The optional mailbox is a zero-knowledge store-and-forward queue.

It has no Shelf membership certificate and no vault key.

Minimal semantics:

```text
PUT mailbox-id object-id ciphertext ttl
GET mailbox-id
ACK object-id
```

The current implementation is newline-delimited JSON over TCP (`shelf-mailbox`, default `127.0.0.1:8743`). Ciphertext is Base64. The mailbox never decrypts.

The exact API may additionally support chunk batching, size limits, quotas, and long-polling, but it should remain intentionally dumb.

Deleting or replacing the mailbox must not alter:

- device identities,
- membership certificates,
- revocation state,
- vault keys,
- enrollment flows.

## Replica vs mailbox

An always-on home server may operate as one of two different things.

### Enrolled replica

An actual Shelf member:

```text
membership certificate
vault key access
CRDT replica
full synchronization capability
```

### Blind mailbox

Not a Shelf member:

```text
no vault key
no membership certificate
no plaintext capability
```

The distinction should be explicit in product and code terminology.

## Storage layout

All ordinary userland Shelf state lives beneath:

```text
~/.shelf/
```

Suggested layout:

```text
~/.shelf/
├── config.toml
├── state.db
├── objects/
├── chunks/
├── logs/
├── runtime/
├── cache/
└── export/
```

Platform-specific wrappers may redirect this directory if required by sandboxing, but the logical layout and single-root model should remain intact.

The desktop GUI must never create a second independent configuration tree.

## Hardware-backed key providers

```rust
trait DeviceKeyProvider {
    fn public_identity(&self) -> DevicePublicIdentity;
    fn sign(&self, data: &[u8]) -> Result<Signature>;
    fn unwrap_device_secret(&self, envelope: &EncryptedEnvelope) -> Result<Secret>;
    fn user_presence_capability(&self) -> UserPresence;
}
```

Providers:

```text
Apple Keychain (`security` generic password; wrap key)
Windows DPAPI (`wrap.dpapi`; TPM-backed when the OS is)
Linux Secret Service (`secret-tool`)
0600 `wrap.key` file fallback
Argon2id passphrase fallback
```

Identity signing/KEM secrets remain wrapped under that wrap key. TPM PKCS#11 / `tpm2-tss` is not a separate provider yet.

Only non-secret configuration, encrypted material, and state should be placed in `~/.shelf/`.
