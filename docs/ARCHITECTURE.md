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

Because iOS does not allow a permanent arbitrary user daemon, the same core
libraries are embedded in-process via `crates/shelf-mobile` (`MobileSession`).
Share Sheet and App Intent Swift call sites live in `apps/shelf-ios/` (not a
Cargo member) and link `libshelf_mobile.a`. Replication is opportunistic
(`MobileSession::sync_once`) when the app or extension is running.

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
├── shelf-client/
└── shelf-mobile/        # in-process vault for iOS (no daemon)
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

Peer sessions are rustls. Replica peers negotiate ALPN `shelf/2`: length-prefixed binary (`SHLF` + version + big-endian `u32` length + a hand-encoded Hello/Have/Op payload — not JSON, and not a bare `SignedOperation`). Outbound sessions are pooled by `SocketAddr` from the membership-aware dial set: the rustls stream stays open across notify/30s ticks, each tick re-sends `Have`, and I/O errors reconnect. Inbound accepts stay open until EOF. Mailbox and local IPC stay newline-delimited JSON (`read_bounded_line` / `write_bounded_line`). Membership hello is bound to the TLS exporter (the exporter is taken from the live TLS connection, never from the serialized hello). Peers exchange `Have` cursor vectors (`origin → max seq`) and send only missing signed operations. Inbound ops are verified, checked for `(origin, seq)` uniqueness and `op_id` replay, persisted as the original signed bytes, then applied. Replica Tailscale dials only the intersection of currently online host-Tailscale IPs and routing hints from a *verified* membership snapshot (`routing_hints` copied from join-file `TransportHint`s). No member hints means no Tailscale dial (do not spray the tailnet); mailbox and LAN fan-out are unchanged. Tailscale membership is never Shelf membership. Tailscale IPs are handshake-or-drop: a failed membership hello never receives ciphertext. LAN UDP is discovery-only. Mailbox items must be signed operations deposited into each *peer's* receive mailbox using that device's write capability; a device polls only its own mailbox with a local read capability. File chunks carry a parent object id and the parent's expiry; missing chunks are requested with `NeedChunks` and answered with `Chunk` ops. Scratch edits are distinct ops (deduped by ciphertext hash); after the first write the sealed body is a Yrs diff from the last-applied state vector. Root-only `EpochTransition` ops carry per-remaining-device hybrid wraps of the new epoch key. Networking loads member keys from a root-signed membership snapshot, not loose cert rows. Unsigned mailbox blobs and raw Yrs are dropped. IPC, mailbox, and peer frames stop reading once they would exceed 8 MiB.

Shelf may inspect whether a peer path is direct or relayed to make bandwidth decisions, but Shelf E2EE is identical in either case.

## LAN transport

LAN discovery uses mDNS/DNS-SD `_shelf._udp.local` (implemented) plus a UDP announce fallback on `lan_port`. `_shelf-enroll._udp.local` is reserved for enrollment and is not registered by `shelfd`.

```text
_shelf._udp.local
_shelf-enroll._udp.local
```

DNS-SD SRV records advertise this daemon's `peer_port`. Announce/browse carry routing metadata only; sealed objects and replica ops stay on rustls ALPN `shelf/2`. Discovery does not confer trust: an attacker on the LAN may discover a daemon but cannot become a Shelf member without an authenticated enrollment grant, and a failed membership hello never receives ciphertext.

## Mailbox transport

The optional mailbox is a zero-knowledge store-and-forward queue.

It has no Shelf membership certificate and no vault key.

Minimal semantics:

```text
PUT mailbox-id write-cap object-id ciphertext ttl
GET mailbox-id read-cap
ACK mailbox-id read-cap object-id
```

Write capability is bound on first PUT; read capability is bound on first GET. Knowing a mailbox address is not enough to drain it. Each enrolled device has its own mailbox id; replicas PUT to *other* members' mailboxes and GET only their own.

The current implementation is newline-delimited JSON over TCP (`shelf-mailbox`, default `127.0.0.1:8743`). Ciphertext is Base64. Lines are read a byte at a time and rejected above 8 MiB (the reader never allocates past the cap). The mailbox never decrypts. Per-mailbox caps are 8 MiB per item, 4096 items, and 64 MiB total. The process persists ciphertext to `--data` (default `shelf-mailbox.json`); it is still not a member and still cannot enroll devices.

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

`state.db` object rows carry ciphertext plus listing metadata (`pinned`, `archived`, `labels`). `ls` omits archived objects unless the client requests them; search decrypts live non-archived objects in memory.

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
Argon2id passphrase
0600 `wrap.key` only with `--allow-file-key` (never on iOS)
```

Identity signing/KEM secrets remain wrapped under that wrap key. TPM PKCS#11 / `tpm2-tss` is not a separate provider yet.

Only non-secret configuration, encrypted material, and state should be placed in `~/.shelf/`.
