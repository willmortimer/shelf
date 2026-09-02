# Stack

Derived from [README.md](README.md) and [ARCHITECTURE.md](ARCHITECTURE.md). This file is the repo-shape contract for scaffolding and later implementation.

## Languages

| Area | Language / UI |
|---|---|
| Core, daemon, CLI, mailbox, desktop logic | Rust |
| Desktop UI | Slint |
| iOS shell | Native iOS (Share Sheet, App Intents, Shortcuts) over the same Rust core where practical |

Package manager: Cargo workspace. Dev toolchain pin: repo-root `mise.toml` (mise, not Nix — docs do not specify a Nix/flake dev workflow).

## Workspace layout

```text
shelf/
├── crates/
│   ├── shelf-core/          # model, identity, enrollment, crypto, CRDT, sync, retention, blob
│   ├── shelf-store/         # SQLite encrypted state
│   ├── shelf-transport/     # Tailscale, LAN, mailbox
│   ├── shelf-keystore/      # Apple, Windows, Linux, Kage (+ passphrase fallback)
│   ├── shelf-protocol/      # wire/storage envelopes
│   ├── shelf-client/        # local IPC client used by CLI/GUI/adapters
│   └── shelf-mobile/       # in-process vault for iOS (no daemon)
│
├── apps/
│   ├── shelfd/              # per-user daemon / replica engine
│   ├── shelf-cli/           # `shelf` CLI (stdin/stdout first-class)
│   ├── shelf-desktop/       # Slint desktop client
│   └── shelf-ios/           # iOS app + extensions (not a Cargo member)
│
└── services/
    └── shelf-mailbox/       # optional zero-knowledge store-and-forward
```

Module directories under each crate's `src/` match the architecture tree. They are empty until implementation.

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

Invariant: `shelf-core` must not depend on `shelf-mailbox`.

## Runtime / state

- Local IPC: Unix domain sockets (macOS/Linux); named pipes or local IPC (Windows).
- Userland state root: `~/.shelf/` (`config.toml`, `state.db`, objects, chunks, logs, runtime, cache, export, enrollment).
- `shelf init` / `shelf enroll` write identity + vault under `--home`. Wrap-key custody is platform store or `--passphrase`; `--allow-file-key` is required for 0600 `wrap.key`. iOS never uses file wrap. When `shelfd` is up, `shelf enroll` uses local IPC against the daemon's open vault; when the daemon is down, the CLI opens the vault directly.
- `shelf recovery export --out` writes a passphrase-wrapped `.shelfrecovery` (`shelf/recovery/v1`: Argon2id + XChaCha20-Poly1305). Passphrase is a hidden TTY or `SHELF_RECOVERY_PASSPHRASE` (not argv). Export uses IPC when `shelfd` is up. `shelf recovery apply --from` is always CLI-direct against an empty `--home` and restores the existing `VaultRoot`. A mailbox cannot recover a vault.
- Replica fan-out: host `tailscale status --json` (no tsnet), rustls `shelf/2` peer sessions on `peer_port` (default 18733) exchanging `Have` cursors and missing signed ops from a durable op log. Outbound TLS is pooled by dial `SocketAddr` and kept across notify/30s ticks (reconnect on I/O error). Tailscale dials only online IPs that also appear in verified member routing hints; an empty hint set does not spray the tailnet (mailbox/LAN still run). LAN DNS-SD `_shelf._udp.local` advertises `peer_port` (UDP announce on `lan_port`, default 18732, as fallback) without ciphertext flood; discovered LAN addrs join the outbound TLS pool separately from Tailscale `dial_addrs`. `config.toml` `sync_mode` (`auto` default; also `prefer_direct`, `always`, `metered`) skips file/chunk ops on relayed Tailscale paths while LAN and direct Tailscale still transfer files. Optional mailbox at `mailbox_url` (mailbox items must be signed frames, PUT to peer write caps). Put/pin/rm/scratch notify the replica immediately. Mailbox protocol is newline JSON PUT/GET/ACK with per-mailbox write/read capabilities; default listen `127.0.0.1:8743` and persist path `--data shelf-mailbox.json`. IPC, mailbox, and peer frames are bounded at 8 MiB. `shelfd` unlocks passphrase vaults via systemd `CREDENTIALS_DIRECTORY`/`shelf.passphrase`, `--passphrase-fd`, `SHELF_PASSPHRASE`, or a hidden TTY prompt. `shelf put --file` sends a path; the daemon streams 4 MiB chunks.
- Desktop GUI must not own a second configuration tree. `shelf-desktop` is a searchable palette (copy-on-select). Bind an OS keyboard shortcut to the `shelf-desktop` binary for a global hotkey.
- iOS: `crates/shelf-mobile` in-process session; Swift stubs in `apps/shelf-ios/` (not a Cargo member). Windows IPC: named pipes `\\.\pipe\shelf-<hash>`.

Peer TLS ALPN `shelf/2` is length-prefixed binary (`SHLF` + version + big-endian `u32` length + a hand-encoded Hello/Have/Op payload). Replica peers use `shelf/2` only (no bare `SignedOperation` JSON on that path). Mailbox and local IPC remain newline-delimited JSON.

## Intended dependencies (not pinned yet)

Listed for later implementation; not added to manifests in the bootstrap pass.

- CRDT text: Yrs (`yrs`) for scratchpads (design pack suggested Automerge; implementation uses Yrs). After the first write, persist seals a Yrs update encoded from the last-applied state vector rather than a full empty-SV document.
- Local store: SQLite via `rusqlite` (bundled)
- Crypto providers: X25519, ML-KEM-768, XChaCha20-Poly1305, Argon2id, keyed BLAKE3
- Desktop: Slint
- CLI: clap
- Discovery: mDNS/DNS-SD via `mdns-sd` (`_shelf._udp.local` implemented; `_shelf-enroll._udp.local` reserved)

Versions live in the workspace `[workspace.dependencies]` table.

## Packaging / CI

Dev pin: `mise.toml` (`rust` 1.98.0 with rustfmt, clippy, rust-src). CI: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` on Ubuntu, macOS, and Windows. The `required` job is the merge gate. `main` should require that check before merge. User-service units (launchd, systemd `--user`, Windows Startup) live under `contrib/`; first-run steps are in [INSTALL.md](INSTALL.md).

## License

MIT. See the repo-root `LICENSE`.
