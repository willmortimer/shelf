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
│   └── shelf-client/        # local IPC client used by CLI/GUI/adapters
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
- `shelf init` / `shelf enroll` write identity + vault under `--home` (file wrap 0600, or Argon2id with `--passphrase`). Platform custody is tried first: macOS Keychain (`security`), Linux Secret Service (`secret-tool`), Windows DPAPI (`wrap.dpapi`). File 0600 remains the fallback. `shelf enroll` must not run while `shelfd` holds `state.db`.
- Replica fan-out: host `tailscale status --json` (no tsnet), framed TCP peer sessions on `peer_port` (default 18733), LAN UDP (`lan_port`, default 18732), optional mailbox at `mailbox_url`. Put/pin/rm notify the replica immediately; signed pin/tombstone frames keep two daemons consistent. Mailbox protocol is newline JSON PUT/GET/ACK; default listen `127.0.0.1:8743`.
- Desktop GUI must not own a second configuration tree. `shelf-desktop` is a searchable palette (copy-on-select). Bind an OS keyboard shortcut to the `shelf-desktop` binary for a global hotkey.
- iOS: `crates/shelf-mobile` in-process session; Swift stubs in `apps/shelf-ios/` (not a Cargo member). Windows IPC: named pipes `\\.\pipe\shelf-<hash>`.

## Intended dependencies (not pinned yet)

Listed for later implementation; not added to manifests in the bootstrap pass.

- CRDT text: Yrs (`yrs`) for scratchpads (design pack suggested Automerge; implementation uses Yrs)
- Local store: SQLite via `rusqlite` (bundled)
- Crypto providers: X25519, ML-KEM-768, XChaCha20-Poly1305, Argon2id, keyed BLAKE3
- Desktop: Slint
- CLI: clap
- Discovery: mDNS/DNS-SD for LAN (`_shelf._udp.local`, `_shelf-enroll._udp.local`) — not pinned yet

Versions live in the workspace `[workspace.dependencies]` table.

## Packaging / CI

Dev pin: `mise.toml` (`rust` 1.98.0 with rustfmt, clippy, rust-src). CI: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.

## License

MIT. See the repo-root `LICENSE`.
