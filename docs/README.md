# Shelf

Shelf is a cross-platform, secure-by-construction personal transient data plane that sits between a system clipboard, a file drop service, and a shared scratch space.

Its purpose is simple:

> Make transient information available across your devices without turning it into permanent cloud storage.

Shelf is intentionally smaller than a knowledge-management system such as Lattice. It does not own long-lived information structures, databases, views, canvases, notebooks, or workflows. It exists to move, temporarily retain, and synchronize data between trusted devices.

## Core model

Shelf exposes two primary user-facing primitives:

1. **Shelf** — an ordered replicated collection of immutable clipboard/file objects with CRDT metadata.
2. **Scratch** — one or more small shared CRDT text documents for temporary notes.

The normal system clipboard is only an optional ingress/egress adapter. Shelf does not continuously scrape or mirror the OS clipboard by default.

## Components

```text
shelfd
  Cross-platform per-user daemon and replica engine.

shelf
  CLI client for stdin/stdout, headless Linux, SSH, scripting, and automation.

shelf-desktop
  Slint desktop application for macOS, Windows, and Linux.

shelf-ios
  iOS client using the same Rust core where practical, exposed through
  Share Sheet, App Intents, Shortcuts, and normal application UI.

shelf-mailbox
  Optional zero-knowledge store-and-forward service. It is not a trusted
  Shelf member and never has vault keys.
```

## Security principle

Shelf must have no plaintext network mode and no plaintext persistent object mode.

Tailscale is the preferred connectivity fabric, not the cryptographic trust boundary. Every persisted object and protocol payload that matters to confidentiality is independently encrypted by Shelf before it reaches a transport.

This gives Shelf useful security even if:

- a relay database is stolen,
- an object store is scraped,
- a backup leaks,
- a Tailnet control service is compromised,
- a future transport is less trustworthy than Tailscale,
- a local Shelf SQLite database is copied.

## Configuration and state

Shelf follows one strict rule:

> Hardware-backed secrets live in the platform keystore/TPM/Secure Enclave when available. Everything else lives under `~/.shelf/`.

Examples:

```text
~/.shelf/
├── config.toml
├── state.db
├── objects/
├── chunks/
├── logs/
├── runtime/
└── export/
```

The directory may contain encrypted metadata, ciphertext, cached replication state, non-secret preferences, and transport settings. It must not contain exportable plaintext private identity keys when a hardware-backed provider is available.

On graphical systems, the GUI is only a client. It does not own an independent configuration directory.

## Suggested defaults

- Normal Shelf item retention: **7 days**
- Explicit ephemeral item: **1 hour**
- Large transferred file: **72 hours after confirmed delivery, maximum 7 days unless pinned**
- Scratchpads: persistent until explicitly removed
- Pinned items: persistent
- Mailbox delivered objects: delete promptly after acknowledgement
- Mailbox undelivered objects: maximum **7 days** by default
- Expiration tombstones: retain substantially longer than content, e.g. **90 days**, with compaction watermarks

## Repository shape

```text
shelf/
├── crates/
│   ├── shelf-core/
│   ├── shelf-store/
│   ├── shelf-transport/
│   ├── shelf-keystore/
│   ├── shelf-protocol/
│   └── shelf-client/
│
├── apps/
│   ├── shelfd/
│   ├── shelf-cli/
│   ├── shelf-desktop/
│   └── shelf-ios/
│
└── services/
    └── shelf-mailbox/
```

## Design invariants

1. Shelf membership is independent of Tailscale membership.
2. The mailbox is optional and cannot enroll devices.
3. Enrollment is transport-independent.
4. Every device has a distinct cryptographic identity.
5. Every object is encrypted before persistence or transmission.
6. Expired objects must not be resurrected by long-offline replicas.
7. The GUI never becomes a required dependency for the daemon or CLI.
8. A headless installation is fully usable with only `shelfd`, `shelf`, the platform keystore, and `~/.shelf/`.
9. System clipboard integration is explicit by default, not continuous surveillance.
10. The security architecture must remain valid when Tailscale, LAN discovery, or the mailbox are absent.

See the other documents in this bundle for details.
