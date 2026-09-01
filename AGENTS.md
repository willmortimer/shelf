# Agent guide

## Source of truth

Product and architecture docs live in `docs/`. Start at `docs/INDEX.md`.

## Locked decisions

See [docs/INDEX.md](docs/INDEX.md#locked-decisions). In brief:

- Membership is independent of Tailscale; enrollment is transport-independent.
- No plaintext network mode and no plaintext persistent-object mode.
- Mailbox is optional, ciphertext-only, and cannot enroll devices. `shelf-core` must not depend on it.
- Hardware-backed identity keys when available; all other state under `~/.shelf/`.
- GUI is never required; headless `shelfd` + `shelf` is a complete install.
- Clipboard capture is explicit, not continuous surveillance.
- Expiration is a signed replicated operation; tombstones prevent resurrection.
- Preferred crypto: X25519 + ML-KEM-768; XChaCha20-Poly1305 AEAD.
- Scratch CRDT: Yrs (not Automerge).
- License: MIT.
- Use host Tailscale; do not embed `tsnet`.

## Working agreements

- Prefer the stack and repo shape in `docs/STACK.md`.
- Do not widen scope past stated non-goals (Shelf is not Lattice; no knowledge-base features).
- No secrets in logs, tests, or fixtures; follow `docs/SECURITY.md`.
- Ask before changing public API/CLI vocabulary fixed in the specs (`shelf put`, `shelf latest`, `shelf enroll`, `.shelfjoin` / `.shelfgrant`, etc.).

## Layout

```text
crates/     shelf-core, shelf-store, shelf-transport, shelf-keystore, shelf-protocol, shelf-client
apps/       shelfd, shelf-cli, shelf-desktop, shelf-ios
services/   shelf-mailbox
docs/       INDEX, STACK, architecture, design, security, encryption, enrollment
```
