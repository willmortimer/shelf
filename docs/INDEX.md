# Docs index

Start here. Product and architecture docs in this directory are the contract.

## Map

| Doc | What it covers |
|---|---|
| [README.md](README.md) | Product overview, components, `~/.shelf/` layout, repo shape, design invariants |
| [INSTALL.md](INSTALL.md) | First-run how-to: `mise` install, `shelf init`, file enroll, user-service units |
| [STACK.md](STACK.md) | Languages, workspace layout, packaging, intended crate/app roles |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Process model, crate graph, transports, storage, key providers |
| [DESIGN.md](DESIGN.md) | User primitives, CLI/GUI/iOS surfaces, retention, transfers |
| [SECURITY.md](SECURITY.md) | Threat model, non-goals, key custody, revocation, security invariants |
| [ENCRYPTION.md](ENCRYPTION.md) | Identity keys, epochs, DEKs, AEAD, domain separation, recovery |
| [ENROLLMENT.md](ENROLLMENT.md) | Device init, grants, fingerprints, offline/QR/LAN/Tailscale flows |

## Locked decisions

Extracted from the design pack; do not contradict these without an explicit decision to change the contract.

1. Shelf membership is independent of Tailscale membership.
2. The mailbox is optional, ciphertext-only, and cannot enroll devices.
3. Enrollment is transport-independent.
4. Every device has a distinct cryptographic identity.
5. Every object is encrypted before persistence or transmission. No plaintext network mode and no plaintext persistent-object mode.
6. Expired objects must not be resurrected by long-offline replicas (signed expire ops + long-lived tombstones).
7. The GUI is never a required dependency for the daemon or CLI.
8. A headless install is fully usable with only `shelfd`, `shelf`, the platform keystore, and `~/.shelf/`.
9. System clipboard integration is explicit by default, not continuous surveillance.
10. The security architecture must remain valid when Tailscale, LAN discovery, or the mailbox are absent.
11. Hardware-backed secrets live in the platform keystore/TPM/Secure Enclave when available; everything else lives under `~/.shelf/`.
12. Preferred hybrid KEM: X25519 + ML-KEM-768. Preferred initial AEAD: XChaCha20-Poly1305.
13. `shelf-core` must not depend on `shelf-mailbox`. The mailbox is one transport implementation.
14. Tailscale is the preferred connectivity fabric, not the cryptographic trust boundary. Use the host Tailscale install; do not embed `tsnet`.
15. License is MIT (chosen after bootstrap; not stated in the original pack).
16. Scratch CRDT implementation is Yrs (pack suggested Automerge).
