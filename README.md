# Shelf

Cross-platform personal transient data plane: move clipboard and file objects across trusted devices without turning them into permanent cloud storage.

Two user-facing primitives: **Shelf** (replicated immutable objects with CRDT metadata) and **Scratch** (small shared CRDT text pads).

## Docs

The design pack is the contract. Start at [docs/INDEX.md](docs/INDEX.md).

## Develop

```bash
mise install
cargo metadata
```

Workspace layout and crate roles: [docs/STACK.md](docs/STACK.md).
