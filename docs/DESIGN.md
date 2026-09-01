# Shelf Design

## Product boundary

Shelf is a personal distributed `/tmp`, not a permanent knowledge base.

The basic lifecycle is:

```text
put
 ↓
encrypt
 ↓
replicate
 ↓
available across devices
 ↓
consume
 ↓
expire
```

Pinning is the explicit transition from transient to durable retention.

This gives Shelf a clear conceptual position:

```text
system clipboard
      ↓
    Shelf
      ↓
filesystem / Lattice / password manager / permanent storage
```

## User-facing primitives

### 1. Shelf objects

A Shelf object is immutable content plus mutable CRDT metadata.

```rust
struct ShelfItem {
    id: ObjectId,
    content: ContentRef,
    kind: ContentKind,
    created: HybridTimestamp,
    origin: DeviceId,

    pinned: bool,
    archived: bool,
    expires_at: Option<Timestamp>,
    labels: Set<Label>,
}
```

Initial content kinds:

```text
text
markdown
url
image
file
json
opaque-bytes
```

The content payload itself is immutable. Pinning, expiration, archive state, labels, and removal are represented as replicated operations.

Shelf is deliberately not modeled as a globally linearizable FIFO. A strict distributed `pop()` would require online coordination and would undermine offline-first behavior. Instead, Shelf is a replicated chronological stream with deterministic conflict handling and tombstones.

### 2. Scratchpads

Scratchpads are small collaborative CRDT text documents.

A minimal default set could be:

```text
Scratch
Inbox
Current
```

Users may create a small number of additional pads, but Shelf must resist becoming a page/database system.

A text CRDT such as Automerge is appropriate here. Shelf metadata does not need to be forced into the same generic CRDT model.

## Desktop interaction model

Three complementary surfaces should exist:

### Palette

Global shortcut, for example:

```text
Cmd/Ctrl + Shift + V
```

opens a searchable recent-item palette.

`shelf-desktop` is that palette. Bind the OS global shortcut to the `shelf-desktop` binary (the app does not register a hotkey crate; that keeps CI and Wayland simple). Type to filter by kind or id. Click, or press Return on a match, copies the item into the system clipboard and closes the palette. The user then uses the normal paste shortcut.

This avoids depending on cross-platform synthetic keystroke injection, especially on Wayland.

### Explicit capture

A second shortcut, for example:

```text
Cmd/Ctrl + Shift + C
```

means:

```text
read current system clipboard
→ create Shelf object
```

Continuous clipboard surveillance is disabled by default.

### Full application

The Slint UI should remain small:

```text
Shelf
Scratch
Transfers
Devices
Settings
```

The GUI is a thin client over `shelfd` on desktop systems.

## CLI

The CLI should treat stdin/stdout as first-class interfaces.

```bash
echo "hello" | shelf put
cat config.json | shelf put --name config.json
shelf latest
shelf latest | jq .
shelf get 4 > file.bin
shelf ls
shelf search kubernetes
shelf pin 2
shelf rm 5
shelf scratch
```

Convenience compatibility commands may also be supplied:

```bash
shelf-copy
shelf-paste
```

Example:

```bash
cat config.json | shelf-copy
shelf-paste > config.json
```

A headless Linux machine must need no GUI libraries to run Shelf.

## iOS integration

Shelf should align with explicit iOS user intent rather than silently reading the system pasteboard.

Primary integrations:

```text
Share Sheet → Add to Shelf
Shortcut → Get Clipboard → Add to Shelf
Shortcut → Get Latest Shelf Item → Copy to Clipboard
App Intent → Add to Shelf
App Intent → Fetch Latest Shelf Item
```

This enables use from the Action Button, Control Center, Siri, Spotlight, Back Tap, and Shortcuts without requiring continuous clipboard monitoring.

There is no always-on `shelfd` on iOS. `crates/shelf-mobile` opens the vault in-process; Swift Share Sheet / App Intent stubs in `apps/shelf-ios/` are the intended call sites.

## File transfer

Large files are content manifests referencing encrypted chunks.

```text
FileManifest
├── filename
├── mime
├── size
└── chunk_ids[]
```

Each chunk should be independently encrypted, resumable, and deduplicable inside a vault without exposing plaintext hashes externally.

A practical default chunk size is approximately 4 MiB, subject to benchmarking.

Peer synchronization can exchange availability bitmaps/ranges so interrupted transfers resume naturally.

## Retention policies

Retention is a first-class property, not merely periodic garbage collection.

```rust
struct Retention {
    created_at: Timestamp,
    expires_at: Option<Timestamp>,
    policy: RetentionPolicy,
}
```

Suggested policies:

```text
Ephemeral
Normal
Pinned
Custom
```

Suggested defaults:

| Content | Default retention |
|---|---:|
| Normal Shelf object | 7 days |
| Explicit ephemeral | 1 hour |
| Large transferred file | 72h after delivery, max 7 days |
| Scratchpad | persistent |
| Pinned item | persistent |
| Mailbox delivered object | delete after acknowledgement |
| Mailbox undelivered object | max 7 days |

Retention must be configurable globally and per item.

## Expiration semantics

Expiration generates a replicated signed operation rather than silently deleting local bytes.

```text
ExpireObject {
    object_id,
    effective_at,
}
```

Replicas delete:

- object ciphertext,
- wrapped object keys,
- derived previews,
- plaintext caches,
- local search artifacts.

They retain tombstones and later compact them behind a monotonic garbage-collection watermark.

This prevents ancient offline replicas from resurrecting content that has already expired everywhere else.

## Transfer policy

Shelf can make transport-aware decisions without weakening cryptographic guarantees.

Suggested modes:

```text
Auto
Prefer Direct
Always Sync
Metered
```

Possible default behavior:

```text
small text/metadata      sync immediately
small files              sync immediately
large files on direct    sync immediately
large files over relay   defer unless requested
thumbnails               sync before full media
```

Shelf should prefer local/direct paths for bandwidth efficiency but treat every network as untrusted for confidentiality.
