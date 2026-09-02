# shelf-ios

Native iOS shell over the same Rust crates. There is **no always-on `shelfd`** on
iOS. The app, Share Sheet extension, and App Intents call `shelf-mobile`
(`MobileSession`) in-process when the system gives the process a runtime.

Host CI does **not** build the iOS target. Leave it that way.

## Layout

```text
apps/shelf-ios/
├── README.md                 (this file)
└── Sources/
    ├── ShelfMobile.swift     C ABI via @_silgen_name
    ├── ShareExtension.swift  Share Sheet → shelf_mobile_put_text
    └── PutIntent.swift        App Intent / Shortcuts / Action Button
```

## Build and link `libshelf_mobile.a`

`shelf-mobile` is `crate-type = ["rlib", "staticlib"]` so host `cargo test`
still uses the rlib, while Xcode links the staticlib.

```bash
rustup target add aarch64-apple-ios
# Simulator (Apple Silicon):
# rustup target add aarch64-apple-ios-sim

cargo build -p shelf-mobile --release --target aarch64-apple-ios
```

In the Xcode target:

1. Add `target/aarch64-apple-ios/release/libshelf_mobile.a` to **Link Binary
   With Libraries**.
2. Add `crates/shelf-mobile/include` to **Header Search Paths**, or copy
   `shelf_mobile.h` into the app. Swift call sites use `@_silgen_name` (see
   `Sources/ShelfMobile.swift`) so a bridging header is optional; keep the
   header next to the staticlib as the ABI contract.
3. Also link the iOS SDK libraries Rust needs (`libiconv`, Security.framework
   for Keychain wrap). No App Store signing is required to compile locally.

The Swift files compile in Xcode, not in this Cargo workspace. There is no
uniffi; the C ABI is the only FFI.

## Wrap-key custody

`MobileSession` opens the vault with `allow_file_key = false`. Wrap keys live
in the iOS Keychain (`shelf.wrap-key`, same account scheme as macOS) through
`security-framework` in `shelf-keystore`. That path is hardware-backed when
the device has a Secure Enclave. iOS never writes `wrap.key`; a passphrase
is the only software fallback.

To type-check the Keychain path on a Mac with the iOS SDK:

```bash
rustup target add aarch64-apple-ios
cargo check -p shelf-keystore --target aarch64-apple-ios
```

## Replication

Replication is opportunistic: `MobileSession::sync_once` (C:
`shelf_mobile_sync_once`) runs when the app or extension is in the foreground.
If `config.toml` has `mailbox_url`, it uses `MailboxClient` to GET signed
replica frames, ingest Put/Pin/Tombstone/Scratch/Chunk through store APIs,
ACK, and PUT local signed Put ops to peer mailbox bindings. It does not run
the `shelfd` replica loop (no Tailscale/LAN, no epoch-transition apply).
Membership still uses `.shelfjoin` / `.shelfgrant` (AirDrop the files) until
an in-app enroll UI exists.

Stop any desktop `shelfd` using the same files before importing a grant on
another OS; iOS uses its own sandbox home.
