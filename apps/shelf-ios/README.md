# shelf-ios

Native iOS shell over the same Rust crates. There is **no always-on `shelfd`** on
iOS. The app, Share Sheet extension, and App Intents call `shelf-mobile`
(`MobileSession`) in-process when the system gives the process a runtime.

## Layout

```text
apps/shelf-ios/
├── README.md                 (this file)
└── Sources/
    ├── ShareExtension.swift  Share Sheet → shelf-mobile put
    └── PutIntent.swift        App Intent / Shortcuts / Action Button
```

Link `shelf-mobile` as a static library from the Xcode project (cargo
`aarch64-apple-ios` / `aarch64-apple-ios-sim`). The Swift files are the
intended call sites; they compile in Xcode, not in this Cargo workspace.

## Wrap-key custody

`MobileSession` opens the vault with `allow_file_key = false`. Wrap keys live
in the iOS Keychain (`shelf.wrap-key`, same account scheme as macOS) through
`security-framework` in `shelf-keystore`. That path is hardware-backed when
the device has a Secure Enclave. iOS never writes `wrap.key`; a passphrase
is the only software fallback.

Host CI does not compile `target_os = "ios"`. To type-check the Keychain
path on a Mac with the iOS SDK:

```bash
rustup target add aarch64-apple-ios
cargo check -p shelf-keystore --target aarch64-apple-ios
```

## Replication

Replication is opportunistic: when the app or extension runs, open the vault
and let a future transport pass use Tailscale/LAN/mailbox if the platform
allows sockets. Membership still uses `.shelfjoin` / `.shelfgrant` (AirDrop
the files) until an in-app enroll UI exists.

Stop any desktop `shelfd` using the same files before importing a grant on
another OS; iOS uses its own sandbox home.
