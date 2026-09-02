# Install Shelf

How to get a usable `shelfd` + `shelf` on one machine, then enroll a second device. The GUI is never required. There is no brew/deb/msi yet; binaries come from `cargo install`.

## Prerequisites

- [mise](https://mise.jdx.dev/) (pins the workspace Rust toolchain)
- Host [Tailscale](https://tailscale.com/) if you want replica dial over the tailnet (optional; membership is independent of Tailscale)
- A graphical session only if you want `shelf-desktop`

## First run

From a clone:

```bash
mise install
mise run install
shelf init --name desktop
```

`mise run install` puts `shelfd`, `shelf`, and `shelf-desktop` in `~/.cargo/bin` (keep that directory on `PATH`). Headless hosts can skip the GUI:

```bash
cargo install --path apps/shelfd --force
cargo install --path apps/shelf-cli --force
```

`shelf init --name …` creates the device identity and vault under `~/.shelf/`. Prefer platform wrap (Keychain, Windows Hello / DPAPI, or the Linux keyring). Pass `--passphrase` only when you accept a passphrase-wrapped wrap key. `--allow-file-key` is the 0600 `wrap.key` escape hatch.

### Enroll a second device (files)

This is the transport-independent path. The mailbox cannot enroll devices.

On the joining device (after `mise run install` and `shelf init --name laptop`):

```bash
shelf enroll export --out laptop.shelfjoin
```

On the vault-root device (the first `shelf init`):

```bash
shelf enroll approve --join laptop.shelfjoin --out laptop.shelfgrant
```

Back on the joining device, confirm the printed SAS matches the approver (or pass `--expect-sas`):

```bash
shelf enroll import --grant laptop.shelfgrant
```

When `shelfd` is already up on that `--home`, `shelf enroll` talks to it over local IPC; otherwise the CLI opens the vault directly.

`shelf devices` is not in this tree yet. Until that command exists, file export / approve / import is the enrollment path.

### Start the user service

Do this **after** `shelf init` so the daemon opens the named vault instead of creating an unnamed one.

**macOS** (LaunchAgent, KeepAlive):

```bash
mise run install-macos
```

**Linux** (systemd `--user`):

```bash
mise run install-linux
```

On a headless Linux box, enable lingering so the user unit runs without a login session: `loginctl enable-linger "$USER"`.

**Windows** (Startup shortcut; named-pipe IPC is already in the daemon):

```powershell
powershell -ExecutionPolicy Bypass -File contrib\windows\install-user.ps1
```

Then log off/on, or start `%USERPROFILE%\.cargo\bin\shelfd.exe` once.

Check the daemon: `shelf ls` (empty is fine).

### Desktop shortcut

`shelf-desktop` is a searchable palette. It does not register a global hotkey. Bind the OS shortcut (for example Cmd/Ctrl+Shift+V) to the `shelf-desktop` binary on `PATH` (`~/.cargo/bin/shelf-desktop`). See [DESIGN.md](DESIGN.md) for the palette vs explicit-capture model.

### Two devices on Tailscale

Replica Tailscale dials only the intersection of currently online host-Tailscale IPs and **verified member routing hints**. An empty hint set does not spray the tailnet (LAN / mailbox can still run).

Join export already fills hints from `tailscale status --json` (self MagicDNS and Tailscale IPs) when that command succeeds. Run Tailscale on **both** members before `shelf enroll export` / `approve` so each side’s hints land in the grant snapshot.

## Passphrase-protected vaults

`shelfd` never takes a passphrase on argv. Unlock order (see `apps/shelfd/src/passphrase.rs`):

1. systemd `CREDENTIALS_DIRECTORY` file `shelf.passphrase`
2. `--passphrase-fd`
3. `SHELF_PASSPHRASE`
4. hidden TTY prompt when stdin is a TTY

A user service has no TTY, so do not rely on the prompt for launchd / systemd / Startup.

**Do not** put the passphrase in the launchd plist, the systemd unit, or the Windows Startup shortcut.

- **Linux:** uncomment `LoadCredential=shelf.passphrase` in `contrib/systemd/shelfd.service` (or a drop-in) after placing a 0600 file at `~/.config/credstore/shelf.passphrase`. systemd then sets `CREDENTIALS_DIRECTORY`; `shelfd` reads `shelf.passphrase` from that directory.
- **macOS:** prefer Keychain wrap at `shelf init` so the agent needs no secret. For a passphrase vault, a wrapper can run `security find-generic-password` and export `SHELF_PASSPHRASE` for that process only — never commit that value into `com.shelf.shelfd.plist`.
- **Windows:** prefer platform custody. If you must use `SHELF_PASSPHRASE`, set it in the user environment, not in `install-user.ps1`.

## Developer tasks

Pinned toolchain stays in repo-root `mise.toml`. Useful tasks:

| Task | What it runs |
|---|---|
| `mise run fmt` | `cargo fmt --all` |
| `mise run clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `mise run test` | `cargo test --workspace` |
| `mise run install` | `cargo install` of `shelfd`, `shelf`, and `shelf-desktop` |
| `mise run install-macos` | `install` plus LaunchAgent bootstrap/load |
| `mise run install-linux` | `install` plus systemd `--user` enable --now |

User-service units live under `contrib/`. Packaging (brew/deb/msi) is out of scope here.
