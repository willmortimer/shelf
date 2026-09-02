//! Integration: `shelf` binary against `shelfd::serve` on a temp socket.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shelf"))
}

#[test]
fn help_lists_core_commands() {
    let output = Command::new(bin())
        .arg("--help")
        .output()
        .expect("shelf --help");
    assert!(output.status.success(), "stderr={}", stderr_str(&output));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for cmd in [
        "put", "latest", "ls", "get", "pin", "rm", "init", "enroll", "scratch", "capture",
        "recovery", "devices",
    ] {
        assert!(
            text.contains(cmd),
            "expected {cmd} in --help output:\n{text}"
        );
    }
}

#[cfg(unix)]
mod ipc {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use shelf_client::Client;
    use shelfd::{MemoryStore, serve, serve_with_replica};

    static SOCK_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_socket_path() -> PathBuf {
        let seq = SOCK_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("sfcli{}-{seq}.sock", std::process::id()))
    }

    async fn wait_for_socket(path: &Path) {
        let mut last = None;
        for _ in 0..200 {
            match Client::connect(path).await {
                Ok(_) => return,
                Err(err) => last = Some(err),
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "daemon did not accept connections at {}: {last:?}",
            path.display()
        );
    }

    fn shelf(sock: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.arg("--socket").arg(sock);
        cmd.args(args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd
    }

    fn run(sock: &Path, args: &[&str]) -> Output {
        shelf(sock, args).output().expect("spawn shelf")
    }

    fn run_with_stdin(sock: &Path, args: &[&str], stdin: &[u8]) -> Output {
        let mut cmd = shelf(sock, args);
        cmd.stdin(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn shelf");
        {
            let mut inp = child.stdin.take().expect("stdin");
            inp.write_all(stdin).expect("write stdin");
        }
        child.wait_with_output().expect("wait shelf")
    }

    fn assert_success(output: &Output) {
        assert!(
            output.status.success(),
            "status={:?} stdout={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            stderr_str(output)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_then_latest_and_ls_hides_plaintext() {
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
        wait_for_socket(&sock).await;

        let put = run_with_stdin(&sock, &["put"], b"hello");
        assert_success(&put);
        let id = String::from_utf8_lossy(&put.stdout).trim().to_string();
        assert_eq!(id.len(), 64, "put should print hex id, got {id:?}");

        let latest = run(&sock, &["latest"]);
        assert_success(&latest);
        assert_eq!(latest.stdout, b"hello", "latest must not add a newline");

        let ls = run(&sock, &["ls"]);
        assert_success(&ls);
        let ls_text = String::from_utf8_lossy(&ls.stdout);
        assert!(ls_text.contains(&id), "ls missing id:\n{ls_text}");
        assert!(
            !ls_text.contains("hello"),
            "ls must not include plaintext:\n{ls_text}"
        );

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_by_one_based_index() {
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
        wait_for_socket(&sock).await;

        assert_success(&run_with_stdin(&sock, &["put"], b"hello"));
        let get = run(&sock, &["get", "1"]);
        assert_success(&get);
        assert_eq!(get.stdout, b"hello");

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rm_then_get_is_not_found() {
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
        wait_for_socket(&sock).await;

        assert_success(&run_with_stdin(&sock, &["put"], b"hello"));
        let rm = run(&sock, &["rm", "1"]);
        assert_success(&rm);

        let get = run(&sock, &["get", "1"]);
        assert_eq!(get.status.code(), Some(1));
        let err = stderr_str(&get);
        assert!(
            err.to_lowercase().contains("not found") || err.contains("object not found"),
            "expected not-found stderr, got {err:?}"
        );
        assert!(!err.to_lowercase().contains("hello"));

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pin_then_ls_shows_pinned() {
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
        wait_for_socket(&sock).await;

        assert_success(&run_with_stdin(&sock, &["put"], b"hello"));
        let before = run(&sock, &["ls"]);
        assert_success(&before);
        assert!(
            !String::from_utf8_lossy(&before.stdout).contains("pinned"),
            "unpinned ls should not say pinned"
        );

        let pin = run(&sock, &["pin", "1"]);
        assert_success(&pin);
        let ls = run(&sock, &["ls"]);
        assert_success(&ls);
        let ls_text = String::from_utf8_lossy(&ls.stdout);
        assert!(ls_text.contains("pinned"), "ls after pin:\n{ls_text}");
        assert!(!ls_text.contains("hello"));

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scratch_append_then_print() {
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
        wait_for_socket(&sock).await;

        assert_success(&run(&sock, &["scratch", "--append", "hello"]));
        let shown = run(&sock, &["scratch"]);
        assert_success(&shown);
        assert_eq!(shown.stdout, b"hello");

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_file_reassembles() {
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve(sock.clone(), MemoryStore::new()));
        wait_for_socket(&sock).await;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.bin");
        std::fs::write(&path, b"file-bytes").unwrap();
        assert_success(&run(&sock, &["put", "--file", path.to_str().unwrap()]));
        let get = run(&sock, &["get", "1"]);
        assert_success(&get);
        assert_eq!(get.stdout, b"file-bytes");

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enroll_export_succeeds_when_daemon_is_up() {
        let home = tempfile::tempdir().unwrap();
        let vault = shelf_keystore::open_or_create_vault(home.path(), Some("test"), None, true)
            .expect("open vault");
        let base = 20_000 + (std::process::id() % 10_000) as u16;
        std::fs::write(
            home.path().join("config.toml"),
            format!(
                "lan_port = {base}\npeer_port = {}\n",
                base.saturating_add(1)
            ),
        )
        .unwrap();
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve_with_replica(
            sock.clone(),
            vault.store,
            home.path().to_path_buf(),
            vault.keys,
        ));
        wait_for_socket(&sock).await;

        let out = home.path().join("x.shelfjoin");
        let export = Command::new(bin())
            .args([
                "--home",
                home.path().to_str().unwrap(),
                "--socket",
                sock.to_str().unwrap(),
                "enroll",
                "export",
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_success(&export);
        let err = String::from_utf8_lossy(&export.stderr);
        assert!(err.contains("SAS:"), "stderr={err}");
        assert!(out.exists(), "expected join file at {}", out.display());

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recovery_export_apply_latest_matches() {
        let home = tempfile::tempdir().unwrap();
        let vault = shelf_keystore::open_or_create_vault(home.path(), Some("root"), None, true)
            .expect("open vault");
        let base = 30_000 + (std::process::id() % 10_000) as u16;
        std::fs::write(
            home.path().join("config.toml"),
            format!(
                "lan_port = {base}\npeer_port = {}\n",
                base.saturating_add(1)
            ),
        )
        .unwrap();
        let sock = temp_socket_path();
        let _ = std::fs::remove_file(&sock);
        let server = tokio::spawn(serve_with_replica(
            sock.clone(),
            vault.store,
            home.path().to_path_buf(),
            vault.keys,
        ));
        wait_for_socket(&sock).await;

        let put = run_with_stdin(&sock, &["put"], b"hello-recovery");
        assert_success(&put);

        let pass = format!("rec-{}", std::process::id());
        let bundle = home.path().join("vault.shelfrecovery");
        let export = Command::new(bin())
            .args([
                "--home",
                home.path().to_str().unwrap(),
                "--socket",
                sock.to_str().unwrap(),
                "recovery",
                "export",
                "--out",
                bundle.to_str().unwrap(),
            ])
            .env("SHELF_RECOVERY_PASSPHRASE", &pass)
            .output()
            .unwrap();
        assert_success(&export);
        assert!(bundle.exists(), "expected {}", bundle.display());
        let bundle_text = std::fs::read_to_string(&bundle).unwrap();
        assert!(!bundle_text.contains(&pass));
        assert!(!bundle_text.contains("hello-recovery"));

        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_file(&sock);

        let restored = tempfile::tempdir().unwrap();
        let apply = Command::new(bin())
            .args([
                "--home",
                restored.path().to_str().unwrap(),
                "recovery",
                "apply",
                "--from",
                bundle.to_str().unwrap(),
                "--allow-file-key",
            ])
            .env("SHELF_RECOVERY_PASSPHRASE", &pass)
            .output()
            .unwrap();
        assert!(apply.status.success(), "{}", stderr_str(&apply));

        let vault2 = shelf_keystore::open_or_create_vault(restored.path(), None, None, true)
            .expect("open restored");
        let base2 = base.saturating_add(2);
        std::fs::write(
            restored.path().join("config.toml"),
            format!(
                "lan_port = {base2}\npeer_port = {}\n",
                base2.saturating_add(1)
            ),
        )
        .unwrap();
        let sock2 = temp_socket_path();
        let _ = std::fs::remove_file(&sock2);
        let server2 = tokio::spawn(serve_with_replica(
            sock2.clone(),
            vault2.store,
            restored.path().to_path_buf(),
            vault2.keys,
        ));
        wait_for_socket(&sock2).await;
        let latest = run(&sock2, &["latest"]);
        assert_success(&latest);
        assert_eq!(latest.stdout, b"hello-recovery");

        server2.abort();
        let _ = server2.await;
        let _ = std::fs::remove_file(&sock2);
    }
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn init_export_approve_import_two_homes() {
    let member = tempfile::tempdir().unwrap();
    let joiner = tempfile::tempdir().unwrap();
    let join = joiner.path().join("device.shelfjoin");
    let grant = member.path().join("device.shelfgrant");

    let init_m = Command::new(bin())
        .args([
            "--home",
            member.path().to_str().unwrap(),
            "init",
            "--name",
            "mac",
            "--allow-file-key",
        ])
        .output()
        .unwrap();
    assert!(init_m.status.success(), "{}", stderr_str(&init_m));

    let init_j = Command::new(bin())
        .args([
            "--home",
            joiner.path().to_str().unwrap(),
            "init",
            "--name",
            "linux",
            "--allow-file-key",
        ])
        .output()
        .unwrap();
    assert!(init_j.status.success(), "{}", stderr_str(&init_j));

    let export = Command::new(bin())
        .args([
            "--home",
            joiner.path().to_str().unwrap(),
            "enroll",
            "export",
            "--out",
            join.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(export.status.success(), "{}", stderr_str(&export));
    let sas_j = stderr_str(&export);
    assert!(sas_j.contains("SAS:"), "{sas_j}");

    let approve = Command::new(bin())
        .args([
            "--home",
            member.path().to_str().unwrap(),
            "enroll",
            "approve",
            "--join",
            join.to_str().unwrap(),
            "--out",
            grant.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(approve.status.success(), "{}", stderr_str(&approve));
    let sas_m = stderr_str(&approve);
    assert!(sas_m.contains("SAS:"), "{sas_m}");
    let grant_sas = sas_m
        .lines()
        .find_map(|l| l.strip_prefix("SAS: "))
        .expect("approve SAS");

    let import = Command::new(bin())
        .args([
            "--home",
            joiner.path().to_str().unwrap(),
            "enroll",
            "import",
            "--grant",
            grant.to_str().unwrap(),
            "--expect-sas",
            grant_sas,
        ])
        .output()
        .unwrap();
    assert!(import.status.success(), "{}", stderr_str(&import));
    assert!(join.exists());
    assert!(grant.exists());
    assert!(member.path().join("config.toml").exists());
    assert!(member.path().join("state.db").exists());
}

fn home_cmd(home: &std::path::Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("--home").arg(home);
    cmd.args(args);
    cmd
}

fn device_lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn devices_list_then_root_revoke_drops_joiner() {
    let member = tempfile::tempdir().unwrap();
    let joiner = tempfile::tempdir().unwrap();
    let join = joiner.path().join("device.shelfjoin");
    let grant = member.path().join("device.shelfgrant");

    let init_m = home_cmd(
        member.path(),
        &["init", "--name", "mac", "--allow-file-key"],
    )
    .output()
    .unwrap();
    assert!(init_m.status.success(), "{}", stderr_str(&init_m));
    let root_id = String::from_utf8_lossy(&init_m.stdout).trim().to_string();

    let init_j = home_cmd(
        joiner.path(),
        &["init", "--name", "linux", "--allow-file-key"],
    )
    .output()
    .unwrap();
    assert!(init_j.status.success(), "{}", stderr_str(&init_j));
    let joiner_id = String::from_utf8_lossy(&init_j.stdout).trim().to_string();

    let export = home_cmd(
        joiner.path(),
        &["enroll", "export", "--out", join.to_str().unwrap()],
    )
    .output()
    .unwrap();
    assert!(export.status.success(), "{}", stderr_str(&export));

    let approve = home_cmd(
        member.path(),
        &[
            "enroll",
            "approve",
            "--join",
            join.to_str().unwrap(),
            "--out",
            grant.to_str().unwrap(),
        ],
    )
    .output()
    .unwrap();
    assert!(approve.status.success(), "{}", stderr_str(&approve));
    let grant_sas = stderr_str(&approve)
        .lines()
        .find_map(|l| l.strip_prefix("SAS: "))
        .expect("approve SAS")
        .to_owned();

    let import = home_cmd(
        joiner.path(),
        &[
            "enroll",
            "import",
            "--grant",
            grant.to_str().unwrap(),
            "--expect-sas",
            &grant_sas,
        ],
    )
    .output()
    .unwrap();
    assert!(import.status.success(), "{}", stderr_str(&import));

    let listed = home_cmd(member.path(), &["devices"]).output().unwrap();
    assert!(listed.status.success(), "{}", stderr_str(&listed));
    let lines = device_lines(&listed.stdout);
    assert_eq!(
        lines.len(),
        2,
        "stdout={:?}",
        String::from_utf8_lossy(&listed.stdout)
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains(&root_id) && l.contains("(root)")),
        "root missing:\n{}",
        lines.join("\n")
    );
    assert!(
        lines.iter().any(|l| l.contains(&joiner_id)),
        "joiner missing:\n{}",
        lines.join("\n")
    );

    let revoke = home_cmd(member.path(), &["devices", "revoke", &joiner_id])
        .output()
        .unwrap();
    assert!(revoke.status.success(), "{}", stderr_str(&revoke));

    let after = home_cmd(member.path(), &["devices"]).output().unwrap();
    assert!(after.status.success(), "{}", stderr_str(&after));
    let after_lines = device_lines(&after.stdout);
    assert_eq!(
        after_lines.len(),
        1,
        "stdout={:?}",
        String::from_utf8_lossy(&after.stdout)
    );
    assert!(after_lines[0].contains(&root_id));
    assert!(after_lines[0].contains("(root)"));
    assert!(!after_lines[0].contains(&joiner_id));
}

#[test]
fn devices_revoke_from_non_root_fails_typed() {
    let member = tempfile::tempdir().unwrap();
    let joiner = tempfile::tempdir().unwrap();
    let join = joiner.path().join("device.shelfjoin");
    let grant = member.path().join("device.shelfgrant");

    let init_m = home_cmd(
        member.path(),
        &["init", "--name", "mac", "--allow-file-key"],
    )
    .output()
    .unwrap();
    assert!(init_m.status.success(), "{}", stderr_str(&init_m));
    let root_id = String::from_utf8_lossy(&init_m.stdout).trim().to_string();

    let init_j = home_cmd(
        joiner.path(),
        &["init", "--name", "linux", "--allow-file-key"],
    )
    .output()
    .unwrap();
    assert!(init_j.status.success(), "{}", stderr_str(&init_j));

    let export = home_cmd(
        joiner.path(),
        &["enroll", "export", "--out", join.to_str().unwrap()],
    )
    .output()
    .unwrap();
    assert!(export.status.success(), "{}", stderr_str(&export));

    let approve = home_cmd(
        member.path(),
        &[
            "enroll",
            "approve",
            "--join",
            join.to_str().unwrap(),
            "--out",
            grant.to_str().unwrap(),
        ],
    )
    .output()
    .unwrap();
    assert!(approve.status.success(), "{}", stderr_str(&approve));
    let grant_sas = stderr_str(&approve)
        .lines()
        .find_map(|l| l.strip_prefix("SAS: "))
        .expect("approve SAS")
        .to_owned();

    let import = home_cmd(
        joiner.path(),
        &[
            "enroll",
            "import",
            "--grant",
            grant.to_str().unwrap(),
            "--expect-sas",
            &grant_sas,
        ],
    )
    .output()
    .unwrap();
    assert!(import.status.success(), "{}", stderr_str(&import));

    let revoke = home_cmd(joiner.path(), &["devices", "revoke", &root_id])
        .output()
        .unwrap();
    assert!(!revoke.status.success());
    let err = stderr_str(&revoke);
    assert!(
        err.contains("only the vault root can revoke a device"),
        "typed non-root failure, got {err:?}"
    );
    assert!(!err.contains("wrap.key"));
    assert!(!err.contains("SHELF_RECOVERY_PASSPHRASE"));
}

#[test]
fn recovery_wrong_passphrase_fails_typed() {
    let home = tempfile::tempdir().unwrap();
    let init = Command::new(bin())
        .args([
            "--home",
            home.path().to_str().unwrap(),
            "init",
            "--name",
            "root",
            "--allow-file-key",
        ])
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", stderr_str(&init));

    let pass = format!("rec-ok-{}", std::process::id());
    let bundle = home.path().join("vault.shelfrecovery");
    let export = Command::new(bin())
        .args([
            "--home",
            home.path().to_str().unwrap(),
            "recovery",
            "export",
            "--out",
            bundle.to_str().unwrap(),
        ])
        .env("SHELF_RECOVERY_PASSPHRASE", &pass)
        .output()
        .unwrap();
    assert!(export.status.success(), "{}", stderr_str(&export));

    let restored = tempfile::tempdir().unwrap();
    let wrong = format!("rec-bad-{}", std::process::id());
    let apply = Command::new(bin())
        .args([
            "--home",
            restored.path().to_str().unwrap(),
            "recovery",
            "apply",
            "--from",
            bundle.to_str().unwrap(),
            "--allow-file-key",
        ])
        .env("SHELF_RECOVERY_PASSPHRASE", &wrong)
        .output()
        .unwrap();
    assert!(!apply.status.success());
    let err = stderr_str(&apply);
    assert!(
        err.contains("wrong passphrase") || err.contains("recovery bundle"),
        "typed recovery failure, got {err:?}"
    );
    assert!(!err.contains(&pass));
    assert!(!err.contains(&wrong));
}
