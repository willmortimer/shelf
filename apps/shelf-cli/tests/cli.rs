//! Integration: `shelf` binary against `shelfd::serve` on a temp socket.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
    for cmd in ["put", "latest", "ls", "get", "pin", "rm"] {
        assert!(
            text.contains(cmd),
            "expected {cmd} in --help output:\n{text}"
        );
    }
}

#[cfg(unix)]
mod ipc {
    use super::*;
    use shelf_client::Client;
    use shelfd::{MemoryStore, serve};

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
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
