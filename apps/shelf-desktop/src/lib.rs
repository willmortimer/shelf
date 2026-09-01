//! Slint recent-item palette. Talks to `shelfd` over local IPC.

/// One line in the palette: `kind  id` (no plaintext).
#[must_use]
pub fn format_line(kind: &str, id: &str) -> String {
    format!("{kind}  {id}")
}

/// Filter listing lines by a case-insensitive substring of kind or id.
#[must_use]
pub fn filter_lines(lines: &[String], query: &str) -> Vec<(usize, String)> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return lines
            .iter()
            .enumerate()
            .map(|(i, l)| (i, l.clone()))
            .collect();
    }
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.to_ascii_lowercase().contains(&q))
        .map(|(i, l)| (i, l.clone()))
        .collect()
}

/// Copy bytes using pbcopy / wl-copy / xclip / xsel / clip.
pub fn copy_clipboard(bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else if cfg!(target_os = "linux") {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard", "-i"]),
            ("xsel", &["--clipboard", "--input"]),
        ]
    } else if cfg!(windows) {
        &[("clip", &[])]
    } else {
        &[]
    };

    let mut last = String::from("no clipboard tool on this platform");
    for (bin, args) in candidates {
        if !tool_exists(bin) && *bin != "pbcopy" && *bin != "clip" {
            continue;
        }
        let mut cmd = Command::new(bin);
        cmd.args(*args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(bytes);
                }
                match child.wait() {
                    Ok(status) if status.success() => return Ok(()),
                    Ok(_) => last = format!("{bin} failed"),
                    Err(e) => last = e.to_string(),
                }
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

fn tool_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_has_kind_and_id_not_payload() {
        let line = format_line("text", "ab".repeat(32).as_str());
        assert!(line.starts_with("text"));
        assert!(!line.contains("secret"));
    }

    #[test]
    fn filter_matches_kind_or_id_and_keeps_original_index() {
        let lines = vec!["text  aaa".into(), "json  bbb".into(), "file  ccc".into()];
        let hits = filter_lines(&lines, "JSON");
        assert_eq!(hits, vec![(1, "json  bbb".into())]);
        assert_eq!(filter_lines(&lines, "").len(), 3);
    }
}
