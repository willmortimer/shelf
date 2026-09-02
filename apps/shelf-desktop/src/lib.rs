//! Slint desktop client. Talks to `shelfd` over local IPC.

/// Default scratch pad name, matching `shelf scratch`.
pub const DEFAULT_SCRATCH_PAD: &str = "Scratch";

/// Wire name for file objects (`file`).
pub const FILE_KIND: &str = "file";

/// Tab titles in display order.
#[must_use]
pub fn tab_labels() -> [&'static str; 6] {
    [
        "Shelf",
        "Capture",
        "Scratch",
        "Transfers",
        "Devices",
        "Settings",
    ]
}

/// One-line Settings note: desktop does not own a second config tree.
#[must_use]
pub fn settings_home_note() -> &'static str {
    "Home is ~/.shelf or $SHELF_HOME."
}

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

/// Keep listing lines whose kind token is the file wire name.
#[must_use]
pub fn filter_file_lines(lines: &[String]) -> Vec<(usize, String)> {
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line_kind(line) == FILE_KIND)
        .map(|(i, l)| (i, l.clone()))
        .collect()
}

fn line_kind(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

/// One Devices row: hex id, optional name, and `root` for the vault root.
#[must_use]
pub fn format_device_line(id: &str, name: Option<&str>, is_root: bool) -> String {
    match (name.filter(|n| !n.is_empty()), is_root) {
        (Some(name), true) => format!("{id}  {name}  root"),
        (Some(name), false) => format!("{id}  {name}"),
        (None, true) => format!("{id}  root"),
        (None, false) => id.to_string(),
    }
}

/// UTF-8 clipboard bytes are `text`; anything else is `opaque-bytes`.
#[must_use]
pub fn infer_capture_kind(bytes: &[u8]) -> &'static str {
    if std::str::from_utf8(bytes).is_ok() {
        "text"
    } else {
        "opaque-bytes"
    }
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

/// Read the system clipboard (pbpaste / wl-paste / xclip / xsel).
///
/// Windows `clip` is write-only, so capture is unavailable there.
pub fn paste_clipboard() -> Result<Vec<u8>, String> {
    use std::process::Command;

    if cfg!(windows) {
        return Err("Windows `clip` is write-only; capture is unavailable on this platform".into());
    }

    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbpaste", &[])]
    } else if cfg!(target_os = "linux") {
        &[
            ("wl-paste", &["--no-newline"]),
            ("xclip", &["-selection", "clipboard", "-o"]),
            ("xsel", &["--clipboard", "--output"]),
        ]
    } else {
        &[]
    };

    let mut last = String::from("no clipboard tool on this platform");
    for (bin, args) in candidates {
        if !tool_exists(bin) && *bin != "pbpaste" {
            continue;
        }
        let mut cmd = Command::new(bin);
        cmd.args(*args);
        match cmd.output() {
            Ok(out) if out.status.success() => return Ok(out.stdout),
            Ok(_) => last = format!("{bin} failed"),
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

    #[test]
    fn tab_labels_match_design_surfaces() {
        assert_eq!(
            tab_labels(),
            [
                "Shelf",
                "Capture",
                "Scratch",
                "Transfers",
                "Devices",
                "Settings"
            ]
        );
    }

    #[test]
    fn filter_file_lines_keeps_file_kind_only() {
        let lines = vec![
            "text  aaa".into(),
            "file  bbb".into(),
            "json  ccc".into(),
            "file  ddd".into(),
        ];
        let hits = filter_file_lines(&lines);
        assert_eq!(hits, vec![(1, "file  bbb".into()), (3, "file  ddd".into())]);
    }

    #[test]
    fn format_device_line_shows_id_name_and_root() {
        assert_eq!(
            format_device_line("abc", Some("laptop"), true),
            "abc  laptop  root"
        );
        assert_eq!(
            format_device_line("abc", Some("phone"), false),
            "abc  phone"
        );
        assert_eq!(format_device_line("abc", None, true), "abc  root");
        assert_eq!(format_device_line("abc", Some(""), false), "abc");
    }

    #[test]
    fn infer_capture_kind_utf8_is_text_else_opaque() {
        assert_eq!(infer_capture_kind(b"hello"), "text");
        assert_eq!(infer_capture_kind(&[0xff, 0xfe]), "opaque-bytes");
        assert_eq!(infer_capture_kind(b""), "text");
    }

    #[test]
    fn settings_note_points_at_shelf_home() {
        let note = settings_home_note();
        assert!(note.contains("~/.shelf"), "{note}");
        assert!(note.contains("$SHELF_HOME"), "{note}");
    }
}
