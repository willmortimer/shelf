//! Slint recent-item palette. Talks to `shelfd` over local IPC.

/// One line in the palette: `kind  id` (no plaintext).
#[must_use]
pub fn format_line(kind: &str, id: &str) -> String {
    format!("{kind}  {id}")
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
}
