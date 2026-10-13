//! Making untrusted strings (manifest, receipt and header fields) safe to show.

/// Replaces every character that can rewrite or disguise what a terminal or a UI shows with
/// `?`: control characters (C0, DEL and C1, which covers ESC and so every ANSI sequence, CR
/// and LF), bidirectional embeddings, overrides and isolates, zero-width characters and the
/// Unicode line and paragraph separators. Letters, digits, punctuation and symbols of any
/// script pass through unchanged.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if is_unsafe(c) { '?' } else { c })
        .collect()
}

fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'                      // Arabic letter mark
                | '\u{200B}'..='\u{200F}'   // zero-width space/joiners, LRM, RLM
                | '\u{2028}'..='\u{202E}'   // line/paragraph separators, LRE..RLO
                | '\u{2060}'..='\u{2069}'   // word joiner, invisible operators, LRI..PDI
                | '\u{FEFF}'                // zero-width no-break space
                | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation controls
        )
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn replaces_terminal_and_bidi_controls() {
        assert_eq!(sanitize("top\u{1b}[31mred\u{7}"), "top?[31mred?");
        assert_eq!(
            sanitize("a\r\nOK: signature valid"),
            "a??OK: signature valid"
        );
        assert_eq!(sanitize("x\u{9b}2J"), "x?2J"); // C1 CSI
        assert_eq!(sanitize("\u{7f}"), "?");
        assert_eq!(sanitize("abc\u{202E}fdp.exe"), "abc?fdp.exe");
        assert_eq!(sanitize("a\u{2066}b\u{2069}"), "a?b?");
        assert_eq!(sanitize("zero\u{200B}width\u{FEFF}"), "zero?width?");
    }

    #[test]
    fn keeps_ordinary_text_in_any_script() {
        for s in [
            "Confidential - internal (Q3) #42 @team",
            "https://release.example.org/v1",
            "Vertraulich: Größe ändern",
            "機密 文書",
            "سري",
            "2026-10-13T09:00:00Z",
            "€ ✓ — “quotes”",
        ] {
            assert_eq!(sanitize(s), s);
        }
    }
}
