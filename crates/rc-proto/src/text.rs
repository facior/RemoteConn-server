//! Cleaning of strings that come from the other side (device names, chat).
//!
//! Control characters and Unicode bidirectional formatting characters are
//! removed: the latter can make `invoice\u{202E}fdp.exe` render as
//! `invoiceexe.pdf` or make a name read as something else entirely.

/// Bidi embedding/override/isolate marks and other invisible formatting
/// characters used for spoofing.
pub fn is_spoofing_char(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // zero-width space/joiners, LRM, RLM
        | '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
        | '\u{061C}'              // Arabic letter mark
        | '\u{FEFF}'              // BOM / zero-width no-break space
    )
}

/// A single-line label: no control or spoofing characters, whitespace
/// collapsed, at most `max_chars` characters.
pub fn clean_label(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut last_space = true;
    for c in input.chars() {
        if c.is_control() || is_spoofing_char(c) {
            continue;
        }
        if c.is_whitespace() {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
        if out.chars().count() >= max_chars {
            break;
        }
    }
    out.trim_end().to_string()
}

/// Multi-line text (chat): newlines and tabs kept, other control and
/// spoofing characters removed, at most `max_chars` characters.
pub fn clean_text(input: &str, max_chars: usize) -> String {
    input
        .chars()
        .filter(|&c| (!c.is_control() || c == '\n' || c == '\t') && !is_spoofing_char(c))
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_bidi_and_controls() {
        assert_eq!(clean_label("faktura\u{202E}fdp.exe", 64), "fakturafdp.exe");
        assert_eq!(clean_label("  Biuro\t\n PC\u{0007} ", 64), "Biuro PC");
        assert_eq!(clean_label("zażółć", 3), "zaż");
        assert_eq!(
            clean_text("linia 1\nlinia\u{2067} 2\u{0000}", 100),
            "linia 1\nlinia 2"
        );
    }
}
