//! File name safety on the receiving side.
//!
//! Version 1.0 transfers single files only: the offered name must be a
//! plain file name, never a path. Folder transfers would need relative
//! subfolders; they are left out until there is a design for them (every
//! component would go through [`check_name`], and the receiver would create
//! the folders itself).
//!
//! Rejected (Windows naming rules, learn.microsoft.com "Naming Files, Paths,
//! and Namespaces", applied on every platform so both sides agree):
//! - empty names, `.` and `..`, names made only of dots;
//! - path separators `/` and `\`, drive or stream colons `:` (alternate
//!   data streams), and `< > " | ? *`;
//! - control characters (U+0000..U+001F, U+007F..U+009F) and bidirectional
//!   or invisible format characters that disguise an extension
//!   (U+200B..U+200F, U+202A..U+202E, U+2066..U+2069, U+FEFF);
//! - trailing dots or spaces (Windows strips them, so the stored name would
//!   differ from the checked one);
//! - reserved device names, with or without an extension and in any case:
//!   CON, PRN, AUX, NUL, COM0..COM9, LPT0..LPT9 (also with superscript
//!   digits ¹ ² ³), CONIN$, CONOUT$;
//! - names over 255 UTF-16 units.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    DotsOnly,
    Separator,
    Colon,
    InvalidChar(char),
    TrailingDotOrSpace,
    Reserved,
    TooLong,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Empty => f.write_str("empty file name"),
            NameError::DotsOnly => f.write_str("the name is only dots"),
            NameError::Separator => f.write_str("the name contains a folder separator"),
            NameError::Colon => f.write_str("the name contains a colon"),
            NameError::InvalidChar(c) => write!(f, "the name contains U+{:04X}", *c as u32),
            NameError::TrailingDotOrSpace => f.write_str("the name ends in a dot or space"),
            NameError::Reserved => f.write_str("the name is a reserved device name"),
            NameError::TooLong => f.write_str("the name is longer than 255 characters"),
        }
    }
}

/// Longest name in UTF-16 units (NTFS limit per component).
pub const MAX_NAME_UTF16: usize = 255;

/// Checks that `name` is a safe plain file name.
pub fn check_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.chars().all(|c| c == '.') {
        return Err(NameError::DotsOnly);
    }
    for c in name.chars() {
        match c {
            '/' | '\\' => return Err(NameError::Separator),
            ':' => return Err(NameError::Colon),
            '<' | '>' | '"' | '|' | '?' | '*' => return Err(NameError::InvalidChar(c)),
            c if c.is_control() => return Err(NameError::InvalidChar(c)),
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}' => return Err(NameError::InvalidChar(c)),
            _ => {}
        }
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(NameError::TrailingDotOrSpace);
    }
    if name.encode_utf16().count() > MAX_NAME_UTF16 {
        return Err(NameError::TooLong);
    }
    if is_reserved(name) {
        return Err(NameError::Reserved);
    }
    Ok(())
}

/// Windows device names. The part before the first dot counts, with
/// trailing spaces removed ("NUL .txt" is NUL).
fn is_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = upper.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let rest: Vec<char> = chars.collect();
    (prefix == "COM" || prefix == "LPT")
        && rest.len() == 1
        && matches!(rest[0], '0'..='9' | '¹' | '²' | '³')
}

/// The `n`th alternative for a taken name: `report (2).pdf`. The number goes
/// before the last extension; names starting with a dot keep it.
pub fn numbered(name: &str, n: u32) -> String {
    match name.rfind('.') {
        Some(dot) if dot > 0 => format!("{} ({n}){}", &name[..dot], &name[dot..]),
        _ => format!("{name} ({n})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_names() {
        for ok in [
            "report.pdf",
            "a",
            ".gitignore",
            "archive.tar.gz",
            "Grüße 2026.txt",
            "日本語.doc",
            "console.txt",
            "COM10",
            "LPT",
            "nul_file",
            " leading space.txt",
            "a..b",
        ] {
            assert_eq!(check_name(ok), Ok(()), "{ok:?}");
        }
    }

    #[test]
    fn rejected_names() {
        use NameError::*;
        let cases: &[(&str, NameError)] = &[
            ("", Empty),
            (".", DotsOnly),
            ("..", DotsOnly),
            ("...", DotsOnly),
            ("../x", Separator),
            ("..\\x", Separator),
            ("a/b", Separator),
            ("/etc/passwd", Separator),
            ("C:\\Windows\\x", Colon),
            ("C:x", Colon),
            ("file.txt:Zone.Identifier", Colon),
            ("file.txt::$DATA", Colon),
            ("\\\\server\\share\\x", Separator),
            ("a<b", InvalidChar('<')),
            ("what?", InvalidChar('?')),
            ("star*", InvalidChar('*')),
            ("pipe|", InvalidChar('|')),
            ("quote\"", InvalidChar('"')),
            ("nul\0byte", InvalidChar('\0')),
            ("tab\there", InvalidChar('\t')),
            ("bell\u{7}", InvalidChar('\u{7}')),
            ("c1\u{85}", InvalidChar('\u{85}')),
            ("invoice\u{202E}fdp.exe", InvalidChar('\u{202E}')),
            ("zero\u{200B}width", InvalidChar('\u{200B}')),
            ("bom\u{FEFF}", InvalidChar('\u{FEFF}')),
            ("trailing.", TrailingDotOrSpace),
            ("trailing ", TrailingDotOrSpace),
            ("file.txt. . ", TrailingDotOrSpace),
            ("CON", Reserved),
            ("con", Reserved),
            ("Con.txt", Reserved),
            ("PRN.tar.gz", Reserved),
            ("AUX", Reserved),
            ("nul.anything", Reserved),
            ("NUL .txt", Reserved),
            ("COM1", Reserved),
            ("com9.log", Reserved),
            ("COM0", Reserved),
            ("LPT1", Reserved),
            ("lpt9.txt", Reserved),
            ("COM¹", Reserved),
            ("LPT³.txt", Reserved),
            ("CONIN$", Reserved),
            ("conout$.x", Reserved),
        ];
        for (name, want) in cases {
            assert_eq!(check_name(name).as_ref(), Err(want), "{name:?}");
        }
        let long = "a".repeat(256);
        assert_eq!(check_name(&long), Err(TooLong));
        assert_eq!(check_name(&"a".repeat(255)), Ok(()));
        // 255 UTF-16 units of a character outside the BMP is 510 units.
        assert_eq!(check_name(&"😀".repeat(128)), Err(TooLong));
    }

    #[test]
    fn numbered_names() {
        assert_eq!(numbered("report.pdf", 2), "report (2).pdf");
        assert_eq!(numbered("archive.tar.gz", 3), "archive.tar (3).gz");
        assert_eq!(numbered("README", 2), "README (2)");
        assert_eq!(numbered(".gitignore", 2), ".gitignore (2)");
        for n in 2..5 {
            assert_eq!(check_name(&numbered("x.txt", n)), Ok(()));
        }
    }
}
