//! A small element tree over quick-xml events, enough for the import
//! formats: names without prefixes, attributes, child elements and text.
//!
//! quick-xml never expands DTD entities: only the five predefined entities
//! and character references are resolved, and any other reference is an
//! error, so a hostile file cannot grow itself ("billion laughs") or read
//! local files. Nesting is capped, so walking the tree cannot overflow the
//! stack.

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};

/// Deeper nesting is refused (real files nest a few dozen levels at most).
pub const MAX_DEPTH: usize = 128;

#[derive(Debug, Default)]
pub struct Elem {
    /// Local name: `mrng:Connections` is `Connections`.
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Elem>,
    /// The element's own text (not its children's).
    pub text: String,
}

impl Elem {
    /// An attribute by name, ASCII case-insensitive.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&Elem> {
        self.children.iter().find(|c| c.name == name)
    }

    /// The trimmed text of a child element.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.trim())
    }
}

/// Bytes as text: UTF-8 (with or without a byte order mark) or UTF-16 with
/// its byte order mark.
pub fn decode(bytes: &[u8]) -> Result<String, String> {
    let utf16 = |be: bool| {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&b| {
                if be {
                    u16::from_be_bytes(b)
                } else {
                    u16::from_le_bytes(b)
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|_| "The file is not valid UTF-16 text.".to_string())
    };
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => std::str::from_utf8(rest).map(str::to_owned),
        [0xFF, 0xFE, ..] => return utf16(false),
        [0xFE, 0xFF, ..] => return utf16(true),
        _ => std::str::from_utf8(bytes).map(str::to_owned),
    }
    .map_err(|_| "The file is not UTF-8 text.".to_string())
}

/// Parses a document (or a fragment of sibling elements) into a synthetic
/// root element named `#root`, whose children are the top-level elements.
pub fn parse(text: &str) -> Result<Elem, String> {
    let bad = |e: &dyn std::fmt::Display| format!("The XML cannot be read: {e}");
    let mut reader = quick_xml::Reader::from_str(text);
    let mut stack = vec![Elem {
        name: "#root".into(),
        ..Elem::default()
    }];
    loop {
        match reader.read_event().map_err(|e| bad(&e))? {
            Event::Start(s) => {
                if stack.len() > MAX_DEPTH {
                    return Err("The XML is nested too deeply.".into());
                }
                stack.push(start(&s).map_err(|e| bad(&e))?);
            }
            Event::Empty(s) => {
                let e = start(&s).map_err(|e| bad(&e))?;
                if let Some(top) = stack.last_mut() {
                    top.children.push(e);
                }
            }
            Event::End(_) => {
                if stack.len() < 2 {
                    return Err(bad(&"unexpected end tag"));
                }
                if let Some(done) = stack.pop()
                    && let Some(top) = stack.last_mut()
                {
                    top.children.push(done);
                }
            }
            Event::Text(t) => push_text(&mut stack, &t.xml10_content()),
            Event::CData(t) => push_text(&mut stack, &t.xml10_content()),
            Event::GeneralRef(r) => {
                let s = match r.resolve_char_ref().map_err(|e| bad(&e))? {
                    Some(c) => c.to_string(),
                    None => resolve_predefined_entity(&r.xml10_content())
                        .ok_or_else(|| bad(&"an entity that is not one of XML's own"))?
                        .to_string(),
                };
                push_text(&mut stack, &s);
            }
            Event::Eof => break,
            // Declarations, comments, processing instructions, DOCTYPE.
            _ => {}
        }
    }
    if stack.len() != 1 {
        return Err(bad(&"the file ends inside an element"));
    }
    Ok(stack.pop().unwrap_or_default())
}

fn push_text(stack: &mut [Elem], s: &str) {
    if let Some(top) = stack.last_mut() {
        top.text.push_str(s);
    }
}

fn start(s: &BytesStart) -> Result<Elem, quick_xml::Error> {
    let mut attrs = Vec::new();
    for a in s.attributes() {
        let a = a.map_err(quick_xml::Error::from)?;
        let key = a.key.local_name().as_ref().to_string();
        let value = a.normalized_value(XmlVersion::Implicit1_0)?.into_owned();
        attrs.push((key, value));
    }
    Ok(Elem {
        name: s.local_name().as_ref().to_string(),
        attrs,
        ..Elem::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_with_attributes_entities_and_prefixes() {
        let x = parse(
            r#"<?xml version="1.0"?><mrng:Connections xmlns:mrng="x" A="1 &amp; 2">
                <Node Name="a&#x41;"/><b>t&lt;u</b></mrng:Connections>"#,
        )
        .unwrap();
        let root = &x.children[0];
        assert_eq!(root.name, "Connections");
        assert_eq!(root.attr("a"), Some("1 & 2"));
        assert_eq!(root.children[0].attr("Name"), Some("aA"));
        assert_eq!(root.child_text("b"), Some("t<u"));
    }

    #[test]
    fn dtd_entities_are_not_expanded() {
        let lol = r#"<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;">]><r>&b;</r>"#;
        assert!(parse(lol).is_err());
    }

    #[test]
    fn deep_nesting_and_broken_files_are_errors() {
        let deep = "<a>".repeat(MAX_DEPTH + 5) + &"</a>".repeat(MAX_DEPTH + 5);
        assert!(parse(&deep).is_err());
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("<a>").is_err());
    }

    #[test]
    fn utf8_bom_and_utf16_decode() {
        assert_eq!(decode(b"\xEF\xBB\xBF<a/>").unwrap(), "<a/>");
        let mut le = vec![0xFF, 0xFE];
        le.extend("<a/>".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode(&le).unwrap(), "<a/>");
        assert!(decode(b"\xC3\x28").is_err());
    }
}
