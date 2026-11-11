//! XML plist output that escapes like Apple's own writers.
//!
//! The `plist` crate writes strings through quick-xml's full escape, so `"`
//! and `'` come out as `&quot;` and `&apos;`. Apple's writers (`plutil`,
//! `PropertyListSerialization`) escape only `&`, `<` and `>`. Both parse to
//! the same value, but the entities turn every code requirement into a diff.

use std::io::Write;

/// Like `plist::to_writer_xml`, but with `"` and `'` left unescaped.
pub fn to_writer_xml<W: Write, T: serde::Serialize>(
    mut writer: W,
    value: &T,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, value)?;
    writer.write_all(&apple_escaped(buf))?;
    Ok(())
}

/// The plist crate's XML with `"` and `'` unescaped, or untouched.
///
/// Always-on guard: the edited text must parse to the same value as the
/// original. If it ever does not, the original bytes are written instead,
/// so the worst case is the old `&quot;` output, never a changed profile.
pub fn apple_escaped(xml: Vec<u8>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(&xml) else {
        return xml;
    };
    let fixed = unescape_quotes(text);
    if fixed == text {
        return xml;
    }
    let parse = |b: &[u8]| plist::from_bytes::<plist::Value>(b).ok();
    match (parse(fixed.as_bytes()), parse(&xml)) {
        (Some(a), Some(b)) if a == b => fixed.into_bytes(),
        _ => xml,
    }
}

/// Turns `&quot;` / `&apos;` back into `"` / `'` in serialized plist XML.
///
/// Lossless: a literal `&quot;` in a string is written as `&amp;quot;`,
/// which does not contain `&quot;`.
pub fn unescape_quotes(xml: &str) -> String {
    xml.replace("&quot;", "\"").replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_stay_readable_and_round_trip() {
        let s = r#"identifier "com.microsoft.dlp.daemon" and it's &quot; <x>"#;
        let mut buf = Vec::new();
        to_writer_xml(&mut buf, &plist::Value::String(s.into())).unwrap();
        let xml = String::from_utf8(buf.clone()).unwrap();
        assert!(
            xml.contains(r#"identifier "com.microsoft.dlp.daemon" and it's &amp;quot; &lt;x&gt;"#),
            "{xml}"
        );
        assert_eq!(
            plist::from_bytes::<plist::Value>(&buf).unwrap(),
            plist::Value::String(s.into())
        );
    }

    /// Every string of up to five tokens that could confuse the unescape
    /// writes with no quote entity left and parses back to itself.
    #[test]
    fn every_tricky_string_round_trips() {
        let tokens = [
            "&", "\"", "'", "<", ">", ";", "quot", "apos", "amp", "#34", "a",
        ];
        let mut strings = vec![String::new()];
        let mut start = 0;
        for _ in 0..5 {
            let end = strings.len();
            for i in start..end {
                for t in tokens {
                    let s = format!("{}{t}", strings[i]);
                    strings.push(s);
                }
            }
            start = end;
        }
        let value =
            plist::Value::Array(strings.iter().cloned().map(plist::Value::String).collect());
        let mut buf = Vec::new();
        to_writer_xml(&mut buf, &value).unwrap();
        assert_eq!(plist::from_bytes::<plist::Value>(&buf).unwrap(), value);
        let xml = String::from_utf8(buf).unwrap();
        // Only `&amp;quot;` / `&amp;apos;` may remain: literal text, not entities.
        assert!(!xml.replace("&amp;", "").contains("&quot;"));
        assert!(!xml.replace("&amp;", "").contains("&apos;"));
    }

    /// The guard: when the edited text cannot be shown to mean the same
    /// (here: neither side parses), the original bytes are kept.
    #[test]
    fn an_edit_that_cannot_be_verified_is_not_written() {
        let xml = b"<plist version=\"1.0\"><dict><key>&quot;</key></dict></plist>".to_vec();
        assert_eq!(apple_escaped(xml.clone()), xml);
    }
}
