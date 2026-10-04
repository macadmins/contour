//! `FieldPath` — a schema path as segments, never as a string to split.
//!
//! # Why a type, and not another test
//!
//! A dotted path handled as a flat string produces a document that
//! validates and matches nothing: a literal `<key>PayloadContent.Challenge</key>`
//! in a mobileconfig, a declaration naming `"Relays.Relay.IdentityAssetReference"`
//! as one key, or two levels of a path merged into one by escaping the
//! joined parent instead of each segment. A test catches one site; this type
//! catches the class: there is no method on it that writes the path flat. A path is parsed once, at the boundary
//! where a string arrives, and from then on it is segments.
//!
//! # The spelling
//!
//! Segments join with `.`. A `.` or `\` inside a segment is escaped with a
//! backslash: `Accounts\.{Id}.Email` is two segments, `Accounts.{Id}` and
//! `Email`. The dataset's `key_path` column is written in this convention — so
//! [`FieldPath::parse`] reads what the dataset carries, and
//! [`Display`](std::fmt::Display) writes what a lookup in `fields` expects.
//!
//! # Conflicts are errors
//!
//! Nesting `A.B` where `A` is already a scalar is not resolved by
//! overwriting `A` or by silently dropping the value. It is the caller's document setting one key as
//! both a value and a container, and it is reported as [`PathConflict`].

use std::fmt;

/// A schema path as its segments. Construct with [`FieldPath::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FieldPath(Vec<String>);

/// A prefix of the path is already a scalar, so the path cannot be nested
/// under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConflict {
    /// The path being written.
    pub path: FieldPath,
    /// The prefix that holds a non-dictionary value.
    pub at: FieldPath,
}

impl fmt::Display for PathConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot nest `{}`: `{}` already holds a value, not a dictionary — the document \
             sets one key both as a value and as a container",
            self.path, self.at
        )
    }
}

impl std::error::Error for PathConflict {}

impl FieldPath {
    /// Parse the dotted, backslash-escaped spelling.
    ///
    /// `\.` is a literal dot inside a segment and `\\` a literal backslash;
    /// a trailing lone backslash is kept as written. An empty string is the
    /// empty path (no segments): inserts are no-ops and `get_json` is `None`.
    pub fn parse(s: &str) -> Self {
        if s.is_empty() {
            return Self(Vec::new());
        }
        let mut segments = Vec::new();
        let mut current = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some(n) => current.push(n),
                    None => current.push('\\'),
                },
                '.' => segments.push(std::mem::take(&mut current)),
                _ => current.push(c),
            }
        }
        segments.push(current);
        Self(segments)
    }

    /// From already-separated segments; nothing is parsed or escaped.
    pub fn from_segments<I, S>(segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(segments.into_iter().map(Into::into).collect())
    }

    pub fn segments(&self) -> &[String] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of segments below the root: `A` is 0, `A.B` is 1.
    pub fn depth(&self) -> usize {
        self.0.len().saturating_sub(1)
    }

    pub fn leaf(&self) -> Option<&str> {
        self.0.last().map(String::as_str)
    }

    pub fn parent(&self) -> Option<FieldPath> {
        match self.0.len() {
            0 | 1 => None,
            n => Some(Self(self.0[..n - 1].to_vec())),
        }
    }

    /// This path with one more segment. The segment is taken literally —
    /// a dot inside it stays inside it — which is exactly what a string
    /// `format!("{parent}.{name}")` cannot promise.
    pub fn join(&self, segment: &str) -> FieldPath {
        let mut v = self.0.clone();
        v.push(segment.to_string());
        Self(v)
    }

    pub fn starts_with(&self, prefix: &FieldPath) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// Write `value` at this path in a JSON object, creating the
    /// dictionaries between. See the module docs for what a conflict is.
    pub fn insert_json(
        &self,
        root: &mut serde_json::Map<String, serde_json::Value>,
        value: serde_json::Value,
    ) -> Result<(), PathConflict> {
        let Some((leaf, parents)) = self.0.split_last() else {
            return Ok(());
        };
        let mut cursor = root;
        for (i, seg) in parents.iter().enumerate() {
            let entry = cursor
                .entry(seg.clone())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            match entry {
                serde_json::Value::Object(m) => cursor = m,
                _ => {
                    return Err(PathConflict {
                        path: self.clone(),
                        at: Self(self.0[..=i].to_vec()),
                    });
                }
            }
        }
        cursor.insert(leaf.clone(), value);
        Ok(())
    }

    /// The JSON value at this path, if every segment is present.
    pub fn get_json<'a>(
        &self,
        root: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Option<&'a serde_json::Value> {
        let (first, rest) = self.0.split_first()?;
        let mut v = root.get(first)?;
        for seg in rest {
            v = v.as_object()?.get(seg)?;
        }
        Some(v)
    }

    /// Write `value` at this path in a plist dictionary, creating the
    /// dictionaries between.
    pub fn insert_plist(
        &self,
        root: &mut plist::Dictionary,
        value: plist::Value,
    ) -> Result<(), PathConflict> {
        let Some((leaf, parents)) = self.0.split_last() else {
            return Ok(());
        };
        let mut cursor = root;
        for (i, seg) in parents.iter().enumerate() {
            if !cursor.contains_key(seg) {
                cursor.insert(
                    seg.clone(),
                    plist::Value::Dictionary(plist::Dictionary::new()),
                );
            }
            match cursor.get_mut(seg) {
                Some(plist::Value::Dictionary(d)) => cursor = d,
                _ => {
                    return Err(PathConflict {
                        path: self.clone(),
                        at: Self(self.0[..=i].to_vec()),
                    });
                }
            }
        }
        cursor.insert(leaf.clone(), value);
        Ok(())
    }
}

impl fmt::Display for FieldPath {
    /// The spelling [`FieldPath::parse`] reads: segments joined with `.`,
    /// with `.` and `\` inside a segment escaped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, seg) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            for c in seg.chars() {
                if c == '.' || c == '\\' {
                    f.write_str("\\")?;
                }
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_and_display_round_trip_including_escaped_dots() {
        for s in [
            "A",
            "A.B.C",
            "Relays.Relay.IdentityAssetReference",
            r"Accounts\.{Id}.Email",
            r"com\.apple\.login\.mcx.Key",
            r"a\\b.c",
        ] {
            let p = FieldPath::parse(s);
            assert_eq!(p.to_string(), s, "round trip of {s:?}");
        }
        let p = FieldPath::parse(r"Accounts\.{Id}.Email");
        assert_eq!(p.segments(), ["Accounts.{Id}", "Email"]);
        assert_eq!(p.depth(), 1);
        assert_eq!(p.leaf(), Some("Email"));
        assert_eq!(p.parent().unwrap().to_string(), r"Accounts\.{Id}");
    }

    #[test]
    fn join_keeps_a_dotted_segment_whole() {
        let p = FieldPath::parse("Privacy.PermissionDefaults").join("us.zoom.xos");
        assert_eq!(p.segments().len(), 3);
        assert_eq!(p.to_string(), r"Privacy.PermissionDefaults.us\.zoom\.xos");
        assert_eq!(
            FieldPath::parse(&p.to_string()),
            p,
            "and it reads back to the same segments"
        );
    }

    /// The compose bug, as a type-level impossibility: there is no way to
    /// write the dotted string as one key.
    #[test]
    fn a_nested_asset_reference_is_written_at_its_path() {
        let mut m = serde_json::Map::new();
        FieldPath::parse("Relays.Relay.IdentityAssetReference")
            .insert_json(&mut m, json!("com.acme.asset.relay"))
            .unwrap();
        assert!(!m.contains_key("Relays.Relay.IdentityAssetReference"));
        assert_eq!(
            m["Relays"]["Relay"]["IdentityAssetReference"],
            "com.acme.asset.relay"
        );
        assert_eq!(
            FieldPath::parse("Relays.Relay.IdentityAssetReference").get_json(&m),
            Some(&json!("com.acme.asset.relay"))
        );
    }

    /// A key that genuinely contains a dot lands as one key, not two levels.
    #[test]
    fn an_escaped_dot_is_one_key() {
        let mut m = serde_json::Map::new();
        FieldPath::parse(r"Accounts\.{Id}.Email")
            .insert_json(&mut m, json!("a@b"))
            .unwrap();
        assert_eq!(m["Accounts.{Id}"]["Email"], "a@b");
        assert!(!m.contains_key("Accounts"));
    }

    #[test]
    fn plist_nesting_matches_json_nesting_and_preserves_siblings() {
        let mut d = plist::Dictionary::new();
        d.insert(
            "PayloadType".into(),
            plist::Value::String("com.apple.x".into()),
        );
        FieldPath::parse("PayloadContent.Challenge")
            .insert_plist(&mut d, plist::Value::String("s3cret".into()))
            .unwrap();
        FieldPath::parse("PayloadContent.URL")
            .insert_plist(&mut d, plist::Value::String("https://x".into()))
            .unwrap();
        assert!(!d.contains_key("PayloadContent.Challenge"));
        let Some(plist::Value::Dictionary(pc)) = d.get("PayloadContent") else {
            panic!("PayloadContent is a dictionary");
        };
        assert_eq!(
            pc.get("Challenge"),
            Some(&plist::Value::String("s3cret".into()))
        );
        assert_eq!(
            pc.get("URL"),
            Some(&plist::Value::String("https://x".into()))
        );
        assert_eq!(
            d.get("PayloadType"),
            Some(&plist::Value::String("com.apple.x".into()))
        );
    }

    /// Neither overwrite (compose) nor drop (generate): a conflict is named.
    #[test]
    fn nesting_under_a_scalar_is_an_error_not_an_overwrite_or_a_drop() {
        let mut m = serde_json::Map::new();
        m.insert("A".into(), json!("scalar"));
        let err = FieldPath::parse("A.B.C")
            .insert_json(&mut m, json!(1))
            .unwrap_err();
        assert_eq!(err.at.to_string(), "A");
        assert_eq!(err.path.to_string(), "A.B.C");
        assert_eq!(m["A"], "scalar", "the scalar was not overwritten");
        assert!(
            err.to_string()
                .contains("both as a value and as a container")
        );

        let mut d = plist::Dictionary::new();
        d.insert("A".into(), plist::Value::String("scalar".into()));
        let err = FieldPath::parse("A.B")
            .insert_plist(&mut d, plist::Value::Integer(1.into()))
            .unwrap_err();
        assert_eq!(err.at.to_string(), "A");
        assert_eq!(d.get("A"), Some(&plist::Value::String("scalar".into())));
    }

    #[test]
    fn the_empty_path_writes_nothing_and_a_single_segment_is_top_level() {
        let mut m = serde_json::Map::new();
        FieldPath::parse("").insert_json(&mut m, json!(1)).unwrap();
        assert!(m.is_empty());
        FieldPath::parse("Top")
            .insert_json(&mut m, json!(1))
            .unwrap();
        assert_eq!(m["Top"], 1);
        assert_eq!(FieldPath::parse("Top").depth(), 0);
        assert!(FieldPath::parse("Top").parent().is_none());
    }
}
