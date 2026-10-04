//! `profile preset` — a Jamf manifest becomes a recipe you own and edit.
//!
//! Jamf's Application & Custom Settings manifests are JSON Schema plus a few
//! editor hints, and a lot of software ships one: vendors publish them, and
//! the Jamf-Custom-Profile-Schemas mirror machine-translates the
//! ProfileManifests community plists into the same shape.
//!
//! They are NOT imported into contour's embedded schema, and this is the
//! reason: a manifest states no OS availability and carries no version, so
//! nothing built from one can say which release of the app it describes. The
//! mirror's own README says its files come with "no warranty as to their
//! accuracy or functionality" and that you should "check the raw plist prior
//! to deploying". Embedding that would make contour assert it. Writing it
//! into a file you review makes it a draft you accept or correct — and every
//! setting arrives commented out, so nothing ships because a conversion said
//! so.
//!
//! ## The dotted-key problem, which this refuses to guess about
//!
//! A manifest key like `app.startAtLogin` may be a literal key whose name
//! contains a dot, or a path into a nested dictionary. The two produce
//! different plists and the JSON cannot tell you which is meant:
//!
//! * `com.1password.1password` — `app.startAtLogin` is LITERAL. The
//!   ProfileManifests plist gives it as one `pfm_name`, with no subkeys.
//! * `com.okta.mobile` — `OktaVerify.OrgUrl` NESTS, into an `OktaVerify`
//!   dictionary. contour's own okta recipe writes it through `extra_fields`
//!   for exactly that reason.
//!
//! Same syntax, opposite structure. Picking one silently would write a
//! profile the app never reads — a failure that looks like success on the
//! device. So dotted keys land in their own section, with both destinations
//! named, and the operator decides.

use anyhow::{Context, Result};
use serde_json::Value;
use std::fmt::Write as _;
use std::path::Path;

/// A settable key read out of a Jamf manifest.
struct ManifestKey {
    name: String,
    title: Option<String>,
    description: Option<String>,
    json_type: Option<String>,
    default: Option<Value>,
    enum_values: Vec<String>,
    pattern: Option<String>,
}

impl ManifestKey {
    /// `true` when the name contains a dot, and is therefore ambiguous
    /// between a literal key and a nesting path.
    fn is_dotted(&self) -> bool {
        self.name.contains('.')
    }

    /// A TOML value that type-checks, for the operator to replace.
    ///
    /// The manifest's own default when it has one — that is the vendor
    /// speaking. Otherwise a value of the right TYPE and obviously
    /// placeholder, never a guess at what the setting should be.
    fn sample(&self) -> String {
        if let Some(d) = &self.default {
            return match d {
                Value::String(s) => format!("{:?}", s),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Array(_) | Value::Object(_) => "# (see the manifest)".to_string(),
                Value::Null => "\"\"".to_string(),
            };
        }
        if let Some(first) = self.enum_values.first() {
            return format!("{first:?}");
        }
        match self.json_type.as_deref() {
            Some("boolean") => "false".into(),
            Some("integer") | Some("number") => "0".into(),
            Some("array") => "[]".into(),
            Some("object") => "{}".into(),
            _ => "\"\"".into(),
        }
    }

    /// One comment line describing the key, as the manifest describes it.
    fn comment(&self) -> String {
        let mut parts = Vec::new();
        if let Some(t) = &self.title {
            parts.push(t.clone());
        }
        if let Some(d) = &self.description {
            let one_line = d.split_whitespace().collect::<Vec<_>>().join(" ");
            let trimmed = if one_line.chars().count() > 160 {
                let cut: String = one_line.chars().take(157).collect();
                format!("{cut}...")
            } else {
                one_line
            };
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
        }
        if !self.enum_values.is_empty() {
            parts.push(format!("one of: {}", self.enum_values.join(", ")));
        }
        if let Some(p) = &self.pattern {
            parts.push(format!("pattern {p}"));
        }
        parts.join(" — ")
    }
}

/// Read the settable keys out of a Jamf manifest document.
///
/// Editor scaffolding is skipped: Jamf renders `property_order`, `options`
/// and `links` and they mean nothing in a profile. So are ProfileCreator's
/// `PFC_`-prefixed UI widgets — the Jamf mirror's build script filters them
/// already, but the raw plists carry them and a hand-made manifest might.
fn read_keys(doc: &Value) -> Vec<ManifestKey> {
    let Some(props) = doc.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    props
        .iter()
        .filter(|(name, _)| !name.starts_with("PFC_") && !name.starts_with('_'))
        .map(|(name, v)| ManifestKey {
            name: name.clone(),
            title: v.get("title").and_then(Value::as_str).map(str::to_string),
            description: v
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string),
            json_type: v.get("type").and_then(Value::as_str).map(str::to_string),
            default: v.get("default").cloned(),
            enum_values: v
                .get("enum")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|x| match x {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            pattern: v.get("pattern").and_then(Value::as_str).map(str::to_string),
        })
        .collect()
}

/// The preference domain a manifest describes.
///
/// Jamf manifests carry no domain field. The convention the mirror and most
/// vendors follow is that the FILE is named for the domain, and the title
/// often repeats it in parentheses. The filename is used, and the title is
/// only consulted to confirm it — a disagreement is reported rather than
/// resolved, because writing a profile under the wrong domain produces a
/// document the app silently ignores.
fn domain_from(path: &Path, doc: &Value, override_domain: Option<&str>) -> Result<String> {
    if let Some(d) = override_domain {
        return Ok(d.to_string());
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .context("manifest path has no filename to take the domain from")?;

    if let Some(title) = doc.get("title").and_then(Value::as_str) {
        if let Some(open) = title.rfind('(') {
            let claimed = title[open + 1..].trim_end_matches(')').trim();
            if !claimed.is_empty() && claimed != stem && claimed.contains('.') {
                // Real cases from the Jamf mirror: a filename carrying a
                // platform or variant suffix (`…-iOS`, `…-Okta`) where the
                // title holds the true domain, and org.videolan.vlc against
                // a title of org.videolan.VLC — a case difference, which a
                // preference domain is sensitive to. One of them is wrong
                // and nothing here can tell which, so neither is picked.
                anyhow::bail!(
                    "the filename says the domain is '{stem}' but the title says '{claimed}'. \
                     A profile written under the wrong domain is silently ignored by the app, \
                     so this is not guessed. Pass --domain with the one you have verified."
                );
            }
        }
    }
    Ok(stem)
}

/// Render the preset.
pub fn render(
    doc: &Value,
    path: &Path,
    source_note: Option<&str>,
    override_domain: Option<&str>,
) -> Result<String> {
    let domain = domain_from(path, doc, override_domain)?;
    let keys = read_keys(doc);
    if keys.is_empty() {
        anyhow::bail!(
            "{} declares no settable properties — nothing to turn into a preset",
            path.display()
        );
    }
    let title = doc
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or(&domain)
        .to_string();
    let description = doc
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let (plain, dotted): (Vec<_>, Vec<_>) = keys.iter().partition(|k| !k.is_dotted());
    let slug = domain.replace('.', "-");

    let mut out = String::new();
    writeln!(
        out,
        "# Preset drafted from a Jamf manifest — NOT a contour schema."
    )?;
    writeln!(out, "#")?;
    writeln!(
        out,
        "# contour does not embed this manifest and cannot validate what you"
    )?;
    writeln!(
        out,
        "# write below against it. A Jamf manifest states no OS availability and"
    )?;
    writeln!(
        out,
        "# carries no version, so nothing built from one can say which release"
    )?;
    writeln!(
        out,
        "# of the app it describes. Check the vendor's documentation."
    )?;
    writeln!(out, "#")?;
    writeln!(out, "# source: {}", path.display())?;
    if let Some(note) = source_note {
        for line in note.lines() {
            writeln!(out, "# {line}")?;
        }
    }
    writeln!(
        out,
        "#\n# Every setting is commented out. Uncomment only what you have checked."
    )?;
    writeln!(out)?;

    writeln!(out, "[recipe]")?;
    writeln!(out, "name = {slug:?}")?;
    writeln!(
        out,
        "description = {:?}",
        if description.is_empty() {
            format!("Managed preferences for {domain}")
        } else {
            description
        }
    )?;
    writeln!(out)?;

    writeln!(out, "[[profile]]")?;
    writeln!(out, "filename = {:?}", format!("{slug}.mobileconfig"))?;
    writeln!(
        out,
        "payload_type = \"com.apple.ManagedClient.preferences\""
    )?;
    writeln!(out, "display_name = {title:?}")?;
    writeln!(out, "mcx_domain = {domain:?}")?;
    writeln!(out)?;

    writeln!(
        out,
        "# Literal keys — written verbatim, exactly as the manifest names them."
    )?;
    writeln!(out, "[profile.fields]")?;
    if plain.is_empty() {
        writeln!(out, "# (this manifest declares none)")?;
    }
    for k in &plain {
        let c = k.comment();
        if !c.is_empty() {
            writeln!(out, "# {c}")?;
        }
        writeln!(out, "# {:?} = {}", k.name, k.sample())?;
    }

    if !dotted.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "# ── {} dotted key(s): contour will not guess ──",
            dotted.len()
        )?;
        writeln!(out, "#")?;
        writeln!(
            out,
            "# A dot may be part of the key's NAME, or a path into a nested"
        )?;
        writeln!(
            out,
            "# dictionary. The manifest cannot tell you which, and the two produce"
        )?;
        writeln!(
            out,
            "# different plists — the wrong one is a profile the app never reads."
        )?;
        writeln!(out, "#")?;
        writeln!(
            out,
            "#   literal key  ->  move it up into [profile.fields] (verbatim)"
        )?;
        writeln!(
            out,
            "#   nesting path ->  put it under [profile.extra_fields] (dot-notation)"
        )?;
        writeln!(out, "#")?;
        writeln!(
            out,
            "# Both are real: 1Password's `app.startAtLogin` is literal, while Okta"
        )?;
        writeln!(
            out,
            "# Verify's `OktaVerify.OrgUrl` nests. Check the vendor's documentation."
        )?;
        writeln!(out, "#")?;
        for k in &dotted {
            let c = k.comment();
            if !c.is_empty() {
                writeln!(out, "# {c}")?;
            }
            writeln!(out, "# {:?} = {}", k.name, k.sample())?;
        }
    }

    Ok(out)
}

/// `profile preset <MANIFEST>` — read a Jamf manifest, write a recipe draft.
pub fn handle(
    manifest: &Path,
    output: Option<&Path>,
    source_note: Option<&str>,
    override_domain: Option<&str>,
) -> Result<()> {
    let raw = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let doc: Value = serde_json::from_str(&raw)
        .with_context(|| format!("{} is not valid JSON", manifest.display()))?;
    let toml = render(&doc, manifest, source_note, override_domain)?;

    match output {
        Some(p) => {
            std::fs::write(p, &toml).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("✓ {}", p.display());
        }
        None => print!("{toml}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> Value {
        json!({
            "title": "Example App (com.example.app)",
            "description": "Settings for Example App",
            "properties": {
                "plainKey":        {"type": "boolean", "title": "Plain", "default": true},
                "withEnum":        {"type": "string", "title": "Mode",
                                    "enum": ["fast", "slow"]},
                "dotted.key":      {"type": "string", "title": "Dotted",
                                    "description": "Ambiguous on purpose"},
                "PFC_Widget_0":    {"type": "string", "title": "editor widget"},
                "_scaffold":       {"type": "string"}
            }
        })
    }

    fn render_default(doc: &Value) -> String {
        render(doc, Path::new("/tmp/com.example.app.json"), None, None).unwrap()
    }

    /// Nothing a conversion produced may deploy because it was produced.
    ///
    /// The whole reason a Jamf manifest becomes a preset rather than a
    /// schema is that nobody has checked it. A preset that arrived ready to
    /// apply would put the unchecked thing straight into a profile.
    #[test]
    fn every_setting_arrives_commented_out() {
        let out = render_default(&manifest());
        for line in out.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            // The recipe scaffolding is real TOML; nothing else may be.
            let allowed = t.starts_with("[recipe]")
                || t.starts_with("[[profile]]")
                || t.starts_with("[profile.fields]")
                || t.starts_with("name =")
                || t.starts_with("description =")
                || t.starts_with("filename =")
                || t.starts_with("payload_type =")
                || t.starts_with("display_name =")
                || t.starts_with("mcx_domain =");
            assert!(allowed, "a setting is live in the output: {t}");
        }
    }

    /// The output parses as a recipe — a draft you can edit, not a sketch.
    #[test]
    fn the_draft_is_valid_toml() {
        let out = render_default(&manifest());
        let parsed: toml::Value = toml::from_str(&out).expect("preset must be valid TOML");
        assert_eq!(
            parsed["profile"][0]["mcx_domain"].as_str(),
            Some("com.example.app")
        );
    }

    /// A dot is never resolved for the operator.
    #[test]
    fn dotted_keys_are_separated_and_not_resolved() {
        let out = render_default(&manifest());
        assert!(out.contains("dotted key(s): contour will not guess"));
        assert!(
            out.contains("[profile.extra_fields]"),
            "the nesting destination must be named"
        );
        // And never emitted as though the question were settled.
        assert!(
            !out.contains("[profile.extra_fields]\n# \"dotted.key\""),
            "a dotted key was placed without the operator deciding"
        );
    }

    /// Editor scaffolding is not a preference.
    #[test]
    fn editor_scaffolding_is_dropped() {
        let out = render_default(&manifest());
        assert!(
            !out.contains("PFC_Widget_0"),
            "a ProfileCreator UI widget leaked"
        );
        assert!(!out.contains("_scaffold"));
        assert!(out.contains("plainKey"), "a real key was dropped");
    }

    /// The vendor's own default is offered; nothing else is invented.
    #[test]
    fn samples_come_from_the_manifest_or_are_obvious_placeholders() {
        let out = render_default(&manifest());
        assert!(
            out.contains(r#"# "plainKey" = true"#),
            "the manifest default is not used"
        );
        assert!(
            out.contains(r#"# "withEnum" = "fast""#),
            "the first enum value is not offered"
        );
    }

    /// A domain disagreement is reported, never resolved.
    #[test]
    fn a_domain_disagreement_refuses_and_names_the_way_out() {
        let doc = json!({
            "title": "VLC (org.videolan.VLC)",
            "properties": {"k": {"type": "string"}}
        });
        let err = render(&doc, Path::new("/tmp/org.videolan.vlc.json"), None, None)
            .expect_err("a case difference in a domain must not be resolved silently");
        let msg = err.to_string();
        assert!(msg.contains("org.videolan.vlc") && msg.contains("org.videolan.VLC"));
        assert!(msg.contains("--domain"), "the way forward must be named");

        // And the override is honoured.
        let ok = render(
            &doc,
            Path::new("/tmp/org.videolan.vlc.json"),
            None,
            Some("org.videolan.VLC"),
        )
        .unwrap();
        assert!(ok.contains(r#"mcx_domain = "org.videolan.VLC""#));
    }

    /// A manifest with nothing settable produces nothing.
    #[test]
    fn a_manifest_with_no_properties_is_refused() {
        let doc = json!({"title": "Empty (com.example.empty)", "properties": {}});
        assert!(render(&doc, Path::new("/tmp/com.example.empty.json"), None, None).is_err());
    }

    /// The header says what the file is and is not.
    #[test]
    fn the_header_states_that_contour_does_not_assert_this() {
        let out = render_default(&manifest());
        assert!(out.contains("NOT a contour schema"));
        assert!(out.contains("does not embed this manifest"));
        assert!(out.contains("commented out"));
    }
}
