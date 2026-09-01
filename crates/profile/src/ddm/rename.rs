//! Recursive, bundle-aware org rename for DDM declarations.
//!
//! Backs `contour profile normalize <dir> --org com.newco` for DDM `.json`
//! declarations (alongside the existing `.mobileconfig` path). It rewrites the
//! org prefix of every declaration's `Identifier` — mirroring the mobileconfig
//! `normalizer::normalize_identifier` semantic — and is *bundle-aware*: a
//! pre-scan builds an old→new `Identifier` map, then any cross-reference to a
//! renamed `Identifier` inside any `Payload` (e.g. an `activation.simple`'s
//! `StandardConfigurations` list) is rewritten too, so activation→configuration
//! links stay intact. Apple's `Type` namespace (`com.apple.*`) is never touched.

use anyhow::Context as _;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Swap the org prefix of a DDM `Identifier`, preserving the full scope.
///
/// If the identifier is already under `new_org` it is returned unchanged.
///
/// When `from_org` is `Some`, the swap is **exact**: only identifiers equal to
/// `from_org` or under a `{from_org}.` prefix are rewritten (prefix replaced,
/// scope kept); anything else is left untouched. This handles cross-depth
/// renames and mixed directories precisely:
/// `uk.co.acme.config.settings` + `com.mdoyvr` (from `uk.co.acme`)
/// → `com.mdoyvr.config.settings`.
///
/// When `from_org` is `None`, the old org is assumed to occupy the same number
/// of leading dot-labels as `new_org` (the common same-depth rename, e.g.
/// `com.acme` → `com.newco`); those labels are replaced and the scope kept:
/// `com.acme.config.content-cache.settings` + `com.newco`
/// → `com.newco.config.content-cache.settings`.
pub fn rename_identifier(identifier: &str, new_org: &str, from_org: Option<&str>) -> String {
    // Already under the target org (exact, or a `{new_org}.` prefix) — no change.
    if identifier == new_org || identifier.starts_with(&format!("{new_org}.")) {
        return identifier.to_string();
    }

    // Explicit old-org prefix: swap exactly, leave non-matching identifiers be.
    if let Some(from) = from_org {
        if identifier == from {
            return new_org.to_string();
        }
        return match identifier.strip_prefix(&format!("{from}.")) {
            Some(scope) => format!("{new_org}.{scope}"),
            None => identifier.to_string(),
        };
    }

    // Default: assume the old org is the same depth as the new one.
    let org_labels = new_org.split('.').count();
    let segments: Vec<&str> = identifier.split('.').collect();
    if segments.len() > org_labels {
        // Replace the org-sized prefix, keep the remaining scope verbatim.
        let scope = segments[org_labels..].join(".");
        format!("{new_org}.{scope}")
    } else {
        // No scope beyond the org-sized prefix — fall back to the trailing name.
        let name = segments.last().copied().unwrap_or(identifier);
        format!("{new_org}.{name}")
    }
}

/// Is this JSON value a DDM declaration? Requires an Apple-namespaced `Type`
/// (`com.apple.*`) and a string `Identifier`. Unrelated `.json` files (e.g.
/// `package.json`) fail this check and are skipped rather than rewritten.
pub fn is_ddm_declaration(value: &Value) -> bool {
    value
        .get("Type")
        .and_then(Value::as_str)
        .is_some_and(|t| t.starts_with("com.apple."))
        && value.get("Identifier").and_then(Value::as_str).is_some()
}

/// Recursively replace any string value that exactly matches a key in `map`
/// with its mapped value, returning the number of replacements. Only string
/// *values* (including those nested in arrays/objects) are considered — object
/// keys are never rewritten. Exact-match keeps this safe: an Apple `Type`
/// (`com.apple.*`) can never equal an org-prefixed old `Identifier`, and partial
/// strings (URLs, free text) are left untouched.
fn rewrite_references(value: &mut Value, map: &HashMap<String, String>, count: &mut usize) {
    match value {
        Value::String(s) => {
            if let Some(replacement) = map.get(s.as_str()) {
                *s = replacement.clone();
                *count += 1;
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_references(item, map, count);
            }
        }
        Value::Object(obj) => {
            for val in obj.values_mut() {
                rewrite_references(val, map, count);
            }
        }
        _ => {}
    }
}

/// Outcome of renaming a single file in the bundle.
#[derive(Debug)]
pub struct DdmFileRename {
    pub input: PathBuf,
    pub output: PathBuf,
    /// `(old, new)` when this declaration's own `Identifier` changed.
    pub identifier: Option<(String, String)>,
    /// Count of cross-reference strings rewritten inside the `Payload`.
    pub reference_updates: usize,
    /// `.json` that is not a DDM declaration — skipped, not written.
    pub skipped_non_ddm: bool,
}

/// Aggregate result of a bundle rename.
#[derive(Debug, Default)]
pub struct DdmBundleRename {
    pub files: Vec<DdmFileRename>,
    pub failures: Vec<(PathBuf, String)>,
}

/// Compute the output path for a renamed declaration: `{stem}{suffix}.json` in
/// `output_dir` if given, else beside the input. An empty `suffix` with no
/// `output_dir` rewrites the file in place.
fn ddm_output_path(input: &Path, output_dir: Option<&str>, suffix: &str) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let filename = format!("{stem}{suffix}.json");
    match output_dir {
        Some(dir) => Path::new(dir).join(filename),
        None => input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(filename),
    }
}

/// Serialize `value` as pretty JSON (trailing newline) to `path`, creating
/// parent directories as needed.
fn write_declaration(path: &Path, value: &Value) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut serialized = serde_json::to_string_pretty(value)?;
    serialized.push('\n');
    std::fs::write(path, serialized)?;
    Ok(())
}

/// How to rewrite declaration identifiers in a batch.
#[derive(Debug, Clone, Copy)]
pub enum IdentifierRewrite<'a> {
    /// Replace one exact identifier with another.
    Exact { from: &'a str, to: &'a str },
    /// Replace a leading prefix on every identifier that carries it, so a
    /// mixed directory can be made to read `com.acme.*` in one pass. Matches
    /// only on a dot boundary (or the whole identifier), so `com.acmecorp`
    /// is never rewritten by a `com.acme` prefix.
    Prefix { from: &'a str, to: &'a str },
}

impl IdentifierRewrite<'_> {
    /// The rewritten identifier, or `None` when this rule does not apply.
    fn apply(&self, identifier: &str) -> Option<String> {
        match *self {
            IdentifierRewrite::Exact { from, to } => (identifier == from).then(|| to.to_string()),
            IdentifierRewrite::Prefix { from, to } => {
                let rest = identifier.strip_prefix(from)?;
                // Whole-identifier match, or the next char starts a new
                // component — never a partial component like `com.acmecorp`.
                if rest.is_empty() || rest.starts_with('.') {
                    Some(format!("{to}{rest}"))
                } else {
                    None
                }
            }
        }
    }
}

impl DdmBundleRename {
    /// How many declarations had their own `Identifier` rewritten. Zero after
    /// a rewrite the operator expected to match means the pattern was wrong —
    /// callers should surface that rather than report success.
    pub fn matched(&self) -> usize {
        self.files.iter().filter(|f| f.identifier.is_some()).count()
    }
}

/// Rewrite declaration identifiers across a set of DDM `.json` files, keeping
/// cross-references consistent.
///
/// Two passes, mirroring [`rename_ddm_bundle`]: build the old→new identifier
/// map from every file the rule matches, then rewrite each declaration's own
/// `Identifier` and any reference to a renamed identifier (an activation's
/// `StandardConfigurations`, an asset reference, …). With `dry_run` nothing is
/// written but the plan is still reported.
///
/// Non-DDM `.json`, parse errors, and I/O errors are recorded rather than
/// aborting the batch.
pub fn set_ddm_identifier(
    files: &[PathBuf],
    rewrite: &IdentifierRewrite<'_>,
    output_dir: Option<&str>,
    suffix: &str,
    dry_run: bool,
) -> DdmBundleRename {
    let mut result = DdmBundleRename::default();
    let mut parsed: Vec<(PathBuf, Value)> = Vec::new();
    let mut map: HashMap<String, String> = HashMap::new();

    // Pass 1 — parse, filter to DDM declarations, build the rename map.
    for path in files {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => {
                result
                    .failures
                    .push((path.clone(), format!("read failed: {e}")));
                continue;
            }
        };
        let value: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(e) => {
                result
                    .failures
                    .push((path.clone(), format!("invalid JSON: {e}")));
                continue;
            }
        };
        if !is_ddm_declaration(&value) {
            result.files.push(DdmFileRename {
                input: path.clone(),
                output: path.clone(),
                identifier: None,
                reference_updates: 0,
                skipped_non_ddm: true,
            });
            continue;
        }
        if let Some(old) = value.get("Identifier").and_then(Value::as_str)
            && let Some(new) = rewrite.apply(old)
        {
            map.insert(old.to_string(), new);
        }
        parsed.push((path.clone(), value));
    }

    // Pass 2 — rewrite identifiers + cross-references, then write.
    for (path, mut value) in parsed {
        let old_id = value
            .get("Identifier")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let new_id = map.get(&old_id).cloned();

        let mut count = 0usize;
        rewrite_references(&mut value, &map, &mut count);
        // The declaration's own Identifier is inside `value`, so it was
        // counted by the walk; the rest are genuine cross-references.
        let reference_updates = count.saturating_sub(usize::from(new_id.is_some()));

        let output = ddm_output_path(&path, output_dir, suffix);
        if !dry_run && (new_id.is_some() || reference_updates > 0) {
            match serde_json::to_string_pretty(&value)
                .map_err(|e| e.to_string())
                .and_then(|body| std::fs::write(&output, body + "\n").map_err(|e| e.to_string()))
            {
                Ok(()) => {}
                Err(e) => {
                    result
                        .failures
                        .push((path.clone(), format!("write failed: {e}")));
                    continue;
                }
            }
        }

        result.files.push(DdmFileRename {
            input: path,
            output,
            identifier: new_id.map(|new| (old_id, new)),
            reference_updates,
            skipped_non_ddm: false,
        });
    }

    result
}

/// Rename the org prefix across a set of DDM `.json` files (bundle-aware).
///
/// Two passes: (1) parse every file, keep the DDM declarations, and build the
/// old→new `Identifier` map; (2) rewrite each declaration's own `Identifier`
/// and any cross-reference to a renamed `Identifier` in any `Payload`, then
/// write to the computed output path. Non-DDM `.json`, parse errors, and I/O
/// errors are recorded rather than aborting the batch. With `dry_run`, no files
/// are written but the planned changes are still reported.
pub fn rename_ddm_bundle(
    files: &[PathBuf],
    new_org: &str,
    from_org: Option<&str>,
    output_dir: Option<&str>,
    suffix: &str,
    dry_run: bool,
) -> DdmBundleRename {
    let mut result = DdmBundleRename::default();
    let mut parsed: Vec<(PathBuf, Value)> = Vec::new();
    let mut map: HashMap<String, String> = HashMap::new();

    // Pass 1 — parse, filter to DDM declarations, build the rename map.
    for path in files {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => {
                result
                    .failures
                    .push((path.clone(), format!("read failed: {e}")));
                continue;
            }
        };
        let value: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(e) => {
                result
                    .failures
                    .push((path.clone(), format!("invalid JSON: {e}")));
                continue;
            }
        };
        if !is_ddm_declaration(&value) {
            result.files.push(DdmFileRename {
                input: path.clone(),
                output: path.clone(),
                identifier: None,
                reference_updates: 0,
                skipped_non_ddm: true,
            });
            continue;
        }
        if let Some(old) = value.get("Identifier").and_then(Value::as_str) {
            let new = rename_identifier(old, new_org, from_org);
            if new != old {
                map.insert(old.to_string(), new);
            }
        }
        parsed.push((path.clone(), value));
    }

    // Pass 2 — rewrite identifiers + cross-references, then write.
    for (path, mut value) in parsed {
        let old_id = value
            .get("Identifier")
            .and_then(Value::as_str)
            .map(String::from);

        let mut count = 0usize;
        rewrite_references(&mut value, &map, &mut count);

        let new_id = value
            .get("Identifier")
            .and_then(Value::as_str)
            .map(String::from);
        let identifier = match (&old_id, &new_id) {
            (Some(old), Some(new)) if old != new => Some((old.clone(), new.clone())),
            _ => None,
        };
        // The top-level Identifier rewrite is one of the counted replacements;
        // the rest are genuine cross-references inside the Payload.
        let reference_updates = count - usize::from(identifier.is_some());

        let output = ddm_output_path(&path, output_dir, suffix);

        if !dry_run && let Err(e) = write_declaration(&output, &value) {
            result
                .failures
                .push((path.clone(), format!("write failed: {e}")));
            continue;
        }

        result.files.push(DdmFileRename {
            input: path,
            output,
            identifier,
            reference_updates,
            skipped_non_ddm: false,
        });
    }

    result
}

/// Rename a single declaration's org in place within the JSON value: its own
/// `Identifier` plus any self-reference. Returns `(identifier_change,
/// reference_updates)`. A lone declaration has no bundle, so references to
/// *other* declarations cannot be resolved — only its own identifier (and rare
/// self-references) change.
pub fn rename_declaration_value(
    value: &mut Value,
    new_org: &str,
    from_org: Option<&str>,
) -> (Option<(String, String)>, usize) {
    let old_id = value
        .get("Identifier")
        .and_then(Value::as_str)
        .map(String::from);

    let mut map = HashMap::new();
    if let Some(old) = &old_id {
        let new = rename_identifier(old, new_org, from_org);
        if &new != old {
            map.insert(old.clone(), new);
        }
    }

    let mut count = 0usize;
    rewrite_references(value, &map, &mut count);

    let new_id = value
        .get("Identifier")
        .and_then(Value::as_str)
        .map(String::from);
    let identifier = match (&old_id, &new_id) {
        (Some(old), Some(new)) if old != new => Some((old.clone(), new.clone())),
        _ => None,
    };
    let reference_updates = count - usize::from(identifier.is_some());
    (identifier, reference_updates)
}

/// Rename the org of a single DDM declaration file, writing to `output` (unless
/// `dry_run`). Errors if the file is not a DDM declaration.
pub fn rename_declaration_file(
    input: &Path,
    output: &Path,
    new_org: &str,
    from_org: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<DdmFileRename> {
    let text = std::fs::read_to_string(input)
        .with_context(|| format!("Failed to read {}", input.display()))?;
    let mut value: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", input.display()))?;
    if !is_ddm_declaration(&value) {
        anyhow::bail!(
            "{} is not a DDM declaration (needs a com.apple.* Type and an Identifier)",
            input.display()
        );
    }

    let (identifier, reference_updates) = rename_declaration_value(&mut value, new_org, from_org);

    if !dry_run {
        write_declaration(output, &value)?;
    }

    Ok(DdmFileRename {
        input: input.to_path_buf(),
        output: output.to_path_buf(),
        identifier,
        reference_updates,
        skipped_non_ddm: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rename_identifier_replaces_org_keeps_name() {
        assert_eq!(
            rename_identifier("com.acme.settings", "com.newco", None),
            "com.newco.settings"
        );
    }

    #[test]
    fn rename_identifier_leaves_already_under_target_org() {
        assert_eq!(
            rename_identifier("com.newco.settings", "com.newco", None),
            "com.newco.settings"
        );
        // A look-alike org with a longer label is NOT under the target org.
        assert_eq!(
            rename_identifier("com.newcocorp.settings", "com.newco", None),
            "com.newco.settings"
        );
    }

    #[test]
    fn rename_identifier_handles_single_segment() {
        assert_eq!(
            rename_identifier("settings", "com.newco", None),
            "com.newco.settings"
        );
    }

    #[test]
    fn rename_identifier_preserves_multi_segment_scope() {
        // The org prefix is swapped but the scope (config.content-cache.settings)
        // is kept intact — it must not collapse to just the trailing segment.
        assert_eq!(
            rename_identifier("com.acme.config.content-cache.settings", "com.mdoyvr", None),
            "com.mdoyvr.config.content-cache.settings"
        );
    }

    #[test]
    fn rename_identifier_from_org_handles_cross_depth() {
        // Explicit old org of a different depth than the new one: prefix swapped
        // exactly, scope preserved.
        assert_eq!(
            rename_identifier(
                "uk.co.acme.config.settings",
                "com.mdoyvr",
                Some("uk.co.acme")
            ),
            "com.mdoyvr.config.settings"
        );
        // An identifier NOT under the named old org is left untouched.
        assert_eq!(
            rename_identifier("io.partner.thing", "com.mdoyvr", Some("uk.co.acme")),
            "io.partner.thing"
        );
        // Bare old org → just the new org.
        assert_eq!(
            rename_identifier("uk.co.acme", "com.mdoyvr", Some("uk.co.acme")),
            "com.mdoyvr"
        );
    }

    #[test]
    fn is_ddm_declaration_requires_apple_type_and_identifier() {
        assert!(is_ddm_declaration(&json!({
            "Type": "com.apple.configuration.passcode.settings",
            "Identifier": "com.acme.settings",
            "Payload": {}
        })));
        // Missing Identifier.
        assert!(!is_ddm_declaration(&json!({
            "Type": "com.apple.configuration.passcode.settings"
        })));
        // Not an Apple-namespaced declaration (e.g. package.json).
        assert!(!is_ddm_declaration(
            &json!({ "name": "thing", "version": "1.0.0" })
        ));
    }

    #[test]
    fn rewrite_references_updates_matches_not_types() {
        let mut map = HashMap::new();
        map.insert(
            "com.acme.settings".to_string(),
            "com.newco.settings".to_string(),
        );
        let mut value = json!({
            "Type": "com.apple.activation.simple",
            "Identifier": "com.acme.activation",
            "Payload": { "StandardConfigurations": ["com.acme.settings", "com.other.keep"] }
        });
        let mut count = 0;
        rewrite_references(&mut value, &map, &mut count);
        assert_eq!(count, 1);
        assert_eq!(
            value["Payload"]["StandardConfigurations"][0],
            json!("com.newco.settings")
        );
        // Non-mapped reference and the Apple Type are untouched.
        assert_eq!(
            value["Payload"]["StandardConfigurations"][1],
            json!("com.other.keep")
        );
        assert_eq!(value["Type"], json!("com.apple.activation.simple"));
    }

    #[test]
    fn bundle_rename_keeps_activation_to_configuration_links() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("passcode.json");
        let activation_path = dir.path().join("activation.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&json!({
                "Type": "com.apple.configuration.passcode.settings",
                "Identifier": "com.acme.settings",
                "Payload": {}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &activation_path,
            serde_json::to_string_pretty(&json!({
                "Type": "com.apple.activation.simple",
                "Identifier": "com.acme.activation",
                "Payload": { "StandardConfigurations": ["com.acme.settings"] }
            }))
            .unwrap(),
        )
        .unwrap();

        let files = vec![config_path.clone(), activation_path.clone()];
        // suffix "" + no output_dir => in-place rewrite
        let result = rename_ddm_bundle(&files, "com.newco", None, None, "", false);
        assert!(result.failures.is_empty(), "{:?}", result.failures);

        let config: Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let activation: Value =
            serde_json::from_str(&std::fs::read_to_string(&activation_path).unwrap()).unwrap();

        assert_eq!(config["Identifier"], json!("com.newco.settings"));
        assert_eq!(activation["Identifier"], json!("com.newco.activation"));
        // The cross-reference followed the rename — the bundle stays deployable.
        assert_eq!(
            activation["Payload"]["StandardConfigurations"][0],
            json!("com.newco.settings")
        );
        // Apple Type namespaces are never touched.
        assert_eq!(
            config["Type"],
            json!("com.apple.configuration.passcode.settings")
        );
    }

    #[test]
    fn bundle_rename_skips_non_ddm_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let pkg = dir.path().join("package.json");
        std::fs::write(&pkg, r#"{"name":"thing","version":"1.0.0"}"#).unwrap();
        let result = rename_ddm_bundle(
            std::slice::from_ref(&pkg),
            "com.newco",
            None,
            None,
            "-normalized",
            false,
        );
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].skipped_non_ddm);
        // Nothing written for a skipped file.
        assert!(!dir.path().join("package-normalized.json").exists());
    }

    // ── Arbitrary identifier replacement (`ddm reidentify`) ──────────────

    fn write_json(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    /// The headline case: swap one declaration's Identifier for an unrelated
    /// one, in place. An org-prefix rename cannot express this.
    #[test]
    fn set_identifier_replaces_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let f = write_json(
            dir.path(),
            "swu.json",
            r#"{"Type":"com.apple.configuration.softwareupdate.settings",
                "Identifier":"com.fleetdm.settings","Payload":{"Notifications":true}}"#,
        );

        let result = set_ddm_identifier(
            std::slice::from_ref(&f),
            &IdentifierRewrite::Exact {
                from: "com.fleetdm.settings",
                to: "com.acme.config.softwareupdate.settings.beta",
            },
            None,
            "",
            false,
        );

        assert!(result.failures.is_empty(), "{:?}", result.failures);
        let body: Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
        assert_eq!(
            body["Identifier"],
            "com.acme.config.softwareupdate.settings.beta"
        );
        // The payload is untouched.
        assert_eq!(body["Payload"]["Notifications"], true);
    }

    /// An activation references its configuration by Identifier. Renaming the
    /// configuration must rewrite the referrer, or the bundle dangles.
    #[test]
    fn set_identifier_rewrites_activation_references() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_json(
            dir.path(),
            "configuration.json",
            r#"{"Type":"com.apple.configuration.softwareupdate.settings",
                "Identifier":"com.fleetdm.settings","Payload":{}}"#,
        );
        let activation = write_json(
            dir.path(),
            "activation.json",
            r#"{"Type":"com.apple.activation.simple","Identifier":"com.fleetdm.activation",
                "Payload":{"StandardConfigurations":["com.fleetdm.settings"]}}"#,
        );

        let result = set_ddm_identifier(
            &[config, activation.clone()],
            &IdentifierRewrite::Exact {
                from: "com.fleetdm.settings",
                to: "com.acme.config.softwareupdate.settings.beta",
            },
            None,
            "",
            false,
        );
        assert!(result.failures.is_empty(), "{:?}", result.failures);

        let act: Value =
            serde_json::from_str(&std::fs::read_to_string(&activation).unwrap()).unwrap();
        assert_eq!(
            act["Payload"]["StandardConfigurations"][0],
            "com.acme.config.softwareupdate.settings.beta",
            "activation must follow the rename"
        );
        // The activation keeps its own identity.
        assert_eq!(act["Identifier"], "com.fleetdm.activation");
        assert!(
            result.files.iter().any(|f| f.reference_updates > 0),
            "the reference rewrite must be reported"
        );
    }

    /// A `--from` that matches nothing is an operator error — silently
    /// writing unchanged files would look like success.
    #[test]
    fn set_identifier_reports_when_nothing_matched() {
        let dir = tempfile::tempdir().unwrap();
        let f = write_json(
            dir.path(),
            "swu.json",
            r#"{"Type":"com.apple.configuration.softwareupdate.settings",
                "Identifier":"com.other.settings","Payload":{}}"#,
        );
        let result = set_ddm_identifier(
            &[f],
            &IdentifierRewrite::Exact {
                from: "com.fleetdm.settings",
                to: "com.acme.x",
            },
            None,
            "",
            false,
        );
        assert!(
            result.files.iter().all(|f| f.identifier.is_none()),
            "nothing should be renamed"
        );
        assert_eq!(result.matched(), 0, "matched() reports the miss");
    }

    #[test]
    fn set_identifier_dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let f = write_json(
            dir.path(),
            "swu.json",
            r#"{"Type":"com.apple.configuration.softwareupdate.settings",
                "Identifier":"com.fleetdm.settings","Payload":{}}"#,
        );
        let before = std::fs::read_to_string(&f).unwrap();
        let result = set_ddm_identifier(
            std::slice::from_ref(&f),
            &IdentifierRewrite::Exact {
                from: "com.fleetdm.settings",
                to: "com.acme.x",
            },
            None,
            "",
            true,
        );
        assert_eq!(result.matched(), 1, "dry run still reports the plan");
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            before,
            "file untouched"
        );
    }

    /// Batch by pattern: every identifier starting with the old prefix is
    /// rewritten, so a mixed directory can be made to read `com.acme.*` in
    /// one pass — including the cross-references between them.
    #[test]
    fn prefix_rewrite_batches_a_whole_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_json(
            dir.path(),
            "configuration.json",
            r#"{"Type":"com.apple.configuration.softwareupdate.settings",
                "Identifier":"com.fleetdm.config.swu","Payload":{}}"#,
        );
        let activation = write_json(
            dir.path(),
            "activation.json",
            r#"{"Type":"com.apple.activation.simple","Identifier":"com.fleetdm.activation.swu",
                "Payload":{"StandardConfigurations":["com.fleetdm.config.swu"]}}"#,
        );

        let result = set_ddm_identifier(
            &[config.clone(), activation.clone()],
            &IdentifierRewrite::Prefix {
                from: "com.fleetdm",
                to: "com.acme",
            },
            None,
            "",
            false,
        );
        assert!(result.failures.is_empty(), "{:?}", result.failures);
        assert_eq!(result.matched(), 2, "both declarations rewritten");

        let cfg: Value = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
        let act: Value =
            serde_json::from_str(&std::fs::read_to_string(&activation).unwrap()).unwrap();
        assert_eq!(cfg["Identifier"], "com.acme.config.swu");
        assert_eq!(act["Identifier"], "com.acme.activation.swu");
        assert_eq!(
            act["Payload"]["StandardConfigurations"][0], "com.acme.config.swu",
            "cross-reference follows the prefix rewrite"
        );
    }

    /// A prefix must match on a dot boundary — `com.acmecorp` is not
    /// `com.acme`, and rewriting it would corrupt an unrelated org.
    #[test]
    fn prefix_rewrite_respects_dot_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let f = write_json(
            dir.path(),
            "other.json",
            r#"{"Type":"com.apple.configuration.softwareupdate.settings",
                "Identifier":"com.fleetdmother.settings","Payload":{}}"#,
        );
        let result = set_ddm_identifier(
            &[f],
            &IdentifierRewrite::Prefix {
                from: "com.fleetdm",
                to: "com.acme",
            },
            None,
            "",
            false,
        );
        assert_eq!(
            result.matched(),
            0,
            "com.fleetdmother must not match com.fleetdm"
        );
    }
}
