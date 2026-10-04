//! `validate()` — values against a schema, as diagnostics.
//!
//! The result shape the crate plan left undefined. Every diagnostic names
//! the path it is about, the rule that fired, and whether it blocks
//! emission. Warnings do not block; a caller may show them and proceed.

use serde::Serialize;

use crate::SchemaRegistry;
use crate::form::Target;
use crate::types::{FieldDefinition, FieldType, PayloadManifest, Platform};
use crate::version;

/// Why an embedded designated requirement is unusable. Mirrors
/// `contour_core::requirement_flaw`, which this crate cannot call: that one
/// lives beside `codesign` and contour-form must build without a
/// filesystem. Syntactic only — `csreq` compiles the expression, this
/// catches the ways a correct one arrives wrapped in codesign's output.
fn requirement_flaw(req: &str) -> Option<&'static str> {
    let t = req.trim();
    if t.is_empty() {
        return Some("is empty");
    }
    if t.starts_with("designated =>") || t.starts_with("designated=>") {
        return Some("still carries the `designated => ` prefix; keep only the text after it");
    }
    if t.lines().any(|l| l.trim_start().starts_with("Executable=")) {
        return Some(
            "carries codesign's `Executable=…` trailer, which is not part of the requirement — \
             csreq rejects it. That line comes from stderr; keep only the text after \
             `designated => `",
        );
    }
    if t.lines().filter(|l| !l.trim().is_empty()).count() > 1 {
        return Some("spans several lines; a designated requirement is one expression");
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Dotted path from the payload root; `""` for the document itself.
    pub path: String,
    pub rule: &'static str,
    pub message: String,
    pub blocks_emit: bool,
}

impl Diagnostic {
    fn error(path: &str, rule: &'static str, message: String) -> Self {
        Self {
            severity: Severity::Error,
            path: path.to_string(),
            rule,
            message,
            blocks_emit: true,
        }
    }
    fn warning(path: &str, rule: &'static str, message: String) -> Self {
        Self {
            severity: Severity::Warning,
            path: path.to_string(),
            rule,
            message,
            blocks_emit: false,
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        if self.path.is_empty() {
            write!(f, "{sev} [{}]: {}", self.rule, self.message)
        } else {
            write!(f, "{sev} [{}] {}: {}", self.rule, self.path, self.message)
        }
    }
}

/// Check `values` against `type_id`'s schema, with no target platform. An
/// unknown type is itself a blocking diagnostic rather than an error, so the
/// shape is uniform.
pub fn validate(
    reg: &SchemaRegistry,
    type_id: &str,
    values: &serde_json::Value,
) -> Vec<Diagnostic> {
    validate_for(reg, type_id, values, None)
}

/// [`validate`] for a target platform. A few rules depend on it: Apple keys
/// `Privacy.PermissionDefaults` by bare bundle id on iOS and by
/// `"Bundle-ID {Designated-Requirement}"` on macOS, so which spelling is the
/// mistake depends on where the declaration is going.
pub fn validate_for(
    reg: &SchemaRegistry,
    type_id: &str,
    values: &serde_json::Value,
    platform: Option<Platform>,
) -> Vec<Diagnostic> {
    validate_target(
        reg,
        type_id,
        values,
        &Target {
            platform,
            ..Default::default()
        },
    )
}

/// [`validate_for`] with the full target — platform AND OS version — which
/// is what availability needs. `form()` has computed `Verdict::Removed` for
/// a while; nothing at emit time acted on it, so a key Apple removed on the
/// target OS was written into a document the device then silently ignored.
/// Now it is refused here, where the emitter asks.
pub fn validate_target(
    reg: &SchemaRegistry,
    type_id: &str,
    values: &serde_json::Value,
    target: &Target,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let Some(m) = reg.get(type_id).or_else(|| reg.get_by_name(type_id)) else {
        out.push(Diagnostic::error(
            "",
            "unknown-type",
            format!("payload type '{type_id}' is not in the schema"),
        ));
        return out;
    };
    if !m.is_authorable() {
        let because = m
            .kind
            .and_then(mdm_schema::PayloadKind::not_authorable_reason)
            .unwrap_or("not a document an operator authors");
        out.push(Diagnostic::error(
            "",
            "not-authorable",
            format!("'{}' is {because}", m.payload_type),
        ));
        return out;
    }
    // The whole payload gone from the target OS: nothing below matters.
    if let Some(p) = target.platform
        && let Some(gone) = m.os_support.get(&p).and_then(|o| o.removed.as_deref())
    {
        match target.os_version.as_deref() {
            Some(os) if version::at_least(os, gone) == Some(true) => {
                out.push(Diagnostic::error(
                    "",
                    "payload-removed-on-target",
                    format!(
                        "'{}' was removed from {} at {gone}; on {os} the device ignores the whole \
                         payload",
                        m.payload_type,
                        p.as_str()
                    ),
                ));
                return out;
            }
            Some(_) => {}
            None => out.push(Diagnostic::warning(
                "",
                "payload-removed",
                format!(
                    "'{}' was removed from {} at {gone} — on that version and later the device \
                     ignores it. Pass --os-version to check your target",
                    m.payload_type,
                    p.as_str()
                ),
            )),
        }
    }
    let Some(obj) = values.as_object() else {
        out.push(Diagnostic::error(
            "",
            "not-an-object",
            "values must be a JSON object keyed by top-level payload key".into(),
        ));
        return out;
    };
    check_object(m, None, "", obj, target, &mut out);
    out
}

/// Apple's replacement, where the schema names one.
///
/// A removed key's description often ends with a sentence naming what to use
/// instead — verified against Apple's own documentation, which renders it as
/// "Removed: use the declarative management `…` configuration". Carrying it
/// into the diagnostic is the difference between an agent being told a key is
/// gone and an agent being told where the setting went; without it, the next
/// step is a guess.
fn replacement_hint(description: &str) -> Option<String> {
    let at = description.find("Removed: ")?;
    let tail = description[at + "Removed: ".len()..].trim();
    let sentence = tail.split_once("\n").map_or(tail, |(head, _)| head).trim();
    if sentence.is_empty() {
        return None;
    }
    Some(sentence.trim_end_matches('.').to_string())
}

/// What Apple states about this key on the target, applied to a key that
/// is PRESENT in the values — the moment it stops being a form verdict and
/// becomes a document.
///
/// Apple: a removed key is silently ignored on that OS and later. So with
/// a version, removal is refused; without one, it is named, because the
/// author is about to ship a key Apple has already taken away somewhere.
fn availability_rules(f: &FieldDefinition, path: &str, target: &Target, out: &mut Vec<Diagnostic>) {
    let Some(p) = target.platform else { return };
    // `n/a` on this platform: the key does not exist here at all.
    if !f.platforms.is_empty() && !f.platforms.contains(&p) {
        out.push(Diagnostic::error(
            path,
            "key-unavailable-on-platform",
            format!(
                "'{}' does not exist on {} — Apple marks it n/a there, and the device ignores it",
                f.name,
                p.as_str()
            ),
        ));
        return;
    }
    let os = target.os_version.as_deref();
    if let Some(gone) = f.removed_by_platform.get(&p) {
        match os {
            Some(os) if version::at_least(os, gone) == Some(true) => {
                let instead = replacement_hint(&f.description)
                    .map(|r| format!(". Apple says: {r}"))
                    .unwrap_or_default();
                out.push(Diagnostic::error(
                    path,
                    "key-removed-on-target",
                    format!(
                        "'{}' was removed from {} at {gone}; on {os} the device ignores it{instead}",
                        f.name,
                        p.as_str()
                    ),
                ));
                return;
            }
            Some(_) => {}
            None => {
                out.push(Diagnostic::warning(
                    path,
                    "key-removed",
                    format!(
                        "'{}' was removed from {} at {gone} — on that version and later the device \
                         ignores it. Pass --os-version to check your target",
                        f.name,
                        p.as_str()
                    ),
                ));
                return;
            }
        }
    }
    if let Some(dep) = f.deprecated_by_platform.get(&p) {
        match os {
            Some(os) if version::at_least(os, dep) == Some(true) => out.push(Diagnostic::warning(
                path,
                "key-deprecated-on-target",
                format!(
                    "'{}' is deprecated on {} since {dep}; it still works on {os}, but Apple has \
                     flagged it for removal",
                    f.name,
                    p.as_str()
                ),
            )),
            Some(_) => {}
            None => out.push(Diagnostic::warning(
                path,
                "key-deprecated",
                format!("'{}' is deprecated on {} since {dep}", f.name, p.as_str()),
            )),
        }
    }
}

fn children<'a>(
    m: &'a PayloadManifest,
    parent: Option<&FieldDefinition>,
) -> Vec<&'a FieldDefinition> {
    let pp = parent.map(|p| p.path.as_str());
    m.fields_in_order()
        .filter(|f| f.parent_key.as_deref() == pp)
        .collect()
}

fn check_object(
    m: &PayloadManifest,
    parent: Option<&FieldDefinition>,
    prefix: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
    target: &Target,
    out: &mut Vec<Diagnostic>,
) {
    let kids = children(m, parent);
    let dynamic = parent.and_then(|p| m.dynamic_value_shape(p));

    for (k, v) in obj {
        let path = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        if FieldDefinition::is_placeholder_name(k) {
            out.push(Diagnostic::error(
                &path,
                "marker-as-key",
                format!("'{k}' is a schema marker for an operator-named key, not a key"),
            ));
            continue;
        }
        match kids.iter().find(|f| f.name == *k) {
            Some(f) => {
                availability_rules(f, &path, target, out);
                check_value(m, f, &path, v, target, out);
            }
            None => match dynamic {
                // Under a dict-of, any key is the operator's; the value
                // takes the shape.
                Some(shape) => check_value(m, shape, &path, v, target, out),
                None => out.push(Diagnostic::error(
                    &path,
                    "unknown-key",
                    format!(
                        "'{k}' is not a key of {}",
                        parent.map_or(m.payload_type.as_str(), |p| p.path.as_str())
                    ),
                )),
            },
        }
    }

    // Composed identifiers in KEY position: the dictionary's keys are
    // `"Bundle-ID {Designated-Requirement}"` or `"Bundle-ID (Team-ID)"`, and
    // Apple types the dictionary as free-form, so any spelling on any
    // platform is schema-valid and the wrong one matches no app. The
    // registry in `composed.rs` says which form and where; this only asks.
    if let Some(parent_path) = parent.map(|p| p.path.as_str())
        && let Some(entry) = crate::composed::key_entry(&m.payload_type, parent_path)
    {
        for k in obj.keys() {
            let path = format!("{prefix}.{k}");
            composed_identifier(entry, k, &path, target, out);
        }
    }

    // Required children of a present parent.
    for f in kids
        .iter()
        .filter(|f| f.flags.required && !f.is_placeholder())
    {
        if !obj.contains_key(&f.name) {
            let path = if prefix.is_empty() {
                f.name.clone()
            } else {
                format!("{prefix}.{}", f.name)
            };
            out.push(Diagnostic::error(
                &path,
                "required-missing",
                format!("'{}' is required", f.name),
            ));
        }
    }
}

fn check_value(
    m: &PayloadManifest,
    f: &FieldDefinition,
    path: &str,
    v: &serde_json::Value,
    target: &Target,
    out: &mut Vec<Diagnostic>,
) {
    use serde_json::Value as J;
    let type_err = |out: &mut Vec<Diagnostic>, want: &str| {
        out.push(Diagnostic::error(
            path,
            "type-mismatch",
            format!("expected {want}, got {}", json_kind(v)),
        ));
    };
    match f.field_type {
        FieldType::Boolean => {
            if !v.is_boolean() {
                type_err(out, "boolean");
            }
        }
        FieldType::Integer => match v {
            J::Number(n) if n.is_i64() || n.is_u64() => check_range(f, path, n.as_f64(), out),
            _ => type_err(out, "integer"),
        },
        FieldType::Real => match v {
            J::Number(n) => check_range(f, path, n.as_f64(), out),
            _ => type_err(out, "number"),
        },
        FieldType::String | FieldType::Date => match v {
            J::String(s) => {
                check_enum(f, path, s, out);
                // Composed identifiers in VALUE position.
                if let Some(entry) = crate::composed::value_entry(&m.payload_type, &f.path) {
                    composed_identifier(entry, s, path, target, out);
                }
            }
            _ => type_err(out, "string"),
        },
        // JSON has no bytes: a <data> key arrives as base64. The emitter
        // writes it as <data> and refuses a string that does not decode, so
        // this says the same thing earlier, where the path is still known.
        FieldType::Data => match v {
            J::String(s) => {
                use base64::Engine as _;
                if base64::engine::general_purpose::STANDARD
                    .decode(s.trim())
                    .is_err()
                {
                    out.push(Diagnostic::error(
                        path,
                        "data-not-base64",
                        "Data-typed key must be base64; this does not decode, and the emitter \
                         would refuse it rather than write a <string> where the schema says <data>"
                            .into(),
                    ));
                }
            }
            _ => type_err(out, "base64 string"),
        },
        FieldType::Array => match v {
            J::Array(items) => {
                let kids = children(m, Some(f));
                if kids.len() == 1 {
                    for (i, item) in items.iter().enumerate() {
                        check_value(m, kids[0], &format!("{path}[{i}]"), item, target, out);
                    }
                }
            }
            _ => type_err(out, "array"),
        },
        FieldType::Dictionary => match v {
            J::Object(o) => check_object(m, Some(f), path, o, target, out),
            _ => type_err(out, "object"),
        },
    }
    if let J::Number(n) = v
        && matches!(f.field_type, FieldType::Integer)
        && !f.allowed_values.is_empty()
        && !f.allowed_values.iter().any(|a| a == &n.to_string())
    {
        out.push(Diagnostic::error(
            path,
            "not-in-enum",
            format!("{n} is not one of {:?}", f.allowed_values),
        ));
    }
}

/// Apply the `composed-identifier` rule to one identifier.
///
/// A braced requirement is first checked for `codesign`'s own output around
/// it — the `Executable=…` trailer most often — which csreq refuses and the
/// device matches nothing against. Then the registry decides whether this
/// spelling is right for the target.
fn composed_identifier(
    entry: &crate::composed::Entry,
    s: &str,
    path: &str,
    target: &Target,
    out: &mut Vec<Diagnostic>,
) {
    let platform = target.platform;
    use crate::composed::{Spelling, check, spelling};
    let push = |out: &mut Vec<Diagnostic>, blocks: bool, msg: String| {
        out.push(if blocks {
            Diagnostic::error(path, "composed-identifier", msg)
        } else {
            Diagnostic::warning(path, "composed-identifier", msg)
        });
    };
    if let Spelling::Braced(inner) = spelling(s)
        && let Some(flaw) = requirement_flaw(inner)
    {
        push(
            out,
            platform.is_some(),
            format!("designated requirement {flaw}"),
        );
        return;
    }
    if let Some(f) = check(entry, s, platform) {
        push(out, f.blocks, f.message);
    }
}

fn check_enum(f: &FieldDefinition, path: &str, s: &str, out: &mut Vec<Diagnostic>) {
    if !f.allowed_values.is_empty() && !f.allowed_values.iter().any(|a| a == s) {
        out.push(Diagnostic::error(
            path,
            "not-in-enum",
            format!("{s:?} is not one of {:?}", f.allowed_values),
        ));
    }
}

fn check_range(f: &FieldDefinition, path: &str, n: Option<f64>, out: &mut Vec<Diagnostic>) {
    let Some(n) = n else { return };
    if let Some(min) = f.range_min
        && n < min
    {
        out.push(Diagnostic::error(
            path,
            "below-range",
            format!("{n} is below the minimum {min}"),
        ));
    }
    if let Some(max) = f.range_max
        && n > max
    {
        out.push(Diagnostic::error(
            path,
            "above-range",
            format!("{n} is above the maximum {max}"),
        ));
    }
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {

    /// Apple's page for `allowRapidSecurityResponseInstallation` renders
    /// exactly this sentence,
    /// and contour's dataset carries it in the key description. An agent told
    /// only that a key is gone has to guess where the setting went.
    #[test]
    fn a_removed_key_carries_apples_replacement() {
        let d = "If `false`, the system prohibits installation of Background Security \
                 Improvements.\n\nRemoved: use the declarative management \
                 `com.apple.configuration.softwareupdate.settings` configuration.";
        assert_eq!(
            replacement_hint(d).as_deref(),
            Some(
                "use the declarative management `com.apple.configuration.softwareupdate.settings` \
                 configuration"
            )
        );
    }

    #[test]
    fn a_description_without_a_replacement_adds_nothing() {
        assert_eq!(replacement_hint("Just a description."), None);
        assert_eq!(replacement_hint(""), None);
        assert_eq!(replacement_hint("Removed: "), None);
    }
    use super::*;
    use serde_json::json;

    fn reg() -> SchemaRegistry {
        SchemaRegistry::embedded().unwrap()
    }

    #[test]
    fn clean_values_produce_no_blocking_diagnostics() {
        let d = validate(
            &reg(),
            "com.apple.configuration.safari.settings",
            &json!({"AcceptCookies": "Never", "AllowDisablingFraudWarning": false}),
        );
        assert!(d.iter().all(|x| !x.blocks_emit), "{d:?}");
    }

    #[test]
    fn unknown_key_enum_and_type_are_caught_by_path() {
        let d = validate(
            &reg(),
            "com.apple.configuration.safari.settings",
            &json!({"AcceptCookies": "Sometimes", "AllowDisablingFraudWarning": "yes", "Bogus": 1}),
        );
        let rules: Vec<(&str, &str)> = d.iter().map(|x| (x.path.as_str(), x.rule)).collect();
        assert!(
            rules.contains(&("AcceptCookies", "not-in-enum")),
            "{rules:?}"
        );
        assert!(
            rules.contains(&("AllowDisablingFraudWarning", "type-mismatch")),
            "{rules:?}"
        );
        assert!(rules.contains(&("Bogus", "unknown-key")), "{rules:?}");
    }

    /// Under a dict-of, the operator's keys are not unknown; their values
    /// take the shape, and a marker used literally is refused.
    #[test]
    fn dict_of_entries_validate_against_the_shape() {
        let d = validate(
            &reg(),
            "com.apple.configuration.app.settings",
            &json!({"Privacy": {"PermissionDefaults": {
                "us.zoom.xos": {"Camera": "Allow", "OrganizationJustification": "Calls"},
                "ANY": {"Camera": "Allow"}
            }}}),
        );
        let rules: Vec<(&str, &str)> = d.iter().map(|x| (x.path.as_str(), x.rule)).collect();
        assert!(
            !rules.iter().any(
                |(p, r)| p.starts_with("Privacy.PermissionDefaults.us.zoom.xos")
                    && *r == "unknown-key"
            ),
            "{rules:?}"
        );
        assert!(
            rules.contains(&("Privacy.PermissionDefaults.ANY", "marker-as-key")),
            "{rules:?}"
        );
    }

    /// Apple's two spellings: bare bundle ID on iOS, "Bundle-ID
    /// {Designated-Requirement}" on macOS. Which one is the mistake depends
    /// on the target; parentheses are neither.
    #[test]
    fn permission_defaults_key_rule_follows_the_target_platform() {
        let r = reg();
        let rule = |key: &str, p: Option<Platform>| -> Vec<Diagnostic> {
            validate_for(
                &r,
                "com.apple.configuration.app.settings",
                &json!({"Privacy": {"PermissionDefaults": {key: {"Camera": "Allow", "OrganizationJustification": "x"}}}}),
                p,
            )
            .into_iter()
            .filter(|d| d.rule == "composed-identifier")
            .collect()
        };
        let bare = "corp.sap.privileges";
        let composed =
            "corp.sap.privileges {anchor apple generic and identifier \"corp.sap.privileges\"}";

        assert!(
            rule(bare, Some(Platform::Ios)).is_empty(),
            "bare is Apple's iOS form"
        );
        assert_eq!(
            rule(bare, Some(Platform::MacOS)).len(),
            1,
            "bare on macOS matches no app"
        );
        assert!(
            rule(composed, Some(Platform::MacOS)).is_empty(),
            "composed is Apple's macOS form"
        );
        assert_eq!(
            rule(composed, Some(Platform::Ios)).len(),
            1,
            "composed on iOS is the wrong spelling"
        );

        let none = rule(bare, None);
        assert_eq!(none.len(), 1);
        assert!(!none[0].blocks_emit, "without a target it can only advise");
        assert!(
            none[0].message.contains("correct for iOS"),
            "{}",
            none[0].message
        );

        assert!(
            rule("corp.sap.privileges (7R5ZEU67FQ)", Some(Platform::MacOS))[0]
                .message
                .contains("parentheses")
        );
    }

    /// `codesign -d -r-` writes the requirement to stdout and
    /// `Executable=…` to stderr. A paste of the terminal carries both;
    /// csreq refuses it, and a declaration carrying it matches nothing.
    #[test]
    fn a_requirement_with_codesigns_trailer_is_refused() {
        let r = reg();
        let dr = r#"identifier "com.apple.Safari" and anchor apple"#;
        let key = |req: &str| format!("com.apple.Safari {{{req}}}");
        let rule = |k: String| -> Vec<Diagnostic> {
            validate_for(
                &r,
                "com.apple.configuration.app.settings",
                &json!({"Privacy": {"PermissionDefaults": {k: {"Camera": "Allow", "OrganizationJustification": "x"}}}}),
                Some(Platform::MacOS),
            )
            .into_iter()
            .filter(|d| d.rule == "composed-identifier")
            .collect()
        };
        assert!(rule(key(dr)).is_empty(), "a clean requirement passes");

        let trailer = rule(key(&format!(
            "{dr}\nExecutable=/Applications/Safari.app/Contents/MacOS/Safari"
        )));
        assert_eq!(trailer.len(), 1);
        assert!(
            trailer[0].message.contains("Executable="),
            "{}",
            trailer[0].message
        );

        let prefixed = rule(key(&format!("designated => {dr}")));
        assert!(
            prefixed[0].message.contains("designated => "),
            "{}",
            prefixed[0].message
        );
    }

    #[test]
    fn commands_are_not_authorable() {
        let d = validate(&reg(), "DeviceLock", &json!({}));
        assert_eq!(d[0].rule, "not-authorable");
    }

    /// With a target platform the wrong spelling is refused, not advised:
    /// Apple states the form, and the wrong one produces a declaration that
    /// reports Verified and matches nothing. `emit` follows.
    #[test]
    fn a_wrong_spelling_blocks_under_an_explicit_target() {
        let r = reg();
        let values = json!({"Privacy": {"PermissionDefaults": {"corp.sap.privileges": {"Camera": "Allow", "OrganizationJustification": "x"}}}});
        let d: Vec<_> = validate_for(
            &r,
            "com.apple.configuration.app.settings",
            &values,
            Some(Platform::MacOS),
        )
        .into_iter()
        .filter(|d| d.rule == "composed-identifier")
        .collect();
        assert_eq!(d.len(), 1);
        assert!(d[0].blocks_emit, "bare on macOS matches no app: refuse");

        let err = crate::emit::emit(
            &r,
            "com.apple.configuration.app.settings",
            &values,
            &crate::emit::EmitOptions {
                org: "com.acme".into(),
                intent: "privileges".into(),
                platform: Some(Platform::MacOS),
                ..Default::default()
            },
        )
        .err()
        .expect("emit refuses what validate blocks");
        assert!(matches!(err, crate::emit::EmitError::Invalid(_)), "{err}");
    }

    /// VALUE position, designated requirement, bare allowed: vpn-plugin's
    /// `Provider.ComposedIdentifier`. Bare on macOS is a warning that says
    /// what it matches, never a refusal; parentheses are the wrong form.
    #[test]
    fn a_value_position_dr_key_follows_the_registry() {
        let r = reg();
        let ty = "com.apple.configuration.network.vpn.vpn-plugin";
        let rule = |id: &str, p: Option<Platform>| -> Vec<Diagnostic> {
            validate_for(&r, ty, &json!({"Provider": {"ComposedIdentifier": id}}), p)
                .into_iter()
                .filter(|d| d.rule == "composed-identifier")
                .collect()
        };
        let bare = rule("com.example.vpn", Some(Platform::MacOS));
        assert_eq!(bare.len(), 1);
        assert!(
            !bare[0].blocks_emit,
            "Apple accepts bare here: advise, do not refuse"
        );
        assert!(bare[0].message.contains("ANY code"), "{}", bare[0].message);

        assert!(
            rule(
                "com.example.vpn {anchor apple generic}",
                Some(Platform::MacOS)
            )
            .is_empty()
        );
        assert!(
            rule("com.example.vpn", Some(Platform::Ios)).is_empty(),
            "iOS is bare"
        );

        let paren = rule("com.example.vpn (ABCD1234)", Some(Platform::MacOS));
        assert_eq!(paren.len(), 1);
        assert!(paren[0].blocks_emit);
        assert!(
            paren[0].message.contains("Team-ID form"),
            "{}",
            paren[0].message
        );

        let composed_on_ios = rule(
            "com.example.vpn {anchor apple generic}",
            Some(Platform::Ios),
        );
        assert_eq!(composed_on_ios.len(), 1);
        assert!(
            composed_on_ios[0].blocks_emit,
            "composed is a macOS construction"
        );
    }

    /// VALUE position, Team ID, bare NOT allowed: extensible-sso. Braces are
    /// the wrong form here — the mirror image of the DR keys.
    #[test]
    fn a_team_id_key_refuses_braces_and_bare_on_macos() {
        let r = reg();
        let ty = "com.apple.configuration.extensible-sso";
        let rule = |id: &str, p: Option<Platform>| -> Vec<Diagnostic> {
            validate_for(&r, ty, &json!({"ExtensionComposedIdentifier": id}), p)
                .into_iter()
                .filter(|d| d.rule == "composed-identifier")
                .collect()
        };
        assert!(rule("com.example.sso (ABCD1234)", Some(Platform::MacOS)).is_empty());
        let braces = rule(
            "com.example.sso {anchor apple generic}",
            Some(Platform::MacOS),
        );
        assert_eq!(braces.len(), 1);
        assert!(braces[0].blocks_emit);
        assert!(
            braces[0].message.contains("braces"),
            "{}",
            braces[0].message
        );
        let bare = rule("com.example.sso", Some(Platform::MacOS));
        assert_eq!(bare.len(), 1);
        assert!(
            bare[0].blocks_emit,
            "Apple documents only the Team form on macOS here"
        );
        assert!(rule("com.example.sso", Some(Platform::Ios)).is_empty());
        let not_team = rule("com.example.sso (not a team id)", Some(Platform::MacOS));
        assert!(
            not_team[0].message.contains("not a Team ID"),
            "{}",
            not_team[0].message
        );
    }

    /// Safari: composed on EVERY platform, and a literal `"*"` is Apple's
    /// documented wildcard — neither may be flagged.
    #[test]
    fn safari_extensions_accept_the_wildcard_and_compose_everywhere() {
        let r = reg();
        let ty = "com.apple.configuration.safari.extensions.settings";
        let rule = |key: &str, p: Option<Platform>| -> Vec<Diagnostic> {
            validate_for(
                &r,
                ty,
                &json!({"ManagedExtensions": {key: {"State": "Allowed"}}}),
                p,
            )
            .into_iter()
            .filter(|d| d.rule == "composed-identifier")
            .collect()
        };
        assert!(
            rule("*", Some(Platform::MacOS)).is_empty(),
            "the documented wildcard"
        );
        assert!(
            rule("com.example.app (ABCD1234)", Some(Platform::Ios)).is_empty(),
            "composed everywhere"
        );
        let braces = rule(
            "com.example.app {anchor apple generic}",
            Some(Platform::MacOS),
        );
        assert_eq!(braces.len(), 1);
        assert!(
            braces[0].message.contains("braces"),
            "{}",
            braces[0].message
        );
    }

    /// A `<data>` key given something that is not base64 is told so here,
    /// with the path, before the emitter refuses it.
    #[test]
    fn a_data_key_that_is_not_base64_is_an_error_here_too() {
        let r = reg();
        let d: Vec<_> = validate_for(
            &r,
            "com.apple.security.scep",
            &json!({"PayloadContent": {"URL": "https://scep.example.com", "CAFingerprint": "not base64!!"}}),
            None,
        )
        .into_iter()
        .filter(|d| d.rule == "data-not-base64")
        .collect();
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].blocks_emit);
        assert!(d[0].path.ends_with("CAFingerprint"));
    }

    // ── availability at emit time ─────────────────────────────────────────

    fn mdm_values(extra: &[(&str, &str)]) -> serde_json::Value {
        let mut v = json!({
            "ServerURL": "https://mdm.example.com/mdm",
            "Topic": "com.apple.mgmt.External.abc",
            "IdentityCertificateUUID": "11111111-1111-1111-1111-111111111111",
        });
        for (k, val) in extra {
            v[*k] = json!(val);
        }
        v
    }
    fn rules<'a>(d: &'a [Diagnostic], rule: &str) -> Vec<&'a Diagnostic> {
        d.iter().filter(|x| x.rule == rule).collect()
    }
    fn t(p: Platform, os: Option<&str>) -> Target {
        Target {
            platform: Some(p),
            os_version: os.map(str::to_string),
            ..Default::default()
        }
    }

    /// `form()` has said Removed for a while; this is the first time the
    /// emitter refuses. com.apple.mdm's ManagedAppleID: deprecated on macOS
    /// 14.0, removed at 15.0.
    #[test]
    fn a_key_apple_removed_is_refused_on_a_target_past_its_removal() {
        let r = reg();
        let v = mdm_values(&[("ManagedAppleID", "user@example.com")]);
        let ty = "com.apple.mdm";

        let d = validate_target(&r, ty, &v, &t(Platform::MacOS, Some("15.0")));
        let removed = rules(&d, "key-removed-on-target");
        assert_eq!(removed.len(), 1, "{d:?}");
        assert!(
            removed[0].blocks_emit,
            "a removed key is refused, not advised"
        );
        assert!(removed[0].message.contains("15.0") && removed[0].message.contains("ignores"));
        assert!(
            rules(&d, "key-deprecated-on-target").is_empty(),
            "removal supersedes deprecation"
        );

        let d = validate_target(&r, ty, &v, &t(Platform::MacOS, Some("14.5")));
        assert!(rules(&d, "key-removed-on-target").is_empty());
        let dep = rules(&d, "key-deprecated-on-target");
        assert_eq!(dep.len(), 1, "{d:?}");
        assert!(!dep[0].blocks_emit, "deprecated still works: advise");

        let d = validate_target(&r, ty, &v, &t(Platform::MacOS, Some("13.0")));
        assert!(
            rules(&d, "key-removed-on-target").is_empty()
                && rules(&d, "key-deprecated-on-target").is_empty()
        );

        // Platform but no version: name the removal, do not refuse — the
        // author's target may predate it.
        let d = validate_target(&r, ty, &v, &t(Platform::MacOS, None));
        let named = rules(&d, "key-removed");
        assert_eq!(named.len(), 1, "{d:?}");
        assert!(!named[0].blocks_emit);
        assert!(named[0].message.contains("--os-version"));

        // No platform at all: availability cannot be judged.
        let d = validate_for(&r, ty, &v, None);
        for rule in [
            "key-removed",
            "key-removed-on-target",
            "key-deprecated",
            "key-deprecated-on-target",
        ] {
            assert!(rules(&d, rule).is_empty(), "{rule} without a platform");
        }
    }

    /// A payload Apple withdrew wholesale: com.apple.AIM.account left macOS
    /// at 10.14. Nothing inside it can be right on 10.15.
    #[test]
    fn a_removed_payload_is_refused_wholesale() {
        let r = reg();
        let d = validate_target(
            &r,
            "com.apple.AIM.account",
            &json!({}),
            &t(Platform::MacOS, Some("10.15")),
        );
        let gone = rules(&d, "payload-removed-on-target");
        assert_eq!(gone.len(), 1, "{d:?}");
        assert!(gone[0].blocks_emit);
        assert_eq!(gone[0].path, "", "the document itself");
        let d = validate_target(
            &r,
            "com.apple.AIM.account",
            &json!({}),
            &t(Platform::MacOS, Some("10.13")),
        );
        assert!(rules(&d, "payload-removed-on-target").is_empty());
    }

    /// A key Apple marks `n/a` on the platform does not exist there.
    /// app.settings' Allowed.DeniedApps is n/a on macOS.
    #[test]
    fn a_key_na_on_the_platform_is_refused() {
        let r = reg();
        let v = json!({"Allowed": {"DeniedApps": []}});
        let d = validate_target(
            &r,
            "com.apple.configuration.app.settings",
            &v,
            &t(Platform::MacOS, None),
        );
        let na = rules(&d, "key-unavailable-on-platform");
        assert_eq!(na.len(), 1, "{d:?}");
        assert!(na[0].blocks_emit);
        assert!(na[0].path.ends_with("DeniedApps"));
        let d = validate_target(
            &r,
            "com.apple.configuration.app.settings",
            &v,
            &t(Platform::Ios, None),
        );
        assert!(
            rules(&d, "key-unavailable-on-platform").is_empty(),
            "it exists on iOS"
        );
    }

    /// And the emitter follows: with --os macos --os-version 15.0 the
    /// removed key stops the document.
    #[test]
    fn emit_refuses_a_removed_key_on_the_target() {
        let r = reg();
        let v = mdm_values(&[("ManagedAppleID", "user@example.com")]);
        let err = crate::emit::emit(
            &r,
            "com.apple.mdm",
            &v,
            &crate::emit::EmitOptions {
                org: "com.acme".into(),
                intent: "mdm".into(),
                platform: Some(Platform::MacOS),
                os_version: Some("15.0".into()),
                ..Default::default()
            },
        )
        .err()
        .expect("refused");
        match err {
            crate::emit::EmitError::Invalid(ds) => {
                assert!(
                    ds.iter().any(|d| d.rule == "key-removed-on-target"),
                    "{ds:?}"
                )
            }
            e => panic!("wrong error: {e}"),
        }
    }
}
