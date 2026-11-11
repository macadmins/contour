//! `profile ddm migrate` — a verdict per payload of a classic profile, and
//! the native declaration where converting is safe.
//!
//! The mapping, the inverted keys and the guard all come from
//! [`crate::migrate::mapping`]; this module applies them to a real payload.
//! A key is carried, renamed, inverted or left behind, and every one of them
//! is reported: nothing is dropped silently.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use colored::Colorize;
use serde_json::{Map, Value, json};

use crate::cli::ddm::{declaration_errors, load_registry_opts, resolve_ddm_org_domain};
use crate::cli::ddm_legacy::{collect_profiles, intent_name};
use crate::config::ProfileConfig;
use crate::ddm::compose::{Bundle, BundleConfiguration, ComposeOptions, compose};
use crate::migrate::mapping::{MigrationMapping, MigrationRegistry, MigrationStatus};
use crate::output::OutputMode;
use crate::profile::PayloadContent;
use crate::profile::parser::parse_profile_auto_unsign;

/// Payload types `migrate` converts. Other mapped types need assets,
/// credentials or more than one declaration.
const CONVERTIBLE: &[&str] = &["com.apple.mobiledevice.passwordpolicy"];

/// What happens to one payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every key converts: the declaration replaces the payload.
    Native,
    /// Convertible type, but some keys have no equivalent.
    Partial,
    /// Converting would change what devices enforce.
    Refused,
    /// A native declaration exists; `migrate` does not build it yet.
    Manual,
    /// No native declaration: the profile stays a profile.
    Legacy,
    /// The type is not in the mapping.
    NotAssessed,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Partial => "partial",
            Self::Refused => "refused",
            Self::Manual => "manual",
            Self::Legacy => "legacy",
            Self::NotAssessed => "not-assessed",
        }
    }
}

/// One payload's verdict, with every key accounted for.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub ddm_type: Option<&'static str>,
    /// `(profile key, declaration key, how)`, `how` being carried, renamed
    /// or inverted.
    pub keys: Vec<(String, String, &'static str)>,
    /// Keys with no place in the declaration.
    pub left: Vec<String>,
    /// The declaration payload, complete only when the verdict is native.
    pub payload: Map<String, Value>,
}

/// A scalar as JSON. Dictionaries, arrays, data and dates are not carried:
/// their shape differs between the two sides, so the key is left behind.
fn scalar(v: &plist::Value) -> Option<Value> {
    match v {
        plist::Value::Boolean(b) => Some(json!(b)),
        plist::Value::Integer(i) => i.as_signed().map(|n| json!(n)),
        plist::Value::Real(r) => Some(json!(r)),
        plist::Value::String(s) => Some(json!(s)),
        _ => None,
    }
}

/// Decide what happens to one payload.
pub fn assess(payload: &PayloadContent, registry: &MigrationRegistry) -> Assessment {
    let verdict = |verdict, reason: String, ddm_type| Assessment {
        verdict,
        reason: Some(reason),
        ddm_type,
        keys: Vec::new(),
        left: Vec::new(),
        payload: Map::new(),
    };
    let Some(m) = registry.get(&payload.payload_type) else {
        return verdict(
            Verdict::NotAssessed,
            "not in contour's migration mapping".into(),
            None,
        );
    };
    if !matches!(
        m.status,
        MigrationStatus::Available | MigrationStatus::Partial
    ) {
        return verdict(
            Verdict::Legacy,
            "no native declaration; `contour profile ddm legacy convert` delivers the profile \
             through DDM"
                .into(),
            None,
        );
    }
    if !CONVERTIBLE.contains(&m.mdm_type) {
        return verdict(
            Verdict::Manual,
            format!(
                "{} exists but is not converted yet; see `contour profile ddm map {}`",
                m.ddm_type, m.mdm_type
            ),
            Some(m.ddm_type),
        );
    }
    convert(payload, m)
}

fn convert(payload: &PayloadContent, m: &MigrationMapping) -> Assessment {
    let mut a = Assessment {
        verdict: Verdict::Native,
        reason: None,
        ddm_type: Some(m.ddm_type),
        keys: Vec::new(),
        left: Vec::new(),
        payload: Map::new(),
    };
    // The envelope keys (PayloadDisplayName, …) describe the payload, not a
    // setting, and the declaration has its own identity.
    let settings = payload
        .content
        .iter()
        .filter(|(k, _)| !k.starts_with("Payload"));
    for (key, value) in settings {
        let renamed = m.transformed_keys.iter().find(|(from, _)| from == key);
        let inverted = m.inverted_keys.iter().find(|(from, _)| from == key);
        let moved = if m.direct_keys.contains(&key.as_str()) {
            scalar(value).map(|v| (key.as_str(), v, "carried"))
        } else if let Some((_, to)) = renamed {
            // A dotted target nests, which a rename cannot do.
            scalar(value)
                .filter(|_| !to.contains('.'))
                .map(|v| (*to, v, "renamed"))
        } else if let Some((_, to)) = inverted {
            value.as_boolean().map(|b| (*to, json!(!b), "inverted"))
        } else {
            None
        };
        match moved {
            Some((to, v, how)) => {
                a.payload.insert(to.to_string(), v);
                a.keys.push((key.clone(), to.to_string(), how));
            }
            None => a.left.push(key.clone()),
        }
    }

    // The guard applies once the payload manages anything besides its key.
    if let Some((key, reason)) = m.requires_true {
        let set = payload.content.get(key).and_then(plist::Value::as_boolean) == Some(true);
        let manages_more = a.keys.iter().any(|(from, _, _)| from != key) || !a.left.is_empty();
        if manages_more && !set {
            a.verdict = Verdict::Refused;
            a.reason = Some(format!("{key} is not true: {reason}"));
            return a;
        }
    }
    if !a.left.is_empty() {
        a.verdict = Verdict::Partial;
        a.reason = Some(format!("no declaration key for: {}", a.left.join(", ")));
    }
    a
}

/// `ddm migrate`: report every payload, write the declarations that are safe.
pub fn handle_ddm_migrate(
    paths: &[String],
    recursive: bool,
    org_flag: Option<&str>,
    output: Option<&str>,
    write: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    let (profiles, _) = collect_profiles(paths, recursive)?;
    let migration = MigrationRegistry::new();
    let schema = load_registry_opts(None, false)?;
    let out_dir = PathBuf::from(output.unwrap_or("."));

    let mut files = Vec::new();
    let mut totals: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut writes: Vec<(PathBuf, String)> = Vec::new();

    for path in &profiles {
        let profile = parse_profile_auto_unsign(&path.to_string_lossy())
            .with_context(|| format!("reading {}", path.display()))?;
        let mut rows = Vec::new();
        let mut native = 0;
        for (i, payload) in profile.payload_content.iter().enumerate() {
            let mut a = assess(payload, &migration);
            let mut target = None;
            if a.verdict == Verdict::Native {
                let Some(domain) = resolve_ddm_org_domain(org_flag, config) else {
                    bail!(
                        "organization domain is required to name the declaration\n  \
                         • --org <domain>\n  \
                         • CONTOUR_ORG\n  \
                         • organization.domain in profile.toml or .contour/config.toml"
                    );
                };
                // One name per profile; a second convertible payload gets a suffix.
                native += 1;
                let mut intent = intent_name(path);
                if native > 1 {
                    intent = format!("{intent}-{native}");
                }
                let bundle = Bundle {
                    intent_name: intent.clone(),
                    platforms: Vec::new(),
                    asset: None,
                    configuration: BundleConfiguration {
                        type_name: a.ddm_type.unwrap_or_default().to_string(),
                        identifier: None,
                        asset_ref_field: None,
                        payload: a.payload.clone(),
                    },
                    activation: None,
                    subscriptions: None,
                };
                let decl = compose(&bundle, &domain, &schema, &ComposeOptions::default())
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .configuration;
                // A declaration the schema rejects is not written.
                let (errors, _) = declaration_errors(&decl, &schema);
                if errors.is_empty() {
                    let file = out_dir.join(format!("{intent}.configuration.json"));
                    writes.push((file.clone(), serde_json::to_string_pretty(&decl)? + "\n"));
                    target = Some(file);
                } else {
                    a.verdict = Verdict::Refused;
                    a.reason = Some(format!(
                        "the declaration fails validation: {}",
                        errors.join("; ")
                    ));
                }
            }
            *totals.entry(a.verdict.as_str()).or_default() += 1;
            rows.push((i + 1, payload.payload_type.clone(), a, target));
        }
        files.push((path.clone(), rows));
    }

    if write {
        for (file, body) in &writes {
            if let Some(parent) = file.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(file, body).with_context(|| format!("writing {}", file.display()))?;
        }
    }

    if output_mode == OutputMode::Json {
        let files: Vec<Value> = files
            .iter()
            .map(|(path, rows)| {
                json!({
                    "file": path.display().to_string(),
                    "payloads": rows.iter().map(|(i, ty, a, target)| json!({
                        "index": i,
                        "type": ty,
                        "verdict": a.verdict.as_str(),
                        "reason": a.reason,
                        "ddm_type": a.ddm_type,
                        "keys": a.keys.iter().map(|(from, to, how)| json!({
                            "from": from, "to": to, "how": how,
                        })).collect::<Vec<_>>(),
                        "left": a.left,
                        "output": target.as_ref().map(|t| t.display().to_string()),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "written": write,
                "totals": totals,
                "files": files,
            }))?
        );
    } else {
        for (path, rows) in &files {
            println!("{}", path.display().to_string().bold());
            for (i, ty, a, target) in rows {
                let label = match a.verdict {
                    Verdict::Native => a.verdict.as_str().green(),
                    Verdict::Partial | Verdict::Refused => a.verdict.as_str().red(),
                    _ => a.verdict.as_str().dimmed(),
                };
                let arrow = a
                    .ddm_type
                    .filter(|_| a.verdict == Verdict::Native)
                    .map(|t| format!(" → {t}"))
                    .unwrap_or_default();
                println!("  [{i}] {ty}  {label}{arrow}");
                if let Some(reason) = &a.reason {
                    println!("      {reason}");
                }
                if a.verdict == Verdict::Native {
                    for (from, to, how) in &a.keys {
                        println!("      {from} → {to}  ({how})");
                    }
                }
                if let Some(t) = target {
                    let verb = if write { "wrote" } else { "would write" };
                    println!("      {verb} {}", t.display());
                }
            }
        }
        let summary: Vec<String> = totals.iter().map(|(v, n)| format!("{n} {v}")).collect();
        println!("\n{}", summary.join(", "));
        if !write && !writes.is_empty() {
            println!("Dry run: pass --write to write the declarations.");
        }
    }

    // A convertible payload that was not converted is the caller's to act on.
    let stopped = totals.get("refused").unwrap_or(&0) + totals.get("partial").unwrap_or(&0);
    if stopped > 0 {
        bail!("{stopped} payload(s) not converted");
    }
    Ok(())
}
