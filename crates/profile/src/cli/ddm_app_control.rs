//! `profile ddm app-control` — allow and deny lists for which binaries may run
//! on macOS, as a `com.apple.configuration.app.settings` declaration.
//!
//! Two verbs, mirroring `app-privacy`, which writes the other half of the same
//! declaration:
//!
//! * `scan` — read the code signatures of installed apps and write
//!   `app-control.toml`, one entry per binary identifier, to review and trim
//! * `generate` — validate that file against Apple's rules and compose the
//!   configuration and its activation
//!
//! Signatures are read with `codesign`, which every Mac has. Santa is not
//! involved: the identifiers are Apple's (`TeamID`, `SigningID`, `CDHash`,
//! `PathPrefix`, `SigningState`), in the shape `AllowedBinaries` and
//! `DeniedBinaries` take.
//!
//! ## Allow lists are exclusive
//!
//! Once `AllowedBinaries` is present, only matching binaries run, apart from
//! the processes macOS deems system-critical. Two consequences shape the
//! defaults:
//!
//! * `allow_apple = true` adds `TeamID = "*APPLE*"` — Apple's sentinel for its
//!   binaries' empty team identifier — so Apple's own apps keep launching.
//! * a scanned allow entry is the vendor's `TeamID`, not the app's
//!   `SigningID`. An app runs helpers, XPC services and updaters under other
//!   signing IDs of the same team; a per-app allow entry blocks them, and the
//!   app with them. `generate` warns about allow entries narrowed by
//!   `SigningID` for that reason. Deny entries name the app.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use santa::app_settings::{
    AppSettings, BinaryIdentifier, BinaryPolicy, SigningState, map::from_scanned_app,
    validate_binary,
};
use santa::cli::ScanRuleType;

use crate::cli::ddm::{load_registry_opts, resolve_ddm_org_domain};
use crate::config::ProfileConfig;
use crate::ddm::compose::{Bundle, BundleActivation, BundleConfiguration, ComposeOptions, compose};

/// Default filename, matching `app-privacy.toml` / `pppc.toml`.
pub const DEFAULT_POLICY_FILE: &str = "app-control.toml";

const DEFAULT_SEARCH_PATHS: &[&str] = &["/Applications", "/Applications/Utilities"];

/// `app-control.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppControlFile {
    /// Names the composed declarations: `{org}.config.{intent_name}` and
    /// `{org}.activation.{intent_name}`.
    #[serde(default = "default_intent_name")]
    pub intent_name: String,
    /// Add `TeamID = "*APPLE*"` to a non-empty allow list.
    #[serde(default = "yes")]
    pub allow_apple: bool,
    /// `AlwaysAllowManagedApps`: MDM-installed apps join the allow list.
    #[serde(default)]
    pub always_allow_managed: bool,
    /// `AllowedBinaries`.
    #[serde(default)]
    pub allow: Vec<BinaryEntry>,
    /// `DeniedBinaries`.
    #[serde(default)]
    pub deny: Vec<BinaryEntry>,
}

fn default_intent_name() -> String {
    "app-control".to_string()
}

fn yes() -> bool {
    true
}

/// One binary identifier. `name` and `source` are notes for the reader and
/// never reach the declaration; the rest are Apple's keys.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BinaryEntry {
    /// The app this came from, for the reader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Where it was scanned, for the reader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdhash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_state: Option<String>,
}

impl BinaryEntry {
    fn label(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.signing_id.clone())
            .or_else(|| self.team_id.clone())
            .or_else(|| self.cdhash.clone())
            .or_else(|| self.path_prefix.clone())
            .unwrap_or_else(|| "(empty entry)".to_string())
    }

    fn from_identifier(bi: &BinaryIdentifier, name: &str, source: &str) -> Self {
        Self {
            name: Some(name.to_string()),
            source: Some(source.to_string()),
            team_id: bi.team_id.clone(),
            signing_id: bi.signing_id.clone(),
            cdhash: bi.cdhash.clone(),
            path_prefix: bi.path_prefix.clone(),
            signing_state: bi.signing_state.map(|s| s.as_str().to_string()),
        }
    }

    fn to_identifier(&self) -> Result<BinaryIdentifier, String> {
        let signing_state = match self.signing_state.as_deref() {
            None => None,
            Some(raw) => Some(
                SigningState::ALL
                    .into_iter()
                    .find(|s| s.as_str() == raw)
                    .ok_or_else(|| {
                        format!(
                            "signing_state {raw:?} is not one of {}",
                            SigningState::ALL.map(SigningState::as_str).join(", ")
                        )
                    })?,
            ),
        };
        Ok(BinaryIdentifier {
            cdhash: self.cdhash.clone(),
            signing_id: self.signing_id.clone(),
            team_id: self.team_id.clone(),
            path_prefix: self.path_prefix.clone(),
            signing_state,
        })
    }
}

/// Apps a scan could not turn into an entry, and why.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedApp {
    pub path: String,
    pub reason: String,
}

/// One scanned app: what the reader sees, and the identity rules come from.
#[derive(Debug, Clone)]
pub struct ScannedTarget {
    pub name: String,
    pub source: String,
    pub app: santa::cli::scan::ScannedApp,
}

impl ScannedTarget {
    /// An Apple platform app: no team identifier, a `platform:` signing ID.
    pub fn is_apple(&self) -> bool {
        self.app.team_id.is_none()
            && self
                .app
                .signing_id
                .as_deref()
                .is_some_and(|s| s.starts_with("platform:"))
    }

    fn team_label(&self) -> String {
        if self.is_apple() {
            "Apple".to_string()
        } else {
            self.app.team_id.clone().unwrap_or_else(|| "no team".into())
        }
    }
}

/// Read the code signature of every app under `paths` (bundles or
/// directories). Unsigned and team-less apps have nothing a rule can match
/// and are reported, not guessed at.
pub fn scan_targets(paths: &[PathBuf]) -> Result<(Vec<ScannedTarget>, Vec<SkippedApp>)> {
    let apps = contour_core::discover_apps(paths)?;
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    for app in &apps {
        let path = app.path.display().to_string();
        match santa::cli::scan::scan_app_codesign(&app.path) {
            Ok(Some(scanned)) => targets.push(ScannedTarget {
                name: app.name.clone(),
                source: path,
                app: scanned,
            }),
            Ok(None) => skipped.push(SkippedApp {
                path,
                reason: "unsigned, or signed with no team — nothing a rule can match".into(),
            }),
            Err(e) => skipped.push(SkippedApp {
                path,
                reason: e.to_string(),
            }),
        }
    }
    Ok((targets, skipped))
}

/// Entries for one list from scanned apps, one per distinct identifier: a
/// vendor-level entry covers every app of that vendor, so it appears once.
pub fn entries_for(
    targets: &[&ScannedTarget],
    rule_type: ScanRuleType,
    policy: BinaryPolicy,
) -> (Vec<BinaryEntry>, Vec<SkippedApp>) {
    let mut entries: Vec<BinaryEntry> = Vec::new();
    let mut skipped = Vec::new();
    for t in targets {
        let ids = from_scanned_app(&t.app, rule_type, policy);
        if ids.is_empty() {
            skipped.push(SkippedApp {
                path: t.source.clone(),
                reason: "no identifier of the chosen --rule-type".into(),
            });
            continue;
        }
        for (bi, _) in ids {
            let entry = BinaryEntry::from_identifier(&bi, &t.name, &t.source);
            let duplicate = entries.iter().any(|e| {
                e.team_id == entry.team_id
                    && e.signing_id == entry.signing_id
                    && e.cdhash == entry.cdhash
                    && e.path_prefix == entry.path_prefix
                    && e.signing_state == entry.signing_state
            });
            if !duplicate {
                entries.push(entry);
            }
        }
    }
    (entries, skipped)
}

/// Scan every app under `paths` into entries for one list.
pub fn scan_paths(
    paths: &[PathBuf],
    rule_type: ScanRuleType,
    policy: BinaryPolicy,
) -> Result<(Vec<BinaryEntry>, Vec<SkippedApp>)> {
    let (targets, mut skipped) = scan_targets(paths)?;
    let refs: Vec<&ScannedTarget> = targets.iter().collect();
    let (entries, more) = entries_for(&refs, rule_type, policy);
    skipped.extend(more);
    Ok((entries, skipped))
}

/// The file an interactive session's answers describe. Separate from the
/// prompts so the part that matters is testable without a terminal.
pub fn build_file(
    targets: &[ScannedTarget],
    allow: &[usize],
    deny: &[usize],
    allow_apple: bool,
    always_allow_managed: bool,
    rule_type: ScanRuleType,
) -> AppControlFile {
    let pick = |idx: &[usize]| {
        idx.iter()
            .filter_map(|&i| targets.get(i))
            .collect::<Vec<_>>()
    };
    let (allow, _) = entries_for(&pick(allow), rule_type, BinaryPolicy::Allow);
    let (deny, _) = entries_for(&pick(deny), rule_type, BinaryPolicy::Deny);
    AppControlFile {
        intent_name: default_intent_name(),
        allow_apple,
        always_allow_managed,
        allow,
        deny,
    }
}

/// A picker row: the label shown, and which target it is.
#[derive(Debug, Clone)]
struct Choice {
    label: String,
    index: usize,
}

impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

/// `scan --interactive`: scan, then pick what to allow and what to deny.
fn run_interactive(
    paths: &[PathBuf],
    rule_type: ScanRuleType,
) -> Result<(AppControlFile, Vec<SkippedApp>)> {
    use inquire::Confirm;

    let (targets, skipped) = scan_targets(paths)?;
    if targets.is_empty() {
        bail!("no signed app found under the scanned paths");
    }
    println!(
        "{} {} signed app(s) scanned ({} Apple, {} skipped)",
        "✓".green(),
        targets.len(),
        targets.iter().filter(|t| t.is_apple()).count(),
        skipped.len()
    );

    let allow_apple = Confirm::new("Include Apple's software in the allow list (TeamID *APPLE*)?")
        .with_default(true)
        .with_help_message(
            "An allow list is exclusive: without this, Apple's own apps stop launching",
        )
        .prompt()?;
    let show_apple = Confirm::new("List Apple's apps below as well?")
        .with_default(false)
        .with_help_message("Only needed to deny a specific Apple app")
        .prompt()?;

    let choices = |exclude: &[usize]| -> Vec<Choice> {
        targets
            .iter()
            .enumerate()
            .filter(|(i, t)| (show_apple || !t.is_apple()) && !exclude.contains(i))
            .map(|(index, t)| Choice {
                label: format!("{}  ({})", t.name, t.team_label()),
                index,
            })
            .collect()
    };

    let allow: Vec<usize> = contour_core::multi_select(
        &choices(&[]),
        "Apps to ALLOW — by vendor Team ID, so everything that vendor signs:",
    )?
    .into_iter()
    .map(|c| c.index)
    .collect();
    let deny: Vec<usize> =
        contour_core::multi_select(&choices(&allow), "Apps to DENY — this app only:")?
            .into_iter()
            .map(|c| c.index)
            .collect();
    let managed = if allow.is_empty() && !allow_apple {
        false
    } else {
        Confirm::new("Always allow MDM-managed apps (AlwaysAllowManagedApps)?")
            .with_default(true)
            .prompt()?
    };

    let file = build_file(&targets, &allow, &deny, allow_apple, managed, rule_type);
    if file.allow.is_empty() && file.deny.is_empty() && !file.allow_apple {
        bail!("nothing selected, so there is nothing to write");
    }
    Ok((file, skipped))
}

/// Render the file with a header that says what the lists mean.
pub fn render_toml(file: &AppControlFile) -> Result<String> {
    let body = toml::to_string_pretty(file).context("rendering app-control.toml")?;
    Ok(format!(
        "# app-control.toml — contour profile ddm app-control\n\
         #\n\
         # [[allow]] becomes AllowedBinaries, [[deny]] DeniedBinaries, in one\n\
         # com.apple.configuration.app.settings declaration (macOS 27+, supervised).\n\
         #\n\
         # An allow list is EXCLUSIVE: only matching binaries run, apart from\n\
         # system-critical processes. allow_apple keeps Apple's own apps running.\n\
         # Keep allow entries at the vendor's team_id — an app's helpers run under\n\
         # other signing IDs of the same team.\n\
         #\n\
         # Apple's rules: an allow entry needs team_id or cdhash; a deny entry needs\n\
         # team_id, cdhash or signing_id. The other fields narrow a match; every\n\
         # field present must match. signing_state is one of All, AppStore,\n\
         # DeveloperID, Enterprise, TestFlight, Apple. name and source are notes.\n\
         #\n\
         # Then: contour profile ddm app-control generate {DEFAULT_POLICY_FILE} --write\n\n\
         {body}"
    ))
}

/// Validate every entry, collecting all problems, and return the binaries.
pub fn to_binaries(
    file: &AppControlFile,
) -> Result<(Vec<(BinaryIdentifier, BinaryPolicy)>, Vec<String>)> {
    let mut binaries = Vec::new();
    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    for (list, policy, name) in [
        (&file.allow, BinaryPolicy::Allow, "allow"),
        (&file.deny, BinaryPolicy::Deny, "deny"),
    ] {
        for (i, entry) in list.iter().enumerate() {
            let at = format!("[[{name}]] #{} ({})", i + 1, entry.label());
            match entry.to_identifier().and_then(|bi| {
                validate_binary(&bi, policy)?;
                Ok(bi)
            }) {
                Ok(bi) => {
                    if policy == BinaryPolicy::Allow && bi.signing_id.is_some() {
                        warnings.push(format!(
                            "{at}: narrowed by signing_id — the app's helpers, XPC services \
                             and updaters run under other signing IDs and will be blocked"
                        ));
                    }
                    binaries.push((bi, policy));
                }
                Err(e) => problems.push(format!("{at}: {e}")),
            }
        }
    }
    if !problems.is_empty() {
        bail!(
            "{} entr(ies) do not meet Apple's rules for app.settings binaries:\n  {}",
            problems.len(),
            problems.join("\n  ")
        );
    }
    Ok((binaries, warnings))
}

/// The compose bundle: the configuration, and an activation that names it.
pub fn build_bundle(file: &AppControlFile) -> Result<(Bundle, Vec<String>)> {
    let (binaries, warnings) = to_binaries(file)?;
    let settings = AppSettings {
        binaries,
        always_allow_managed: file.always_allow_managed,
        omit_apple: !file.allow_apple,
        ..Default::default()
    };
    if settings.is_empty() {
        bail!("nothing to emit: no [[allow]] or [[deny]] entries, and always_allow_managed is off");
    }
    let payload: Map<String, Value> = match settings.to_declaration("x", "x")["Payload"].clone() {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    Ok((
        Bundle {
            intent_name: file.intent_name.clone(),
            platforms: Vec::new(),
            asset: None,
            configuration: BundleConfiguration {
                type_name: santa::app_settings::APP_SETTINGS_TYPE.to_string(),
                identifier: None,
                asset_ref_field: None,
                payload,
            },
            activation: Some(BundleActivation {
                type_name: Some("com.apple.activation.simple".to_string()),
                identifier: None,
                predicate: None,
                references: None,
            }),
            subscriptions: None,
        },
        warnings,
    ))
}

/// `profile ddm app-control scan [paths…]`
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_scan(
    paths: &[String],
    interactive: bool,
    deny: bool,
    rule_type: ScanRuleType,
    always_allow_managed: bool,
    no_apple: bool,
    output: Option<&str>,
    json: bool,
) -> Result<()> {
    let search: Vec<PathBuf> = if paths.is_empty() {
        DEFAULT_SEARCH_PATHS.iter().map(PathBuf::from).collect()
    } else {
        paths.iter().map(PathBuf::from).collect()
    };
    if interactive {
        if json {
            bail!("--interactive cannot be combined with --json: it needs a terminal");
        }
        if deny || always_allow_managed || no_apple {
            bail!(
                "--interactive asks for the lists, Apple's software and managed apps itself; \
                 drop --deny, --always-allow-managed and --no-apple"
            );
        }
        let (file, skipped) = run_interactive(&search, rule_type)?;
        let dest = PathBuf::from(output.unwrap_or(DEFAULT_POLICY_FILE));
        std::fs::write(&dest, render_toml(&file)?)
            .with_context(|| format!("writing {}", dest.display()))?;
        for s in &skipped {
            println!("  {} skipped {}: {}", "!".yellow(), s.path, s.reason);
        }
        println!(
            "{} {} ({} allow, {} deny entr(ies){})",
            "✓".green(),
            dest.display(),
            file.allow.len(),
            file.deny.len(),
            if file.allow_apple {
                ", Apple's software allowed"
            } else {
                ""
            }
        );
        println!(
            "  Review it, then run `contour profile ddm app-control generate {} --write`.",
            dest.display()
        );
        return Ok(());
    }

    let policy = if deny {
        BinaryPolicy::Deny
    } else {
        BinaryPolicy::Allow
    };
    let (entries, skipped) = scan_paths(&search, rule_type, policy)?;
    if entries.is_empty() {
        bail!(
            "no app under {} yielded an identifier, so there is nothing to write",
            search
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Distinct per list, so an allow file and a deny file compose to
    // different identifiers rather than one replacing the other on the device.
    let file = AppControlFile {
        intent_name: if deny {
            "app-denylist"
        } else {
            "app-allowlist"
        }
        .to_string(),
        allow_apple: !no_apple,
        always_allow_managed,
        allow: if deny { Vec::new() } else { entries.clone() },
        deny: if deny { entries.clone() } else { Vec::new() },
    };
    let dest = PathBuf::from(output.unwrap_or(DEFAULT_POLICY_FILE));
    std::fs::write(&dest, render_toml(&file)?)
        .with_context(|| format!("writing {}", dest.display()))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": dest.display().to_string(),
                "list": if deny { "deny" } else { "allow" },
                "entries": entries,
                "skipped": skipped,
            }))?
        );
        return Ok(());
    }
    for s in &skipped {
        println!("  {} skipping {}: {}", "!".yellow(), s.path, s.reason);
    }
    println!(
        "{} {} ({} {} entr(ies))",
        "✓".green(),
        dest.display(),
        entries.len(),
        if deny { "deny" } else { "allow" }
    );
    if !deny && no_apple {
        println!(
            "  {} allow_apple = false: an allow list is exclusive, so Apple apps not \
             listed will not launch.",
            "!".yellow()
        );
    } else if !deny {
        println!("  Allow lists are exclusive; allow_apple = true keeps Apple's apps running.");
    }
    println!(
        "  Review it, then run `contour profile ddm app-control generate {} --write`.",
        dest.display()
    );
    Ok(())
}

/// `profile ddm app-control generate <file>`
pub fn handle_generate(
    input: &str,
    org: Option<&str>,
    config: Option<&ProfileConfig>,
    output: Option<&str>,
    write: bool,
    json: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(input).with_context(|| format!("reading {input}"))?;
    let file: AppControlFile = toml::from_str(&text).with_context(|| format!("parsing {input}"))?;

    let Some(domain) = resolve_ddm_org_domain(org, config) else {
        bail!(
            "organization domain is required\n  \
             • --org <domain>\n  \
             • CONTOUR_ORG\n  \
             • organization.domain in profile.toml or .contour/config.toml"
        );
    };
    let (bundle, warnings) = build_bundle(&file)?;
    let registry = load_registry_opts(None, false)?;
    let composed = compose(&bundle, &domain, &registry, &ComposeOptions::default())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let out_dir = PathBuf::from(output.unwrap_or("."));
    let activation = composed
        .activation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("compose produced no activation"))?;
    let planned: Vec<(PathBuf, String)> = vec![
        (
            out_dir.join("configuration.json"),
            serde_json::to_string_pretty(&composed.configuration)?,
        ),
        (
            out_dir.join("activation.json"),
            serde_json::to_string_pretty(activation)?,
        ),
    ];
    if write {
        std::fs::create_dir_all(&out_dir)
            .with_context(|| format!("creating {}", out_dir.display()))?;
        for (path, body) in &planned {
            std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "written": write,
                "allow": file.allow.len(),
                "deny": file.deny.len(),
                "files": planned.iter().map(|(p, _)| p.display().to_string()).collect::<Vec<_>>(),
                "identifier": composed.configuration.identifier,
                "warnings": warnings,
            }))?
        );
        return Ok(());
    }
    for w in &warnings {
        println!("  {} {w}", "!".yellow());
    }
    let verb = if write { "Wrote" } else { "Would write" };
    println!(
        "{verb} {} declaration(s) — {} allow, {} deny entr(ies){}:",
        planned.len(),
        file.allow.len(),
        file.deny.len(),
        if file.allow_apple && !file.allow.is_empty() {
            " + Apple's software"
        } else {
            ""
        }
    );
    for (path, _) in &planned {
        println!("  {}", path.display());
    }
    if !write {
        println!("\n  Dry run — pass --write to apply.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(team: Option<&str>, signing: Option<&str>) -> BinaryEntry {
        BinaryEntry {
            team_id: team.map(str::to_string),
            signing_id: signing.map(str::to_string),
            ..Default::default()
        }
    }

    fn file(allow: Vec<BinaryEntry>, deny: Vec<BinaryEntry>) -> AppControlFile {
        AppControlFile {
            intent_name: "t".into(),
            allow_apple: true,
            always_allow_managed: false,
            allow,
            deny,
        }
    }

    fn allowed(f: &AppControlFile) -> Value {
        let (b, _) = build_bundle(f).unwrap();
        Value::Object(b.configuration.payload)["Allowed"].clone()
    }

    /// The file round-trips through its own rendering.
    #[test]
    fn the_rendered_file_parses_back() {
        let f = file(vec![entry(Some("ABCDE12345"), None)], vec![]);
        let text = render_toml(&f).unwrap();
        let back: AppControlFile = toml::from_str(&text).unwrap();
        assert_eq!(back.allow, f.allow);
        assert!(back.allow_apple);
    }

    /// An allow list carries Apple's software by default, and not when told.
    #[test]
    fn an_allow_list_keeps_apple_running_unless_told_otherwise() {
        let mut f = file(vec![entry(Some("ABCDE12345"), None)], vec![]);
        assert_eq!(allowed(&f)["AllowedBinaries"][0]["TeamID"], "*APPLE*");
        f.allow_apple = false;
        assert_eq!(allowed(&f)["AllowedBinaries"][0]["TeamID"], "ABCDE12345");
    }

    /// Apple's rules, every problem at once: an allow entry needs TeamID or
    /// CDHash; a signing state must be one of Apple's.
    #[test]
    fn entries_breaking_apples_rules_are_refused_together() {
        let mut bad_state = entry(Some("ABCDE12345"), None);
        bad_state.signing_state = Some("Signed".into());
        let f = file(vec![entry(None, Some("com.x.app")), bad_state], vec![]);
        let e = build_bundle(&f).unwrap_err().to_string();
        assert!(e.contains("2 entr(ies)"), "{e}");
        assert!(e.contains("#1") && e.contains("#2"), "{e}");
        assert!(e.contains("\"Signed\" is not one of"), "{e}");
    }

    /// A per-app allow entry is valid, and warned about.
    #[test]
    fn a_signing_id_allow_entry_is_warned_about() {
        let f = file(vec![entry(Some("ABCDE12345"), Some("com.x.app"))], vec![]);
        let (_, warnings) = build_bundle(&f).unwrap();
        assert!(warnings[0].contains("helpers"), "{warnings:?}");
    }

    /// A deny entry may name the app by SigningID alone.
    #[test]
    fn a_deny_list_takes_signing_ids_and_adds_nothing() {
        let f = file(vec![], vec![entry(None, Some("com.x.app"))]);
        let a = allowed(&f);
        assert_eq!(a["DeniedBinaries"][0]["SigningID"], "com.x.app");
        assert!(
            a["AllowedBinaries"].is_null(),
            "a deny list is not exclusive"
        );
    }

    fn target(name: &str, team: Option<&str>, signing: &str) -> ScannedTarget {
        ScannedTarget {
            name: name.into(),
            source: format!("/Applications/{name}.app"),
            app: santa::cli::scan::ScannedApp {
                name: name.into(),
                path: format!("/Applications/{name}.app"),
                version: None,
                team_id: team.map(str::to_string),
                signing_id: Some(signing.to_string()),
                sha256: None,
                cdhash: None,
                bundle_id: None,
                cdhash_slices: Vec::new(),
            },
        }
    }

    /// What an interactive session's picks become: allow by vendor, one entry
    /// per vendor however many of its apps were picked; deny by app.
    #[test]
    fn interactive_picks_become_vendor_allows_and_app_denies() {
        let targets = vec![
            target("Word", Some("UBF8T346G9"), "UBF8T346G9:com.microsoft.Word"),
            target(
                "Excel",
                Some("UBF8T346G9"),
                "UBF8T346G9:com.microsoft.Excel",
            ),
            target("Game", Some("ABCDE12345"), "ABCDE12345:com.x.game"),
            target("Chess", None, "platform:com.apple.Chess"),
        ];
        assert!(targets[3].is_apple());
        let f = build_file(&targets, &[0, 1], &[2, 3], false, true, ScanRuleType::Auto);
        assert_eq!(
            f.allow.len(),
            1,
            "two Microsoft apps, one vendor entry: {:?}",
            f.allow
        );
        assert_eq!(f.allow[0].team_id.as_deref(), Some("UBF8T346G9"));
        assert_eq!(f.deny.len(), 2);
        assert_eq!(f.deny[0].signing_id.as_deref(), Some("com.x.game"));
        assert_eq!(f.deny[1].signing_id.as_deref(), Some("com.apple.Chess"));
        assert!(!f.allow_apple && f.always_allow_managed);
        build_bundle(&f).expect("what the picker writes, generate accepts");
    }
}
