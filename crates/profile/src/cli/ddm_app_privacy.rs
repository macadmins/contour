//! `profile ddm app-privacy` — pre-answer privacy prompts with DDM.
//!
//! Three verbs, mirroring the `pppc` and `btm` workflows:
//!
//! * `scan` — read installed apps and write `app-privacy.toml`
//! * `generate` — turn that TOML into a deployable declaration bundle
//! * `import-pppc` — seed the TOML from an existing `pppc.toml`
//!
//! Declarations go through [`crate::ddm::compose::compose`] rather than being
//! serialised here, so identifiers, activation wiring and the org-domain
//! policy stay on one code path.
//!
//! ## Why `scan` refuses rather than guesses
//!
//! Each `PermissionDefaults` entry is keyed by bundle id plus the app's
//! designated requirement. Get that string wrong — a stale requirement, a
//! placeholder somebody forgot to fill in — and the declaration still
//! validates, still deploys, still reports Verified, and manages nothing. An
//! app whose requirement cannot be read is therefore an error naming the app,
//! never a TODO in the output.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::cli::ddm::{load_registry_opts, resolve_ddm_org_domain};
use crate::config::ProfileConfig;
use crate::ddm::app_privacy::{
    APP_SETTINGS_TYPE, AppEntry, AppPrivacyError, Permission, build_privacy_payload,
    pppc_service_mapping,
};
use crate::ddm::compose::{Bundle, BundleActivation, BundleConfiguration, ComposeOptions, compose};

/// Default filename for the policy file, matching `pppc.toml` / `btm.toml`.
pub const DEFAULT_POLICY_FILE: &str = "app-privacy.toml";

// ---------------------------------------------------------------------------
// Policy file model
// ---------------------------------------------------------------------------

/// `app-privacy.toml` — the editable policy file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppPrivacyFile {
    /// Suffix segment for computed identifiers (`{org}.config.{intent_name}`).
    #[serde(default = "default_intent_name")]
    pub intent_name: String,

    /// One entry per managed app.
    #[serde(default, rename = "app")]
    pub apps: Vec<AppTomlEntry>,
}

fn default_intent_name() -> String {
    "app-privacy".to_string()
}

/// One app in `app-privacy.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppTomlEntry {
    /// Display name — comment only, never emitted into the declaration.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,

    /// Bundle identifier, e.g. `us.zoom.xos`.
    pub bundle_id: String,

    /// The designated requirement exactly as `codesign -d -r-` printed it.
    pub designated_requirement: String,

    /// Team identifier; `*APPLE*` for an Apple platform binary, absent when
    /// the signature carries none (ad-hoc).
    ///
    /// Informational for *this* file — the privacy declaration keys on the
    /// designated requirement — but it is exactly what `app.settings`
    /// `AllowedBinaries.TeamID` wants, so one scan serves both. contour read
    /// it already and threw it away.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// Bare signing identifier (`us.zoom.xos`), the `SigningID` shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,

    /// Code directory hash per architecture slice, keyed as `codesign` names
    /// them (`arm64`, `x86_64`). Every slice, because a CDHash rule matches
    /// only the slice that executes; which ones become rules is the
    /// operator's call. NOT a file hash.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cdhash: BTreeMap<String, String>,

    /// User-visible reason. Apple requires it on every entry.
    #[serde(default)]
    pub justification: String,

    /// Permission name → value. Names may be snake_case (`local_network`) or
    /// Apple's own (`LocalNetwork`).
    #[serde(default, flatten)]
    pub permissions: BTreeMap<String, String>,
}

impl AppPrivacyFile {
    /// Validate and convert to the core model.
    ///
    /// Every permission value is checked against Apple's allowed set here, so
    /// a bad value fails before anything is written — and `Deny`, the most
    /// likely mistake, fails with an explanation rather than a generic error.
    pub fn to_entries(&self) -> Result<Vec<AppEntry>> {
        let mut out = Vec::new();

        for app in &self.apps {
            if app.bundle_id.trim().is_empty() {
                bail!("an [[app]] entry is missing bundle_id");
            }
            if app.designated_requirement.trim().is_empty() {
                bail!(
                    "{}: designated_requirement is empty — re-run `app-privacy scan` \
                     for this app rather than filling it in by hand",
                    app.bundle_id
                );
            }
            // The file is hand-editable, and the usual way a requirement goes
            // wrong is a paste that carried what codesign printed around it.
            if let Some(flaw) = contour_core::requirement_flaw(&app.designated_requirement) {
                bail!(
                    "{}: designated_requirement {flaw}.\n\
                     Re-run `app-privacy scan` for this app, or take only the text after \
                     `designated => ` from `codesign -d -r-`.",
                    app.bundle_id
                );
            }

            let mut permissions = BTreeMap::new();
            for (raw_name, raw_value) in &app.permissions {
                let permission = Permission::from_toml_key(raw_name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}: {}",
                        app.bundle_id,
                        AppPrivacyError::UnknownPermission {
                            name: raw_name.clone()
                        }
                    )
                })?;
                let value = permission
                    .parse_value(raw_value)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", app.bundle_id))?;
                permissions.insert(permission, value.to_string());
            }

            out.push(AppEntry {
                bundle_id: app.bundle_id.trim().to_string(),
                designated_requirement: app.designated_requirement.trim().to_string(),
                justification: app.justification.clone(),
                permissions,
            });
        }

        if out.is_empty() {
            bail!("no [[app]] entries — nothing to generate");
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/// Read one app bundle into a policy entry.
///
/// Returns the error rather than a placeholder when the designated
/// requirement is unreadable — see the module docs.
pub fn scan_app(path: &Path) -> Result<AppTomlEntry> {
    if !path.exists() {
        bail!("{}: no such path", path.display());
    }

    let requirement = contour_core::get_code_requirement(path).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            AppPrivacyError::NoDesignatedRequirement {
                path: path.display().to_string(),
                reason: e.to_string(),
            }
        )
    })?;

    if requirement.trim().is_empty() {
        bail!(
            "{}",
            AppPrivacyError::NoDesignatedRequirement {
                path: path.display().to_string(),
                reason: "codesign reported no designated requirement (unsigned?)".to_string(),
            }
        );
    }

    let bundle_id = contour_core::get_bundle_id(path)
        .with_context(|| format!("{}: cannot read CFBundleIdentifier", path.display()))?;
    let name = contour_core::get_app_name(path);

    // Same `codesign` invocation family that produced the requirement, so a
    // failure here is a real anomaly rather than an expected gap — surfaced,
    // not swallowed.
    let identity = contour_core::read_code_identity(path)
        .with_context(|| format!("{}: cannot read code identity", path.display()))?;

    Ok(AppTomlEntry {
        name,
        bundle_id,
        designated_requirement: requirement.trim().to_string(),
        team_id: identity.team_id,
        signing_id: identity.signing_id,
        cdhash: identity
            .slices
            .into_iter()
            .map(|s| (s.arch, s.cdhash))
            .collect(),
        justification: String::new(),
        permissions: BTreeMap::new(),
    })
}

/// Render a policy file as commented TOML.
///
/// Written by hand rather than through `toml::to_string` so the output can
/// carry the guidance an operator needs at the moment of editing: which values
/// are legal per permission, and that omitting a key is not the same as
/// denying it.
pub fn render_policy_toml(file: &AppPrivacyFile) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();

    s.push_str(
        "# App privacy defaults — com.apple.configuration.app.settings\n\
         #\n\
         # Values: Allow | None   (Apple has NO \"Deny\" — contour refuses it)\n\
         #   location:          None | WhileUsing | Always\n\
         #   location_accuracy: None | Approximate | Precise\n\
         #\n\
         # Leaving a permission OUT is not the same as denying it: the app is\n\
         # simply unmanaged for that permission and the user is still prompted.\n\
         #\n\
         # justification is REQUIRED and is shown to the user.\n\
         #\n\
         # Requires macOS 26+, user-channel enrollment.\n\n",
    );

    let _ = writeln!(s, "intent_name = \"{}\"\n", file.intent_name);

    for app in &file.apps {
        s.push_str("[[app]]\n");
        if !app.name.is_empty() {
            let _ = writeln!(s, "name = {}", toml_string(&app.name));
        }
        let _ = writeln!(s, "bundle_id = {}", toml_string(&app.bundle_id));
        // Single-quoted literal string: designated requirements are full of
        // double quotes, and a literal string needs no escaping at all.
        let _ = writeln!(
            s,
            "designated_requirement = {}",
            toml_literal(&app.designated_requirement)
        );
        // Identity is informational here and consumed by app.settings binary
        // rules; kept together so the block reads as one fact about the app.
        if let Some(t) = &app.team_id {
            let _ = writeln!(s, "team_id = {}", toml_string(t));
        }
        if let Some(sid) = &app.signing_id {
            let _ = writeln!(s, "signing_id = {}", toml_string(sid));
        }
        if !app.cdhash.is_empty() {
            let slices = app
                .cdhash
                .iter()
                .map(|(arch, h)| format!("{arch} = {}", toml_string(h)))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(s, "cdhash = {{ {slices} }}");
        }
        let _ = writeln!(
            s,
            "justification = {}   # REQUIRED — shown to the user",
            toml_string(&app.justification)
        );

        if app.permissions.is_empty() {
            s.push_str("\n# Uncomment the permissions this app needs:\n");
            for p in Permission::ALL {
                let _ = writeln!(
                    s,
                    "# {} = \"{}\"",
                    p.toml_key(),
                    p.allowed_values().last().unwrap_or(&"Allow")
                );
            }
        } else {
            for (k, v) in &app.permissions {
                let _ = writeln!(s, "{k} = {}", toml_string(v));
            }
        }
        s.push('\n');
    }

    s
}

/// Quote a TOML basic string.
fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Quote a TOML literal string, falling back to a basic string when the value
/// itself contains a single quote (literal strings cannot escape).
fn toml_literal(s: &str) -> String {
    if s.contains('\'') {
        toml_string(s)
    } else {
        format!("'{s}'")
    }
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

/// Build the compose bundle for a set of validated entries.
pub fn build_bundle(intent_name: &str, entries: &[AppEntry]) -> Result<Bundle> {
    let privacy = build_privacy_payload(entries).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut payload = Map::new();
    payload.insert("Privacy".to_string(), Value::Object(privacy));

    Ok(Bundle {
        intent_name: intent_name.to_string(),
        platforms: Vec::new(),
        asset: None,
        configuration: BundleConfiguration {
            type_name: APP_SETTINGS_TYPE.to_string(),
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
    })
}

// ---------------------------------------------------------------------------
// import-pppc
// ---------------------------------------------------------------------------

/// What an import could and could not carry across.
#[derive(Debug, Default)]
pub struct ImportReport {
    /// Entries produced.
    pub imported: Vec<AppTomlEntry>,
    /// `(bundle id, service)` pairs with no `app.settings` equivalent.
    pub unmapped: Vec<(String, String)>,
    /// Apps skipped entirely because they had no usable code requirement.
    pub skipped: Vec<String>,
}

/// Convert a `pppc.toml` into app-privacy entries.
///
/// Parsed generically rather than through the `pppc` crate: the profile crate
/// does not depend on it, and only four fields are needed (`bundle_id`,
/// `code_requirement`, `name`, `services`).
pub fn import_pppc(toml_text: &str) -> Result<ImportReport> {
    let doc: toml::Value = toml::from_str(toml_text).context("parsing pppc.toml")?;
    let apps = doc
        .get("apps")
        .and_then(|a| a.as_array())
        .ok_or_else(|| anyhow::anyhow!("pppc.toml has no [[apps]] entries"))?;

    let mut report = ImportReport::default();

    for app in apps {
        let bundle_id = app
            .get("bundle_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let requirement = app
            .get("code_requirement")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if bundle_id.is_empty() || requirement.is_empty() {
            // Path-mode PPPC entries have no bundle id; they cannot be keyed
            // the way app.settings requires.
            let label = app
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("<unnamed>")
                .to_string();
            report.skipped.push(label);
            continue;
        }

        let mut permissions = BTreeMap::new();
        if let Some(services) = app.get("services").and_then(|s| s.as_array()) {
            for service in services.iter().filter_map(|s| s.as_str()) {
                match pppc_service_mapping(service) {
                    Some(p) => {
                        permissions.insert(p.toml_key().to_string(), "Allow".to_string());
                    }
                    None => report
                        .unmapped
                        .push((bundle_id.clone(), service.to_string())),
                }
            }
        }

        report.imported.push(AppTomlEntry {
            name: app
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            bundle_id,
            designated_requirement: requirement,
            team_id: None,
            signing_id: None,
            cdhash: BTreeMap::new(),
            justification: String::new(),
            permissions,
        });
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// Interactive
// ---------------------------------------------------------------------------

/// Default search locations when `--interactive` is given no paths.
const DEFAULT_SEARCH_PATHS: &[&str] = &["/Applications", "/Applications/Utilities"];

/// Walk the operator through choosing apps, permissions and a justification.
///
/// Mirrors `pppc scan --interactive`: discover, multi-select apps, then
/// per-app permissions. Two differences follow from Apple's schema rather
/// than from taste:
///
/// * `Location` and `LocationAccuracy` are not yes/no, so selecting them
///   prompts for which value — offering `Allow` there would be invalid.
/// * `OrganizationJustification` is required and user-visible, so the prompt
///   will not accept an empty string. A fleet-wide default is asked once and
///   offered per app, which is how these files are written in practice.
pub fn run_interactive_scan(paths: &[String]) -> Result<AppPrivacyFile> {
    let search: Vec<PathBuf> = if paths.is_empty() {
        DEFAULT_SEARCH_PATHS.iter().map(PathBuf::from).collect()
    } else {
        paths.iter().map(PathBuf::from).collect()
    };

    let discovered = contour_core::discover_apps(&search)?;
    if discovered.is_empty() {
        bail!(
            "no applications found in {}",
            search
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let chosen = contour_core::select_apps(&discovered, "Apps to manage privacy defaults for:")?;
    if chosen.is_empty() {
        bail!("no apps selected");
    }

    let default_justification = inquire::Text::new("Default justification (shown to users):")
        .with_default("Required for approved business use.")
        .with_help_message("Apple requires one per app; you can override it per app next")
        .prompt()?;

    let mut file = AppPrivacyFile {
        intent_name: default_intent_name(),
        apps: Vec::new(),
    };

    for idx in chosen {
        let app = &discovered[idx];

        // Read the requirement before asking anything else: an app that
        // cannot be keyed is not worth configuring.
        let mut entry = match scan_app(&app.path) {
            Ok(e) => e,
            Err(e) => {
                println!("  {} skipping {}: {e}", "!".yellow(), app.name);
                continue;
            }
        };

        println!("\n{} ({})", entry.name.bold(), entry.bundle_id.dimmed());

        let picked = contour_core::multi_select(
            &Permission::ALL.iter().map(|p| p.key()).collect::<Vec<_>>(),
            "Permissions to pre-answer:",
        )?;

        for key in picked {
            let permission =
                Permission::from_toml_key(key).expect("keys come from Permission::ALL");
            // Binary permissions need no second question; the multi-valued
            // ones do, and "Allow" is not among their legal values.
            let value = if permission.allowed_values().len() > 2 {
                let choices: Vec<&str> = permission
                    .allowed_values()
                    .iter()
                    .copied()
                    .filter(|v| *v != "None")
                    .collect();
                inquire::Select::new(&format!("  {} —", permission.key()), choices.clone())
                    .prompt()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| choices[0].to_string())
            } else {
                "Allow".to_string()
            };
            entry
                .permissions
                .insert(permission.toml_key().to_string(), value);
        }

        if entry.permissions.is_empty() {
            println!(
                "  {} no permissions chosen — this entry will not generate",
                "!".yellow()
            );
        }

        entry.justification = inquire::Text::new("  Justification:")
            .with_default(&default_justification)
            .prompt()?;

        file.apps.push(entry);
    }

    if file.apps.is_empty() {
        bail!("no apps configured");
    }
    Ok(file)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// One input that could not be scanned, and the reason.
///
/// Carried through to the JSON as `failed[]` so a partial result says what it
/// missed. A consumer that ignores this block gets a smaller policy file than
/// it asked for and no indication why, which is the failure mode the batch
/// abort was protecting against in the first place.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedApp {
    /// The path as the operator gave it.
    pub path: String,
    /// Why `scan_app` refused it.
    pub reason: String,
}

impl SkippedApp {
    /// `path: reason`, or just the reason when it already names the path.
    ///
    /// `scan_app` prefixes most of its errors with the path, so joining
    /// unconditionally yields `/x.app: /x.app: no such path`. The `path` field
    /// stays separate in the JSON regardless — a consumer should not have to
    /// parse it back out of prose.
    fn describe(&self) -> String {
        if self.reason.starts_with(&self.path) {
            self.reason.clone()
        } else {
            format!("{}: {}", self.path, self.reason)
        }
    }

    /// One indented line per failure, for an error message or a terminal.
    fn render(skipped: &[Self]) -> String {
        skipped
            .iter()
            .map(|f| format!("  {}", f.describe()))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Scan every path, separating the ones that worked from the ones that did not.
///
/// Every input is attempted even when the caller intends to fail, so the error
/// can name all of them at once. Walking 61 bundles to report the first is a
/// worse trade than walking 61 to report all four.
fn scan_all(paths: &[String]) -> (Vec<AppTomlEntry>, Vec<SkippedApp>) {
    scan_all_with(paths, |p| scan_app(Path::new(p)))
}

/// [`scan_all`] with the per-app read injected.
///
/// The seam exists for the tests: a mixed batch — some apps readable, some not
/// — is the case worth pinning, and reaching a real signed bundle from a unit
/// test would make it depend on what happens to be installed.
fn scan_all_with<F>(paths: &[String], mut scan: F) -> (Vec<AppTomlEntry>, Vec<SkippedApp>)
where
    F: FnMut(&str) -> Result<AppTomlEntry>,
{
    let mut scanned = Vec::new();
    let mut skipped = Vec::new();
    for p in paths {
        match scan(p) {
            Ok(entry) => scanned.push(entry),
            Err(e) => skipped.push(SkippedApp {
                path: p.clone(),
                reason: e.to_string(),
            }),
        }
    }
    (scanned, skipped)
}

/// The JSON body of a `scan`, built rather than printed so tests can read it.
fn scan_report_json(dest: &Path, file: &AppPrivacyFile, skipped: &[SkippedApp]) -> Value {
    serde_json::json!({
        "file": dest.display().to_string(),
        "apps": file.apps.iter().map(|a| &a.bundle_id).collect::<Vec<_>>(),
        // Everything the scan learned, identity included — `apps` stays a
        // plain id list for the consumers that already read it.
        "scanned": file.apps,
        // Always present, empty when nothing was skipped, so a consumer can
        // read it without probing for the key.
        "failed": skipped,
    })
}

/// `profile ddm app-privacy scan <paths…>`
pub fn handle_scan(
    paths: &[String],
    interactive: bool,
    skip_unreadable: bool,
    output: Option<&str>,
    json: bool,
) -> Result<()> {
    if interactive && json {
        bail!("--interactive cannot be combined with --json: it needs a terminal");
    }

    let mut skipped: Vec<SkippedApp> = Vec::new();

    let file = if interactive {
        run_interactive_scan(paths)?
    } else {
        if paths.is_empty() {
            bail!(
                "no apps given. Pass app bundles, or use --interactive to pick them \
                 from /Applications"
            );
        }

        let (scanned, failures) = scan_all(paths);

        // Default stays an error: a caller who did not ask for tolerance gets
        // none. It reports every failure rather than the first, because
        // re-running to discover the next one is the actual cost here.
        if !failures.is_empty() && !skip_unreadable {
            bail!(
                "{} of {} app(s) could not be read:\n{}\n\n\
                 Fix them, or pass --skip-unreadable to write the {} that worked \
                 and list the rest.",
                failures.len(),
                paths.len(),
                SkippedApp::render(&failures),
                scanned.len()
            );
        }

        // Tolerance means omitting the broken ones, never guessing at them.
        // With nothing left to write, the file would be an empty policy that
        // silently generates no declarations — so that is still an error.
        if scanned.is_empty() {
            bail!(
                "no app could be read, so there is nothing to write:\n{}",
                SkippedApp::render(&failures)
            );
        }

        skipped = failures;

        AppPrivacyFile {
            intent_name: default_intent_name(),
            apps: scanned,
        }
    };

    let rendered = render_policy_toml(&file);
    let dest = PathBuf::from(output.unwrap_or(DEFAULT_POLICY_FILE));
    std::fs::write(&dest, &rendered).with_context(|| format!("writing {}", dest.display()))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&scan_report_json(&dest, &file, &skipped))?
        );
    } else {
        for s in &skipped {
            println!("  {} skipping {}", "!".yellow(), s.describe());
        }
        println!(
            "{} {} ({} app(s))",
            "✓".green(),
            dest.display(),
            file.apps.len()
        );
        if !skipped.is_empty() {
            println!(
                "  {} {} app(s) skipped, listed above",
                "!".yellow(),
                skipped.len()
            );
        }
        println!(
            "  Set a justification and the permissions each app needs, then run \
             `contour profile ddm app-privacy generate`."
        );
    }
    Ok(())
}

/// `profile ddm app-privacy generate <file>`
pub fn handle_generate(
    input: &str,
    org: Option<&str>,
    config: Option<&ProfileConfig>,
    output: Option<&str>,
    payload_scope: Option<&str>,
    write: bool,
    json: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(input).with_context(|| format!("reading {input}"))?;
    let file: AppPrivacyFile = toml::from_str(&text).with_context(|| format!("parsing {input}"))?;
    let entries = file.to_entries()?;

    let Some(domain) = resolve_ddm_org_domain(org, config) else {
        bail!(
            "organization domain is required\n  \
             • --org <domain>\n  \
             • CONTOUR_ORG\n  \
             • organization.domain in profile.toml or .contour/config.toml"
        );
    };
    let bundle = build_bundle(&file.intent_name, &entries)?;
    let registry = load_registry_opts(None, false)?;
    let mut composed = compose(&bundle, &domain, &registry, &ComposeOptions::default())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Opt-in, because `PayloadScope` is Fleet-specific and not part of
    // Apple's DDM spec — emitting it unconditionally would put a key in
    // every declaration that only one MDM understands.
    //
    // It matters here more than anywhere else: every declaration this
    // command produces is a Privacy block, and Privacy is macOS USER-scope
    // only. Delivered on the device channel — Fleet's default — it is
    // accepted and ignored, silently. `--payload-scope user` is what makes
    // the output work there.
    if let Some(raw) = payload_scope {
        let scope = crate::ddm::scope::Scope::parse(raw).ok_or_else(|| {
            anyhow::anyhow!(
                "--payload-scope must be system or user; got '{raw}'. Fleet falls \
                 back to System on an unrecognised value, so this is refused rather \
                 than written through."
            )
        })?;
        // Fleet's own spelling, not the user's.
        composed.configuration.payload_scope = Some(scope.payload_scope_value().to_string());
    }

    let out_dir = PathBuf::from(output.unwrap_or("."));
    let planned: Vec<(PathBuf, String)> = vec![
        (
            out_dir.join("configuration.json"),
            serde_json::to_string_pretty(&composed.configuration)?,
        ),
        (
            out_dir.join("activation.json"),
            serde_json::to_string_pretty(
                composed
                    .activation
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("compose produced no activation"))?,
            )?,
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
                "apps": entries.len(),
                "files": planned.iter().map(|(p, _)| p.display().to_string()).collect::<Vec<_>>(),
                "identifier": composed.configuration.identifier,
            }))?
        );
    } else {
        let verb = if write { "Wrote" } else { "Would write" };
        println!(
            "{} {} declaration(s) for {} app(s):",
            verb,
            planned.len(),
            entries.len()
        );
        for (path, _) in &planned {
            println!("  {}", path.display());
        }
        if !write {
            println!("\n  Dry run — pass --write to apply.");
        }
    }
    Ok(())
}

/// `profile ddm app-privacy import-pppc <pppc.toml>`
pub fn handle_import_pppc(input: &str, output: Option<&str>, json: bool) -> Result<()> {
    let text = std::fs::read_to_string(input).with_context(|| format!("reading {input}"))?;
    let report = import_pppc(&text)?;

    let file = AppPrivacyFile {
        intent_name: default_intent_name(),
        apps: report.imported.clone(),
    };
    let dest = PathBuf::from(output.unwrap_or(DEFAULT_POLICY_FILE));
    std::fs::write(&dest, render_policy_toml(&file))
        .with_context(|| format!("writing {}", dest.display()))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": dest.display().to_string(),
                "imported": report.imported.len(),
                "unmapped": report.unmapped.iter()
                    .map(|(b, s)| format!("{b}: {s}")).collect::<Vec<_>>(),
                "skipped": report.skipped,
            }))?
        );
    } else {
        println!(
            "{} {} ({} app(s) imported)",
            "✓".green(),
            dest.display(),
            report.imported.len()
        );
        if !report.unmapped.is_empty() {
            println!(
                "\n{} {} PPPC grant(s) have no app.settings equivalent and were NOT carried over:",
                "!".yellow(),
                report.unmapped.len()
            );
            for (bundle, service) in &report.unmapped {
                println!("  {bundle}: {service}");
            }
            println!("  Keep the PPPC profile deployed for these.");
        }
        if !report.skipped.is_empty() {
            println!(
                "\n{} {} entry/entries skipped (no bundle id or code requirement): {}",
                "!".yellow(),
                report.skipped.len(),
                report.skipped.join(", ")
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PPPC_SAMPLE: &str = r#"
[config]
org = "com.acme"

[[apps]]
name = "Zoom"
bundle_id = "us.zoom.xos"
code_requirement = "identifier \"us.zoom.xos\" and anchor apple generic"
services = ["camera", "microphone", "fda", "apple-events"]

[[apps]]
name = "Bare binary"
bundle_id = ""
code_requirement = "identifier \"x\""
services = ["camera"]
"#;

    /// A stand-in for an app that `codesign` could read.
    fn fake_entry(bundle_id: &str) -> AppTomlEntry {
        AppTomlEntry {
            name: bundle_id.to_string(),
            bundle_id: bundle_id.to_string(),
            designated_requirement: format!("identifier \"{bundle_id}\""),
            justification: String::new(),
            ..Default::default()
        }
    }

    /// Some inputs read, some did not.
    ///
    /// Both halves must survive — the entries in order, and a reason for each
    /// failure — because a partial result that cannot say what it missed is
    /// what an all-or-nothing abort guards against.
    #[test]
    fn scan_all_keeps_both_halves_of_a_mixed_batch() {
        let paths: Vec<String> = ["/a.app", "/broken.app", "/b.app", "/gone.app"]
            .into_iter()
            .map(String::from)
            .collect();

        let (scanned, skipped) = scan_all_with(&paths, |p| match p {
            "/broken.app" => bail!("cannot read CFBundleIdentifier"),
            "/gone.app" => bail!("no such path"),
            other => Ok(fake_entry(other.trim_start_matches('/'))),
        });

        assert_eq!(
            scanned
                .iter()
                .map(|e| e.bundle_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a.app", "b.app"],
            "readable apps must survive, in the order given"
        );
        assert_eq!(
            skipped.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(),
            vec!["/broken.app", "/gone.app"]
        );
        assert!(
            skipped[0].reason.contains("CFBundleIdentifier"),
            "the reason must reach the caller, got {:?}",
            skipped[0].reason
        );
    }

    /// Without `--skip-unreadable` the batch still fails — but it names every
    /// bad input, not just the first. Discovering the next failure by
    /// re-running is the cost this removes.
    #[test]
    fn default_batch_reports_every_failure_not_just_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("app-privacy.toml");
        let paths: Vec<String> = ["/nope-one.app", "/nope-two.app"]
            .into_iter()
            .map(String::from)
            .collect();

        let err = handle_scan(&paths, false, false, dest.to_str(), false)
            .expect_err("unreadable apps must fail without --skip-unreadable");
        let msg = err.to_string();

        assert!(msg.contains("nope-one.app"), "got {msg}");
        assert!(
            msg.contains("nope-two.app"),
            "second failure omitted: {msg}"
        );
        assert!(
            msg.contains("--skip-unreadable"),
            "no way out offered: {msg}"
        );
        assert!(!dest.exists(), "nothing may be written on the failure path");
    }

    /// Tolerance omits broken apps; it does not invent them. With none left,
    /// writing an empty policy would produce a file that generates no
    /// declarations and reports success, so this stays an error.
    #[test]
    fn skip_unreadable_still_fails_when_nothing_survives() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("app-privacy.toml");
        let paths = vec!["/nope.app".to_string()];

        let err = handle_scan(&paths, false, true, dest.to_str(), false)
            .expect_err("an empty policy file is not a useful result");
        assert!(err.to_string().contains("nothing to write"), "got {err}");
        assert!(!dest.exists());
    }

    /// `scan_app` prefixes its errors with the path, so the human line must
    /// not prefix it again — `/x.app: /x.app: no such path` reads as two
    /// different problems.
    #[test]
    fn a_failure_names_its_path_exactly_once() {
        let already_prefixed = SkippedApp {
            path: "/x.app".into(),
            reason: "/x.app: no such path".into(),
        };
        assert_eq!(already_prefixed.describe(), "/x.app: no such path");

        let bare = SkippedApp {
            path: "/y.app".into(),
            reason: "unsigned".into(),
        };
        assert_eq!(bare.describe(), "/y.app: unsigned");
    }

    /// Identity must be declared on the struct, or serde's flatten swallows
    /// `team_id` into `permissions` and `generate` fails with "unknown
    /// permission team_id". Round-trip through the rendered TOML and prove
    /// the entries still convert.
    #[test]
    fn identity_round_trips_and_is_not_mistaken_for_a_permission() {
        let mut entry = fake_entry("us.zoom.xos");
        entry.team_id = Some("BJ4HAAB9B3".into());
        entry.signing_id = Some("us.zoom.xos".into());
        entry.cdhash = [("arm64", "a".repeat(40)), ("x86_64", "b".repeat(40))]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        entry.justification = "Video calls".into();
        entry.permissions.insert("camera".into(), "Allow".into());

        let file = AppPrivacyFile {
            intent_name: default_intent_name(),
            apps: vec![entry],
        };
        let rendered = render_policy_toml(&file);
        assert!(rendered.contains("team_id = \"BJ4HAAB9B3\""), "{rendered}");
        assert!(rendered.contains("cdhash = { arm64 = "), "{rendered}");

        let parsed: AppPrivacyFile = toml::from_str(&rendered).unwrap();
        let app = &parsed.apps[0];
        assert_eq!(app.team_id.as_deref(), Some("BJ4HAAB9B3"));
        assert_eq!(app.cdhash.len(), 2);
        assert_eq!(
            app.permissions.keys().collect::<Vec<_>>(),
            vec!["camera"],
            "identity keys leaked into permissions: {:?}",
            app.permissions
        );

        let entries = parsed
            .to_entries()
            .expect("identity must not break generate");
        assert_eq!(entries[0].bundle_id, "us.zoom.xos");
    }

    /// An entry without identity — a pppc import, or a hand-written file —
    /// renders no identity lines rather than empty ones.
    #[test]
    fn absent_identity_renders_nothing() {
        let file = AppPrivacyFile {
            intent_name: default_intent_name(),
            apps: vec![fake_entry("com.example.app")],
        };
        let rendered = render_policy_toml(&file);
        assert!(!rendered.contains("team_id"), "{rendered}");
        assert!(!rendered.contains("cdhash"), "{rendered}");
    }

    /// `failed[]` is always present, so a consumer can read it unconditionally
    /// rather than treating a missing key as "nothing went wrong".
    #[test]
    fn json_report_always_carries_a_failed_block() {
        let file = AppPrivacyFile {
            intent_name: default_intent_name(),
            apps: vec![fake_entry("us.zoom.xos")],
        };

        let clean = scan_report_json(Path::new("app-privacy.toml"), &file, &[]);
        assert_eq!(clean["failed"].as_array().map(Vec::len), Some(0));
        assert_eq!(clean["apps"][0], "us.zoom.xos");

        let partial = scan_report_json(
            Path::new("app-privacy.toml"),
            &file,
            &[SkippedApp {
                path: "/broken.app".into(),
                reason: "unsigned".into(),
            }],
        );
        assert_eq!(partial["failed"][0]["path"], "/broken.app");
        assert_eq!(partial["failed"][0]["reason"], "unsigned");
    }

    #[test]
    fn import_maps_the_overlap_and_reports_the_rest() {
        let report = import_pppc(PPPC_SAMPLE).unwrap();
        assert_eq!(report.imported.len(), 1, "path-mode entry must be skipped");
        assert_eq!(report.skipped, vec!["Bare binary".to_string()]);

        let zoom = &report.imported[0];
        assert_eq!(zoom.bundle_id, "us.zoom.xos");
        assert_eq!(
            zoom.permissions.get("camera").map(String::as_str),
            Some("Allow")
        );
        assert_eq!(
            zoom.permissions.get("microphone").map(String::as_str),
            Some("Allow")
        );

        // The PPPC-only grants must be reported, never dropped in silence.
        let unmapped: Vec<&str> = report.unmapped.iter().map(|(_, s)| s.as_str()).collect();
        assert!(unmapped.contains(&"fda"), "got {unmapped:?}");
        assert!(unmapped.contains(&"apple-events"), "got {unmapped:?}");
    }

    #[test]
    fn rendered_toml_round_trips() {
        let report = import_pppc(PPPC_SAMPLE).unwrap();
        let file = AppPrivacyFile {
            intent_name: "app-privacy".to_string(),
            apps: report.imported,
        };
        let rendered = render_policy_toml(&file);

        let parsed: AppPrivacyFile = toml::from_str(&rendered)
            .unwrap_or_else(|e| panic!("rendered TOML must re-parse: {e}\n---\n{rendered}"));
        assert_eq!(parsed.apps.len(), 1);
        assert_eq!(parsed.apps[0].bundle_id, "us.zoom.xos");
        // The requirement's embedded double quotes must survive the round trip.
        assert!(parsed.apps[0].designated_requirement.contains('"'));
    }

    #[test]
    fn deny_in_the_toml_fails_with_an_explanation() {
        let text = r#"
intent_name = "t"

[[app]]
bundle_id = "us.zoom.xos"
designated_requirement = 'identifier "us.zoom.xos"'
justification = "Video calls"
camera = "Deny"
"#;
        let file: AppPrivacyFile = toml::from_str(text).unwrap();
        let err = file.to_entries().unwrap_err().to_string();
        assert!(
            err.contains("no 'Deny' value"),
            "must explain Deny, got: {err}"
        );
    }

    #[test]
    fn unknown_permission_is_named() {
        let text = r#"
intent_name = "t"

[[app]]
bundle_id = "us.zoom.xos"
designated_requirement = 'identifier "us.zoom.xos"'
justification = "Video calls"
screen_recording = "Allow"
"#;
        let file: AppPrivacyFile = toml::from_str(text).unwrap();
        let err = file.to_entries().unwrap_err().to_string();
        assert!(err.contains("screen_recording"), "got: {err}");
    }

    #[test]
    fn bundle_has_the_privacy_payload_and_an_activation() {
        let text = r#"
intent_name = "app-privacy"

[[app]]
bundle_id = "us.zoom.xos"
designated_requirement = 'identifier "us.zoom.xos" and anchor apple generic'
justification = "Video conferencing"
camera = "Allow"
microphone = "allow"
"#;
        let file: AppPrivacyFile = toml::from_str(text).unwrap();
        let entries = file.to_entries().unwrap();
        let bundle = build_bundle(&file.intent_name, &entries).unwrap();

        assert_eq!(bundle.configuration.type_name, APP_SETTINGS_TYPE);
        assert!(bundle.activation.is_some(), "configuration alone is inert");

        let defaults = bundle.configuration.payload["Privacy"]["PermissionDefaults"]
            .as_object()
            .unwrap();
        let (key, entry) = defaults.iter().next().unwrap();
        assert!(key.starts_with("us.zoom.xos {identifier"), "key: {key}");
        // lowercase "allow" in the TOML normalises to Apple's casing.
        assert_eq!(entry["Microphone"], "Allow");
        assert_eq!(entry["OrganizationJustification"], "Video conferencing");
    }

    #[test]
    fn empty_requirement_is_refused_with_a_pointer_to_scan() {
        let text = r#"
intent_name = "t"

[[app]]
bundle_id = "us.zoom.xos"
designated_requirement = ""
justification = "x"
camera = "Allow"
"#;
        let file: AppPrivacyFile = toml::from_str(text).unwrap();
        let err = file.to_entries().unwrap_err().to_string();
        assert!(err.contains("app-privacy scan"), "got: {err}");
    }
}
