//! DEP/ADE enrollment profile generation from embedded skip_keys data.
//!
//! Provides `list` and `generate` subcommands for working with Setup Assistant
//! skip keys across Apple platforms.

use crate::output::OutputMode;
use anyhow::{Context, Result};
use colored::Colorize;
use mdm_schema::SkipKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use std::path::Path;

/// Skip keys that must never be present in a generated enrollment profile.
///
/// FileVault: skipping bypasses the user-led recovery-key flow.
/// SoftwareUpdate: skipping leaves devices on shipping-time OS during onboarding.
/// Documented in sop-enrollment.md; this constant enforces the SOP at PRECONDITIONS time.
pub const NEVER_SKIP: &[&str] = &["FileVault", "SoftwareUpdate"];

/// Reusable enrollment skip-list file format (TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkipListFile {
    /// Schema version; reserved for forward compatibility.
    #[serde(default = "default_skip_list_version")]
    pub version: u8,
    /// Platform override (e.g. "macOS", "iOS"). When set, takes precedence
    /// over the `--platform` default; an explicit `--platform` CLI flag
    /// overrides this in turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// OS version override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Profile name override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// Skip keys to apply.
    #[serde(default)]
    pub skip: Vec<String>,
}

fn default_skip_list_version() -> u8 {
    1
}

/// Read and parse a skip-list TOML file from disk.
pub fn parse_skip_list_file(path: &Path) -> Result<SkipListFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read skip-list file: {}", path.display()))?;
    let file: SkipListFile = toml::from_str(&content)
        .with_context(|| format!("Failed to parse skip-list TOML: {}", path.display()))?;
    Ok(file)
}

/// Load and filter skip keys for a given platform and optional OS version.
///
/// `beta` selects the pre-release OS seed dataset (e.g. OS 27.0 keys like
/// `AccessibilityAppearance` / `LiquidGlass`); the stable set is the default.
fn load_skip_keys(platform: &str, os_version: Option<&str>, beta: bool) -> Result<Vec<SkipKey>> {
    let raw = if beta {
        mdm_schema::embedded_skip_keys_beta()
    } else {
        mdm_schema::embedded_skip_keys()
    };
    let all = mdm_schema::skip_keys::read(raw).context("Failed to read embedded skip_keys")?;

    let filtered = all
        .into_iter()
        .filter(|k| k.platform.eq_ignore_ascii_case(platform))
        .filter(|k| {
            if let Some(ver) = os_version {
                let introduced_ok = k.introduced.as_deref().is_none_or(|intro| intro <= ver);
                let not_removed = k.removed.as_deref().is_none_or(|rem| rem > ver);
                introduced_ok && not_removed
            } else {
                true
            }
        })
        .collect();

    Ok(filtered)
}

/// Default region for a language fast-preset (en→US, de→DE, fr→FR, es→ES).
/// `--region` overrides; unknown languages fall back to US.
fn default_region_for(language: &str) -> &'static str {
    match language.to_ascii_lowercase().as_str() {
        "de" => "DE",
        "fr" => "FR",
        "es" => "ES",
        // "en" and anything else default to US.
        _ => "US",
    }
}

/// Numeric version comparison: `a <= b` where each is a dotted version like
/// `10.13.4` / `26.0`. Avoids the lexical-ordering bug of string compare
/// (e.g. "9.0" vs "10.0"). Missing components count as 0.
fn version_le(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    let (av, bv) = (parse(a), parse(b));
    for i in 0..av.len().max(bv.len()) {
        let (x, y) = (
            av.get(i).copied().unwrap_or(0),
            bv.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x < y;
        }
    }
    true // equal
}

/// ADE profile envelope flags (everything besides `skip_setup_items`).
#[derive(Debug)]
struct Envelope {
    auto_advance_setup: bool,
    is_supervised: bool,
    is_mdm_removable: bool,
    allow_pairing: bool,
}

impl Default for Envelope {
    fn default() -> Self {
        Self {
            auto_advance_setup: false,
            is_supervised: true,
            is_mdm_removable: false,
            allow_pairing: true,
        }
    }
}

/// A built-in enrollment preset: ADE envelope flags + the panes to LEAVE
/// unskipped (`keep`). Generation skips every other available skip key for the
/// platform; `NEVER_SKIP` panes (FileVault/SoftwareUpdate) are always preserved.
#[derive(Debug)]
pub struct EnrollmentPreset {
    pub name: &'static str,
    pub description: &'static str,
    pub platform: &'static str,
    pub auto_advance_setup: bool,
    pub is_supervised: bool,
    pub is_mdm_removable: bool,
    pub allow_pairing: bool,
    /// Setup-Assistant panes the user should still see (everything else skipped).
    pub keep: &'static [&'static str],
}

/// The three shipped enrollment presets.
pub const PRESETS: &[EnrollmentPreset] = &[
    EnrollmentPreset {
        name: "auto-advance",
        description: "macOS · auto-advances Setup Assistant; skips everything \
                      except Biometric (Touch ID) and Location Services.",
        platform: "macOS",
        auto_advance_setup: true,
        is_supervised: true,
        is_mdm_removable: false,
        allow_pairing: true,
        keep: &["Biometric", "Location"],
    },
    EnrollmentPreset {
        name: "shared-ipad",
        description: "iOS/iPadOS for Shared iPad; skips everything except \
                      Biometric and Location. (Shared iPad is enabled via MDM \
                      enrollment settings, not the ADE skip profile.)",
        platform: "iOS",
        auto_advance_setup: false,
        is_supervised: true,
        is_mdm_removable: false,
        allow_pairing: true,
        keep: &["Biometric", "Location"],
    },
    EnrollmentPreset {
        name: "manual",
        description: "macOS · manual Setup Assistant (no auto-advance); skips \
                      everything except Biometric and Location.",
        platform: "macOS",
        auto_advance_setup: false,
        is_supervised: true,
        is_mdm_removable: false,
        allow_pairing: true,
        keep: &["Biometric", "Location"],
    },
];

/// Look up a preset by name.
pub fn find_preset(name: &str) -> Option<&'static EnrollmentPreset> {
    PRESETS.iter().find(|p| p.name == name)
}

/// Handle `enrollment presets` — list the built-in presets.
pub fn handle_enrollment_presets(mode: OutputMode) -> Result<()> {
    if mode == OutputMode::Json {
        let rows: Vec<_> = PRESETS
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "description": p.description,
                    "platform": p.platform,
                    "auto_advance_setup": p.auto_advance_setup,
                    "is_supervised": p.is_supervised,
                    "is_mdm_removable": p.is_mdm_removable,
                    "allow_pairing": p.allow_pairing,
                    "keep": p.keep,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    println!("{}\n", "Enrollment presets".bold());
    for p in PRESETS {
        println!(
            "  {} {}",
            p.name.green().bold(),
            format!("[{}]", p.platform).dimmed()
        );
        println!("    {}", p.description);
        println!(
            "    {} {}  ·  keeps: {}\n",
            "auto-advance:".dimmed(),
            p.auto_advance_setup,
            p.keep.join(", ")
        );
    }
    println!(
        "{}",
        "Generate one: contour profile enrollment generate --preset <name> -o profile.json"
            .dimmed()
    );
    Ok(())
}

/// Write the generated ADE profile JSON to `output` (or stdout) with a summary.
/// Write a companion `.md` next to the generated enrollment JSON: the skip keys
/// used (with their pane titles from the schema) + links to Apple's Profile and
/// SkipKeys documentation. Returns the path written.
fn write_skip_readme(
    json_path: &str,
    profile_name: &str,
    platform: &str,
    language: &str,
    region: &str,
    selected: &[String],
    available: &[SkipKey],
) -> Result<std::path::PathBuf> {
    use std::fmt::Write as _;
    let titles: std::collections::HashMap<&str, &str> = available
        .iter()
        .map(|k| (k.key.as_str(), k.title.as_str()))
        .collect();

    let mut md = String::with_capacity(2 * 1024);
    writeln!(md, "# {profile_name}\n").unwrap();
    writeln!(md, "DEP/ADE enrollment profile — generated by contour.\n").unwrap();
    writeln!(md, "- **Platform:** {platform}").unwrap();
    writeln!(md, "- **Language / Region:** {language} / {region}").unwrap();
    writeln!(md, "- **Skipped panes:** {}\n", selected.len()).unwrap();

    writeln!(md, "## Skipped Setup Assistant panes\n").unwrap();
    writeln!(
        md,
        "These `SkipSetupItems` keys suppress their Setup Assistant pane during \
         Automated Device Enrollment.\n"
    )
    .unwrap();
    writeln!(md, "| Key | Pane |\n|-----|------|").unwrap();
    let mut keys: Vec<&String> = selected.iter().collect();
    keys.sort();
    for k in keys {
        let title = titles.get(k.as_str()).copied().unwrap_or("");
        writeln!(md, "| `{k}` | {title} |").unwrap();
    }
    writeln!(
        md,
        "\n> Panes not listed here (e.g. Biometric / Location) are shown to the user. \
         `FileVault` and `SoftwareUpdate` are never skipped (contour NEVER_SKIP guardrail).\n"
    )
    .unwrap();

    writeln!(md, "## References\n").unwrap();
    writeln!(
        md,
        "- [Profile (ADE/DEP enrollment profile)](https://developer.apple.com/documentation/devicemanagement/profile)"
    )
    .unwrap();
    writeln!(
        md,
        "- [SkipKeys (Setup Assistant pane keys)](https://developer.apple.com/documentation/devicemanagement/skipkeys)"
    )
    .unwrap();

    let md_path = std::path::Path::new(json_path).with_extension("md");
    std::fs::write(&md_path, md).with_context(|| format!("writing {}", md_path.display()))?;
    Ok(md_path)
}

fn write_enrollment_json(
    profile: &serde_json::Value,
    output: Option<&str>,
    summary: &str,
    mode: OutputMode,
) -> Result<()> {
    let json_output = serde_json::to_string_pretty(profile)?;
    if let Some(path) = output {
        std::fs::write(path, format!("{json_output}\n"))
            .with_context(|| format!("Failed to write {path}"))?;
        if mode == OutputMode::Human {
            println!("{} {summary} → {}", "OK".green().bold(), path.bold());
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"success": true, "output_file": path, "profile": profile})
                )?
            );
        }
    } else {
        // No output path: print to stdout (same for human + JSON modes).
        println!("{json_output}");
    }
    Ok(())
}

/// Interactive enrollment wizard: prompts platform → OS version → language →
/// panes to keep → auto-advance, then generates the profile. Schema-backed:
/// every offered pane comes from the embedded skip-key data for the chosen
/// platform/version.
fn run_enrollment_wizard(
    beta: bool,
    output: Option<&str>,
    readme: bool,
    mode: OutputMode,
) -> Result<()> {
    use inquire::{Confirm, MultiSelect, Select, Text};

    let platform = Select::new("Platform:", vec!["macOS", "iOS", "tvOS", "visionOS"])
        .prompt()
        .context("wizard cancelled")?;

    let version_choice = Select::new(
        "Target OS version (excludes panes removed/deprecated by then):",
        vec!["all (no version filter)", "15", "26", "27"],
    )
    .prompt()
    .context("wizard cancelled")?;
    let os_version: Option<&str> = if version_choice.starts_with("all") {
        None
    } else {
        Some(version_choice)
    };

    let available = load_skip_keys(platform, os_version, beta)?;
    if available.is_empty() {
        anyhow::bail!("No skip keys for {platform} at version {version_choice}");
    }

    let language = Select::new("Language:", vec!["en", "de", "fr", "es"])
        .prompt()
        .context("wizard cancelled")?;
    let region = default_region_for(language);

    let key_names: Vec<String> = available.iter().map(|k| k.key.clone()).collect();
    let defaults: Vec<usize> = available
        .iter()
        .enumerate()
        .filter(|(_, k)| matches!(k.key.as_str(), "Biometric" | "Location"))
        .map(|(i, _)| i)
        .collect();
    let keep = MultiSelect::new(
        "Panes to KEEP visible (everything else is skipped):",
        key_names,
    )
    .with_default(&defaults)
    .with_page_size(20)
    .prompt()
    .context("wizard cancelled")?;

    let auto_advance = Confirm::new("Auto-advance Setup Assistant?")
        .with_default(false)
        .prompt()
        .context("wizard cancelled")?;
    let profile_name = Text::new("Profile name:")
        .with_default("Automatic enrollment profile")
        .prompt()
        .context("wizard cancelled")?;

    let keep_set: std::collections::HashSet<&str> = keep.iter().map(String::as_str).collect();
    let skip: Vec<String> = available
        .iter()
        .map(|k| k.key.as_str())
        .filter(|k| !keep_set.contains(k) && !NEVER_SKIP.contains(k))
        .map(str::to_string)
        .collect();

    let env = Envelope {
        auto_advance_setup: auto_advance,
        ..Default::default()
    };
    let profile = build_enrollment_profile(&profile_name, &skip, &env, language, region);
    write_enrollment_json(
        &profile,
        output,
        &format!("{} skip keys for {platform}", skip.len()),
        mode,
    )?;
    if readme && let Some(path) = output {
        let md = write_skip_readme(
            path,
            &profile_name,
            platform,
            language,
            region,
            &skip,
            &available,
        )?;
        if mode == OutputMode::Human {
            println!("   {} {}", "Docs:".bold(), md.display());
        }
    }
    Ok(())
}

/// Handle `enrollment migrate` — re-validate an existing ADE profile's skip
/// items against a target OS version, dropping keys Apple removed or deprecated
/// by then (and any not in the platform schema). Remove-only: never adds keys.
pub fn handle_enrollment_migrate(
    input: &Path,
    to_version: &str,
    platform: &str,
    output: Option<&str>,
    beta: bool,
    mode: OutputMode,
) -> Result<()> {
    let content =
        std::fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
    let mut profile: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("parsing {} as JSON", input.display()))?;

    // Full platform key set → each key's (deprecated, removed) version.
    let all = load_skip_keys(platform, None, beta)?;
    let known: std::collections::HashMap<&str, (Option<&str>, Option<&str>)> = all
        .iter()
        .map(|k| {
            (
                k.key.as_str(),
                (k.deprecated.as_deref(), k.removed.as_deref()),
            )
        })
        .collect();

    let items: Vec<serde_json::Value> = profile
        .get("skip_setup_items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut kept: Vec<serde_json::Value> = Vec::new();
    let mut dropped: Vec<(String, String)> = Vec::new();
    for item in items {
        let Some(key) = item.as_str() else { continue };
        match known.get(key) {
            None => dropped.push((key.to_string(), format!("not a known {platform} skip key"))),
            Some((dep, rem)) => {
                if let Some(r) = rem.filter(|r| version_le(r, to_version)) {
                    dropped.push((key.to_string(), format!("removed in {r}")));
                } else if let Some(d) = dep.filter(|d| version_le(d, to_version)) {
                    dropped.push((key.to_string(), format!("deprecated in {d}")));
                } else {
                    kept.push(item.clone());
                }
            }
        }
    }

    profile["skip_setup_items"] = serde_json::Value::Array(kept.clone());

    let out_path = output.map_or_else(|| input.display().to_string(), str::to_string);
    std::fs::write(
        &out_path,
        format!("{}\n", serde_json::to_string_pretty(&profile)?),
    )
    .with_context(|| format!("writing {out_path}"))?;

    if mode == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "success": true,
                "to_version": to_version,
                "platform": platform,
                "kept": kept.len(),
                "dropped": dropped.iter().map(|(k, r)| json!({"key": k, "reason": r})).collect::<Vec<_>>(),
                "output_file": out_path,
            }))?
        );
    } else {
        println!(
            "{} Migrated {} → version {to_version} ({})",
            "OK".green().bold(),
            input.display(),
            out_path.bold()
        );
        if dropped.is_empty() {
            println!("   No deprecated/removed keys — nothing to drop.");
        } else {
            println!("   Dropped {} key(s):", dropped.len().to_string().bold());
            for (k, reason) in &dropped {
                println!("     {} {}", format!("- {k}").red(), reason.dimmed());
            }
        }
        println!("   {} keys kept.", kept.len());
    }
    Ok(())
}

/// Handle the `enrollment list` subcommand.
pub fn handle_enrollment_list(
    platform: &str,
    os_version: Option<&str>,
    beta: bool,
    deprecated: bool,
    mode: OutputMode,
) -> Result<()> {
    let mut keys = load_skip_keys(platform, os_version, beta)?;

    // `--deprecated`: focus on keys Apple has flagged deprecated or removed.
    if deprecated {
        keys.retain(|k| k.deprecated.is_some() || k.removed.is_some());
        if mode == OutputMode::Json {
            let rows: Vec<_> = keys
                .iter()
                .map(|k| json!({"key": k.key, "deprecated": k.deprecated, "removed": k.removed}))
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
            return Ok(());
        }
        println!(
            "\n{} deprecated/removed skip keys for {}\n",
            keys.len().to_string().bold(),
            platform.bold()
        );
        for k in &keys {
            let mut tags = Vec::new();
            if let Some(d) = &k.deprecated {
                tags.push(format!("deprecated {d}"));
            }
            if let Some(r) = &k.removed {
                tags.push(format!("removed {r}").red().to_string());
            }
            println!("  {:<26} {}", k.key.yellow(), tags.join(", ").dimmed());
        }
        return Ok(());
    }

    if keys.is_empty() {
        if mode == OutputMode::Json {
            println!("[]");
        } else {
            println!(
                "No skip keys found for platform '{platform}'{}",
                os_version.map_or(String::new(), |v| format!(" at version {v}"))
            );
        }
        return Ok(());
    }

    match mode {
        OutputMode::Json => {
            let json_keys: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| {
                    json!({
                        "key": k.key,
                        "title": k.title,
                        "description": k.description,
                        "platform": k.platform,
                        "introduced": k.introduced,
                        "deprecated": k.deprecated,
                        "removed": k.removed,
                        "always_skippable": k.always_skippable,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_keys)?);
        }
        OutputMode::Human => {
            println!(
                "\n{} skip keys for {} {}",
                keys.len().to_string().bold(),
                platform.bold(),
                os_version.map_or(String::new(), |v| format!("(>= {v})"))
            );
            println!(
                "{:<25} {:<30} {:<12} {:<12}",
                "Key".bold(),
                "Title".bold(),
                "Introduced".bold(),
                "Deprecated".bold()
            );
            println!("{}", "-".repeat(79));
            for k in &keys {
                println!(
                    "{:<25} {:<30} {:<12} {:<12}",
                    k.key,
                    truncate(&k.title, 28),
                    k.introduced.as_deref().unwrap_or("-"),
                    k.deprecated.as_deref().unwrap_or("-"),
                );
            }
        }
    }

    Ok(())
}

/// Handle the `enrollment generate` subcommand.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI handler mirrors the many flags available"
)]
pub fn handle_enrollment_generate(
    platform: &str,
    os_version: Option<&str>,
    skip_all: bool,
    skip: &[String],
    skip_list_path: Option<&Path>,
    output: Option<&str>,
    profile_name: &str,
    interactive: bool,
    beta: bool,
    preset: Option<&str>,
    language: Option<&str>,
    region: Option<&str>,
    readme: bool,
    mode: OutputMode,
) -> Result<()> {
    // Interactive mode is a guided wizard (platform → version → language → keep).
    if interactive {
        return run_enrollment_wizard(beta, output, readme, mode);
    }

    // Load skip-list file first so its fields can supply defaults.
    let skip_list = skip_list_path.map(parse_skip_list_file).transpose()?;

    // Resolve scalars: CLI > file > caller-passed default.
    let platform_owned: String;
    let resolved_platform: &str = match skip_list.as_ref().and_then(|s| s.platform.as_deref()) {
        Some(p) if platform == "macOS" => {
            // platform CLI flag has a clap default of "macOS"; treat that as
            // "not explicitly set" so the file can override it.
            platform_owned = p.to_string();
            &platform_owned
        }
        _ => platform,
    };
    let os_version_owned: Option<String>;
    let resolved_os_version: Option<&str> = if os_version.is_some() {
        os_version
    } else {
        os_version_owned = skip_list.as_ref().and_then(|s| s.os_version.clone());
        os_version_owned.as_deref()
    };
    let profile_name_owned: String;
    let resolved_profile_name: &str =
        if profile_name == "Automatic enrollment profile" && skip_list.is_some() {
            // CLI default; let the file override if it set one.
            match skip_list.as_ref().and_then(|s| s.profile_name.clone()) {
                Some(n) => {
                    profile_name_owned = n;
                    &profile_name_owned
                }
                None => profile_name,
            }
        } else {
            profile_name
        };

    // A preset overrides the target platform and supplies the ADE envelope
    // flags + the keep-set (panes left unskipped); everything else is skipped.
    let preset_def = match preset {
        Some(name) => Some(find_preset(name).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown enrollment preset '{name}'. Run `contour profile enrollment presets` to list them."
            )
        })?),
        None => None,
    };
    let resolved_platform: &str = preset_def.map_or(resolved_platform, |p| p.platform);
    let env = match preset_def {
        Some(p) => Envelope {
            auto_advance_setup: p.auto_advance_setup,
            is_supervised: p.is_supervised,
            is_mdm_removable: p.is_mdm_removable,
            allow_pairing: p.allow_pairing,
        },
        None => Envelope::default(),
    };

    let available_keys = load_skip_keys(resolved_platform, resolved_os_version, beta)?;

    if available_keys.is_empty() {
        anyhow::bail!(
            "No skip keys found for platform '{resolved_platform}'{}",
            resolved_os_version.map_or(String::new(), |v| format!(" at version {v}"))
        );
    }

    let mut selected_keys: Vec<String> = if let Some(p) = preset_def {
        // Skip every available pane except the preset's keep-set and the
        // NEVER_SKIP guardrail panes.
        available_keys
            .iter()
            .map(|k| k.key.as_str())
            .filter(|k| !p.keep.contains(k) && !NEVER_SKIP.contains(k))
            .map(str::to_string)
            .collect()
    } else if skip_all {
        available_keys.iter().map(|k| k.key.clone()).collect()
    } else if skip_list.is_some() || !skip.is_empty() {
        // Union of file's `skip` and `--skip` CLI args. Dedup preserves first-seen order.
        let mut combined: Vec<String> = skip_list
            .as_ref()
            .map(|s| s.skip.clone())
            .unwrap_or_default();
        for k in skip {
            if !combined.contains(k) {
                combined.push(k.clone());
            }
        }
        // Validate every key against the available set for the platform/OS.
        for requested in &combined {
            if !available_keys.iter().any(|k| k.key == *requested) {
                anyhow::bail!(
                    "Unknown skip key '{requested}' for platform '{resolved_platform}'. \
                     Use 'enrollment list --platform {resolved_platform}' to see available keys."
                );
            }
        }
        combined
    } else {
        anyhow::bail!(
            "Specify --preset NAME, --skip-all, --skip KEY1,KEY2, --skip-list <PATH>, or --interactive to select skip keys."
        );
    };

    // NEVER_SKIP guardrail — refuse to emit FileVault or SoftwareUpdate.
    // Applied to the final, post-merge selection regardless of source.
    let forbidden: Vec<&String> = selected_keys
        .iter()
        .filter(|k| NEVER_SKIP.contains(&k.as_str()))
        .collect();
    if !forbidden.is_empty() {
        let names: Vec<&str> = forbidden.iter().map(|s| s.as_str()).collect();
        anyhow::bail!(
            "Refusing to generate enrollment profile: {} must not appear in skip_setup_items \
             (NEVER_SKIP guardrail). Remove these from your skip list or --skip flag.",
            names.join(", ")
        );
    }

    // Dedup any user-supplied dupes while preserving order. Cheap and harmless.
    let mut seen = std::collections::HashSet::new();
    selected_keys.retain(|k| seen.insert(k.clone()));

    // Language fast-preset: --language pairs to a default region (en→US,
    // de→DE, fr→FR, es→ES); an explicit --region overrides. Region is
    // upper-cased for ISO-3166.
    let language = language.unwrap_or("en");
    let region_owned = region
        .map(str::to_uppercase)
        .unwrap_or_else(|| default_region_for(language).to_string());
    let region = region_owned.as_str();

    let profile = build_enrollment_profile(
        resolved_profile_name,
        &selected_keys,
        &env,
        language,
        region,
    );

    let json_output = serde_json::to_string_pretty(&profile)?;

    if let Some(path) = output {
        let mut file = std::fs::File::create(path)
            .with_context(|| format!("Failed to create output file: {path}"))?;
        file.write_all(json_output.as_bytes())?;
        file.write_all(b"\n")?;

        if mode == OutputMode::Human {
            println!(
                "{} Wrote enrollment profile to {}",
                "OK".green().bold(),
                path.bold()
            );
            println!(
                "   {} skip keys selected for {}",
                selected_keys.len().to_string().bold(),
                resolved_platform.bold()
            );
        }

        // Companion docs sidecar.
        if readme {
            let md = write_skip_readme(
                path,
                resolved_profile_name,
                resolved_platform,
                language,
                region,
                &selected_keys,
                &available_keys,
            )?;
            if mode == OutputMode::Human {
                println!("   {} {}", "Docs:".bold(), md.display());
            }
        }
    } else if mode == OutputMode::Human {
        println!("{json_output}");
    }

    if mode == OutputMode::Json {
        let result = json!({
            "success": true,
            "profile_name": resolved_profile_name,
            "platform": resolved_platform,
            "os_version": resolved_os_version,
            "skip_setup_items": selected_keys,
            "skip_count": selected_keys.len(),
            "available_count": available_keys.len(),
            "output_file": output,
            "profile": profile,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Build the DEP enrollment profile JSON structure.
fn build_enrollment_profile(
    profile_name: &str,
    skip_keys: &[String],
    env: &Envelope,
    language: &str,
    region: &str,
) -> serde_json::Value {
    json!({
        "profile_name": profile_name,
        "allow_pairing": env.allow_pairing,
        "auto_advance_setup": env.auto_advance_setup,
        "is_supervised": env.is_supervised,
        "is_mdm_removable": env.is_mdm_removable,
        "org_magic": "1",
        "language": language,
        "region": region,
        "skip_setup_items": skip_keys,
    })
}

/// Truncate a string to a given width, adding ellipsis if needed.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readme_sidecar_lists_keys_and_apple_refs() {
        fn key(k: &str, title: &str) -> SkipKey {
            SkipKey {
                key: k.to_string(),
                title: title.to_string(),
                description: None,
                platform: "macOS".to_string(),
                introduced: None,
                deprecated: None,
                removed: None,
                always_skippable: None,
            }
        }
        let available = vec![key("Siri", "Disables Siri"), key("Biometric", "Touch ID")];
        let selected = vec!["Siri".to_string()];
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("p.json");
        let md = write_skip_readme(
            json.to_str().unwrap(),
            "Test Profile",
            "macOS",
            "de",
            "DE",
            &selected,
            &available,
        )
        .unwrap();
        assert_eq!(md, dir.path().join("p.md"));
        let text = std::fs::read_to_string(&md).unwrap();
        assert!(text.contains("`Siri`") && text.contains("Disables Siri"));
        // Biometric is kept (not a skipped table row); it only appears in the
        // prose note, so it must not be listed as a `backtick`-wrapped key.
        assert!(!text.contains("`Biometric`"));
        assert!(text.contains("devicemanagement/profile"));
        assert!(text.contains("devicemanagement/skipkeys"));
    }

    #[test]
    fn language_fast_presets_pair_regions() {
        assert_eq!(default_region_for("de"), "DE");
        assert_eq!(default_region_for("fr"), "FR");
        assert_eq!(default_region_for("es"), "ES");
        assert_eq!(default_region_for("en"), "US");
        assert_eq!(default_region_for("DE"), "DE"); // case-insensitive
        assert_eq!(default_region_for("zz"), "US"); // unknown → US
    }

    #[test]
    fn version_compare_is_numeric_not_lexical() {
        assert!(version_le("15.0", "26.0"));
        assert!(version_le("9.0", "10.0")); // lexical would say false
        assert!(version_le("26.0", "26.0")); // equal
        assert!(!version_le("26.1", "26.0"));
        assert!(version_le("10.13.4", "10.14"));
        assert!(!version_le("27.0", "26.0"));
    }

    #[test]
    fn preset_keep_set_excludes_biometric_and_location() {
        let p = find_preset("auto-advance").unwrap();
        assert_eq!(p.platform, "macOS");
        assert!(p.auto_advance_setup);
        assert!(p.keep.contains(&"Biometric"));
        assert!(p.keep.contains(&"Location"));
        assert!(find_preset("shared-ipad").unwrap().platform == "iOS");
        assert!(find_preset("nope").is_none());
    }

    #[test]
    fn parse_skip_list_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("skip-list.toml");
        std::fs::write(
            &path,
            r#"
version = 1
platform = "iOS"
os_version = "18.0"
profile_name = "Acme Onboarding"
skip = ["Appearance", "Siri", "Diagnostics"]
"#,
        )
        .unwrap();

        let file = parse_skip_list_file(&path).unwrap();
        assert_eq!(file.version, 1);
        assert_eq!(file.platform.as_deref(), Some("iOS"));
        assert_eq!(file.os_version.as_deref(), Some("18.0"));
        assert_eq!(file.profile_name.as_deref(), Some("Acme Onboarding"));
        assert_eq!(file.skip, vec!["Appearance", "Siri", "Diagnostics"]);
    }

    #[test]
    fn parse_skip_list_minimal_defaults_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("skip-list.toml");
        std::fs::write(&path, r#"skip = ["Siri"]"#).unwrap();

        let file = parse_skip_list_file(&path).unwrap();
        assert_eq!(file.version, 1);
        assert!(file.platform.is_none());
        assert!(file.os_version.is_none());
        assert!(file.profile_name.is_none());
        assert_eq!(file.skip, vec!["Siri"]);
    }

    #[test]
    fn never_skip_constant_covers_filevault_and_softwareupdate() {
        assert!(NEVER_SKIP.contains(&"FileVault"));
        assert!(NEVER_SKIP.contains(&"SoftwareUpdate"));
    }

    #[test]
    fn never_skip_rejected_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(
            &path,
            r#"
platform = "macOS"
skip = ["Siri", "FileVault"]
"#,
        )
        .unwrap();

        let err = handle_enrollment_generate(
            "macOS",
            None,
            false,
            &[],
            Some(&path),
            None,
            "Automatic enrollment profile",
            false,
            false,
            None,
            None,
            None,
            false,
            OutputMode::Json,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("FileVault") && msg.contains("NEVER_SKIP"),
            "expected NEVER_SKIP rejection mentioning FileVault, got: {msg}"
        );
    }

    #[test]
    fn never_skip_rejected_from_cli_skip_flag() {
        let err = handle_enrollment_generate(
            "macOS",
            None,
            false,
            &["SoftwareUpdate".to_string()],
            None,
            None,
            "Automatic enrollment profile",
            false,
            false,
            None,
            None,
            None,
            false,
            OutputMode::Json,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("SoftwareUpdate") && msg.contains("NEVER_SKIP"));
    }
}
