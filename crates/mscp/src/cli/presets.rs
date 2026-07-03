//! Built-in mSCP compliance presets.
//!
//! Friendly, memorable names (`nist-high`, `cmmc2`, `cui`) that expand to a
//! baseline keyword plus its target platform, so generating a compliance
//! baseline is a one-liner. Mirrors the profile enrollment presets pattern.
//!
//! Raw baseline keywords (e.g. `800-53r5_high`) keep working everywhere —
//! both via `--keyword` and via `--preset` (a non-preset value is passed
//! through unchanged).

use crate::cli::OsArg;
use anyhow::{Result, bail};
use colored::Colorize;
use contour_core::output::OutputMode;

/// A built-in preset: a friendly name mapping to one mSCP baseline keyword and
/// the platform it targets.
#[derive(Debug)]
pub struct MscpPreset {
    /// Friendly preset name, used with `--preset`.
    pub name: &'static str,
    /// The compliance framework this preset covers.
    pub framework: &'static str,
    /// The mSCP baseline keyword this preset expands to.
    pub keyword: &'static str,
    /// Target platform for the generated baseline.
    pub os: OsArg,
    /// One-line description.
    pub description: &'static str,
}

/// The built-in presets, grouped by framework. Keywords match the mSCP 2.0
/// tag/benchmark names on the `main` branch.
pub const PRESETS: &[MscpPreset] = &[
    // NIST SP 800-53 Rev 5
    MscpPreset {
        name: "nist-high",
        framework: "NIST 800-53 Rev 5",
        keyword: "800-53r5_high",
        os: OsArg::Macos,
        description: "NIST SP 800-53 Rev 5 — High baseline.",
    },
    MscpPreset {
        name: "nist-moderate",
        framework: "NIST 800-53 Rev 5",
        keyword: "800-53r5_moderate",
        os: OsArg::Macos,
        description: "NIST SP 800-53 Rev 5 — Moderate baseline.",
    },
    MscpPreset {
        name: "nist-low",
        framework: "NIST 800-53 Rev 5",
        keyword: "800-53r5_low",
        os: OsArg::Macos,
        description: "NIST SP 800-53 Rev 5 — Low baseline.",
    },
    MscpPreset {
        name: "nist-privacy",
        framework: "NIST 800-53 Rev 5",
        keyword: "800-53r5_privacy",
        os: OsArg::Macos,
        description: "NIST SP 800-53 Rev 5 — Privacy overlay.",
    },
    // NIST SP 800-171
    MscpPreset {
        name: "cui",
        framework: "NIST 800-171",
        keyword: "800-171",
        os: OsArg::Macos,
        description: "NIST SP 800-171 — protecting Controlled Unclassified Information.",
    },
    // CMMC 2.0
    MscpPreset {
        name: "cmmc1",
        framework: "CMMC 2.0",
        keyword: "cmmc_lvl1",
        os: OsArg::Macos,
        description: "CMMC 2.0 — Level 1 (Foundational).",
    },
    MscpPreset {
        name: "cmmc2",
        framework: "CMMC 2.0",
        keyword: "cmmc_lvl2",
        os: OsArg::Macos,
        description: "CMMC 2.0 — Level 2 (Advanced).",
    },
    // DISA STIG
    MscpPreset {
        name: "stig",
        framework: "DISA STIG",
        keyword: "disa_stig",
        os: OsArg::Macos,
        description: "DISA STIG — macOS.",
    },
    MscpPreset {
        name: "ios-stig",
        framework: "DISA STIG",
        keyword: "ios_stig",
        os: OsArg::Ios,
        description: "DISA STIG — iOS.",
    },
    // CIS Benchmarks — macOS
    MscpPreset {
        name: "cis1",
        framework: "CIS Benchmark (macOS)",
        keyword: "cis_lvl1",
        os: OsArg::Macos,
        description: "CIS Benchmark — macOS Level 1.",
    },
    MscpPreset {
        name: "cis2",
        framework: "CIS Benchmark (macOS)",
        keyword: "cis_lvl2",
        os: OsArg::Macos,
        description: "CIS Benchmark — macOS Level 2.",
    },
    // CIS Benchmarks — iOS
    MscpPreset {
        name: "cis1-byod",
        framework: "CIS Benchmark (iOS)",
        keyword: "cis_lvl1_byod",
        os: OsArg::Ios,
        description: "CIS Benchmark — iOS Level 1 (BYOD).",
    },
    MscpPreset {
        name: "cis2-byod",
        framework: "CIS Benchmark (iOS)",
        keyword: "cis_lvl2_byod",
        os: OsArg::Ios,
        description: "CIS Benchmark — iOS Level 2 (BYOD).",
    },
    MscpPreset {
        name: "cis1-enterprise",
        framework: "CIS Benchmark (iOS)",
        keyword: "cis_lvl1_enterprise",
        os: OsArg::Ios,
        description: "CIS Benchmark — iOS Level 1 (Enterprise).",
    },
    MscpPreset {
        name: "cis2-enterprise",
        framework: "CIS Benchmark (iOS)",
        keyword: "cis_lvl2_enterprise",
        os: OsArg::Ios,
        description: "CIS Benchmark — iOS Level 2 (Enterprise).",
    },
    // CIS Controls v8
    MscpPreset {
        name: "cis-controls",
        framework: "CIS Controls v8",
        keyword: "cisv8",
        os: OsArg::Macos,
        description: "CIS Controls v8.",
    },
    // CNSSI-1253
    MscpPreset {
        name: "cnssi-high",
        framework: "CNSSI-1253",
        keyword: "cnssi-1253_high",
        os: OsArg::Macos,
        description: "CNSSI-1253 — High.",
    },
    MscpPreset {
        name: "cnssi-moderate",
        framework: "CNSSI-1253",
        keyword: "cnssi-1253_moderate",
        os: OsArg::Macos,
        description: "CNSSI-1253 — Moderate.",
    },
    MscpPreset {
        name: "cnssi-low",
        framework: "CNSSI-1253",
        keyword: "cnssi-1253_low",
        os: OsArg::Macos,
        description: "CNSSI-1253 — Low.",
    },
];

/// Look up a preset by exact name.
pub fn find_preset(name: &str) -> Option<&'static MscpPreset> {
    PRESETS.iter().find(|p| p.name == name)
}

/// Resolve the effective baseline keyword + OS target from the mutually
/// exclusive `--preset` / `--keyword` inputs (clap guarantees exactly one is
/// set on `generate`).
///
/// A `--preset` value that isn't a built-in name is passed through as a raw
/// baseline keyword, keeping the supplied `os` — so tech names like
/// `800-53r5_high` work with `--preset` too.
pub fn resolve(
    preset: Option<&str>,
    keyword: Option<String>,
    os: OsArg,
) -> Result<(String, OsArg)> {
    match (preset, keyword) {
        (Some(p), _) => match find_preset(p) {
            Some(entry) => Ok((entry.keyword.to_string(), entry.os)),
            None => Ok((p.to_string(), os)),
        },
        (None, Some(k)) => Ok((k, os)),
        (None, None) => bail!(
            "provide a baseline: --keyword <name> or --preset <name> \
             (see `contour mscp presets`)"
        ),
    }
}

/// Human-readable platform label for an [`OsArg`].
fn os_label(os: OsArg) -> &'static str {
    match os {
        OsArg::Macos => "macOS",
        OsArg::Ios => "iOS",
        OsArg::Visionos => "visionOS",
    }
}

/// Handle `mscp presets` — list the built-in compliance presets.
pub fn handle_presets(mode: OutputMode) -> Result<()> {
    if mode == OutputMode::Json {
        let rows: Vec<_> = PRESETS
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "framework": p.framework,
                    "keyword": p.keyword,
                    "platform": os_label(p.os),
                    "description": p.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    println!("{}\n", "mSCP compliance presets".bold());
    let mut current_framework = "";
    for p in PRESETS {
        if p.framework != current_framework {
            println!("{}", p.framework.bold().underline());
            current_framework = p.framework;
        }
        println!(
            "  {:<16} {}  →  {}",
            p.name.green().bold(),
            format!("[{}]", os_label(p.os)).dimmed(),
            p.keyword.cyan()
        );
        println!("    {}", p.description.dimmed());
    }
    println!(
        "\n{}",
        "Generate one: contour mscp generate --preset <name> -m ./macos_security -o ./out".dimmed()
    );
    println!(
        "{}",
        "Tech names work too: --preset 800-53r5_high  (or -k 800-53r5_high)".dimmed()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_preset_hits_known_and_misses_unknown() {
        assert_eq!(find_preset("cmmc2").unwrap().keyword, "cmmc_lvl2");
        assert!(find_preset("nope").is_none());
    }

    #[test]
    fn resolve_expands_friendly_preset_to_keyword_and_platform() {
        let (kw, os) = resolve(Some("nist-high"), None, OsArg::Macos).unwrap();
        assert_eq!(kw, "800-53r5_high");
        assert_eq!(os, OsArg::Macos);

        let (kw, os) = resolve(Some("ios-stig"), None, OsArg::Macos).unwrap();
        assert_eq!(kw, "ios_stig");
        assert_eq!(os, OsArg::Ios, "preset overrides platform");
    }

    #[test]
    fn resolve_passes_through_raw_tech_name_via_preset() {
        // A raw baseline keyword handed to --preset is used verbatim, keeping os.
        let (kw, os) = resolve(Some("800-53r5_high"), None, OsArg::Macos).unwrap();
        assert_eq!(kw, "800-53r5_high");
        assert_eq!(os, OsArg::Macos);
    }

    #[test]
    fn resolve_uses_keyword_when_no_preset() {
        let (kw, os) = resolve(None, Some("cis_lvl1".to_string()), OsArg::Ios).unwrap();
        assert_eq!(kw, "cis_lvl1");
        assert_eq!(os, OsArg::Ios);
    }

    #[test]
    fn resolve_errors_when_neither_given() {
        resolve(None, None, OsArg::Macos).unwrap_err();
    }

    #[test]
    fn preset_names_are_unique_and_keywords_nonempty() {
        let mut names: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "preset names must be unique");
        assert!(PRESETS.iter().all(|p| !p.keyword.is_empty()));
        // The user's go-to baselines must be reachable by preset.
        for kw in ["800-171", "800-53r5_high", "cmmc_lvl2"] {
            assert!(
                PRESETS.iter().any(|p| p.keyword == kw),
                "missing go-to keyword: {kw}"
            );
        }
    }
}
