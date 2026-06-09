//! `santa app-settings` — generate a `com.apple.configuration.app.settings`
//! declaration from a scan, or convert existing Santa rules into one.
//!
//! Binary execution control on macOS 27 is enforced by Endpoint Security:
//! `DeniedBinaries` not only blocks launch but terminates running processes of
//! the matched binary. The command warns when it emits deny entries.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::app_settings::{
    AppIdentifier, AppSettings, BinaryIdentifier, BinaryPolicy, PermissionDefault, build,
    from_permission_policy, map, partition_binaries, scaffold_policy,
    validate::{permission_ios_na, permission_macos_na, validate_permission_default},
};
use crate::cli::scan::read_scan_csvs;
use crate::cli::{ScanRuleType, TargetPlatform};
use crate::output::{print_info, print_success, print_warning};
use crate::parser::parse_files;

/// Collected binary entries paired with reasons for any skipped inputs.
type CollectedBinaries = (Vec<(BinaryIdentifier, BinaryPolicy)>, Vec<String>);

/// App bundle-ID list entries (`AllowedApps`/`DeniedApps`).
type AppEntries = Vec<(AppIdentifier, BinaryPolicy)>;

/// What the binary input is.
#[derive(Debug, Clone, Copy)]
enum Source {
    /// Santa rule files to convert (policy carried per rule).
    Rules,
    /// Scan CSV files (one policy applied to all).
    Scan,
}

#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn run(
    input: &[PathBuf],
    from_rules: bool,
    permissions: Option<&Path>,
    scaffold: bool,
    always_allow_managed: bool,
    rule_type: ScanRuleType,
    platform: TargetPlatform,
    deny: bool,
    org: &str,
    strict: bool,
    output: Option<&Path>,
    json_output: bool,
) -> Result<()> {
    let source = if from_rules {
        Source::Rules
    } else {
        Source::Scan
    };

    // --scaffold short-circuits: emit an editable Privacy policy from a scan.
    if scaffold {
        return run_scaffold(input, source, output, json_output);
    }

    let org = resolve_org(org)?;
    let default_policy = if deny {
        BinaryPolicy::Deny
    } else {
        BinaryPolicy::Allow
    };

    // 1. Collect binary + app entries from the source, gated by the target
    //    platform (macOS → binaries, iOS/tvOS/visionOS → app bundle IDs).
    let mut app_entries: AppEntries = Vec::new();
    let (raw_binaries, skipped) = match source {
        Source::Rules => {
            if platform.includes_apps() && !platform.includes_binaries() {
                print_warning(
                    "Santa rules carry no bundle IDs — AllowedApps/DeniedApps need a scan CSV",
                );
            }
            if platform.includes_binaries() {
                collect_from_rules(input)?
            } else {
                (Vec::new(), Vec::new())
            }
        }
        Source::Scan => {
            let apps = read_scan_csvs(input)?;
            let mut binaries = Vec::new();
            let mut skipped = Vec::new();
            if platform.includes_binaries() {
                for app in &apps {
                    match map::from_scanned_app(app, rule_type, default_policy) {
                        Some(entry) => binaries.push(entry),
                        None => {
                            skipped.push(format!("{}: no usable code-signing identifier", app.name))
                        }
                    }
                }
            }
            if platform.includes_apps() {
                app_entries.extend(
                    apps.iter()
                        .filter_map(|app| map::app_from_scanned(app, default_policy)),
                );
            }
            (binaries, skipped)
        }
    };

    if strict && !skipped.is_empty() {
        for s in &skipped {
            print_warning(s);
        }
        bail!(
            "{} input entr(ies) could not be converted (--strict)",
            skipped.len()
        );
    }

    // 2. Validate against the schema's notes rules.
    let (binaries, violations) = partition_binaries(raw_binaries);
    if !violations.is_empty() {
        if strict {
            for v in &violations {
                print_warning(&format!("{}: {}", v.entry, v.reason));
            }
            bail!(
                "{} entr(ies) failed schema validation (--strict)",
                violations.len()
            );
        } else if !json_output {
            print_info(&format!(
                "Dropped {} entr(ies) failing the schema's identifier rules",
                violations.len()
            ));
        }
    }

    // 3. Privacy permission defaults from an authored policy file (optional),
    //    with permissions gated to those the target platform supports.
    let privacy = match permissions {
        Some(path) if platform.includes_privacy() => {
            let mut defaults = from_permission_policy(path)?;
            for pd in &mut defaults {
                gate_permissions(pd, platform);
            }
            for pd in &defaults {
                validate_permission_default(pd)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", pd.app_identifier))?;
            }
            defaults
        }
        Some(_) => {
            print_warning(
                "Privacy is not available on the selected platform — ignoring --permissions",
            );
            Vec::new()
        }
        None => Vec::new(),
    };

    // 4. Assemble + write.
    let settings = AppSettings {
        binaries,
        apps: app_entries,
        privacy,
        always_allow_managed,
    };
    if settings.is_empty() {
        bail!("nothing to emit — no valid binaries, apps, or privacy defaults");
    }

    let deny_count = settings
        .binaries
        .iter()
        .filter(|(_, p)| *p == BinaryPolicy::Deny)
        .count();

    let declaration = settings.to_declaration(&org, "santa");
    let out_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("app-settings.json"));
    std::fs::write(&out_path, serde_json::to_string_pretty(&declaration)?)
        .with_context(|| format!("writing {}", out_path.display()))?;

    if !json_output {
        print_success(&format!(
            "Wrote {} ({} binaries, {} privacy default(s))",
            out_path.display(),
            settings.binaries.len(),
            settings.privacy.len()
        ));
        if deny_count > 0 {
            print_warning(&format!(
                "{deny_count} DeniedBinaries entr(ies): Endpoint Security terminates running \
                 processes of denied binaries, not just future launches"
            ));
        }
        print_info(&format!(
            "Validate: contour profile ddm validate --beta {}",
            out_path.display()
        ));
    }

    Ok(())
}

/// Emit an editable Privacy policy skeleton (TOML) from scan input.
fn run_scaffold(
    input: &[PathBuf],
    source: Source,
    output: Option<&Path>,
    json_output: bool,
) -> Result<()> {
    if matches!(source, Source::Rules) {
        bail!("--scaffold needs a scan CSV (app inventory), not Santa rules");
    }
    let apps = read_scan_csvs(input)?;
    let policy = scaffold_policy(&apps);
    let out_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("app-permissions.toml"));
    std::fs::write(&out_path, policy.to_toml()?)
        .with_context(|| format!("writing {}", out_path.display()))?;
    if !json_output {
        print_success(&format!(
            "Wrote Privacy policy skeleton: {} ({} app(s))",
            out_path.display(),
            policy.app.len()
        ));
        print_info("Edit justifications + permissions, then pass via --permissions.");
    }
    Ok(())
}

/// Convert Santa rule files into binary entries (policy per rule).
fn collect_from_rules(input: &[PathBuf]) -> Result<CollectedBinaries> {
    let rules = parse_files(input)?;
    let mut binaries = Vec::new();
    let mut skipped = Vec::new();
    for rule in rules.rules() {
        match map::from_santa_rule(rule) {
            Ok(entry) => binaries.push(entry),
            Err(reason) => skipped.push(format!("{}: {reason}", rule.identifier)),
        }
    }
    Ok((binaries, skipped))
}

/// Drop permission keys that are `n/a` on the target platform (no-op for
/// `Combined`, which lets each platform ignore keys that don't apply).
fn gate_permissions(pd: &mut PermissionDefault, platform: TargetPlatform) {
    pd.permissions.retain(|perm, _| match platform {
        TargetPlatform::Macos => !permission_macos_na(*perm),
        TargetPlatform::Ios => !permission_ios_na(*perm),
        _ => true,
    });
}

/// Resolve the org domain: `--org` flag → `CONTOUR_ORG` env → error.
/// Never falls back to `com.example`.
fn resolve_org(flag: &str) -> Result<String> {
    if !flag.is_empty() && flag != "com.example" {
        return Ok(flag.to_string());
    }
    if let Ok(env) = std::env::var("CONTOUR_ORG") {
        if !env.is_empty() {
            return Ok(env);
        }
    }
    bail!("organization domain required — pass --org <domain> or set CONTOUR_ORG")
}

// Reference build constants so a rename keeps this module in sync.
const _: &str = build::APP_SETTINGS_TYPE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_settings::Permission;
    use std::collections::BTreeMap;

    fn pd(perms: &[(Permission, &str)]) -> PermissionDefault {
        PermissionDefault {
            app_identifier: "com.x".to_string(),
            organization_justification: "j".to_string(),
            permissions: perms
                .iter()
                .map(|(p, v)| (*p, v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn platform_inclusion_flags() {
        assert!(TargetPlatform::Macos.includes_binaries());
        assert!(!TargetPlatform::Macos.includes_apps());
        assert!(TargetPlatform::Ios.includes_apps());
        assert!(!TargetPlatform::Ios.includes_binaries());
        assert!(TargetPlatform::Combined.includes_binaries());
        assert!(TargetPlatform::Combined.includes_apps());
        assert!(TargetPlatform::Macos.includes_privacy());
        assert!(!TargetPlatform::Tvos.includes_privacy());
    }

    #[test]
    fn macos_gating_drops_location_accuracy_keeps_accessibility() {
        let mut p = pd(&[
            (Permission::LocationAccuracy, "Precise"),
            (Permission::Accessibility, "Allow"),
            (Permission::Camera, "Allow"),
        ]);
        gate_permissions(&mut p, TargetPlatform::Macos);
        assert!(!p.permissions.contains_key(&Permission::LocationAccuracy));
        assert!(p.permissions.contains_key(&Permission::Accessibility));
        assert!(p.permissions.contains_key(&Permission::Camera));
    }

    #[test]
    fn ios_gating_drops_accessibility_keeps_location_accuracy() {
        let mut p = pd(&[
            (Permission::Accessibility, "Allow"),
            (Permission::LocationAccuracy, "Precise"),
        ]);
        gate_permissions(&mut p, TargetPlatform::Ios);
        assert!(!p.permissions.contains_key(&Permission::Accessibility));
        assert!(p.permissions.contains_key(&Permission::LocationAccuracy));
    }

    #[test]
    fn combined_gating_keeps_everything() {
        let mut p = pd(&[
            (Permission::Accessibility, "Allow"),
            (Permission::LocationAccuracy, "Precise"),
        ]);
        gate_permissions(&mut p, TargetPlatform::Combined);
        assert_eq!(p.permissions.len(), 2);
    }
}
