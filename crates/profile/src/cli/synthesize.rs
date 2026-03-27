//! Synthesize mobileconfig profiles from managed preference plists.
//!
//! Reads bare `.plist` files (as found in `/Library/Managed Preferences/`),
//! matches each against the embedded Apple schema, validates keys, and
//! produces proper `.mobileconfig` profiles via `ProfileBuilder`.

use crate::cli::generate::load_registry;
use crate::output::OutputMode;
use crate::schema::{FieldType, PayloadManifest, SchemaRegistry};
use anyhow::{Context, Result};
use colored::Colorize;
use contour_profiles::ProfileBuilder;
use inquire::MultiSelect;
use plist::{Dictionary, Value};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Management metadata keys that should be stripped from bare plists
/// before wrapping into a mobileconfig payload.
const MANAGEMENT_KEYS: &[&str] = &[
    "PayloadUUID",
    "PayloadIdentifier",
    "PayloadType",
    "PayloadVersion",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
    "PayloadScope",
    "PayloadRemovalDisallowed",
    "PayloadContent",
    "PayloadEnabled",
];

// ── Data structures ──────────────────────────────────────────────────

/// A discovered plist file with its parsed content and schema match info.
#[derive(Debug)]
struct DiscoveredPlist {
    domain: String,
    dict: Dictionary,
    schema_matched: bool,
    title: String,
}

/// Validation diagnostic for a single key.
#[derive(Debug, Clone)]
struct KeyDiagnostic {
    key: String,
    kind: DiagnosticKind,
    message: String,
}

#[derive(Debug, Clone)]
enum DiagnosticKind {
    TypeMismatch,
    DidYouMean,
    UnknownKey,
}

/// Result of synthesizing one plist into a mobileconfig.
#[derive(Debug)]
struct SynthesizeResult {
    domain: String,
    title: String,
    schema_matched: bool,
    key_count: usize,
    unknown_keys: Vec<String>,
    type_mismatches: Vec<String>,
    output_path: Option<PathBuf>,
}

// ── Main entry point ─────────────────────────────────────────────────

pub fn handle_synthesize(
    paths: &[PathBuf],
    output: Option<&Path>,
    org: Option<&str>,
    validate: bool,
    dry_run: bool,
    interactive: bool,
    mode: OutputMode,
) -> Result<()> {
    let registry = load_registry(None)?;

    // Phase 1: Discover plist files
    let mut discovered = Vec::new();
    for path in paths {
        if path.is_dir() {
            discover_plists_in_dir(path, &registry, &mut discovered)?;
        } else if path.is_file() {
            if let Some(d) = parse_single_plist(path, &registry)? {
                discovered.push(d);
            }
        } else if mode == OutputMode::Human {
            eprintln!(
                "  {} Skipping non-existent path: {}",
                "!".yellow(),
                path.display()
            );
        }
    }

    if discovered.is_empty() {
        if mode == OutputMode::Json {
            println!("[]");
        } else {
            println!("{}", "No .plist files found.".yellow());
        }
        return Ok(());
    }

    // Phase 2: Show discovery summary (human mode)
    if mode == OutputMode::Human {
        println!();
        println!("{}", "=".repeat(66));
        println!(
            "{}",
            "  Profile Synthesize — Managed Preference Converter"
                .bold()
                .cyan()
        );
        println!("{}", "=".repeat(66));
        println!();
        let matched = discovered.iter().filter(|d| d.schema_matched).count();
        let unmatched = discovered.len() - matched;
        println!("{}", "Discovery:".bold());
        println!(
            "  {} .plist files found",
            discovered.len().to_string().green()
        );
        println!("  {} matched to Apple schema", matched.to_string().green());
        if unmatched > 0 {
            println!(
                "  {} unmatched (will still generate)",
                unmatched.to_string().yellow()
            );
        }
        println!();
    }

    // Phase 3: Interactive selection (if requested)
    let selected: Vec<&DiscoveredPlist> = if interactive && mode == OutputMode::Human {
        let options: Vec<String> = discovered
            .iter()
            .map(|d| {
                let status = if d.schema_matched {
                    "matched".green().to_string()
                } else {
                    "unmatched".yellow().to_string()
                };
                format!(
                    "{} — {} ({}, {} keys)",
                    d.domain,
                    d.title,
                    status,
                    d.dict.len()
                )
            })
            .collect();

        let defaults: Vec<usize> = (0..options.len()).collect();
        let selected_labels = MultiSelect::new(
            "Select plists to synthesize (Space to toggle, Enter to confirm):",
            options.clone(),
        )
        .with_page_size(20)
        .with_default(&defaults)
        .with_help_message("All pre-selected. Deselect any you don't want.")
        .prompt()?;

        // Map selections back
        discovered
            .iter()
            .enumerate()
            .filter(|(i, _)| selected_labels.contains(&options[*i]))
            .map(|(_, d)| d)
            .collect()
    } else {
        discovered.iter().collect()
    };

    if selected.is_empty() {
        if mode == OutputMode::Human {
            println!("{}", "No plists selected.".yellow());
        }
        return Ok(());
    }

    let effective_org = org.unwrap_or("com.example");

    // Phase 4: Validate + Build
    let mut results = Vec::new();
    for plist_entry in &selected {
        let diagnostics = if validate {
            validate_keys(&plist_entry.dict, &plist_entry.domain, &registry)
        } else {
            Vec::new()
        };

        let unknown_keys: Vec<String> = diagnostics
            .iter()
            .filter(|d| {
                matches!(
                    d.kind,
                    DiagnosticKind::UnknownKey | DiagnosticKind::DidYouMean
                )
            })
            .map(|d| d.key.clone())
            .collect();

        let type_mismatches: Vec<String> = diagnostics
            .iter()
            .filter(|d| matches!(d.kind, DiagnosticKind::TypeMismatch))
            .map(|d| d.key.clone())
            .collect();

        // Show validation diagnostics in human mode
        if mode == OutputMode::Human && validate && !diagnostics.is_empty() {
            println!(
                "\n{}",
                format!("  Validation: {}", plist_entry.domain).bold()
            );
            for diag in &diagnostics {
                let icon = match diag.kind {
                    DiagnosticKind::TypeMismatch => "!".red(),
                    DiagnosticKind::DidYouMean => "?".yellow(),
                    DiagnosticKind::UnknownKey => "i".cyan(),
                };
                println!("    {} {}", icon, diag.message);
            }
        }

        // Build mobileconfig
        let identifier = format!("{effective_org}.{}", plist_entry.domain);
        let display_name = plist_entry.title.clone();
        let builder = ProfileBuilder::new(effective_org, &identifier).display_name(&display_name);
        let xml = builder.build(&plist_entry.domain, plist_entry.dict.clone())?;

        // Determine output path
        let output_path =
            output.map(|dir| dir.join(format!("{}.mobileconfig", plist_entry.domain)));

        if !dry_run {
            if let Some(ref out_path) = output_path {
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("Failed to create directory: {}", parent.display())
                    })?;
                }
                fs::write(out_path, &xml)
                    .with_context(|| format!("Failed to write: {}", out_path.display()))?;

                if mode == OutputMode::Human {
                    println!(
                        "  {} {} -> {}",
                        "->".green(),
                        plist_entry.domain,
                        out_path.display()
                    );
                }
            } else {
                // No output dir: write to stdout (single file) or CWD
                if selected.len() == 1 {
                    std::io::Write::write_all(&mut std::io::stdout(), &xml)?;
                } else {
                    let filename = format!("{}.mobileconfig", plist_entry.domain);
                    fs::write(&filename, &xml)?;
                    if mode == OutputMode::Human {
                        println!("  {} {} -> {}", "->".green(), plist_entry.domain, filename);
                    }
                }
            }
        } else if mode == OutputMode::Human {
            let target = output_path.as_ref().map_or_else(
                || format!("{}.mobileconfig", plist_entry.domain),
                |p| p.display().to_string(),
            );
            println!(
                "  {} Would create: {} ({} keys)",
                "~".cyan(),
                target,
                plist_entry.dict.len()
            );
        }

        results.push(SynthesizeResult {
            domain: plist_entry.domain.clone(),
            title: plist_entry.title.clone(),
            schema_matched: plist_entry.schema_matched,
            key_count: plist_entry.dict.len(),
            unknown_keys,
            type_mismatches,
            output_path,
        });
    }

    // Phase 5: Output
    if mode == OutputMode::Json {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "domain": r.domain,
                    "title": r.title,
                    "schema_matched": r.schema_matched,
                    "keys": r.key_count,
                    "unknown_keys": r.unknown_keys,
                    "type_mismatches": r.type_mismatches,
                    "output": r.output_path.as_ref().map(|p| p.display().to_string())
                        .unwrap_or_else(|| format!("{}.mobileconfig", r.domain)),
                    "dry_run": dry_run,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_results)?);
    } else if mode == OutputMode::Human {
        println!();
        println!("{}", "Summary".bold());
        println!("{}", "-".repeat(50));
        let ok_count = results.len();
        let matched_count = results.iter().filter(|r| r.schema_matched).count();
        println!(
            "  {} profile(s) {}",
            ok_count.to_string().green(),
            if dry_run {
                "would be created"
            } else {
                "created"
            }
        );
        println!(
            "  {} matched Apple schema",
            matched_count.to_string().green()
        );
        if validate {
            let warn_count: usize = results
                .iter()
                .map(|r| r.unknown_keys.len() + r.type_mismatches.len())
                .sum();
            if warn_count > 0 {
                println!("  {} validation warnings", warn_count.to_string().yellow());
            }
        }
    }

    Ok(())
}

// ── Discovery ────────────────────────────────────────────────────────

fn discover_plists_in_dir(
    dir: &Path,
    registry: &SchemaRegistry,
    out: &mut Vec<DiscoveredPlist>,
) -> Result<()> {
    for entry in WalkDir::new(dir)
        .follow_links(true)
        .max_depth(1)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !ext.eq_ignore_ascii_case("plist") {
            continue;
        }
        if let Some(d) = parse_single_plist(path, registry)? {
            out.push(d);
        }
    }
    // Sort by domain for consistent ordering
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    Ok(())
}

fn parse_single_plist(path: &Path, registry: &SchemaRegistry) -> Result<Option<DiscoveredPlist>> {
    let domain = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();

    if domain.is_empty() {
        return Ok(None);
    }

    let value: Value = plist::from_file(path)
        .with_context(|| format!("Failed to parse plist: {}", path.display()))?;

    let Value::Dictionary(mut dict) = value else {
        // Not a dictionary plist — skip silently
        return Ok(None);
    };

    // Strip management metadata keys
    for key in MANAGEMENT_KEYS {
        dict.remove(key);
    }

    // Match against schema
    let manifest = registry.get(&domain);
    let schema_matched = manifest.is_some();
    let title = manifest.map_or_else(|| domain.clone(), |m| m.title.clone());

    Ok(Some(DiscoveredPlist {
        domain,
        dict,
        schema_matched,
        title,
    }))
}

// ── Validation ───────────────────────────────────────────────────────

fn validate_keys(dict: &Dictionary, domain: &str, registry: &SchemaRegistry) -> Vec<KeyDiagnostic> {
    let mut diagnostics = Vec::new();

    let Some(manifest) = registry.get(domain) else {
        return diagnostics;
    };

    for key in dict.keys() {
        if let Some(field_def) = manifest.fields.get(key) {
            // Known key — check type
            if let Some(value) = dict.get(key) {
                let expected = &field_def.field_type;
                if !plist_value_matches_type(value, expected) {
                    diagnostics.push(KeyDiagnostic {
                        key: key.clone(),
                        kind: DiagnosticKind::TypeMismatch,
                        message: format!(
                            "{}: expected {}, got {}",
                            key,
                            expected.as_str(),
                            plist_value_type_name(value)
                        ),
                    });
                }
            }
        } else {
            // Unknown key — try fuzzy match
            if let Some(suggestion) = find_closest_key(key, manifest) {
                diagnostics.push(KeyDiagnostic {
                    key: key.clone(),
                    kind: DiagnosticKind::DidYouMean,
                    message: format!("{}: unknown key — did you mean '{}'?", key, suggestion),
                });
            } else {
                diagnostics.push(KeyDiagnostic {
                    key: key.clone(),
                    kind: DiagnosticKind::UnknownKey,
                    message: format!("{}: unknown key (may be vendor-specific)", key),
                });
            }
        }
    }

    diagnostics
}

/// Check if a plist value matches the expected schema field type.
fn plist_value_matches_type(value: &Value, expected: &FieldType) -> bool {
    match (value, expected) {
        (Value::String(_), FieldType::String) => true,
        (Value::Integer(_), FieldType::Integer) => true,
        (Value::Boolean(_), FieldType::Boolean) => true,
        (Value::Array(_), FieldType::Array) => true,
        (Value::Dictionary(_), FieldType::Dictionary) => true,
        (Value::Data(_), FieldType::Data) => true,
        (Value::Date(_), FieldType::Date) => true,
        (Value::Real(_), FieldType::Real) => true,
        // Integer values can sometimes appear as Real
        (Value::Integer(_), FieldType::Real) => true,
        (Value::Real(_), FieldType::Integer) => true,
        _ => false,
    }
}

/// Get a human-readable type name for a plist value.
fn plist_value_type_name(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "String",
        Value::Integer(_) => "Integer",
        Value::Boolean(_) => "Boolean",
        Value::Array(_) => "Array",
        Value::Dictionary(_) => "Dictionary",
        Value::Data(_) => "Data",
        Value::Date(_) => "Date",
        Value::Real(_) => "Real",
        Value::Uid(_) => "Uid",
        _ => "Unknown",
    }
}

/// Find the closest matching key in the manifest using simple edit distance.
fn find_closest_key(key: &str, manifest: &PayloadManifest) -> Option<String> {
    let key_lower = key.to_lowercase();
    let mut best: Option<(String, usize)> = None;

    for known_key in manifest.fields.keys() {
        let known_lower = known_key.to_lowercase();
        let distance = levenshtein(&key_lower, &known_lower);
        // Only suggest if distance is small relative to key length
        let threshold = (key.len() / 3).max(2);
        if distance <= threshold {
            if best.as_ref().is_none_or(|(_, d)| distance < *d) {
                best = Some((known_key.clone(), distance));
            }
        }
    }

    best.map(|(k, _)| k)
}

/// Simple Levenshtein distance (no external crate needed for this).
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = usize::from(a_bytes[i - 1] != b_bytes[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_management_key_stripping() {
        let mut dict = Dictionary::new();
        dict.insert("PayloadUUID".to_string(), Value::String("test".to_string()));
        dict.insert(
            "PayloadIdentifier".to_string(),
            Value::String("com.test".to_string()),
        );
        dict.insert(
            "PayloadType".to_string(),
            Value::String("com.apple.test".to_string()),
        );
        dict.insert("PayloadVersion".to_string(), Value::Integer(1.into()));
        dict.insert("allowCamera".to_string(), Value::Boolean(false));
        dict.insert("allowScreenShot".to_string(), Value::Boolean(true));

        for key in MANAGEMENT_KEYS {
            dict.remove(key);
        }

        // Management keys should be stripped
        assert!(!dict.contains_key("PayloadUUID"));
        assert!(!dict.contains_key("PayloadIdentifier"));
        assert!(!dict.contains_key("PayloadType"));
        assert!(!dict.contains_key("PayloadVersion"));

        // Real keys should remain
        assert!(dict.contains_key("allowCamera"));
        assert!(dict.contains_key("allowScreenShot"));
        assert_eq!(dict.len(), 2);
    }

    #[test]
    fn test_parse_and_match_schema() {
        let registry = SchemaRegistry::embedded().expect("Failed to load embedded schemas");

        // The domain "com.apple.applicationaccess" should match
        let matched = registry.get("com.apple.applicationaccess");
        assert!(matched.is_some());
        assert!(matched.unwrap().title.starts_with("Restrictions"));
    }

    #[test]
    fn test_unknown_domain_no_match() {
        let registry = SchemaRegistry::embedded().expect("Failed to load embedded schemas");

        let matched = registry.get("com.vendor.custom.app");
        assert!(matched.is_none());
    }

    #[test]
    fn test_plist_value_type_matching() {
        assert!(plist_value_matches_type(
            &Value::String("test".to_string()),
            &FieldType::String
        ));
        assert!(plist_value_matches_type(
            &Value::Boolean(true),
            &FieldType::Boolean
        ));
        assert!(plist_value_matches_type(
            &Value::Integer(42.into()),
            &FieldType::Integer
        ));
        assert!(!plist_value_matches_type(
            &Value::String("test".to_string()),
            &FieldType::Boolean
        ));
        // Integer/Real coercion
        assert!(plist_value_matches_type(
            &Value::Integer(1.into()),
            &FieldType::Real
        ));
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("abc", "abd"), 1);
    }

    #[test]
    fn test_validate_keys_with_schema() {
        let registry = SchemaRegistry::embedded().expect("Failed to load embedded schemas");

        let mut dict = Dictionary::new();
        dict.insert("allowCamera".to_string(), Value::Boolean(false));
        dict.insert("totallyFakeKeyXYZ123".to_string(), Value::Boolean(true));

        let diagnostics = validate_keys(&dict, "com.apple.applicationaccess", &registry);

        // The fake key should produce a diagnostic
        assert!(
            diagnostics.iter().any(|d| d.key == "totallyFakeKeyXYZ123"),
            "Expected diagnostic for unknown key"
        );
    }

    #[test]
    fn test_build_mobileconfig_from_dict() {
        let mut dict = Dictionary::new();
        dict.insert("allowCamera".to_string(), Value::Boolean(false));

        let builder = ProfileBuilder::new("com.example", "com.example.com.apple.applicationaccess")
            .display_name("Restrictions");
        let xml = builder
            .build("com.apple.applicationaccess", dict)
            .expect("Failed to build profile");

        let xml_str = String::from_utf8(xml).expect("Invalid UTF-8");
        assert!(xml_str.contains("allowCamera"));
        assert!(xml_str.contains("com.apple.applicationaccess"));
        assert!(xml_str.contains("Restrictions"));
        assert!(xml_str.contains("Configuration"));
    }
}
