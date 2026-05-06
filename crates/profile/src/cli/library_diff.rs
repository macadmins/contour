//! `profile library diff` — semantic diff between two recipe TOML files.
//!
//! `diff` (the existing command) compares `.mobileconfig` files. This
//! command is the recipe-side analogue — useful for review/PR comments
//! when two team members fork a library recipe and need to see what
//! changed at the *intent* level, not the rendered-XML level.
//!
//! Matching strategy:
//! - Profiles match by `(payload_type, filename)` — both stable across
//!   minor edits.
//! - DDM bundles match by `intent_name`.
//! - Recipe metadata diffs key-by-key (name, description, vendor,
//!   variables, secrets).
//!
//! Exit code: `0` if identical, `1` if any change found. Human mode
//! emits ANSI colour; JSON mode emits a structured findings array.

use crate::output::OutputMode;
use crate::recipe::{ProfileSpec, Recipe};
use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug)]
pub struct LibraryDiffOptions<'a> {
    pub a: &'a Path,
    pub b: &'a Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Added,
    Removed,
    Changed,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Added => "added",
            Direction::Removed => "removed",
            Direction::Changed => "changed",
        }
    }

    fn marker(self) -> char {
        match self {
            Direction::Added => '+',
            Direction::Removed => '-',
            Direction::Changed => '~',
        }
    }
}

#[derive(Debug)]
struct Finding {
    direction: Direction,
    path: String,
    before: Option<String>,
    after: Option<String>,
}

pub fn handle_library_diff(opts: LibraryDiffOptions<'_>, output_mode: OutputMode) -> Result<()> {
    let a = load_recipe_from_file(opts.a)?;
    let b = load_recipe_from_file(opts.b)?;

    let mut findings = Vec::new();
    diff_meta(&a, &b, &mut findings);
    diff_profiles(&a.profiles, &b.profiles, &mut findings);
    diff_ddm(&a.ddm, &b.ddm, &mut findings);

    match output_mode {
        OutputMode::Json => {
            let payload = serde_json::json!({
                "identical": findings.is_empty(),
                "a": opts.a.display().to_string(),
                "b": opts.b.display().to_string(),
                "findings": findings.iter().map(|f| serde_json::json!({
                    "direction": f.direction.as_str(),
                    "path": f.path,
                    "before": f.before,
                    "after": f.after,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputMode::Human => {
            if findings.is_empty() {
                println!(
                    "{} {} ↔ {} are semantically identical",
                    "✓".green(),
                    opts.a.display(),
                    opts.b.display()
                );
            } else {
                println!(
                    "{} → {}\n",
                    opts.a.display().to_string().dimmed(),
                    opts.b.display().to_string().dimmed()
                );
                for f in &findings {
                    let marker = f.direction.marker().to_string();
                    let coloured = match f.direction {
                        Direction::Added => marker.green().to_string(),
                        Direction::Removed => marker.red().to_string(),
                        Direction::Changed => marker.yellow().to_string(),
                    };
                    println!("{coloured} {}", f.path);
                    if let (Some(before), Some(after)) = (&f.before, &f.after) {
                        println!("    {} {}", "-".red(), before.dimmed());
                        println!("    {} {}", "+".green(), after.dimmed());
                    } else if let Some(after) = &f.after {
                        println!("    {} {}", "+".green(), after.dimmed());
                    } else if let Some(before) = &f.before {
                        println!("    {} {}", "-".red(), before.dimmed());
                    }
                }
            }
        }
    }

    if !findings.is_empty() {
        // Match `diff(1)` semantics: non-zero exit when files differ.
        std::process::exit(1);
    }
    Ok(())
}

fn load_recipe_from_file(path: &Path) -> Result<Recipe> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    toml::from_str(&body).with_context(|| format!("Failed to parse {} as a Recipe", path.display()))
}

fn diff_meta(a: &Recipe, b: &Recipe, out: &mut Vec<Finding>) {
    str_change(&a.recipe.name, &b.recipe.name, "recipe.name", out);
    str_change(
        &a.recipe.description,
        &b.recipe.description,
        "recipe.description",
        out,
    );
    opt_change(
        a.recipe.vendor.as_deref(),
        b.recipe.vendor.as_deref(),
        "recipe.vendor",
        out,
    );

    // variables / secrets are advisory lists; emit a single change line
    // listing what was added/removed.
    list_change(
        a.recipe.variables.as_deref().unwrap_or(&[]),
        b.recipe.variables.as_deref().unwrap_or(&[]),
        "recipe.variables",
        out,
    );
    list_change(
        a.recipe.secrets.as_deref().unwrap_or(&[]),
        b.recipe.secrets.as_deref().unwrap_or(&[]),
        "recipe.secrets",
        out,
    );
}

fn diff_profiles(a: &[ProfileSpec], b: &[ProfileSpec], out: &mut Vec<Finding>) {
    // Match by (payload_type, filename). A change in either alone is a
    // remove + add — the profile lost its stable identity.
    let key = |p: &ProfileSpec| (p.payload_type.clone(), p.filename.clone());
    let a_keys: BTreeSet<_> = a.iter().map(key).collect();
    let b_keys: BTreeSet<_> = b.iter().map(key).collect();

    for k in &a_keys {
        if !b_keys.contains(k) {
            out.push(Finding {
                direction: Direction::Removed,
                path: format!("profile[{}]", k.1),
                before: Some(k.0.clone()),
                after: None,
            });
        }
    }
    for k in &b_keys {
        if !a_keys.contains(k) {
            out.push(Finding {
                direction: Direction::Added,
                path: format!("profile[{}]", k.1),
                before: None,
                after: Some(k.0.clone()),
            });
        }
    }

    // For matching profiles, diff field-by-field.
    for ap in a {
        let Some(bp) = b.iter().find(|p| key(p) == key(ap)) else {
            continue;
        };
        let prefix = format!("profile[{}]", ap.filename);
        str_change(
            &ap.display_name,
            &bp.display_name,
            &format!("{prefix}.display_name"),
            out,
        );
        str_change(
            &ap.description,
            &bp.description,
            &format!("{prefix}.description"),
            out,
        );
        bool_change(
            ap.removal_disallowed,
            bp.removal_disallowed,
            &format!("{prefix}.removal_disallowed"),
            out,
        );
        opt_change(
            ap.mcx_domain.as_deref(),
            bp.mcx_domain.as_deref(),
            &format!("{prefix}.mcx_domain"),
            out,
        );
        diff_field_map(&ap.fields, &bp.fields, &format!("{prefix}.fields"), out);
        diff_field_map(
            &ap.extra_fields,
            &bp.extra_fields,
            &format!("{prefix}.extra_fields"),
            out,
        );
    }
}

fn diff_ddm(
    a: &[crate::ddm::compose::Bundle],
    b: &[crate::ddm::compose::Bundle],
    out: &mut Vec<Finding>,
) {
    // Match DDM bundles by intent_name.
    let a_names: BTreeSet<_> = a.iter().map(|x| x.intent_name.clone()).collect();
    let b_names: BTreeSet<_> = b.iter().map(|x| x.intent_name.clone()).collect();

    for name in &a_names {
        if !b_names.contains(name) {
            out.push(Finding {
                direction: Direction::Removed,
                path: format!("ddm[{name}]"),
                before: Some(format!("intent_name = {name}")),
                after: None,
            });
        }
    }
    for name in &b_names {
        if !a_names.contains(name) {
            out.push(Finding {
                direction: Direction::Added,
                path: format!("ddm[{name}]"),
                before: None,
                after: Some(format!("intent_name = {name}")),
            });
        }
    }

    for ab in a {
        let Some(bb) = b.iter().find(|x| x.intent_name == ab.intent_name) else {
            continue;
        };
        let prefix = format!("ddm[{}]", ab.intent_name);
        str_change(
            &ab.configuration.type_name,
            &bb.configuration.type_name,
            &format!("{prefix}.configuration.type"),
            out,
        );
        // Payload diff: serialize each side's payload to canonical JSON
        // so we don't need a recursive deep-equal for the dynamic
        // serde_json values. A single change line keeps the report
        // scannable; reviewers can view the recipe TOMLs side-by-side
        // for the deep diff.
        let a_payload = serde_json::to_string(&ab.configuration.payload).unwrap_or_default();
        let b_payload = serde_json::to_string(&bb.configuration.payload).unwrap_or_default();
        if a_payload != b_payload {
            out.push(Finding {
                direction: Direction::Changed,
                path: format!("{prefix}.configuration.payload"),
                before: Some(short(&a_payload)),
                after: Some(short(&b_payload)),
            });
        }
    }
}

fn diff_field_map(
    a: &std::collections::BTreeMap<String, toml::Value>,
    b: &std::collections::BTreeMap<String, toml::Value>,
    prefix: &str,
    out: &mut Vec<Finding>,
) {
    let a_keys: BTreeSet<_> = a.keys().collect();
    let b_keys: BTreeSet<_> = b.keys().collect();

    for k in &a_keys {
        if !b_keys.contains(k) {
            out.push(Finding {
                direction: Direction::Removed,
                path: format!("{prefix}.{k}"),
                before: Some(short(&toml_to_compact(&a[*k]))),
                after: None,
            });
        }
    }
    for k in &b_keys {
        if !a_keys.contains(k) {
            out.push(Finding {
                direction: Direction::Added,
                path: format!("{prefix}.{k}"),
                before: None,
                after: Some(short(&toml_to_compact(&b[*k]))),
            });
        }
    }
    for k in a_keys.intersection(&b_keys) {
        let av = toml_to_compact(a.get(*k).expect("intersection key in a"));
        let bv = toml_to_compact(b.get(*k).expect("intersection key in b"));
        if av != bv {
            out.push(Finding {
                direction: Direction::Changed,
                path: format!("{prefix}.{k}"),
                before: Some(short(&av)),
                after: Some(short(&bv)),
            });
        }
    }
}

fn toml_to_compact(v: &toml::Value) -> String {
    // Round-trip via JSON for a stable single-line compact rep —
    // toml's serializer wants tables to be section-headed, which
    // breaks for inline diff display.
    serde_json::to_string(v).unwrap_or_else(|_| format!("{v:?}"))
}

fn short(s: &str) -> String {
    const MAX: usize = 80;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(MAX).collect();
        format!("{truncated}…")
    }
}

fn str_change(a: &str, b: &str, path: &str, out: &mut Vec<Finding>) {
    if a != b {
        out.push(Finding {
            direction: Direction::Changed,
            path: path.to_string(),
            before: Some(a.to_string()),
            after: Some(b.to_string()),
        });
    }
}

fn bool_change(a: bool, b: bool, path: &str, out: &mut Vec<Finding>) {
    if a != b {
        out.push(Finding {
            direction: Direction::Changed,
            path: path.to_string(),
            before: Some(a.to_string()),
            after: Some(b.to_string()),
        });
    }
}

fn opt_change(a: Option<&str>, b: Option<&str>, path: &str, out: &mut Vec<Finding>) {
    match (a, b) {
        (None, None) => {}
        (None, Some(s)) => out.push(Finding {
            direction: Direction::Added,
            path: path.to_string(),
            before: None,
            after: Some(s.to_string()),
        }),
        (Some(s), None) => out.push(Finding {
            direction: Direction::Removed,
            path: path.to_string(),
            before: Some(s.to_string()),
            after: None,
        }),
        (Some(av), Some(bv)) if av != bv => out.push(Finding {
            direction: Direction::Changed,
            path: path.to_string(),
            before: Some(av.to_string()),
            after: Some(bv.to_string()),
        }),
        _ => {}
    }
}

fn list_change(a: &[String], b: &[String], path: &str, out: &mut Vec<Finding>) {
    let a_set: BTreeSet<_> = a.iter().collect();
    let b_set: BTreeSet<_> = b.iter().collect();
    if a_set == b_set {
        return;
    }
    out.push(Finding {
        direction: Direction::Changed,
        path: path.to_string(),
        before: Some(short(&format!("{a:?}"))),
        after: Some(short(&format!("{b:?}"))),
    });
}
