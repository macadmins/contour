//! Generate machine-readable CLI reference for AI agents.
//!
//! Three output modes for progressive discovery:
//! - **Index** (default): Agent guide + command index (~120 lines)
//! - **Command**: Full detail for a single command by dotted path
//! - **Full**: Complete CLI reference (all commands, all flags)

use std::fmt::Write as _;
use std::io::Write;

use anyhow::{Result, bail};

/// Global flags that are documented once in the header and skipped in subcommands.
const GLOBAL_FLAGS: &[&str] = &["verbose", "json"];

/// Built-in subcommands to skip.
const SKIP_SUBCOMMANDS: &[&str] = &["help", "completions"];

// ── Index mode (default) ─────────────────────────────────────────────

/// Generate the agent guide and command index.
pub fn generate_index(cmd: &clap::Command, writer: &mut impl Write) -> Result<()> {
    let mut buf = String::with_capacity(4 * 1024);
    let name = cmd.get_name();

    // Agent guide
    writeln!(buf, "# {name} — macOS MDM configuration toolkit")?;
    writeln!(buf)?;
    writeln!(buf, "## Agent guide")?;
    writeln!(buf)?;
    writeln!(
        buf,
        "{name} is a CLI toolkit for generating and managing macOS MDM configuration profiles."
    )?;
    writeln!(buf)?;
    writeln!(buf, "**Discovery workflow:**")?;
    writeln!(
        buf,
        "1. Read the command index below to find relevant commands"
    )?;
    writeln!(
        buf,
        "2. Run `{name} help-ai --command <dotted.path>` for full flags and usage of a specific command"
    )?;
    writeln!(
        buf,
        "3. Run `{name} help-ai --section <name>` for a full tool section (profile, pppc, santa, mscp, btm, notifications)"
    )?;
    writeln!(
        buf,
        "4. Run `{name} help-ai --full` for the complete reference (large output)"
    )?;
    writeln!(buf)?;
    writeln!(buf, "**JSON schema (for structured parsing):**")?;
    writeln!(buf, "- `{name} help-json` — full CLI schema as JSON")?;
    writeln!(
        buf,
        "- `{name} help-json <dotted.path>` — scoped subtree, globals stripped"
    )?;
    writeln!(buf, "- Example: `{name} help-json profile.validate`")?;
    writeln!(buf)?;
    writeln!(
        buf,
        "**Command naming:** Commands use SPACES: `{name} profile ddm info`, `{name} santa cel check`"
    )?;
    writeln!(
        buf,
        "IMPORTANT: The index below uses dots (ddm.info) for readability only. When RUNNING commands, always use spaces."
    )?;
    writeln!(
        buf,
        "Dots are ONLY for --command lookup: `{name} help-ai --command profile.ddm.info`"
    )?;
    writeln!(buf)?;
    writeln!(buf, "**Common patterns:**")?;
    writeln!(buf, "- Most tools follow: init → scan → generate")?;
    writeln!(buf, "- `--json` on any command for machine-readable output")?;
    writeln!(
        buf,
        "- `--dry-run` to preview changes without writing files"
    )?;
    writeln!(
        buf,
        "- `--org` sets the organization identifier (or use .contour/config.toml)"
    )?;
    writeln!(buf)?;
    writeln!(
        buf,
        "**When to use which SOP (match user intent to the right SOP):**"
    )?;
    writeln!(
        buf,
        "- write/create/add a Fleet policy, osquery query, compliance check, detection → `--sop osquery`"
    )?;
    writeln!(
        buf,
        "- install software, auto-install, self-service, app deployment, package → `--sop osquery`"
    )?;
    writeln!(
        buf,
        "- generate/create/validate a mobileconfig, configuration profile, payload → `--sop profile`"
    )?;
    writeln!(
        buf,
        "- generate/send an MDM command (restart, lock, erase, remote desktop) → `--sop profile`"
    )?;
    writeln!(
        buf,
        "- mSCP, CIS, STIG, 800-53, compliance baseline, security rules → `--sop mscp`"
    )?;
    writeln!(
        buf,
        "- DEP, ADE, enrollment, Setup Assistant, skip keys, onboarding → `--sop enrollment`"
    )?;
    writeln!(
        buf,
        "- migrate, restructure, move from lib/ to platforms/, update GitOps → `--sop fleet-migrate`"
    )?;
    writeln!(
        buf,
        "- Santa, allowlist, blocklist, CEL, FAA, ring deployment → `--sop santa`"
    )?;
    writeln!(
        buf,
        "- DDM, declarative management, declaration, activation → `--sop ddm`"
    )?;
    writeln!(
        buf,
        "- GitHub Actions, CI, env vars, CONTOUR_ORG, workflow setup → `--sop ci`"
    )?;
    writeln!(buf)?;

    // SOP pointer (keep index compact)
    writeln!(
        buf,
        "**SOPs:** Run `{name} help-ai --sop <tool>` for step-by-step workflows:"
    )?;
    writeln!(
        buf,
        "- `--sop profile` — generate/validate mobileconfig profiles + MDM command payloads"
    )?;
    writeln!(
        buf,
        "- `--sop mscp` — query baselines, rules, ODVs, generate compliance artifacts"
    )?;
    writeln!(buf, "- `--sop ddm` — generate DDM declarations")?;
    writeln!(
        buf,
        "- `--sop santa` — Santa allowlist generation + Fleet ring deployment"
    )?;
    writeln!(buf, "- `--sop pppc` — PPPC/TCC profile generation")?;
    writeln!(buf, "- `--sop btm` — Background Task Management profiles")?;
    writeln!(
        buf,
        "- `--sop notifications` — Notification settings profiles"
    )?;
    writeln!(buf, "- `--sop support` — Root3 Support App profiles")?;
    writeln!(
        buf,
        "- `--sop osquery` — osquery schema lookup + policy query patterns + software-assignment recipes"
    )?;
    writeln!(
        buf,
        "- `--sop fleet-migrate` — migrate Fleet GitOps repo from legacy/v4.82 to v4.83 structure\n\
         - `--sop enrollment` — DEP/ADE enrollment profiles (Setup Assistant skip keys)\n\
         - `--sop ci` — GitHub Actions setup, env vars (CONTOUR_ORG, CONTOUR_NAME), workflow config\n\
         - `--sop precommit` — wire contour validators into a Git pre-commit hook (uvx pre-commit)"
    )?;
    // schema-data is intentionally NOT advertised — it's a contour-developer
    // SOP about refreshing embedded parquet data from the upstream `posture`
    // pipeline. Reachable via `generate_sop("schema-data", ...)` for devs
    // who know about it; agents shouldn't be routing through it.
    writeln!(buf)?;

    // Command index
    writeln!(buf, "## Command index")?;
    writeln!(buf)?;

    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() || SKIP_SUBCOMMANDS.contains(&sub.get_name()) {
            continue;
        }
        write_index_group(&mut buf, sub, name)?;
    }

    writer.write_all(buf.as_bytes())?;
    Ok(())
}

// ── SOP mode ─────────────────────────────────────────────────────────

/// Generate standard operating procedures for a specific tool.
pub fn generate_sop(tool: &str, writer: &mut impl Write) -> Result<()> {
    let sop = match tool.to_lowercase().as_str() {
        "profile" => SOP_PROFILE,
        "mscp" => SOP_MSCP,
        "ddm" => SOP_DDM,
        "santa" => SOP_SANTA,
        "pppc" => SOP_PPPC,
        "btm" => SOP_BTM,
        "notifications" => SOP_NOTIFICATIONS,
        "support" => SOP_SUPPORT,
        "fleet-migrate" | "migrate" | "fleet" => SOP_FLEET_MIGRATE,
        "ci" | "github-actions" | "actions" | "env" | "workflow" => SOP_CI,
        "schema-data" | "schema" | "data" | "parquet" => SOP_SCHEMA_DATA,
        "enrollment" | "dep" | "ade" | "setup-assistant" => SOP_ENROLLMENT,
        "osquery" => SOP_OSQUERY,
        "precommit" | "pre-commit" | "hook" | "git-hook" | "githook" => SOP_PRECOMMIT,
        "profile-changes" | "plan" | "rollback" | "change-impact" | "review" => SOP_PROFILE_CHANGES,
        _ => bail!(
            "Unknown SOP tool: '{tool}'. Available: profile, mscp, ddm, santa, pppc, btm, notifications, support, osquery, precommit, profile-changes"
        ),
    };
    writer.write_all(sop.as_bytes())?;
    Ok(())
}

/// SOP_PROFILE — first SOP migrated to the procedural format for piloted ops
/// (generate, normalize, jamf import). Other ops remain prose pending trace.
///
/// Sourced from the markdown file rather than embedded as a raw string so the
/// procedure blocks (which contain nested backticks and quotes) are easier to
/// author and review. Same pattern as `SOP_ROUTING_TEMPLATE` below.
const SOP_PROFILE: &str = include_str!("../skills/contour/references/sop-profile.md");

/// SOP_MSCP — third SOP migrated to the procedural format. Same external-
/// markdown pattern as SOP_PROFILE and SOP_DDM.
const SOP_MSCP: &str = include_str!("../skills/contour/references/sop-mscp.md");

/// SOP_DDM — second SOP migrated to the procedural format.
///
/// Sourced from the markdown file via include_str! (same pattern as
/// SOP_PROFILE and SOP_ROUTING_TEMPLATE) so the procedure blocks (which
/// contain nested backticks and quotes) are easier to author and review.
const SOP_DDM: &str = include_str!("../skills/contour/references/sop-ddm.md");

/// SOP_SANTA — 11th SOP. Different format from procedural: a decision
/// tree at the top + 6 named recipes (cookbook). Procedural would
/// produce worse output for a fan-out command surface like Santa where
/// multiple goals each have a different end-to-end pipeline. Verified
/// against `santa/Source/common/cel/Activation.{h,mm}` + santa.proto
/// for the CEL `target.*` field surface.
const SOP_SANTA: &str = include_str!("../skills/contour/references/sop-santa.md");

/// SOP_PPPC — sixth SOP migrated to the procedural format. Same external-
/// markdown pattern as SOP_PROFILE / SOP_DDM / SOP_MSCP / SOP_OSQUERY /
/// SOP_ENROLLMENT.
const SOP_PPPC: &str = include_str!("../skills/contour/references/sop-pppc.md");

/// SOP_BTM — seventh SOP migrated to the procedural format. The killer
/// decision pinned by the procedure is mobileconfig-vs-DDM target
/// selection on macOS 15+.
const SOP_BTM: &str = include_str!("../skills/contour/references/sop-btm.md");

/// SOP_NOTIFICATIONS — eighth SOP migrated to the procedural format.
const SOP_NOTIFICATIONS: &str = include_str!("../skills/contour/references/sop-notifications.md");

/// SOP_SUPPORT — ninth SOP migrated to the procedural format. Includes
/// an INVARIANT that pins the `nl.root3.support` PayloadType so a CLI
/// regression cannot silently emit profiles the Support app won't read.
const SOP_SUPPORT: &str = include_str!("../skills/contour/references/sop-support.md");

/// SOP_PRECOMMIT — tenth SOP. Documents wiring contour's validators
/// into a Git pre-commit hook (canonical path: `uvx pre-commit`) so
/// malformed profiles, dangling DDM references, and broken TOML
/// configs block the commit at the developer's keyboard rather than
/// failing in CI 20+ minutes later.
const SOP_PRECOMMIT: &str = include_str!("../skills/contour/references/sop-precommit.md");

/// SOP_PROFILE_CHANGES — 15th SOP. Procedural format. Covers the
/// risk model behind bulk `.mobileconfig` edits (PayloadUUID churn,
/// orphaned cross-references, plist type-shape errors, scope
/// broadening) and the `profile plan` / `profile rollback` workflow.
/// Forward-spec for the new commands; the SOP is the authoring contract
/// the implementations target.
const SOP_PROFILE_CHANGES: &str =
    include_str!("../skills/contour/references/sop-profile-changes.md");

/// SOP_FLEET_MIGRATE — 12th SOP. Numbered migration playbook (NOT a
/// callable procedure). Validated against fleetctl v4.84.2 scaffold +
/// fleet/docs/Configuration/yaml-files.md. Keeps human diff-checkpoints
/// at each step because YAML migrations have meaningful semantic deltas.
const SOP_FLEET_MIGRATE: &str = include_str!("../skills/contour/references/sop-fleet-migrate.md");

/// SOP_ENROLLMENT — fifth SOP migrated to the procedural format. The killer
/// trap it catches: `--skip-all` includes FileVault and SoftwareUpdate, both
/// of which should almost never be skipped in production. The procedural
/// format's INVARIANTS block enforces this at the agent layer.
const SOP_ENROLLMENT: &str = include_str!("../skills/contour/references/sop-enrollment.md");

/// SOP_CI — 13th SOP. Hybrid: bootstrap procedure (`configure_ci`) plus
/// a workflow-recipe reference. The procedural part has typed
/// preconditions on `gh variable set` / `gh secret set`; the recipes
/// are configuration patterns that don't fit a procedure shape.
const SOP_CI: &str = include_str!("../skills/contour/references/sop-ci.md");

/// SOP_SCHEMA_DATA — 14th (final) SOP. Hybrid: developer reference
/// (data inventory, three-layer versioning) + thin update_schema_data
/// PROCEDURE for the happy-path refresh flow. Internal contour-dev
/// documentation, not user-facing.
const SOP_SCHEMA_DATA: &str = include_str!("../skills/contour/references/sop-schema-data.md");

/// SOP_OSQUERY — fourth SOP migrated to the procedural format. Combines
/// procedural lookup (find_query_table → write_policy_query) with a
/// reference cookbook of battle-tested SQL patterns.
const SOP_OSQUERY: &str = include_str!("../skills/contour/references/sop-osquery.md");

/// Write a top-level command group and its subcommands as an index.
fn write_index_group(buf: &mut String, cmd: &clap::Command, root: &str) -> Result<()> {
    let about = cmd.get_about().map(|a| a.to_string()).unwrap_or_default();
    let name = cmd.get_name();

    writeln!(buf, "### {root} {name} — {about}")?;

    let subs: Vec<_> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .collect();

    if subs.is_empty() {
        // Leaf command at top level (e.g. `contour init`)
        writeln!(buf)?;
        return Ok(());
    }

    for sub in &subs {
        let sub_about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
        let sub_name = sub.get_name();

        // Check if this sub has its own subcommands
        let nested: Vec<_> = sub
            .get_subcommands()
            .filter(|s| !s.is_hide_set() && s.get_name() != "help")
            .collect();

        if nested.is_empty() {
            writeln!(buf, "  {sub_name:20} {sub_about}")?;
        } else {
            // Show nested group (e.g. profile docs, profile payload, mscp odv)
            writeln!(buf, "  {sub_name:20} {sub_about}")?;
            for n in &nested {
                let n_about = n.get_about().map(|a| a.to_string()).unwrap_or_default();
                writeln!(buf, "    {}.{:16} {n_about}", sub_name, n.get_name())?;
            }
        }
    }

    writeln!(buf)?;
    Ok(())
}

// ── Command mode (--command) ─────────────────────────────────────────

/// Generate full detail for a single command identified by dotted path.
///
/// Path examples: `santa.add`, `profile.docs.generate`, `pppc.scan`
pub fn generate_command(cmd: &clap::Command, path: &str, writer: &mut impl Write) -> Result<()> {
    let parts: Vec<&str> = path.split('.').collect();

    let mut current = cmd;
    let mut prefix = cmd.get_name().to_string();

    for part in &parts {
        let found = current.get_subcommands().find(|s| s.get_name() == *part);

        match found {
            Some(sub) => {
                prefix = format!("{prefix} {part}");
                current = sub;
            }
            None => {
                let available: Vec<_> = current
                    .get_subcommands()
                    .filter(|s| !s.is_hide_set() && s.get_name() != "help")
                    .map(|s| s.get_name().to_string())
                    .collect();
                bail!(
                    "Unknown command '{}' at '{}'. Available: {}",
                    part,
                    prefix,
                    available.join(", ")
                );
            }
        }
    }

    let mut buf = String::with_capacity(2 * 1024);
    write_command(
        &mut buf,
        current,
        &prefix_without_last(&prefix, current.get_name()),
        2,
    )?;
    writer.write_all(buf.as_bytes())?;
    Ok(())
}

/// Get the prefix (everything before the last segment).
fn prefix_without_last(full: &str, last: &str) -> String {
    if let Some(stripped) = full.strip_suffix(last) {
        stripped.trim_end().to_string()
    } else {
        full.to_string()
    }
}

// ── Full mode (--full, existing behavior) ────────────────────────────

/// Generate the complete CLI reference as markdown and write it to `writer`.
pub fn generate_full(cmd: &clap::Command, writer: &mut impl Write) -> Result<()> {
    let mut buf = String::with_capacity(8 * 1024);

    // Header
    writeln!(buf, "# {} CLI reference (for AI agents)", cmd.get_name())?;
    writeln!(buf)?;
    if let Some(version) = cmd.get_version() {
        writeln!(buf, "Version: {version}")?;
    }
    if let Some(about) = cmd.get_about() {
        writeln!(buf, "{about}")?;
    }
    writeln!(buf)?;

    // Global flags
    let global_args: Vec<_> = cmd
        .get_arguments()
        .filter(|a| GLOBAL_FLAGS.contains(&a.get_id().as_str()))
        .collect();

    if !global_args.is_empty() {
        writeln!(buf, "## Global flags")?;
        writeln!(buf)?;
        write_flags_table(&mut buf, &global_args)?;
        writeln!(buf)?;
    }

    // Walk subcommands
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() || SKIP_SUBCOMMANDS.contains(&sub.get_name()) {
            continue;
        }
        write_command(&mut buf, sub, cmd.get_name(), 2)?;
    }

    writer.write_all(buf.as_bytes())?;
    Ok(())
}

/// Backwards-compatible alias — calls `generate_full`.
pub fn generate(cmd: &clap::Command, writer: &mut impl Write) -> Result<()> {
    generate_full(cmd, writer)
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Recursively write a command and its subcommands.
fn write_command(buf: &mut String, cmd: &clap::Command, prefix: &str, depth: usize) -> Result<()> {
    let full_name = format!("{prefix} {}", cmd.get_name());
    let heading = "#".repeat(depth.min(6));

    writeln!(buf, "{heading} {full_name}")?;
    writeln!(buf)?;

    if let Some(about) = cmd.get_long_about().or_else(|| cmd.get_about()) {
        writeln!(buf, "{about}")?;
        writeln!(buf)?;
    }

    // Collect non-hidden, non-global, non-builtin args
    let args: Vec<_> = cmd
        .get_arguments()
        .filter(|a| {
            !a.is_hide_set()
                && a.get_id() != "help"
                && a.get_id() != "version"
                && !GLOBAL_FLAGS.contains(&a.get_id().as_str())
        })
        .collect();

    // Positional args — show in usage line
    let positionals: Vec<_> = args.iter().filter(|a| a.is_positional()).collect();
    if !positionals.is_empty() {
        let usage: Vec<String> = positionals
            .iter()
            .map(|a| {
                let name = a
                    .get_value_names()
                    .map(|v| {
                        v.iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_else(|| a.get_id().to_string().to_uppercase());
                if a.is_required_set() {
                    format!("<{name}>")
                } else {
                    format!("[{name}]")
                }
            })
            .collect();
        writeln!(buf, "Usage: `{full_name} {}`", usage.join(" "))?;
        writeln!(buf)?;

        // Describe positionals if they have help text
        for a in &positionals {
            if let Some(help) = a.get_help() {
                let name = a.get_id().as_str();
                writeln!(buf, "- `{name}`: {help}")?;
            }
        }
        if positionals.iter().any(|a| a.get_help().is_some()) {
            writeln!(buf)?;
        }
    }

    // Flag args
    let flags: Vec<_> = args
        .iter()
        .filter(|a| !a.is_positional())
        .copied()
        .collect();
    if !flags.is_empty() {
        write_flags_table(buf, &flags)?;
        writeln!(buf)?;
    }

    // Recurse into subcommands
    let subs: Vec<_> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .collect();

    for sub in subs {
        write_command(buf, sub, &full_name, depth + 1)?;
    }

    Ok(())
}

/// Write a markdown table of flags.
fn write_flags_table(buf: &mut String, args: &[&clap::Arg]) -> Result<()> {
    // Sort: required first, then alphabetical
    let mut sorted: Vec<_> = args.to_vec();
    sorted.sort_by(|a, b| {
        b.is_required_set()
            .cmp(&a.is_required_set())
            .then_with(|| flag_name(a).cmp(&flag_name(b)))
    });

    writeln!(buf, "| Flag | Type | Default | Description |")?;
    writeln!(buf, "|------|------|---------|-------------|")?;

    for arg in &sorted {
        let name = flag_name(arg);
        let type_str = arg_type(arg);
        let default = arg_default(arg);
        let desc = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
        let req = if arg.is_required_set() {
            " **(required)**"
        } else {
            ""
        };

        writeln!(buf, "| `{name}` | {type_str} | {default} | {desc}{req} |")?;
    }

    Ok(())
}

/// Format the flag name (--long / -short).
fn flag_name(arg: &clap::Arg) -> String {
    match (arg.get_long(), arg.get_short()) {
        (Some(l), Some(s)) => format!("--{l}, -{s}"),
        (Some(l), None) => format!("--{l}"),
        (None, Some(s)) => format!("-{s}"),
        (None, None) => arg.get_id().to_string(),
    }
}

/// Determine the type string for an argument.
fn arg_type(arg: &clap::Arg) -> String {
    // Boolean flags (SetTrue/SetFalse) — just show "flag"
    if matches!(
        arg.get_action(),
        clap::ArgAction::SetTrue | clap::ArgAction::SetFalse
    ) {
        return "flag".to_string();
    }

    let possible = arg.get_possible_values();
    if !possible.is_empty() {
        let vals: Vec<_> = possible
            .iter()
            .filter(|v| !v.is_hide_set())
            .map(|v| v.get_name().to_string())
            .collect();
        return format!("`{}`", vals.join("\\|"));
    }

    if arg.get_action().takes_values() {
        if let Some(names) = arg.get_value_names() {
            return names
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ");
        }
        return "STRING".to_string();
    }

    "flag".to_string()
}

/// Format the default value.
fn arg_default(arg: &clap::Arg) -> String {
    let defaults = arg.get_default_values();
    if defaults.is_empty() {
        return "—".to_string();
    }
    let vals: Vec<_> = defaults.iter().filter_map(|v| v.to_str()).collect();
    format!("`{}`", vals.join(", "))
}

// ── JSON mode (--json) ───────────────────────────────────────────────

/// Generate the command tree as structured JSON.
/// If `path` is provided, scopes to that subtree with global flags stripped.
pub fn generate_json(
    cmd: &clap::Command,
    path: Option<&str>,
    writer: &mut impl Write,
) -> Result<()> {
    let json = if let Some(path) = path {
        // Walk to the target command, then output without globals
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = cmd;
        for part in &parts {
            current = current
                .get_subcommands()
                .find(|s| s.get_name() == *part)
                .ok_or_else(|| {
                    let available: Vec<_> = current
                        .get_subcommands()
                        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
                        .map(|s| s.get_name().to_string())
                        .collect();
                    anyhow::anyhow!(
                        "Unknown command '{part}'. Available: {}",
                        available.join(", ")
                    )
                })?;
        }
        command_to_json_no_globals(current)
    } else {
        command_to_json(cmd)
    };
    let output = serde_json::to_string_pretty(&json)?;
    writer.write_all(output.as_bytes())?;
    writeln!(writer)?;
    Ok(())
}

/// Convert a command to JSON, stripping global flags (for subtree scoping).
fn command_to_json_no_globals(cmd: &clap::Command) -> serde_json::Value {
    let args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| {
            !a.is_hide_set()
                && a.get_id() != "help"
                && a.get_id() != "version"
                && !a.is_global_set()
        })
        .map(arg_to_json)
        .collect();

    let subcommands: Vec<serde_json::Value> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .map(command_to_json_no_globals)
        .collect();

    let mut obj = serde_json::json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(|a| a.to_string()),
    });

    if let Some(long_about) = cmd.get_long_about() {
        obj["long_about"] = serde_json::json!(long_about.to_string());
    }

    if !args.is_empty() {
        obj["args"] = serde_json::json!(args);
    }

    if !subcommands.is_empty() {
        obj["subcommands"] = serde_json::json!(subcommands);
    }

    obj
}

/// Convert a clap Command into a JSON value recursively.
fn command_to_json(cmd: &clap::Command) -> serde_json::Value {
    let args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set() && a.get_id() != "help" && a.get_id() != "version")
        .map(arg_to_json)
        .collect();

    let subcommands: Vec<serde_json::Value> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .map(command_to_json)
        .collect();

    let mut obj = serde_json::json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(|a| a.to_string()),
    });

    if let Some(version) = cmd.get_version() {
        obj["version"] = serde_json::json!(version);
    }

    if let Some(long_about) = cmd.get_long_about() {
        obj["long_about"] = serde_json::json!(long_about.to_string());
    }

    if !args.is_empty() {
        obj["args"] = serde_json::json!(args);
    }

    if !subcommands.is_empty() {
        obj["subcommands"] = serde_json::json!(subcommands);
    }

    obj
}

/// Convert a clap Arg into a JSON value.
fn arg_to_json(arg: &clap::Arg) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "name": arg.get_id().as_str(),
        "required": arg.is_required_set(),
        "positional": arg.is_positional(),
    });

    if let Some(long) = arg.get_long() {
        obj["long"] = serde_json::json!(format!("--{long}"));
    }

    if let Some(short) = arg.get_short() {
        obj["short"] = serde_json::json!(format!("-{short}"));
    }

    if let Some(help) = arg.get_help() {
        obj["help"] = serde_json::json!(help.to_string());
    }

    let defaults = arg.get_default_values();
    if !defaults.is_empty() {
        let vals: Vec<&str> = defaults.iter().filter_map(|v| v.to_str()).collect();
        obj["default"] = serde_json::json!(vals.join(", "));
    }

    if arg.get_action().takes_values() {
        let possible: Vec<_> = arg
            .get_possible_values()
            .iter()
            .map(|v| v.get_name().to_string())
            .collect();
        if !possible.is_empty() {
            obj["possible_values"] = serde_json::json!(possible);
        }
    }

    if arg.is_global_set() {
        obj["global"] = serde_json::json!(true);
    }

    obj
}

// ── Skill file installation ─────────────────────────────────────────

/// Install a Claude Code / Kilo Code skill file for contour.
///
/// Creates `.claude/skills/contour.md` in the current working directory so
/// AI agents automatically discover contour capabilities.
/// Embedded skill file templates.
const SKILL_TEMPLATE: &str = include_str!("../skills/contour/SKILL.md");
const SOP_ROUTING_TEMPLATE: &str = include_str!("../skills/contour/references/sop-routing.md");

/// Install contour skill files for AI agents.
///
/// Creates:
/// - `.claude/skills/contour.md` — skill file (for local Claude Code sessions)
/// - Appends full contour instructions to `CLAUDE.md` (for CI/GitHub Actions)
/// - Appends full contour instructions to `AGENTS.md` (for Kilo Code and others)
///
/// The full content goes into CLAUDE.md/AGENTS.md because CI agents read those
/// but NOT `.claude/skills/`. A pointer isn't enough — the full instructions
/// must be in the file the agent reads at session start.
pub fn install_skill(version: &str) -> Result<()> {
    use std::fs;
    use std::path::Path;

    let skill_content = SKILL_TEMPLATE.replace("{{VERSION}}", version);

    // 1. Install .claude/skills/contour/ directory (for local sessions)
    let skill_dir = Path::new(".claude/skills/contour");
    let refs_dir = skill_dir.join("references");
    fs::create_dir_all(&refs_dir)?;
    fs::write(skill_dir.join("SKILL.md"), &skill_content)?;
    fs::write(refs_dir.join("sop-routing.md"), SOP_ROUTING_TEMPLATE)?;
    eprintln!("\u{2713} Installed .claude/skills/contour/SKILL.md");

    // 2. Write full content into CLAUDE.md and AGENTS.md (for CI)
    for agent_file in &["CLAUDE.md", "AGENTS.md"] {
        let path = Path::new(agent_file);
        if path.exists() {
            let existing = fs::read_to_string(path)?;
            if existing.contains("contour — macOS MDM Configuration Toolkit") {
                // Already has full content — replace the contour section
                eprintln!(
                    "  {agent_file} already has contour instructions (use --force to replace)"
                );
            } else {
                // Append full skill content
                let mut updated = existing;
                if !updated.ends_with('\n') {
                    updated.push('\n');
                }
                updated.push('\n');
                updated.push_str(&skill_content);
                fs::write(path, updated)?;
                eprintln!("\u{2713} Added contour instructions to {agent_file}");
            }
        } else {
            // Create with full content
            fs::write(path, &skill_content)?;
            eprintln!("\u{2713} Created {agent_file} with contour instructions");
        }
    }

    eprintln!();
    eprintln!("  Agents will now discover contour in both local and CI environments.");
    eprintln!("  Regenerate with: contour help-ai --install-skill");
    eprintln!();
    eprintln!("  TIP: Set your org domain in CLAUDE.md to avoid com.example defaults:");
    eprintln!("    ## Organization");
    eprintln!("    Default org domain: com.yourcompany");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, Command};

    fn sample_cmd() -> Command {
        Command::new("test-tool")
            .version("1.0.0")
            .about("A test tool")
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .short('v')
                    .global(true)
                    .action(clap::ArgAction::SetTrue)
                    .help("Enable verbose output"),
            )
            .subcommand(
                Command::new("sub")
                    .about("A subcommand")
                    .arg(
                        Arg::new("input")
                            .long("input")
                            .required(true)
                            .help("Input file path"),
                    )
                    .arg(
                        Arg::new("format")
                            .long("format")
                            .value_parser(["json", "yaml", "toml"])
                            .default_value("json")
                            .help("Output format"),
                    ),
            )
    }

    #[test]
    fn generates_full_markdown() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_full(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("# test-tool CLI reference"));
        assert!(text.contains("Version: 1.0.0"));
        assert!(text.contains("## Global flags"));
        assert!(text.contains("--verbose"));
        assert!(text.contains("## test-tool sub"));
        assert!(text.contains("--input"));
        assert!(text.contains("**(required)**"));
        assert!(text.contains("json\\|yaml\\|toml"));
        // Boolean flags should show "flag", not "true|false"
        assert!(!text.contains("true\\|false"));
    }

    #[test]
    fn generates_index() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_index(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("# test-tool"));
        assert!(text.contains("Agent guide"));
        assert!(text.contains("Command index"));
        assert!(text.contains("sub"));
        assert!(text.contains("A subcommand"));
        // Index should NOT contain flag details
        assert!(!text.contains("--input"));
    }

    #[test]
    fn generates_single_command() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_command(&cmd, "sub", &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("test-tool sub"));
        assert!(text.contains("--input"));
        assert!(text.contains("--format"));
    }

    #[test]
    fn command_not_found_error() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        let err = generate_command(&cmd, "nonexistent", &mut output).unwrap_err();
        assert!(err.to_string().contains("Unknown command"));
        assert!(err.to_string().contains("sub"));
    }

    #[test]
    fn skips_help_subcommand() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate_full(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        // clap auto-adds a help subcommand; we should skip it
        assert!(!text.contains("## test-tool help"));
    }

    #[test]
    fn skips_hidden_args() {
        let cmd = Command::new("app").arg(
            Arg::new("secret")
                .long("secret")
                .hide(true)
                .help("Hidden arg"),
        );
        let mut output = Vec::new();
        generate_full(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(!text.contains("secret"));
    }

    #[test]
    fn backward_compat_generate() {
        let cmd = sample_cmd();
        let mut output = Vec::new();
        generate(&cmd, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("# test-tool CLI reference"));
    }
}
