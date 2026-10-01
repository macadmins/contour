//! Every embedded Parquet table must be read by something.
//!
//! "The file is in the archive" and "the data is live" are different facts:
//! a table can sit in a published zip, embedded by nothing, read by nothing.
//!
//! A table passes through four stages, and only the last one means anything
//! to a user:
//!
//! 1. **generated** — the dataset pipeline writes it
//! 2. **published** — it is inside a released zip
//! 3. **embedded** — a schema crate `include_bytes!` it
//! 4. **read** — something outside that crate calls the accessor
//!
//! Stages 1 and 2 are checked where the dataset is built, which fails when a
//! published file is missing from a crate's `LOCAL_SCHEMA_FILES`. This file owns the two failures on either side of
//! the seam:
//!
//! - **3 without 4** — bytes compiled into the binary that no code path can
//!   reach. `every_embedded_table_is_read_by_something`.
//! - **2 without 3** — a table the published dataset did not carry, which
//!   the build fills with a zero-length placeholder so an older dataset
//!   still compiles. `no_embedded_table_is_an_empty_placeholder`.
//!
//! The second matters when archives go out **split** — some at a new build,
//! some at the previous one. Every URL returns 200, every file is present,
//! and a test that skips on a missing table passes.
//!
//! That is the shape of every silent failure in this codebase: **absence
//! that reads as emptiness**. A placeholder is a legitimate build mechanism
//! and an illegitimate test outcome. Here it is loud: a zero-length table is
//! a failure with a name, or an entry in the allow-list with a reason.
//!
//! When either test fails, wire the table to a surface, republish the
//! dataset, or stop embedding it. Do not add to an allow-list without a
//! reason written down.

use std::collections::BTreeSet;
use std::path::Path;

/// Accessors that are deliberately unread today, with why.
///
/// Empty on purpose. An entry here is a promise to come back, so it carries
/// the reason and stays uncomfortable to add.
///
/// It has held one entry, `embedded_stig_registry_checks`, and the way it
/// left is the point. The note on it said that making `census` count the
/// rows would turn this test green while leaving every check unreachable —
/// so when the exemption was retired, the bar was whether an operator could
/// get one check out, not whether the accessor was called. `profile windows
/// stig show V-253444` prints it. That is what discharged the promise.
const ALLOWED_UNREAD: &[(&str, &str)] = &[];

/// `(crate, accessor fn, table)` for every `include_bytes!` of a parquet.
fn embedded_accessors(root: &Path) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for entry in walk(&root.join("crates")) {
        let Some(crate_name) = entry
            .strip_prefix(root.join("crates"))
            .ok()
            .and_then(|p| p.components().next())
            .map(|c| c.as_os_str().to_string_lossy().to_string())
        else {
            continue;
        };
        let Ok(src) = std::fs::read_to_string(&entry) else {
            continue;
        };
        // pub fn NAME() -> &'static [u8] { … include_bytes!("…/TABLE.parquet") … }
        for chunk in src.split("pub fn ").skip(1) {
            let Some(fn_name) = chunk.split('(').next() else {
                continue;
            };
            let Some(body_start) = chunk.find('{') else {
                continue;
            };
            let Some(body_end) = chunk[body_start..].find("\n}") else {
                continue;
            };
            let body = &chunk[body_start..body_start + body_end];
            if !chunk[..body_start].contains("&'static [u8]") {
                continue;
            }
            for table in body
                .match_indices("include_bytes!(")
                .filter_map(|(i, _)| body[i..].split('"').nth(1))
                .filter_map(|p| p.rsplit('/').next())
                .filter_map(|f| f.strip_suffix(".parquet"))
            {
                out.push((
                    crate_name.clone(),
                    fn_name.trim().to_string(),
                    table.to_string(),
                ));
            }
        }
    }
    out
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == "data") {
                continue;
            }
            out.extend(walk(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// Is `fn_name` referenced from outside `owner`?
///
/// Crate-qualified, because one accessor is called plainly `embedded` and a
/// bare word search matched the English word in comments across twelve
/// crates — the false positive that hid the false negative.
fn read_outside(root: &Path, owner: &str, fn_name: &str) -> BTreeSet<String> {
    let qualified = format!("{}::{fn_name}", owner.replace('-', "_"));
    let mut out = BTreeSet::new();
    for file in walk(&root.join("crates")) {
        let Some(crate_name) = file
            .strip_prefix(root.join("crates"))
            .ok()
            .and_then(|p| p.components().next())
            .map(|c| c.as_os_str().to_string_lossy().to_string())
        else {
            continue;
        };
        if crate_name == owner {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        if src.contains(&qualified) {
            out.insert(crate_name);
        }
    }
    out
}

fn workspace_root() -> std::path::PathBuf {
    // crates/contour/tests/… → workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn every_embedded_table_is_read_by_something() {
    let root = workspace_root();
    let accessors = embedded_accessors(&root);
    assert!(
        accessors.len() > 20,
        "expected the workspace to embed many tables, found {} — the scanner is broken, \
         not the code",
        accessors.len()
    );

    let allowed: BTreeSet<&str> = ALLOWED_UNREAD.iter().map(|(f, _)| *f).collect();
    let mut dead = Vec::new();
    for (owner, fn_name, table) in &accessors {
        if allowed.contains(fn_name.as_str()) {
            continue;
        }
        if read_outside(&root, owner, fn_name).is_empty() {
            dead.push(format!(
                "  {table}.parquet — {owner}::{fn_name}() is called nowhere"
            ));
        }
    }
    assert!(
        dead.is_empty(),
        "embedded but never read — bytes in the binary no code path reaches:\n{}\n\n\
         Wire the table to a surface, or stop embedding it. Adding it to \
         ALLOWED_UNREAD needs a reason written beside it.",
        dead.join("\n")
    );
}

#[test]
fn the_allow_list_has_not_gone_stale() {
    let root = workspace_root();
    let accessors = embedded_accessors(&root);
    let mut fixed = Vec::new();
    for (name, _) in ALLOWED_UNREAD {
        match accessors.iter().find(|(_, f, _)| f == name) {
            None => fixed.push(format!("  {name} — no longer embedded anywhere")),
            Some((owner, f, _)) if !read_outside(&root, owner, f).is_empty() => {
                fixed.push(format!("  {name} — now read; remove the exemption"));
            }
            _ => {}
        }
    }
    assert!(
        fixed.is_empty(),
        "ALLOWED_UNREAD is stale:\n{}",
        fixed.join("\n")
    );
}

/// Tables the published dataset is allowed not to carry yet, with why.
///
/// Empty on purpose. An entry is a promise that a surface degrades
/// gracefully without this table — not a shrug at a failed upload.
const ALLOWED_PLACEHOLDER: &[(&str, &str)] = &[];

/// Every `data/*.parquet` the crates embed, with its size on disk.
fn embedded_data_files(root: &Path) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root.join("crates")) else {
        return out;
    };
    for krate in rd.flatten() {
        let data = krate.path().join("data");
        let Ok(files) = std::fs::read_dir(&data) else {
            continue;
        };
        let crate_name = krate.file_name().to_string_lossy().to_string();
        for f in files.flatten() {
            let p = f.path();
            if p.extension().is_some_and(|x| x == "parquet")
                && let Ok(meta) = f.metadata()
            {
                out.push((
                    crate_name.clone(),
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    meta.len(),
                ));
            }
        }
    }
    out
}

/// A zero-length table is a table the published dataset did not carry.
///
/// The build writes the placeholder so a checkout pinned to an older
/// dataset still compiles — a reasonable build mechanism that becomes a
/// liar the moment a test treats it as "no rows". This is where it stops
/// being quiet.
#[test]
fn no_embedded_table_is_an_empty_placeholder() {
    let root = workspace_root();
    let files = embedded_data_files(&root);
    assert!(
        !files.is_empty(),
        "no data/*.parquet under crates/ — the schema crates' build.rs populates them before \
         tests compile, so this run is not looking at a built tree"
    );
    let allowed: BTreeSet<&str> = ALLOWED_PLACEHOLDER.iter().map(|(f, _)| *f).collect();
    let empty: Vec<String> = files
        .iter()
        .filter(|(_, name, len)| *len == 0 && !allowed.contains(name.as_str()))
        .map(|(krate, name, _)| format!("  {krate}/data/{name} — 0 bytes"))
        .collect();
    assert!(
        empty.is_empty(),
        "these tables are placeholders, not data — the dataset this build \
         used does not carry them:\n{}\n\n\
         Republish the dataset, or record the table in ALLOWED_PLACEHOLDER \
         with the reason its surface can do without it.",
        empty.join("\n")
    );
}

#[test]
fn the_placeholder_allow_list_has_not_gone_stale() {
    let root = workspace_root();
    let files = embedded_data_files(&root);
    assert!(
        !files.is_empty(),
        "no data/*.parquet under crates/ — not a built tree"
    );
    let stale: Vec<String> = ALLOWED_PLACEHOLDER
        .iter()
        .filter(|(name, _)| !files.iter().any(|(_, f, len)| f == name && *len == 0))
        .map(|(name, _)| format!("  {name} — now carries data, or is gone; drop the exemption"))
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED_PLACEHOLDER is stale:\n{}",
        stale.join("\n")
    );
}

/// Accessors that hand back another accessor's bytes, and who calls them.
///
/// `embedded_accessors` only records a function whose body contains
/// `include_bytes!`, because it is answering "which table do these bytes
/// come from". That leaves a whole class unscanned: an accessor that
/// delegates. `embedded_rule_meta_beta()` is one line — `embedded_rule_meta()`
/// — so it names no table, and the check above never looked at it.
///
/// Six of them sat unread in `mscp-schema` while `--beta` advertised a
/// preview dataset, and nothing here noticed, because a delegating accessor
/// is invisible to a test that only sees `include_bytes!`.
///
/// The stakes are different from the check above and worth stating: an
/// unread `include_bytes!` is bytes in the binary no path can reach. An
/// unread delegating accessor wastes no bytes — it is dead public API, which
/// Rust will not warn about on a library's `pub` surface. It matters because
/// it is usually the residue of a feature that was withdrawn without anyone
/// saying so.
fn delegating_accessors(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in walk(&root.join("crates")) {
        let Some(crate_name) = entry
            .strip_prefix(root.join("crates"))
            .ok()
            .and_then(|p| p.components().next())
            .map(|c| c.as_os_str().to_string_lossy().to_string())
        else {
            continue;
        };
        let Ok(src) = std::fs::read_to_string(&entry) else {
            continue;
        };
        for chunk in src.split("pub fn ").skip(1) {
            let Some(fn_name) = chunk.split('(').next() else {
                continue;
            };
            let Some(body_start) = chunk.find('{') else {
                continue;
            };
            let Some(body_end) = chunk[body_start..].find("\n}") else {
                continue;
            };
            if !chunk[..body_start].contains("&'static [u8]") {
                continue;
            }
            let body = &chunk[body_start..body_start + body_end];
            if body.contains("include_bytes!") {
                continue; // covered by embedded_accessors
            }
            out.push((crate_name.clone(), fn_name.trim().to_string()));
        }
    }
    out
}

/// Delegating accessors nobody calls, with why they stay.
const ALLOWED_UNREAD_DELEGATES: &[(&str, &str)] = &[
    (
        "embedded_baseline_meta_beta",
        "mSCP preview channel, dormant while no preview seed is carried. Kept because the channel returns with the next OS seed and \
         deleting the accessor would mean re-adding it; `--beta` refuses today rather \
         than serving stable, and sop_traps_beta.rs holds that.",
    ),
    (
        "embedded_sections_beta",
        "Same — mSCP preview channel, dormant.",
    ),
    (
        "embedded_control_tiers_beta",
        "Same — mSCP preview channel, dormant.",
    ),
    (
        "embedded_rule_meta_beta",
        "Same — mSCP preview channel, dormant.",
    ),
    (
        "embedded_envelope_patterns_beta",
        "Same — mSCP preview channel, dormant.",
    ),
    (
        "embedded_envelope_meta_keys_beta",
        "Same — mSCP preview channel, dormant.",
    ),
];

#[test]
fn every_delegating_accessor_is_read_or_explained() {
    let root = workspace_root();
    let accessors = delegating_accessors(&root);
    assert!(
        !accessors.is_empty(),
        "no delegating accessors found — the scanner is broken, not the code"
    );
    let allowed: BTreeSet<&str> = ALLOWED_UNREAD_DELEGATES.iter().map(|(f, _)| *f).collect();
    let mut dead = Vec::new();
    for (owner, fn_name) in &accessors {
        if allowed.contains(fn_name.as_str()) {
            continue;
        }
        if read_outside(&root, owner, fn_name).is_empty() {
            dead.push(format!("  {owner}::{fn_name}() is called nowhere"));
        }
    }
    assert!(
        dead.is_empty(),
        "these accessors hand back another table's bytes and nothing calls them:\n{}\n\n\
         A delegating accessor usually appears when a channel or variant is withdrawn. \
         Delete it, wire it, or record it in ALLOWED_UNREAD_DELEGATES with the reason \
         it survives.",
        dead.join("\n")
    );
}

#[test]
fn the_delegate_allow_list_has_not_gone_stale() {
    let root = workspace_root();
    let accessors = delegating_accessors(&root);
    let mut fixed = Vec::new();
    for (name, _) in ALLOWED_UNREAD_DELEGATES {
        match accessors.iter().find(|(_, f)| f == name) {
            None => fixed.push(format!("  {name} — no longer a delegating accessor")),
            Some((owner, f)) if !read_outside(&root, owner, f).is_empty() => {
                fixed.push(format!("  {name} — now read; remove the exemption"));
            }
            _ => {}
        }
    }
    assert!(
        fixed.is_empty(),
        "ALLOWED_UNREAD_DELEGATES is stale:\n{}",
        fixed.join("\n")
    );
}
