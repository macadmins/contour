//! Surface generated Fleet queries as ready-to-run, path-resolved osquery
//! commands for manual testing. contour **never executes** them — it only
//! prints the command so an operator can run it on the right host:
//!
//! - **Dev / CI** have standalone `osqueryi`: `osqueryi --json "<sql>"`.
//! - **Fleet-managed devices** have no `osqueryi`, only Fleet's agent manager
//!   `orbit`. Its shell starts a standalone osquery instance and needs root:
//!   `sudo orbit shell -- --json "<sql>"` (everything after `--` goes to
//!   osquery). This is also the most faithful check — same osquery build and
//!   extension tables Fleet ships.
//!
//! Binary paths are resolved (PATH, then the standard install location) so the
//! printed command is copy-pasteable. Used by `contour osquery verify` and
//! `mscp generate --verify-queries`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Which osquery front-end a suggested command targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runner {
    /// Standalone `osqueryi --json <sql>` (dev machines, CI).
    Osqueryi(PathBuf),
    /// Fleet/Orbit-managed `sudo orbit shell -- --json <sql>` (enrolled hosts).
    OrbitShell(PathBuf),
}

impl Runner {
    /// A human-readable label for messages.
    pub fn label(&self) -> String {
        match self {
            Runner::Osqueryi(p) => format!("osqueryi ({})", p.display()),
            Runner::OrbitShell(p) => format!("orbit shell ({})", p.display()),
        }
    }

    /// A copy-pasteable, path-resolved shell command to run `sql`. Orbit gets the
    /// `sudo orbit shell -- …` form (osquery args after `--`); osqueryi the plain
    /// invocation.
    pub fn suggest(&self, sql: &str) -> String {
        let sql = sql.replace('"', "\\\"");
        match self {
            Runner::Osqueryi(path) => format!("{} --json \"{sql}\"", path.display()),
            Runner::OrbitShell(path) => {
                format!("sudo {} shell -- --json \"{sql}\"", path.display())
            }
        }
    }
}

/// First existing path for `name` (PATH entries first, then absolute fallbacks).
fn first_on_disk(name: &str, absolute_fallbacks: &[&str]) -> Option<PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join(name);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    absolute_fallbacks
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// Locate standalone `osqueryi` (PATH or `/usr/local/bin`). `None` if absent.
pub fn find_osqueryi() -> Option<Runner> {
    first_on_disk("osqueryi", &["/usr/local/bin/osqueryi"]).map(Runner::Osqueryi)
}

/// Locate Fleet's `orbit` (PATH or `/opt/orbit/bin/orbit`). `None` if absent.
pub fn find_orbit() -> Option<Runner> {
    first_on_disk("orbit", &["/opt/orbit/bin/orbit"]).map(Runner::OrbitShell)
}

/// The osqueryi runner: the resolved binary, or the conventional
/// `/usr/local/bin/osqueryi` so a command is emitted even when osqueryi isn't
/// installed locally (dev/CI form).
pub fn osqueryi_or_conventional() -> Runner {
    find_osqueryi().unwrap_or_else(|| Runner::Osqueryi(PathBuf::from("/usr/local/bin/osqueryi")))
}

/// The Orbit runner for a Fleet host: the resolved `orbit`, or the conventional
/// `/opt/orbit/bin/orbit` so commands are emitted even when `orbit` isn't
/// installed locally (they run on the managed device, not here).
pub fn orbit_or_conventional() -> Runner {
    find_orbit().unwrap_or_else(|| Runner::OrbitShell(PathBuf::from("/opt/orbit/bin/orbit")))
}

/// A `name` (+ optional `query`) entry as it appears in a generated Fleet list
/// file. `query` is absent for non-osquery policies — e.g. Fleet `type: patch`
/// software/FMA policies — which have nothing to run and are skipped. Unknown
/// fields (description, platform, install_software, …) are ignored.
#[derive(Debug, Deserialize)]
struct QueryItem {
    name: String,
    #[serde(default)]
    query: Option<String>,
}

/// A query to render, tagged with the file it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedQuery {
    /// The report/policy display name.
    pub name: String,
    /// The osquery SQL.
    pub query: String,
    /// The source file, relative to the scanned root.
    pub source: String,
}

/// Whether a file is a generated Fleet query list (`*.policies.yml` /
/// `*.reports.yml`).
fn is_query_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n.ends_with(".policies.yml") || n.ends_with(".reports.yml"))
}

/// Parse the query-bearing entries from one generated Fleet list file. Entries
/// without a `query` (e.g. Fleet `type: patch` software policies) are skipped.
///
/// # Errors
/// Returns an error if the file can't be read or isn't a flat list of objects.
pub fn queries_in_file(path: &Path) -> Result<Vec<NamedQuery>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let items: Vec<QueryItem> =
        yaml_serde::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let source = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    Ok(items
        .into_iter()
        .filter_map(|i| {
            // Skip non-osquery policies (no `query`, e.g. Fleet `type: patch`).
            i.query.map(|query| NamedQuery {
                name: i.name,
                query,
                source: source.clone(),
            })
        })
        .collect())
}

/// Recursively collect every query under `root` — a single query file, or a
/// directory tree scanned for `*.policies.yml` / `*.reports.yml`. `source` is the
/// path relative to `root`; sorted for stable output.
///
/// # Errors
/// Returns an error if `root` doesn't exist or a query file fails to parse.
pub fn collect_queries(root: &Path) -> Result<Vec<NamedQuery>> {
    let mut files = Vec::new();
    if root.is_file() {
        files.push(root.to_path_buf());
    } else if root.is_dir() {
        collect_files(root, &mut files)?;
    } else {
        anyhow::bail!("path not found: {}", root.display());
    }
    files.sort();

    let mut out = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();
        let source = if rel.is_empty() {
            file.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string()
        } else {
            rel
        };
        for mut q in queries_in_file(file)? {
            q.source = source.clone();
            out.push(q);
        }
    }
    Ok(out)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if is_query_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// Render every query as a Markdown reference, grouped by source file, with both
/// runner forms per query (`osqueryi` for dev/CI, `sudo orbit shell` for a
/// Fleet-managed host) so one document is testable on either host. Binary paths
/// are resolved where present, else the conventional install location.
pub fn render_markdown(queries: &[NamedQuery]) -> String {
    let osq = osqueryi_or_conventional();
    let orbit = orbit_or_conventional();

    let mut md = String::new();
    md.push_str("# osquery verification commands\n\n");
    md.push_str(&format!(
        "Generated by contour for {} quer{}. These are **not executed** — run a \
         command on the target host to test the query.\n\n",
        queries.len(),
        if queries.len() == 1 { "y" } else { "ies" }
    ));
    md.push_str(&format!("- **Dev / CI:** `{}`\n", osq.label()));
    md.push_str(&format!(
        "- **Fleet-managed host** (no osqueryi; needs root): `{}`\n\n",
        orbit.label()
    ));

    let mut last_source = "";
    for q in queries {
        if q.source != last_source {
            md.push_str(&format!("## {}\n\n", q.source));
            last_source = &q.source;
        }
        md.push_str(&format!("### {}\n\n", q.name));
        md.push_str("```bash\n");
        md.push_str(&format!("# dev / CI\n{}\n", osq.suggest(&q.query)));
        md.push_str(&format!(
            "# Fleet-managed host (needs root)\n{}\n",
            orbit.suggest(&q.query)
        ));
        md.push_str("```\n\n");
    }
    md
}

/// Write the [`render_markdown`] reference for `queries` to `path`, creating
/// parent directories.
///
/// # Errors
/// Propagates directory-creation or write failures.
pub fn write_markdown(path: &Path, queries: &[NamedQuery]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, render_markdown(queries))
        .with_context(|| format!("write {}", path.display()))
}

/// Post-generation hook for `--verify-queries`: write a Markdown reference of the
/// emitted policy/report query commands to `<output_dir>/osquery/verify-commands.md`.
/// Never executes; generation already succeeded, so this never errors beyond a
/// failure to scan `output_dir` or write the file.
///
/// # Errors
/// Propagates a failure to scan `output_dir` or write the document.
pub fn verify_generated(output_dir: &Path) -> Result<()> {
    let queries = collect_queries(output_dir)?;
    if queries.is_empty() {
        return Ok(());
    }
    let md_path = output_dir.join("osquery").join("verify-commands.md");
    write_markdown(&md_path, &queries)?;
    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "verify-queries: wrote {} query command{} (osqueryi + orbit forms) → {}",
        queries.len(),
        if queries.len() == 1 { "" } else { "s" },
        md_path.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_resolves_paths_and_wraps_orbit_in_sudo() {
        let osq = Runner::Osqueryi(PathBuf::from("/usr/local/bin/osqueryi"));
        assert_eq!(
            osq.suggest("SELECT 1;"),
            "/usr/local/bin/osqueryi --json \"SELECT 1;\""
        );

        let orbit = Runner::OrbitShell(PathBuf::from("/opt/orbit/bin/orbit"));
        assert_eq!(
            orbit.suggest("SELECT 1;"),
            "sudo /opt/orbit/bin/orbit shell -- --json \"SELECT 1;\""
        );
    }

    #[test]
    fn orbit_or_conventional_uses_the_standard_path_when_absent() {
        // On a dev box without orbit installed, the conventional Fleet path is
        // used so the command is still emitted for the managed device.
        if find_orbit().is_none() {
            assert_eq!(
                orbit_or_conventional(),
                Runner::OrbitShell(PathBuf::from("/opt/orbit/bin/orbit"))
            );
        }
    }

    #[test]
    fn is_query_file_matches_only_generated_lists() {
        assert!(is_query_file(Path::new("a/cis_lvl1.policies.yml")));
        assert!(is_query_file(Path::new("b/security-posture.reports.yml")));
        assert!(!is_query_file(Path::new("workstations.yml")));
        assert!(!is_query_file(Path::new("notes.md")));
    }

    #[test]
    fn collect_queries_reads_policies_and_reports_across_a_tree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pol = tmp.path().join("osquery/cis_lvl1");
        let rep = tmp.path().join("platforms/macos/reports");
        std::fs::create_dir_all(&pol).unwrap();
        std::fs::create_dir_all(&rep).unwrap();
        std::fs::write(
            pol.join("cis_lvl1.policies.yml"),
            "- name: P1\n  query: SELECT 1;\n",
        )
        .unwrap();
        std::fs::write(
            rep.join("security-posture.reports.yml"),
            "- name: R1\n  query: SELECT name FROM os_version;\n- name: R2\n  query: SELECT 1;\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("default.yml"), "name: x\n").unwrap();

        let qs = collect_queries(tmp.path()).unwrap();
        assert_eq!(qs.len(), 3);
        assert!(
            qs.iter()
                .any(|q| q.name == "P1" && q.source.contains("policies"))
        );
        assert!(
            qs.iter()
                .any(|q| q.name == "R2" && q.source.contains("reports"))
        );
    }

    #[test]
    fn collect_queries_skips_non_query_policies() {
        // A real Fleet repo mixes osquery policies with `type: patch` software
        // policies (no `query`). The latter must be skipped, not error the scan.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("fma.policies.yml"),
            "- name: \"1Password up to date\"\n  type: patch\n  fleet_maintained_app_slug: 1password/darwin\n  install_software: true\n- name: real\n  query: SELECT 1;\n",
        )
        .unwrap();
        let qs = collect_queries(tmp.path()).unwrap();
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].name, "real");
    }

    #[test]
    fn collect_queries_errors_on_missing_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        collect_queries(&tmp.path().join("nope")).unwrap_err();
    }

    #[test]
    fn render_markdown_lists_both_runner_forms_grouped_by_source() {
        let qs = vec![
            NamedQuery {
                name: "OS version".into(),
                query: "SELECT version FROM os_version;".into(),
                source: "security-posture.reports.yml".into(),
            },
            NamedQuery {
                name: "Firewall".into(),
                query: "SELECT global_state FROM alf;".into(),
                source: "security-posture.reports.yml".into(),
            },
        ];
        let md = render_markdown(&qs);
        assert!(md.contains("## security-posture.reports.yml"));
        assert!(md.contains("### OS version"));
        // Both runner forms appear: osqueryi and sudo orbit shell.
        assert!(md.contains("--json \"SELECT version FROM os_version;\""));
        assert!(md.contains("sudo "));
        assert!(md.contains("orbit shell -- --json \"SELECT global_state FROM alf;\""));
        assert!(md.contains("for 2 queries"));
    }

    #[test]
    fn write_markdown_creates_parent_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("osquery/verify-commands.md");
        let qs = vec![NamedQuery {
            name: "x".into(),
            query: "SELECT 1;".into(),
            source: "a.reports.yml".into(),
        }];
        write_markdown(&path, &qs).unwrap();
        assert!(path.exists());
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("# osquery verification commands")
        );
    }
}
