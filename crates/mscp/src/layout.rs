//! mSCP repository layout detection (1.x vs 2.0).
//!
//! Today the macos_security project ships in two coexisting shapes. The
//! `main` branch (mSCP 2.0; `dev_2.0` is now a legacy alias) leaves the
//! 1.x-style `rules`/`baselines` symlinks in place, so path-based
//! extraction keeps reaching the YAML files — but the
//! schema underneath has changed substantially. We need to detect which
//! shape the operator pointed `--mscp-repo` at and parse accordingly.
//!
//! Detection sniffs the first rule YAML it finds and inspects the top-level
//! keys. `platforms:` ⇒ 2.0; `tags:` + `check:` ⇒ 1.x. Anything else returns
//! a clear error so the operator can decide.

use anyhow::{Context, Result, anyhow, bail};
use std::fmt;
use std::path::{Path, PathBuf};

/// Named mSCP repository layout versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MscpLayout {
    /// 1.x — flat rule schema with top-level `tags`, `check`, `fix`,
    /// `result`, `mobileconfig_info` (dict shape), and per-baseline YAML
    /// files under `baselines/`.
    V1x,
    /// 2.0 — multi-OS rule schema with `platforms.{macOS,iOS,visionOS}.<version>`,
    /// nested `enforcement_info`, array-shaped `mobileconfig_info`, and
    /// dynamic baselines derived from `platforms.X.benchmarks[]`.
    #[default]
    V2x,
}

#[allow(
    dead_code,
    reason = "lib API: `all`/`rules_subdir`/`rules_dir`/`baselines_dir` reachable from external consumers + tests; not transitively from the bin's `detect_or_from` → `detect` path"
)]
impl MscpLayout {
    /// All known layouts, newest first.
    pub fn all() -> &'static [Self] {
        &[Self::V2x, Self::V1x]
    }

    /// Resolve a layout from a CLI string. Returns `None` for "auto" so
    /// callers can fall through to [`Self::detect`].
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "1.x" | "v1.x" | "v1" | "1" | "legacy" => Some(Self::V1x),
            "2.0" | "v2.0" | "v2" | "2" | "current" | "latest" => Some(Self::V2x),
            _ => None,
        }
    }

    /// Human-readable name for help text.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::V1x => "1.x (flat schema)",
            Self::V2x => "2.0 (multi-OS schema)",
        }
    }

    /// Subpath under the repo root holding rule YAML files.
    /// Both layouts use `rules/` thanks to the mSCP 2.0 (`main`) symlink,
    /// but callers may want the canonical 2.0 path for diagnostics.
    pub fn rules_subdir(self) -> &'static str {
        match self {
            Self::V1x => "rules",
            // 2.0 still exposes `rules` as a symlink to config/default/rules.
            Self::V2x => "rules",
        }
    }

    /// Resolve `<repo>/rules` for this layout.
    pub fn rules_dir(self, repo: &Path) -> PathBuf {
        repo.join(self.rules_subdir())
    }

    /// Resolve `<repo>/baselines` for this layout. Only meaningful for
    /// 1.x — 2.0 baselines are derived from rule metadata, but the
    /// directory exists as a symlink so callers can probe it.
    pub fn baselines_dir(self, repo: &Path) -> PathBuf {
        repo.join("baselines")
    }

    /// Auto-detect the layout from the contents of a rule YAML file.
    ///
    /// Walks `<repo>/rules/` (resolves symlinks), takes the first
    /// `*.yaml` it can read, and inspects the top-level keys.
    ///
    /// # Errors
    /// - No `rules/` directory under `repo`
    /// - No `*.yaml` files found in the tree
    /// - First rule's top-level keys match neither schema
    pub fn detect(repo: &Path) -> Result<Self> {
        let rules_root = repo.join("rules");
        if !rules_root.exists() {
            bail!(
                "could not detect mSCP layout: no rules/ directory under {}",
                repo.display()
            );
        }

        let sample = first_rule_yaml(&rules_root)?;
        let raw = std::fs::read_to_string(&sample)
            .with_context(|| format!("reading sample rule {}", sample.display()))?;
        let value: yaml_serde::Value = yaml_serde::from_str(&raw)
            .with_context(|| format!("parsing sample rule {}", sample.display()))?;

        let map = value
            .as_mapping()
            .ok_or_else(|| anyhow!("sample rule {} is not a YAML mapping", sample.display()))?;

        // The discriminating signal is the 2.0 `platforms` key. Anything
        // without it is treated as 1.x — covers script-only rules,
        // mobileconfig-only rules, and rules missing optional fields.
        let has_platforms = map.contains_key(yaml_serde::Value::String("platforms".into()));
        let has_id = map.contains_key(yaml_serde::Value::String("id".into()));
        if has_platforms {
            Ok(Self::V2x)
        } else if has_id {
            Ok(Self::V1x)
        } else {
            bail!(
                "could not detect mSCP layout from {}: not a recognizable mSCP rule \
                 (no `id` or `platforms` at top level). Pass --mscp-version 1.x|2.0 to override.",
                sample.display()
            )
        }
    }

    /// Resolve a layout from a CLI override string, falling back to
    /// auto-detection on `None` or `"auto"`.
    pub fn detect_or_from(opt: Option<&str>, repo: &Path) -> Result<Self> {
        match opt {
            None => Self::detect(repo),
            Some(s) if s.eq_ignore_ascii_case("auto") => Self::detect(repo),
            Some(s) => Self::from_name(s).ok_or_else(|| {
                anyhow!("unknown mscp layout '{s}'; expected one of: 1.x, 2.0, auto")
            }),
        }
    }
}

impl fmt::Display for MscpLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Walk `rules_root` and return the first readable `*.yaml` file.
fn first_rule_yaml(rules_root: &Path) -> Result<PathBuf> {
    for entry in walkdir::WalkDir::new(rules_root)
        .max_depth(3)
        .follow_links(true)
        .into_iter()
        .filter_map(Result::ok)
    {
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("yaml") {
            return Ok(p.to_path_buf());
        }
    }
    bail!(
        "no rule YAML files found under {} — is this a macos_security checkout?",
        rules_root.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_rule(dir: &Path, name: &str, body: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn from_name_accepts_aliases() {
        assert_eq!(MscpLayout::from_name("1.x"), Some(MscpLayout::V1x));
        assert_eq!(MscpLayout::from_name("legacy"), Some(MscpLayout::V1x));
        assert_eq!(MscpLayout::from_name("2.0"), Some(MscpLayout::V2x));
        assert_eq!(MscpLayout::from_name("current"), Some(MscpLayout::V2x));
        assert_eq!(MscpLayout::from_name("nope"), None);
    }

    #[test]
    fn detect_v1x_from_flat_rule() {
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules").join("audit");
        write_rule(
            &rules,
            "sample.yaml",
            "id: x\ntitle: x\ncheck: 'true'\nfix: 'true'\ntags: [cis_lvl1]\n",
        );
        assert_eq!(MscpLayout::detect(tmp.path()).unwrap(), MscpLayout::V1x);
    }

    #[test]
    fn detect_v2x_from_platforms_rule() {
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules").join("os");
        write_rule(
            &rules,
            "sample.yaml",
            "id: x\ntitle: x\ndiscussion: x\nplatforms:\n  macOS:\n    '15.0':\n      benchmarks:\n        - name: cis_lvl1\nreferences: {}\n",
        );
        assert_eq!(MscpLayout::detect(tmp.path()).unwrap(), MscpLayout::V2x);
    }

    #[test]
    fn detect_errors_on_missing_rules_dir() {
        let tmp = tempdir().unwrap();
        let err = MscpLayout::detect(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("no rules/ directory"));
    }

    #[test]
    fn detect_v1x_when_only_id_present() {
        // Mobileconfig-only or minimal 1.x rules may lack `check`/`tags`;
        // the absence of `platforms` is enough to call it V1x.
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules");
        write_rule(&rules, "sample.yaml", "id: x\ntitle: x\n");
        assert_eq!(MscpLayout::detect(tmp.path()).unwrap(), MscpLayout::V1x);
    }

    #[test]
    fn detect_errors_on_unrecognized_schema() {
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules");
        write_rule(&rules, "sample.yaml", "title: missing-id\n");
        let err = MscpLayout::detect(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("could not detect"));
    }

    #[test]
    fn detect_or_from_explicit_override() {
        let tmp = tempdir().unwrap();
        // Empty repo — detect would fail, but explicit flag wins.
        assert_eq!(
            MscpLayout::detect_or_from(Some("2.0"), tmp.path()).unwrap(),
            MscpLayout::V2x
        );
    }

    /// Live smoke: only runs if the local mSCP 2.0 (`main`) checkout is
    /// present. Skipped silently in CI where the path doesn't exist.
    #[test]
    fn detect_live_main_tree() {
        let repo = Path::new("/Users/henry/Projects/Dev/macos_security");
        if !repo.join("rules").exists() {
            return;
        }
        let detected = MscpLayout::detect(repo).expect("live detect");
        assert_eq!(detected, MscpLayout::V2x, "main should detect as V2x");
    }
}
