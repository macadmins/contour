//! mSCP repository layout verification (2.0 only).
//!
//! contour reads the mSCP 2.0 schema: the `main` branch of macos_security,
//! where every rule carries a `platforms:` block and baselines live at
//! `baselines/<os>/<name>_<os>_<version>.yaml`. The 1.x layout (flat rule
//! schema with top-level `tags`/`check`/`fix`, baselines at
//! `baselines/<name>.yaml`, the `tahoe`/`sequoia`/… release branches) is
//! deprecated upstream and no longer parsed here.
//!
//! [`MscpLayout::detect`] sniffs the first rule YAML it finds. `platforms:`
//! ⇒ 2.0. An `id:` without `platforms:` is the 1.x shape and is refused with
//! the fix spelled out, rather than parsed into something plausible: the
//! embedded dataset, the recipe pipeline and the build all assume 2.0, and a
//! 1.x tree quietly answered "zero rules" before this was a hard stop.

use anyhow::{Context, Result, anyhow, bail};
use std::fmt;
use std::path::{Path, PathBuf};

/// Proof that a repository holds the mSCP 2.0 layout, and the owner of its
/// file-name grammar.
///
/// Obtained from [`Self::detect`]. Carrying the value (rather than a bool)
/// keeps every path computation behind one type that has already checked
/// the tree, so callers cannot build a 2.0 path against a 1.x checkout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MscpLayout;

impl MscpLayout {
    /// Human-readable name for help text and diagnostics.
    pub fn display_name(self) -> &'static str {
        "2.0 (multi-OS schema)"
    }

    /// Resolve `<repo>/rules`. mSCP 2.0 keeps `rules` as a symlink to the
    /// canonical tree, so path-based access works on a plain checkout.
    pub fn rules_dir(self, repo: &Path) -> PathBuf {
        repo.join("rules")
    }

    /// Resolve `<repo>/baselines`, the parent of the per-OS directories.
    pub fn baselines_dir(self, repo: &Path) -> PathBuf {
        repo.join("baselines")
    }

    /// Every baseline file defined for `os`, as `(name, os_version, path)`,
    /// sorted by name then version.
    ///
    /// `baselines/<os>/<name>_<os>_<version>.yaml` → the canonical name with
    /// the `_<os>_<version>` suffix stripped, and the version. This is the one
    /// place that knows the file-name grammar. Callers that listed
    /// `baselines/` themselves found only the `ios/ macos/ visionos/`
    /// directories and no YAML — an empty answer that looked like "no
    /// baselines" rather than "wrong directory".
    pub fn list_baselines(self, repo: &Path, os: &str) -> Result<Vec<(String, String, PathBuf)>> {
        let dir = self.baselines_dir(repo).join(os);
        let entries = std::fs::read_dir(&dir).map_err(|e| {
            anyhow!(
                "reading mSCP {self} baselines directory {}: {e}",
                dir.display()
            )
        })?;

        let mut out = Vec::new();
        for entry in entries.filter_map(std::result::Result::ok) {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // `<name>_<os>_<version>` — split on the LAST `_<os>_` so a name
            // that itself contains the token cannot shift the cut.
            let token = format!("_{os}_");
            if let Some((name, version)) = stem.rsplit_once(&token) {
                out.push((name.to_string(), version.to_string(), path));
            }
            // A yaml in this directory without the suffix is not a baseline
            // for this OS; skip it rather than invent a name.
        }
        out.sort();
        Ok(out)
    }

    /// The baseline YAML for `name` on `os`, or an error naming the path
    /// that was tried.
    ///
    /// With `os_version = None` the newest version present is chosen, by
    /// numeric major.minor — not lexically, so `10.15` never beats `26.0`.
    ///
    /// This deliberately does **not** return `Option`: `None` would let a
    /// caller fall back to tag membership, and a wrong name would silently
    /// produce an empty answer. Callers that have a legitimate fallback
    /// (tag-only baselines exist) decide that themselves, with the failed
    /// path in hand.
    pub fn baseline_file(
        self,
        repo: &Path,
        name: &str,
        os: &str,
        os_version: Option<&str>,
    ) -> Result<PathBuf> {
        let version = match os_version {
            Some(v) => v.to_string(),
            None => {
                let mut versions: Vec<(u32, u32, String)> = self
                    .list_baselines(repo, os)?
                    .into_iter()
                    .filter(|(n, _, _)| n == name)
                    .filter_map(|(_, v, _)| {
                        let mut parts = v.split('.');
                        let major: u32 = parts.next()?.parse().ok()?;
                        let minor: u32 = parts.next().and_then(|m| m.parse().ok()).unwrap_or(0);
                        Some((major, minor, v))
                    })
                    .collect();
                versions.sort();
                versions.pop().map(|(_, _, v)| v).ok_or_else(|| {
                    anyhow!(
                        "no mSCP 2.0 baseline files matching `{name}_{os}_*.yaml` under {}",
                        self.baselines_dir(repo).join(os).display()
                    )
                })?
            }
        };
        let path = self
            .baselines_dir(repo)
            .join(os)
            .join(format!("{name}_{os}_{version}.yaml"));

        if !path.exists() {
            bail!(
                "baseline YAML not found: {} (mSCP {self} layout)",
                path.display()
            );
        }
        Ok(path)
    }

    /// Verify that `repo` holds the mSCP 2.0 layout.
    ///
    /// Walks `<repo>/rules/` (resolves symlinks), takes the first `*.yaml`
    /// it can read, and inspects the top-level keys.
    ///
    /// # Errors
    /// - No `rules/` directory under `repo`
    /// - No `*.yaml` files found in the tree
    /// - The rule is the deprecated 1.x shape (`id:` without `platforms:`):
    ///   the error names the file and says how to move to `main`
    /// - The rule matches neither schema
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

        let has_platforms = map.contains_key(yaml_serde::Value::String("platforms".into()));
        let has_id = map.contains_key(yaml_serde::Value::String("id".into()));
        if has_platforms {
            Ok(Self)
        } else if has_id {
            // Script-only and mobileconfig-only 1.x rules may lack `check`
            // or `tags`; an `id` with no `platforms` block is the 1.x shape.
            bail!(
                "mSCP 1.x layout detected at {sample}: rules carry top-level \
                 `tags`/`check` and no `platforms:` block. contour reads mSCP 2.0 \
                 only; 1.x is deprecated upstream and its release branches \
                 (`tahoe`, `sequoia`, …) receive no new rules. Switch the checkout \
                 to `main`:\n  git -C {repo} fetch origin main && git -C {repo} \
                 checkout main\nCustom 1.x baselines migrate with mSCP's own \
                 `--migrate` flag.",
                sample = sample.display(),
                repo = repo.display()
            )
        } else {
            bail!(
                "could not detect mSCP layout from {}: not a recognizable mSCP rule \
                 (no `id` or `platforms` at top level)",
                sample.display()
            )
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
    fn detect_accepts_a_platforms_rule() {
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules").join("os");
        write_rule(
            &rules,
            "sample.yaml",
            "id: x\ntitle: x\ndiscussion: x\nplatforms:\n  macOS:\n    '15.0':\n      benchmarks:\n        - name: cis_lvl1\nreferences: {}\n",
        );
        assert_eq!(MscpLayout::detect(tmp.path()).unwrap(), MscpLayout);
    }

    /// The 1.x shape is refused, not parsed — and the refusal says what to do.
    #[test]
    fn detect_refuses_a_1x_flat_rule_and_names_the_fix() {
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules").join("audit");
        write_rule(
            &rules,
            "sample.yaml",
            "id: x\ntitle: x\ncheck: 'true'\nfix: 'true'\ntags: [cis_lvl1]\n",
        );
        let err = MscpLayout::detect(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("1.x layout"), "err: {err}");
        assert!(err.contains("sample.yaml"), "err must name the file: {err}");
        assert!(
            err.contains("checkout main"),
            "err must give the fix: {err}"
        );
    }

    /// Mobileconfig-only 1.x rules lack `check`/`tags`; an `id` with no
    /// `platforms` is still 1.x and still refused.
    #[test]
    fn detect_refuses_an_id_only_rule_as_1x() {
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules");
        write_rule(&rules, "sample.yaml", "id: x\ntitle: x\n");
        let err = MscpLayout::detect(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("1.x layout"), "err: {err}");
    }

    #[test]
    fn detect_errors_on_missing_rules_dir() {
        let tmp = tempdir().unwrap();
        let err = MscpLayout::detect(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("no rules/ directory"));
    }

    #[test]
    fn detect_errors_on_unrecognized_schema() {
        let tmp = tempdir().unwrap();
        let rules = tmp.path().join("rules");
        write_rule(&rules, "sample.yaml", "title: missing-id\n");
        let err = MscpLayout::detect(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("could not detect"), "err: {err}");
        assert!(
            !err.contains("1.x"),
            "an id-less file is not a 1.x rule: {err}"
        );
    }

    /// Live smoke against a real checkout: point `CONTOUR_MSCP_REPO` at an
    /// mSCP 2.0 (`main`) tree to enable it. Skipped when unset, so the suite
    /// does not depend on any one machine's layout.
    #[test]
    fn detect_live_main_tree() {
        let Some(repo) = std::env::var_os("CONTOUR_MSCP_REPO").map(PathBuf::from) else {
            return;
        };
        if !repo.join("rules").exists() {
            return;
        }
        MscpLayout::detect(&repo).expect("main should verify as 2.0");
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn list_baselines_strips_the_os_version_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            &tmp.path()
                .join("baselines/macos/example_baseline_macos_27.0.yaml"),
            "profile: []\n",
        );
        write(
            &tmp.path()
                .join("baselines/macos/example_baseline_macos_26.0.yaml"),
            "profile: []\n",
        );
        write(
            &tmp.path()
                .join("baselines/ios/example_baseline_ios_27.0.yaml"),
            "profile: []\n",
        );
        // A stray yaml without the suffix is not a baseline for this OS.
        write(&tmp.path().join("baselines/macos/README.yaml"), "x: 1\n");
        let got = MscpLayout.list_baselines(tmp.path(), "macos").unwrap();
        let pairs: Vec<(&str, &str)> = got
            .iter()
            .map(|(n, v, _)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![("example_baseline", "26.0"), ("example_baseline", "27.0")]
        );
    }

    #[test]
    fn baseline_file_picks_the_newest_version_numerically() {
        let tmp = tempfile::tempdir().unwrap();
        // 10.15 sorts AFTER 26.0 lexically; numerically it is older. The
        // lookup must not hand back a Catalina baseline on a 26.0 tree.
        write(
            &tmp.path()
                .join("baselines/macos/example_baseline_macos_10.15.yaml"),
            "profile: []\n",
        );
        write(
            &tmp.path()
                .join("baselines/macos/example_baseline_macos_26.0.yaml"),
            "profile: []\n",
        );
        let p = MscpLayout
            .baseline_file(tmp.path(), "example_baseline", "macos", None)
            .unwrap();
        assert!(
            p.ends_with("example_baseline_macos_26.0.yaml"),
            "got {}",
            p.display()
        );
    }

    #[test]
    fn baseline_file_honours_an_explicit_version() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            &tmp.path()
                .join("baselines/macos/example_baseline_macos_26.0.yaml"),
            "profile: []\n",
        );
        write(
            &tmp.path()
                .join("baselines/macos/example_baseline_macos_27.0.yaml"),
            "profile: []\n",
        );
        let p = MscpLayout
            .baseline_file(tmp.path(), "example_baseline", "macos", Some("26.0"))
            .unwrap();
        assert!(p.ends_with("example_baseline_macos_26.0.yaml"));
    }

    #[test]
    fn missing_baseline_file_errors_with_the_path_and_layout() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("baselines/macos")).unwrap();
        let err = MscpLayout
            .baseline_file(tmp.path(), "nope", "macos", Some("27.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope_macos_27.0.yaml"), "err: {err}");
        assert!(err.contains("2.0"), "err should name the layout: {err}");
    }
}
