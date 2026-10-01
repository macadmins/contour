use crate::layout::MscpLayout;
use crate::models::MscpRule;
use crate::models::mscp::Platform;
use crate::models::rule_v2::MscpRuleV2x;
use anyhow::{Context, Result};
use std::cell::OnceCell;
use std::fs;
use std::path::{Path, PathBuf};

/// Extractor for mSCP 2.0 rule YAML files.
///
/// Verifies the repository layout on first use unless [`with_layout`]
/// supplies an already-verified one. [`with_os`] picks the OS+version
/// target; defaults are macOS + the latest version found in the rule set.
/// A 1.x checkout is refused by [`MscpLayout::detect`], not parsed.
///
/// [`with_layout`]: RuleExtractor::with_layout
/// [`with_os`]: RuleExtractor::with_os
#[derive(Debug)]
pub struct RuleExtractor {
    mscp_repo_path: PathBuf,
    layout: OnceCell<MscpLayout>,
    os: Platform,
    os_version: Option<String>,
}

impl RuleExtractor {
    /// Construct an extractor that verifies the layout on first use.
    /// Defaults to macOS targeting; the latest available macOS version is
    /// chosen automatically.
    pub fn new<P: AsRef<Path>>(mscp_repo_path: P) -> Self {
        Self {
            mscp_repo_path: mscp_repo_path.as_ref().to_path_buf(),
            layout: OnceCell::new(),
            os: Platform::MacOS,
            os_version: None,
        }
    }

    /// Supply an already-verified layout (skips detection).
    #[must_use]
    pub fn with_layout(self, layout: MscpLayout) -> Self {
        // OnceCell::set takes &self via interior mutability; no `mut` needed.
        let _ = self.layout.set(layout);
        self
    }

    /// Set the OS target and, optionally, the OS version.
    #[must_use]
    pub fn with_os(mut self, os: Platform, os_version: Option<String>) -> Self {
        self.os = os;
        self.os_version = os_version;
        self
    }

    /// Verify the layout — cached after first call.
    fn layout(&self) -> Result<MscpLayout> {
        if let Some(l) = self.layout.get() {
            return Ok(*l);
        }
        let detected = MscpLayout::detect(&self.mscp_repo_path)?;
        let _ = self.layout.set(detected);
        Ok(detected)
    }

    /// Resolve the OS version: explicit override, or the latest version
    /// the rule set advertises for the chosen OS.
    fn resolved_os_version(&self) -> Option<String> {
        if let Some(ref v) = self.os_version {
            return Some(v.clone());
        }
        // Sniff one rule and pick the highest version key for our OS.
        // Cheap fallback — Phase 6 fixtures and live tree both surface
        // versions like "26.0", "18.0", "15.0" lexicographically sortable.
        self.latest_os_version_in_repo().ok()
    }

    fn latest_os_version_in_repo(&self) -> Result<String> {
        let rules_dir = self.mscp_repo_path.join("rules");
        let mut max: Option<String> = None;
        for entry in walkdir::WalkDir::new(&rules_dir)
            .max_depth(3)
            .follow_links(true)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .take(50)
        // 50 rule sample is enough to surface the OS's highest version
        {
            let p = entry.path();
            if !p.is_file() || p.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            let Ok(text) = fs::read_to_string(p) else {
                continue;
            };
            let Ok(rule) = yaml_serde::from_str::<MscpRuleV2x>(&text) else {
                continue;
            };
            let platform_os = match self.os {
                Platform::MacOS => rule.platforms.macos.as_ref(),
                Platform::Ios => rule.platforms.ios.as_ref(),
                Platform::VisionOS => rule.platforms.visionos.as_ref(),
            };
            if let Some(p) = platform_os {
                for v in p.versions.keys() {
                    if max.as_deref().is_none_or(|m| v.as_str() > m) {
                        max = Some(v.clone());
                    }
                }
            }
        }
        max.ok_or_else(|| anyhow::anyhow!("no OS versions found for {} in 2.0 rule set", self.os))
    }

    /// Extract all rules from the mSCP repository, normalized to [`MscpRule`].
    pub fn extract_all_rules(&self) -> Result<Vec<MscpRule>> {
        self.layout()?;
        let os_version = self
            .resolved_os_version()
            .context("no OS version available for 2.0 extraction")?;
        self.extract_v2x(self.os, &os_version)
    }

    /// Extract rules for a specific baseline.
    ///
    /// Membership comes from the baseline file's own explicit `profile[].rules[]`
    /// id list when a file exists — the authoritative source. When there is no
    /// file, membership falls back to `tags`, which is legitimate for the
    /// baselines mSCP 2.0 defines only as rule benchmark tags (`indigo_*`,
    /// `ios_*`, `nlmapgov_*`, `mscp`): on 2.0 each rule's tags are already
    /// scoped to this extractor's (os, version), so the fallback cannot bleed
    /// across platforms.
    ///
    /// What it will not do is answer with an empty set on a 2.0 tree. No file
    /// AND no rule tagging the name means the name is wrong, and zero rules
    /// with a green exit would hide that.
    pub fn extract_rules_for_baseline(&self, baseline_name: &str) -> Result<Vec<MscpRule>> {
        let all_rules = self.extract_all_rules()?;
        let filtered: Vec<MscpRule> = match self.baseline_rule_ids(baseline_name)? {
            BaselineMembership::Explicit(ids) => {
                let id_set: std::collections::HashSet<&str> =
                    ids.iter().map(String::as_str).collect();
                all_rules
                    .into_iter()
                    .filter(|r| id_set.contains(r.id.as_str()))
                    .collect()
            }
            BaselineMembership::NoFile(tried) => {
                let by_tag: Vec<MscpRule> = all_rules
                    .into_iter()
                    .filter(|r| r.is_in_baseline(baseline_name))
                    .collect();
                // Empty is a legitimate answer when the baseline exists but has
                // no members for THIS target — `ios_only` asked for on macOS.
                // It is only a wrong name when nothing on any OS knows it: no
                // file in any `baselines/<os>/` and no rule tagging it for any
                // platform. Zero rules with a green exit would be
                // indistinguishable from the legitimate case.
                if by_tag.is_empty() && !self.baseline_known_anywhere(baseline_name)? {
                    anyhow::bail!(
                        "baseline `{baseline_name}`: no file at {} and no rule on any platform \
                         carries it as a benchmark tag — check the name (`mscp schema baselines` \
                         lists what exists)",
                        tried.display()
                    );
                }
                by_tag
            }
        };
        tracing::info!(
            "Found {} rules for baseline '{}'",
            filtered.len(),
            baseline_name
        );
        Ok(filtered)
    }

    /// Is `name` a baseline this 2.0 tree knows about on ANY platform — either
    /// as a file under some `baselines/<os>/`, or as a benchmark tag on some
    /// rule for some OS/version?
    ///
    /// Distinguishes "no members for this target" (fine, return empty) from
    /// "no such baseline" (a typo, refuse). Error path only, so walking every
    /// rule once is acceptable.
    fn baseline_known_anywhere(&self, name: &str) -> Result<bool> {
        let layout = self.layout()?;
        for os in ["macos", "ios", "visionos"] {
            // A missing platform directory is not evidence of anything.
            if let Ok(files) = layout.list_baselines(&self.mscp_repo_path, os)
                && files.iter().any(|(n, _, _)| n == name)
            {
                return Ok(true);
            }
        }

        let rules_dir = layout.rules_dir(&self.mscp_repo_path);
        if !rules_dir.exists() {
            return Ok(false);
        }
        for entry in walkdir::WalkDir::new(&rules_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let p = entry.path();
            if !p.is_file() || p.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            let Ok(text) = fs::read_to_string(p) else {
                continue;
            };
            // Cheap textual pre-filter before paying for a YAML parse.
            if !text.contains(name) {
                continue;
            }
            let Ok(rule) = yaml_serde::from_str::<MscpRuleV2x>(&text) else {
                continue;
            };
            for platform_os in [
                rule.platforms.macos.as_ref(),
                rule.platforms.ios.as_ref(),
                rule.platforms.visionos.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if platform_os
                    .versions
                    .values()
                    .any(|v| v.benchmarks.iter().any(|b| b.name == name))
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// The explicit rule-id membership list a baseline file declares under
    /// `profile[].rules[]`, flattened across sections in document order — or
    /// the path that was looked for, so the caller can say what was missing.
    ///
    /// The path comes from [`MscpLayout::baseline_file`], which owns the
    /// file-name grammar: on a 2.0 tree it is
    /// `baselines/<os>/<name>_<os>_<version>.yaml`, not `baselines/<name>.yaml`.
    fn baseline_rule_ids(&self, baseline_name: &str) -> Result<BaselineMembership> {
        let layout = self.layout()?;
        let os = self.os.mscp_dir_name();
        // Match the version the rules themselves are extracted at, so the
        // membership file and the rule set describe the same OS release.
        let version = self
            .resolved_os_version()
            .context("no OS version available for 2.0 baseline lookup")?;

        let path =
            match layout.baseline_file(&self.mscp_repo_path, baseline_name, os, Some(&version)) {
                Ok(p) => p,
                Err(_) => {
                    // Reconstruct the path that was tried purely for the message;
                    // baseline_file already established it does not exist.
                    let tried = layout
                        .baselines_dir(&self.mscp_repo_path)
                        .join(os)
                        .join(format!("{baseline_name}_{os}_{version}.yaml"));
                    return Ok(BaselineMembership::NoFile(tried));
                }
            };

        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading baseline {}", path.display()))?;
        let parsed: BaselineMembership_ = yaml_serde::from_str(&text)
            .with_context(|| format!("parsing baseline {}", path.display()))?;
        let ids: Vec<String> = parsed
            .profile
            .into_iter()
            .flat_map(|section| section.rules)
            .collect();
        if ids.is_empty() {
            return Ok(BaselineMembership::NoFile(path));
        }
        Ok(BaselineMembership::Explicit(ids))
    }

    fn extract_v2x(&self, os: Platform, os_version: &str) -> Result<Vec<MscpRule>> {
        let rules_dir = self.mscp_repo_path.join("rules");
        if !rules_dir.exists() {
            anyhow::bail!(
                "Rules directory not found: {}. Is this a valid mSCP repository?",
                rules_dir.display()
            );
        }
        let mut rules = Vec::new();
        for entry in walkdir::WalkDir::new(&rules_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                match parse_v2x_rule(path).map(|r| r.into_normalized(os, os_version)) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => tracing::warn!("Failed to parse 2.0 rule {}: {}", path.display(), e),
                }
            }
        }
        tracing::info!(
            "Extracted {} rules from {} (v2.0, os={}, version={})",
            rules.len(),
            rules_dir.display(),
            os,
            os_version,
        );
        Ok(rules)
    }

    /// Get statistics about rules in a baseline
    #[allow(dead_code, reason = "lib API; bin doesn't currently surface stats")]
    pub fn get_baseline_stats(&self, baseline_name: &str) -> Result<RuleStats> {
        let rules = self.extract_rules_for_baseline(baseline_name)?;
        Ok(RuleStats::from_rules(&rules))
    }
}

/// How a baseline's membership was determined.
#[derive(Debug)]
enum BaselineMembership {
    /// The baseline file's explicit `profile[].rules[]` list.
    Explicit(Vec<String>),
    /// No usable file; carries the path that was looked for.
    NoFile(std::path::PathBuf),
}

/// Minimal view of a 1.x baseline file: just the rule-id membership under
/// `profile[].rules[]`. All other baseline fields are ignored.
#[derive(serde::Deserialize)]
struct BaselineMembership_ {
    #[serde(default)]
    profile: Vec<BaselineSection>,
}

#[derive(serde::Deserialize)]
struct BaselineSection {
    #[serde(default)]
    rules: Vec<String>,
}

fn parse_v2x_rule<P: AsRef<Path>>(path: P) -> Result<MscpRuleV2x> {
    let content = fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read 2.0 rule file: {}", path.as_ref().display()))?;
    let rule: MscpRuleV2x = yaml_serde::from_str(&content)
        .with_context(|| format!("Failed to parse 2.0 rule YAML: {}", path.as_ref().display()))?;
    Ok(rule)
}

/// Statistics about rules in a baseline
#[derive(Debug, Default)]
pub struct RuleStats {
    pub total: usize,
    pub mobileconfig_rules: usize,
    pub script_rules: usize,
    pub executable_script_rules: usize,
    pub non_executable_script_rules: usize,
    pub check_only_rules: usize,
}

impl RuleStats {
    /// Build statistics from a pre-loaded slice of rules.
    pub fn from_rules(rules: &[MscpRule]) -> Self {
        let mut stats = Self {
            total: rules.len(),
            ..Default::default()
        };

        for rule in rules {
            if rule.mobileconfig {
                stats.mobileconfig_rules += 1;
            }

            if rule.has_script_remediation() {
                stats.script_rules += 1;

                if rule.has_executable_fix() {
                    stats.executable_script_rules += 1;
                } else {
                    stats.non_executable_script_rules += 1;
                }
            }

            if rule.check.is_some() && rule.fix.is_none() {
                stats.check_only_rules += 1;
            }
        }

        stats
    }

    pub fn print_summary(&self, baseline_name: &str) {
        println!("\n=== Rule Statistics for '{baseline_name}' ===");
        println!("Total rules: {}", self.total);
        println!("  - Mobileconfig rules: {}", self.mobileconfig_rules);
        println!("  - Script-based rules: {}", self.script_rules);
        println!(
            "    - Executable fix scripts: {}",
            self.executable_script_rules
        );
        println!(
            "    - Non-executable fixes: {}",
            self.non_executable_script_rules
        );
        println!("  - Check-only rules: {}", self.check_only_rules);
        println!(
            "\nMunki nopkg items will be generated for: {} rules",
            self.executable_script_rules
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checkout named by `CONTOUR_MSCP_REPO`, as the other mSCP tests
    /// find theirs. Panics when asked to run without one: an ignored test
    /// that cannot find its input must say so, not pass.
    fn checkout() -> String {
        let repo = std::env::var("CONTOUR_MSCP_REPO").unwrap_or_else(|_| {
            panic!("asked to run (--include-ignored) but CONTOUR_MSCP_REPO is not set")
        });
        assert!(
            std::path::Path::new(&repo).join("rules").is_dir(),
            "CONTOUR_MSCP_REPO={repo} has no rules/ directory"
        );
        repo
    }

    #[test]
    #[ignore = "needs an mSCP checkout — set CONTOUR_MSCP_REPO and run with --include-ignored"]
    fn test_extract_rules() {
        let extractor = RuleExtractor::new(checkout());
        let rules = extractor.extract_all_rules().unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    #[ignore = "needs an mSCP checkout — set CONTOUR_MSCP_REPO and run with --include-ignored"]
    fn test_extract_baseline_rules() {
        let extractor = RuleExtractor::new(checkout());
        let rules = extractor.extract_rules_for_baseline("cis_lvl1").unwrap();
        assert!(!rules.is_empty());
    }

    /// 2.0 tree: the lookup must resolve `baselines/<os>/<name>_<os>_<version>.yaml`.
    #[test]
    fn baseline_rule_ids_resolves_the_2_0_nested_path() {
        let tmp = tempfile::tempdir().unwrap();
        let bdir = tmp.path().join("baselines").join("macos");
        std::fs::create_dir_all(&bdir).unwrap();
        std::fs::write(
            bdir.join("example_baseline_macos_27.0.yaml"),
            "title: 'macOS 27.0: Security Configuration - example_baseline'\nparent_values: recommended\nplatform:\n  os: macOS\n  version: 27.0\nprofile:\n  - section: os\n    rules:\n      - os_example_rule_enable\n      - os_example_other_disable\n",
        )
        .unwrap();
        let ex = RuleExtractor::new(tmp.path())
            .with_layout(MscpLayout)
            .with_os(Platform::MacOS, Some("27.0".to_string()));
        match ex.baseline_rule_ids("example_baseline").expect("lookup") {
            BaselineMembership::Explicit(ids) => {
                assert_eq!(
                    ids,
                    vec!["os_example_rule_enable", "os_example_other_disable"]
                );
            }
            other @ BaselineMembership::NoFile(_) => {
                panic!("expected explicit ids from the 2.0 file, got {other:?}")
            }
        }
    }

    /// 2.0 tree, wrong name: the miss must name the nested path it tried,
    /// not the 1.x flat one.
    #[test]
    fn baseline_rule_ids_names_the_2_0_path_it_tried() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("baselines").join("macos")).unwrap();
        let ex = RuleExtractor::new(tmp.path())
            .with_layout(MscpLayout)
            .with_os(Platform::MacOS, Some("27.0".to_string()));
        match ex.baseline_rule_ids("nope").expect("lookup") {
            BaselineMembership::NoFile(tried) => {
                let t = tried.to_string_lossy();
                assert!(
                    t.contains("baselines/macos/nope_macos_27.0.yaml"),
                    "tried {t}"
                );
            }
            other @ BaselineMembership::Explicit(_) => panic!("expected NoFile, got {other:?}"),
        }
    }

    /// Live: extract from a real mSCP 2.0 (`main`) checkout and confirm it
    /// runs. Point `CONTOUR_MSCP_REPO` at one to enable; skipped otherwise, so
    /// CI and any other machine stay green without it.
    #[test]
    fn live_v2x_extraction_smoke() {
        let Some(repo) = std::env::var_os("CONTOUR_MSCP_REPO").map(PathBuf::from) else {
            return;
        };
        if !repo.join("rules").exists() {
            return;
        }
        let extractor = RuleExtractor::new(&repo);
        let rules = extractor.extract_all_rules().expect("extract");
        assert!(!rules.is_empty(), "expected non-zero rules from main");
        // At least some rules should have macOS as a target.
        assert!(
            rules.iter().any(|r| !r.macos.is_empty()),
            "no rules carry macOS targets"
        );
    }
}
