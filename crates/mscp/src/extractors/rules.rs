use crate::layout::MscpLayout;
use crate::models::MscpRule;
use crate::models::mscp::Platform;
use crate::models::rule_v2::MscpRuleV2x;
use anyhow::{Context, Result};
use std::cell::OnceCell;
use std::fs;
use std::path::{Path, PathBuf};

/// Extractor for mSCP rule YAML files.
///
/// Supports both 1.x (flat schema) and 2.0 (multi-OS schema) repository
/// layouts. Auto-detects on first use unless [`with_layout`] sets one
/// explicitly. For 2.0 trees, [`with_os`] picks the OS+version target;
/// defaults are macOS + the latest version found in the rule set.
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
    /// Construct an extractor that auto-detects layout on first use.
    /// Defaults to macOS targeting; for 2.0 trees the latest available
    /// macOS version is chosen automatically.
    pub fn new<P: AsRef<Path>>(mscp_repo_path: P) -> Self {
        Self {
            mscp_repo_path: mscp_repo_path.as_ref().to_path_buf(),
            layout: OnceCell::new(),
            os: Platform::MacOS,
            os_version: None,
        }
    }

    /// Pin the layout explicitly (skips auto-detection).
    #[must_use]
    pub fn with_layout(self, layout: MscpLayout) -> Self {
        // OnceCell::set takes &self via interior mutability; no `mut` needed.
        let _ = self.layout.set(layout);
        self
    }

    /// Set the OS target (only meaningful for 2.0 layouts).
    #[must_use]
    pub fn with_os(mut self, os: Platform, os_version: Option<String>) -> Self {
        self.os = os;
        self.os_version = os_version;
        self
    }

    /// Resolve the layout — cached after first call.
    fn layout(&self) -> Result<MscpLayout> {
        if let Some(l) = self.layout.get() {
            return Ok(*l);
        }
        let detected = MscpLayout::detect(&self.mscp_repo_path)?;
        let _ = self.layout.set(detected);
        Ok(detected)
    }

    /// Resolve the OS version: explicit override, or the latest version
    /// the rule set advertises for the chosen OS, or `None` if 1.x.
    fn resolved_os_version(&self, layout: MscpLayout) -> Option<String> {
        if matches!(layout, MscpLayout::V1x) {
            return None;
        }
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
        let layout = self.layout()?;
        match layout {
            MscpLayout::V1x => self.extract_v1x(),
            MscpLayout::V2x => {
                let os_version = self
                    .resolved_os_version(layout)
                    .context("no OS version available for 2.0 extraction")?;
                self.extract_v2x(self.os, &os_version)
            }
        }
    }

    /// Extract rules for a specific baseline (filtered by `tags` membership
    /// after normalization).
    pub fn extract_rules_for_baseline(&self, baseline_name: &str) -> Result<Vec<MscpRule>> {
        let all_rules = self.extract_all_rules()?;
        let filtered: Vec<MscpRule> = all_rules
            .into_iter()
            .filter(|r| r.is_in_baseline(baseline_name))
            .collect();
        tracing::info!(
            "Found {} rules for baseline '{}'",
            filtered.len(),
            baseline_name
        );
        Ok(filtered)
    }

    fn extract_v1x(&self) -> Result<Vec<MscpRule>> {
        let rules_dir = self.mscp_repo_path.join("rules");
        if !rules_dir.exists() {
            anyhow::bail!(
                "Rules directory not found: {}. Is this a valid mSCP repository?",
                rules_dir.display()
            );
        }
        let mut rules = Vec::new();
        for entry in walkdir::WalkDir::new(&rules_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                match parse_v1x_rule(path) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => tracing::warn!("Failed to parse rule {}: {}", path.display(), e),
                }
            }
        }
        tracing::info!(
            "Extracted {} rules from {} (v1.x)",
            rules.len(),
            rules_dir.display()
        );
        Ok(rules)
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
    pub fn get_baseline_stats(&self, baseline_name: &str) -> Result<RuleStats> {
        let rules = self.extract_rules_for_baseline(baseline_name)?;
        Ok(RuleStats::from_rules(&rules))
    }
}

fn parse_v1x_rule<P: AsRef<Path>>(path: P) -> Result<MscpRule> {
    let content = fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read rule file: {}", path.as_ref().display()))?;
    let rule: MscpRule = yaml_serde::from_str(&content)
        .with_context(|| format!("Failed to parse rule YAML: {}", path.as_ref().display()))?;
    Ok(rule)
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

    #[test]
    #[ignore = "requires actual mSCP repository"]
    fn test_extract_rules() {
        let extractor = RuleExtractor::new("./macos_security");
        let rules = extractor.extract_all_rules().unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    #[ignore = "requires actual mSCP repository"]
    fn test_extract_baseline_rules() {
        let extractor = RuleExtractor::new("./macos_security");
        let rules = extractor.extract_rules_for_baseline("cis_lvl1").unwrap();
        assert!(!rules.is_empty());
    }

    /// Live: extract from dev_2.0 tree and confirm V2x path runs.
    #[test]
    fn live_v2x_extraction_smoke() {
        let repo = Path::new("/Users/henry/Projects/Dev/macos_security");
        if !repo.join("rules").exists() {
            return;
        }
        let extractor = RuleExtractor::new(repo);
        let rules = extractor.extract_all_rules().expect("extract");
        assert!(!rules.is_empty(), "expected non-zero rules from dev_2.0");
        // At least some rules should have macOS as a target.
        assert!(
            rules.iter().any(|r| !r.macos.is_empty()),
            "no rules carry macOS targets"
        );
    }
}
