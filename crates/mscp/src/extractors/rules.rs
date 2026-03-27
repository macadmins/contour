use crate::models::MscpRule;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Extractor for mSCP rule YAML files
#[derive(Debug)]
pub struct RuleExtractor {
    mscp_repo_path: PathBuf,
}

impl RuleExtractor {
    pub fn new<P: AsRef<Path>>(mscp_repo_path: P) -> Self {
        Self {
            mscp_repo_path: mscp_repo_path.as_ref().to_path_buf(),
        }
    }

    /// Extract all rules from the mSCP repository
    pub fn extract_all_rules(&self) -> Result<Vec<MscpRule>> {
        let rules_dir = self.mscp_repo_path.join("rules");

        if !rules_dir.exists() {
            anyhow::bail!(
                "Rules directory not found: {}. Is this a valid mSCP repository?",
                rules_dir.display()
            );
        }

        let mut rules = Vec::new();

        // Walk the rules directory
        for entry in walkdir::WalkDir::new(&rules_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();

            // Only process .yaml files
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                match self.parse_rule_file(path) {
                    Ok(rule) => {
                        rules.push(rule);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse rule {}: {}", path.display(), e);
                    }
                }
            }
        }

        tracing::info!(
            "Extracted {} rules from {}",
            rules.len(),
            rules_dir.display()
        );

        Ok(rules)
    }

    /// Extract rules for a specific baseline
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

    /// Parse a single rule YAML file
    fn parse_rule_file<P: AsRef<Path>>(&self, path: P) -> Result<MscpRule> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read rule file: {}", path.as_ref().display()))?;

        let rule: MscpRule = yaml_serde::from_str(&content)
            .with_context(|| format!("Failed to parse rule YAML: {}", path.as_ref().display()))?;

        Ok(rule)
    }

    /// Get statistics about rules in a baseline
    #[allow(
        dead_code,
        reason = "public API for library consumers; internal callers use RuleStats::from_rules"
    )]
    pub fn get_baseline_stats(&self, baseline_name: &str) -> Result<RuleStats> {
        let rules = self.extract_rules_for_baseline(baseline_name)?;
        Ok(RuleStats::from_rules(&rules))
    }
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
}
