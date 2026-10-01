//! Category-based rule exclusion resolver.
//!
//! Resolves user-provided category names (e.g., "audit", "smartcard") to
//! concrete rule IDs, profiles, and scripts that should be excluded.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::extractors::RuleExtractor;
use crate::models::MscpRule;

/// Information about a discovered category
#[derive(Debug, Clone)]
pub struct CategoryInfo {
    /// Category name (directory name or keyword)
    pub name: String,
    /// Whether this is a top-level directory category
    pub is_directory: bool,
    /// Number of rules in this category (within the baseline, if specified)
    pub rule_count: usize,
}

/// A resolved category with its matched rules and affected artifacts
#[derive(Debug, Clone)]
pub struct ResolvedCategory {
    /// The user-provided category name
    pub name: String,
    /// Rule IDs that matched this category
    pub matched_rules: Vec<String>,
    /// Profile filenames affected (domain.mobileconfig)
    pub affected_profiles: Vec<String>,
    /// Script rule IDs affected
    pub affected_scripts: Vec<String>,
}

/// A profile to be excluded
#[derive(Debug, Clone)]
pub struct ExcludedProfileEntry {
    /// Profile filename (e.g., com.apple.security.smartcard.mobileconfig)
    pub filename: String,
    /// Reason for exclusion
    pub reason: String,
    /// Rule IDs that contribute to this profile
    pub affected_rules: Vec<String>,
}

/// A script to be excluded
#[derive(Debug, Clone)]
pub struct ExcludedScriptEntry {
    /// Rule ID
    pub rule_id: String,
    /// Reason for exclusion
    pub reason: String,
}

/// Result of resolving category names to rules and profiles
#[derive(Debug, Clone)]
pub struct CategoryExclusionPlan {
    /// Successfully resolved categories
    pub resolved: Vec<ResolvedCategory>,
    /// Category names that couldn't be resolved
    pub unresolved: Vec<String>,
    /// Profiles that should be fully excluded
    pub excluded_profiles: Vec<ExcludedProfileEntry>,
    /// Scripts that should be excluded
    pub excluded_scripts: Vec<ExcludedScriptEntry>,
    /// Warnings (e.g., partial profile exclusions)
    pub warnings: Vec<String>,
}

/// Discover available categories by scanning rule directories and extracting
/// sub-category keywords from rule IDs in the baseline.
pub fn discover_categories(mscp_repo: &Path, baseline: Option<&str>) -> Result<Vec<CategoryInfo>> {
    let rules_dir = mscp_repo.join("rules");
    if !rules_dir.exists() {
        anyhow::bail!(
            "Rules directory not found: {}. Is this a valid mSCP repository?",
            rules_dir.display()
        );
    }

    let extractor = RuleExtractor::new(mscp_repo);
    let rules = if let Some(b) = baseline {
        extractor.extract_rules_for_baseline(b)?
    } else {
        extractor.extract_all_rules()?
    };

    let mut categories = Vec::new();

    // 1. Top-level directory categories
    let dir_categories = discover_directory_categories(&rules_dir)?;
    for dir_name in &dir_categories {
        let count = rules
            .iter()
            .filter(|r| rule_matches_directory(&r.id, dir_name))
            .count();
        categories.push(CategoryInfo {
            name: dir_name.clone(),
            is_directory: true,
            rule_count: count,
        });
    }

    // 2. Sub-category keywords extracted from rule IDs
    let keywords = extract_subcategory_keywords(&rules);
    for (keyword, count) in keywords {
        // Skip if it's already a directory category
        if !dir_categories.contains(&keyword) {
            categories.push(CategoryInfo {
                name: keyword,
                is_directory: false,
                rule_count: count,
            });
        }
    }

    // Sort: directories first, then by name
    categories.sort_by(|a, b| {
        b.is_directory
            .cmp(&a.is_directory)
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(categories)
}

/// Resolve user-provided category names to a full exclusion plan.
pub fn build_exclusion_plan(
    categories: &[String],
    mscp_repo: &Path,
    baseline: &str,
) -> Result<CategoryExclusionPlan> {
    let extractor = RuleExtractor::new(mscp_repo);
    let all_baseline_rules = extractor
        .extract_rules_for_baseline(baseline)
        .with_context(|| format!("Failed to extract rules for baseline '{baseline}'"))?;

    let rules_dir = mscp_repo.join("rules");
    let dir_categories = discover_directory_categories(&rules_dir)?;

    let mut plan = CategoryExclusionPlan {
        resolved: Vec::new(),
        unresolved: Vec::new(),
        excluded_profiles: Vec::new(),
        excluded_scripts: Vec::new(),
        warnings: Vec::new(),
    };

    // Collect all excluded rule IDs across all categories
    let mut all_excluded_rule_ids: HashSet<String> = HashSet::new();

    for category in categories {
        let category_lower = category.to_lowercase();

        // Step 1: Try exact match on rules/ subdirectory names
        let matched_rules: Vec<&MscpRule> = if dir_categories.contains(&category_lower) {
            all_baseline_rules
                .iter()
                .filter(|r| rule_matches_directory(&r.id, &category_lower))
                .collect()
        } else {
            Vec::new()
        };

        // Step 2: If no directory match, try substring on rule IDs
        let matched_rules = if matched_rules.is_empty() {
            let substring_matches: Vec<&MscpRule> = all_baseline_rules
                .iter()
                .filter(|r| r.id.to_lowercase().contains(&category_lower))
                .collect();
            substring_matches
        } else {
            matched_rules
        };

        // Step 3: If still no matches, add to unresolved
        if matched_rules.is_empty() {
            plan.unresolved.push(category.clone());
            continue;
        }

        let mut resolved = ResolvedCategory {
            name: category.clone(),
            matched_rules: Vec::new(),
            affected_profiles: Vec::new(),
            affected_scripts: Vec::new(),
        };

        for rule in &matched_rules {
            resolved.matched_rules.push(rule.id.clone());
            all_excluded_rule_ids.insert(rule.id.clone());

            // Determine affected artifacts
            if rule.mobileconfig {
                if let Some(ref mc_info) = rule.mobileconfig_info {
                    let domains = extract_mobileconfig_domains(mc_info);
                    for domain in domains {
                        let filename = format!("{domain}.mobileconfig");
                        if !resolved.affected_profiles.contains(&filename) {
                            resolved.affected_profiles.push(filename);
                        }
                    }
                }
            }

            if rule.has_executable_fix() {
                resolved.affected_scripts.push(rule.id.clone());
            }
        }

        plan.resolved.push(resolved);
    }

    finalize_exclusion_plan(
        &mut plan,
        &all_baseline_rules,
        &all_excluded_rule_ids,
        "--exclude",
    );
    Ok(plan)
}

/// Work out which profiles a set of excluded rules actually removes.
///
/// Shared by the category and rule-ID builders so the two cannot drift: the
/// interesting decision here is that a profile survives unless EVERY rule
/// feeding its domain is excluded, and a partial exclusion warns instead. A
/// second copy of that rule would eventually disagree with the first, and a
/// profile written when it should have been dropped is not something an
/// operator would notice.
///
/// `source` names what asked, and goes into the reason recorded in the
/// constraints file — "--exclude" or "excluded_rules" — so someone reading
/// that file later can tell a CLI flag from a config setting.
fn finalize_exclusion_plan(
    plan: &mut CategoryExclusionPlan,
    all_baseline_rules: &[MscpRule],
    all_excluded_rule_ids: &HashSet<String>,
    source: &str,
) {
    // Determine which profiles can be fully excluded.
    // Group all baseline rules by their mobileconfig domain
    let domain_rules = build_domain_rule_map(&all_baseline_rules);

    // For each domain that has at least one excluded rule, check if ALL rules are excluded
    for (domain, rule_ids) in &domain_rules {
        let filename = format!("{domain}.mobileconfig");
        let all_excluded = rule_ids.iter().all(|id| all_excluded_rule_ids.contains(id));
        let any_excluded = rule_ids.iter().any(|id| all_excluded_rule_ids.contains(id));

        if all_excluded {
            // All rules for this domain are excluded → exclude the profile
            let reasons: Vec<String> = plan
                .resolved
                .iter()
                .filter(|rc| rc.affected_profiles.contains(&filename))
                .map(|rc| rc.name.clone())
                .collect();

            let reason = format!("Excluded by {source} {}", reasons.join(","));

            plan.excluded_profiles.push(ExcludedProfileEntry {
                filename,
                reason,
                affected_rules: rule_ids.clone(),
            });
        } else if any_excluded {
            // Partial exclusion → warning
            let excluded: Vec<&String> = rule_ids
                .iter()
                .filter(|id| all_excluded_rule_ids.contains(*id))
                .collect();
            let remaining: Vec<&String> = rule_ids
                .iter()
                .filter(|id| !all_excluded_rule_ids.contains(*id))
                .collect();

            plan.warnings.push(format!(
                "Profile '{}' partially excluded: {} of {} rules excluded (excluded: {}, remaining: {}). Profile will NOT be excluded.",
                filename,
                excluded.len(),
                rule_ids.len(),
                excluded.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                remaining.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            ));
        }
    }

    // Collect script exclusions
    for resolved in &plan.resolved {
        for script_rule_id in &resolved.affected_scripts {
            let reason = format!("Excluded by {source} {}", resolved.name);
            plan.excluded_scripts.push(ExcludedScriptEntry {
                rule_id: script_rule_id.clone(),
                reason,
            });
        }
    }
}

/// Resolve explicit rule IDs to the artifacts they contribute to.
///
/// The rule-level sibling of [`build_exclusion_plan`]. `mscp.toml`'s
/// `[[baselines]] excluded_rules` names rules directly; categories name
/// groups. Both end in the same plan, so both get the same treatment
/// downstream: a profile is dropped only when every rule feeding it is
/// excluded, a partial match warns, and scripts go per rule.
///
/// Matching is EXACT, case-insensitively. `--exclude` falls back to a
/// substring pass because a category is a loose human label; a rule ID is a
/// precise name, and substring matching it would quietly exclude neighbours
/// — `os_sshd_login` would take every `os_sshd_login_*` with it. An ID that
/// matches nothing lands in `unresolved`, and the caller refuses rather than
/// proceeding: silently excluding nothing is how this setting spent its
/// whole life.
pub fn build_rule_exclusion_plan(
    rule_ids: &[String],
    mscp_repo: &Path,
    baseline: &str,
) -> Result<CategoryExclusionPlan> {
    let extractor = RuleExtractor::new(mscp_repo);
    let all_baseline_rules = extractor
        .extract_rules_for_baseline(baseline)
        .with_context(|| format!("Failed to extract rules for baseline '{baseline}'"))?;

    let mut plan = CategoryExclusionPlan {
        resolved: Vec::new(),
        unresolved: Vec::new(),
        excluded_profiles: Vec::new(),
        excluded_scripts: Vec::new(),
        warnings: Vec::new(),
    };
    let mut all_excluded_rule_ids: HashSet<String> = HashSet::new();

    for wanted in rule_ids {
        let Some(rule) = all_baseline_rules
            .iter()
            .find(|r| r.id.eq_ignore_ascii_case(wanted))
        else {
            plan.unresolved.push(wanted.clone());
            continue;
        };

        let mut resolved = ResolvedCategory {
            // The rule's own id, not what was typed: the plan is written into
            // a constraints file and read back by people.
            name: rule.id.clone(),
            matched_rules: vec![rule.id.clone()],
            affected_profiles: Vec::new(),
            affected_scripts: Vec::new(),
        };
        all_excluded_rule_ids.insert(rule.id.clone());

        if rule.mobileconfig
            && let Some(ref mc_info) = rule.mobileconfig_info
        {
            for domain in extract_mobileconfig_domains(mc_info) {
                let filename = format!("{domain}.mobileconfig");
                if !resolved.affected_profiles.contains(&filename) {
                    resolved.affected_profiles.push(filename);
                }
            }
        }
        if rule.has_executable_fix() {
            resolved.affected_scripts.push(rule.id.clone());
        }
        plan.resolved.push(resolved);
    }

    finalize_exclusion_plan(
        &mut plan,
        &all_baseline_rules,
        &all_excluded_rule_ids,
        "excluded_rules",
    );
    Ok(plan)
}

/// Discover top-level directory names under rules/
fn discover_directory_categories(rules_dir: &Path) -> Result<HashSet<String>> {
    let mut categories = HashSet::new();

    if !rules_dir.exists() {
        return Ok(categories);
    }

    for entry in std::fs::read_dir(rules_dir)
        .with_context(|| format!("Failed to read rules directory: {}", rules_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                // Skip hidden directories
                if !name.starts_with('.') {
                    categories.insert(name.to_lowercase());
                }
            }
        }
    }

    Ok(categories)
}

/// Check if a rule ID matches a directory category.
/// Rules in `rules/audit/` have IDs starting with `audit_`.
fn rule_matches_directory(rule_id: &str, dir_name: &str) -> bool {
    let id_lower = rule_id.to_lowercase();
    let prefix = format!("{}_", dir_name.to_lowercase());
    id_lower.starts_with(&prefix)
}

/// Extract sub-category keywords from rule IDs.
/// E.g., "smartcard" from auth_smartcard_enforce, auth_pam_login_smartcard_enforce
fn extract_subcategory_keywords(rules: &[MscpRule]) -> Vec<(String, usize)> {
    let mut keyword_counts: HashMap<String, usize> = HashMap::new();

    // Known meaningful sub-category keywords used to group rules into finer
    // categories (e.g. "smartcard", "firewall"). When a rule ID contains one
    // of these tokens the rule is tagged with that sub-category.
    // To extend: add a new lowercase keyword that appears as a substring in
    // the relevant rule IDs.
    let known_keywords = [
        "smartcard",
        "ssh",
        "sshd",
        "filevault",
        "firewall",
        "gatekeeper",
        "bluetooth",
        "airdrop",
        "airplay",
        "icloud",
        "siri",
        "password",
        "screensaver",
        "screen_sharing",
        "remote_management",
        "wifi",
        "usb",
        "bonjour",
        "nfs",
        "smb",
        "httpd",
        "ftp",
        "tftp",
    ];

    for rule in rules {
        let id_lower = rule.id.to_lowercase();
        for keyword in &known_keywords {
            if id_lower.contains(keyword) {
                *keyword_counts.entry((*keyword).to_string()).or_insert(0) += 1;
            }
        }
    }

    let mut result: Vec<(String, usize)> = keyword_counts.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    result
}

/// Extract mobileconfig domain names from mobileconfig_info YAML value.
/// The top-level keys in mobileconfig_info are the domains.
fn extract_mobileconfig_domains(mc_info: &yaml_serde::Value) -> Vec<String> {
    let mut domains = Vec::new();

    if let Some(mapping) = mc_info.as_mapping() {
        for (key, _) in mapping {
            if let Some(key_str) = key.as_str() {
                domains.push(key_str.to_string());
            }
        }
    }

    domains
}

/// Build a map from mobileconfig domain to the rule IDs that contribute to it.
fn build_domain_rule_map(rules: &[MscpRule]) -> HashMap<String, Vec<String>> {
    let mut domain_map: HashMap<String, Vec<String>> = HashMap::new();

    for rule in rules {
        if rule.mobileconfig {
            if let Some(ref mc_info) = rule.mobileconfig_info {
                let domains = extract_mobileconfig_domains(mc_info);
                for domain in domains {
                    domain_map.entry(domain).or_default().push(rule.id.clone());
                }
            }
        }
    }

    domain_map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matches_directory() {
        assert!(rule_matches_directory(
            "audit_acls_files_configure",
            "audit"
        ));
        assert!(rule_matches_directory("audit_flags_aa", "audit"));
        assert!(rule_matches_directory("auth_smartcard_enforce", "auth"));
        assert!(!rule_matches_directory("os_filevault_enabled", "audit"));
        assert!(!rule_matches_directory("audit_flags_aa", "auth"));
    }

    #[test]
    fn test_rule_matches_directory_case_insensitive() {
        assert!(rule_matches_directory("Audit_Flags_AA", "audit"));
        assert!(rule_matches_directory("audit_flags_aa", "Audit"));
    }

    #[test]
    fn test_extract_mobileconfig_domains() {
        // Test with empty/non-mapping value
        let null_val = yaml_serde::Value::Null;
        assert!(extract_mobileconfig_domains(&null_val).is_empty());
    }

    #[test]
    fn test_extract_subcategory_keywords() {
        let rules = vec![
            make_test_rule("auth_smartcard_enforce"),
            make_test_rule("auth_smartcard_allow"),
            make_test_rule("auth_pam_login_smartcard_enforce"),
            make_test_rule("os_ssh_fips_ciphers"),
            make_test_rule("os_sshd_client_alive"),
            make_test_rule("audit_flags_aa"),
        ];

        let keywords = extract_subcategory_keywords(&rules);
        let keyword_map: HashMap<&str, usize> =
            keywords.iter().map(|(k, v)| (k.as_str(), *v)).collect();

        assert_eq!(keyword_map.get("smartcard"), Some(&3));
        assert_eq!(keyword_map.get("ssh"), Some(&2)); // ssh matches both ssh and sshd rules
        assert_eq!(keyword_map.get("sshd"), Some(&1));
    }

    /// A rule that names a domain, for the profile-exclusion arithmetic.
    fn mobileconfig_rule(id: &str, domain: &str) -> MscpRule {
        let mut rule = make_test_rule(id);
        rule.mobileconfig = true;
        let mut map = yaml_serde::Mapping::new();
        map.insert(
            yaml_serde::Value::String(domain.to_string()),
            yaml_serde::Value::Null,
        );
        rule.mobileconfig_info = Some(yaml_serde::Value::Mapping(map));
        rule
    }

    fn plan_for(excluded: &[&str], all: &[MscpRule], source: &str) -> CategoryExclusionPlan {
        let mut plan = CategoryExclusionPlan {
            resolved: Vec::new(),
            unresolved: Vec::new(),
            excluded_profiles: Vec::new(),
            excluded_scripts: Vec::new(),
            warnings: Vec::new(),
        };
        let mut ids: HashSet<String> = HashSet::new();
        for id in excluded {
            let rule = all.iter().find(|r| r.id == *id).expect("rule exists");
            ids.insert(rule.id.clone());
            let mut resolved = ResolvedCategory {
                name: rule.id.clone(),
                matched_rules: vec![rule.id.clone()],
                affected_profiles: Vec::new(),
                affected_scripts: Vec::new(),
            };
            if let Some(ref mc) = rule.mobileconfig_info {
                for d in extract_mobileconfig_domains(mc) {
                    resolved.affected_profiles.push(format!("{d}.mobileconfig"));
                }
            }
            plan.resolved.push(resolved);
        }
        finalize_exclusion_plan(&mut plan, all, &ids, source);
        plan
    }

    /// A profile survives while any rule still needs it.
    ///
    /// The load-bearing rule of both exclusion paths, and the one a second
    /// implementation would eventually get wrong. Dropping a profile because
    /// one of its rules was excluded would silently remove settings nobody
    /// asked to remove — and a missing profile is not something an operator
    /// notices in a directory of generated artifacts.
    #[test]
    fn a_partly_excluded_profile_is_kept_and_warned_about() {
        let all = vec![
            mobileconfig_rule("os_a", "com.apple.example"),
            mobileconfig_rule("os_b", "com.apple.example"),
            mobileconfig_rule("os_c", "com.apple.example"),
        ];
        let plan = plan_for(&["os_a"], &all, "excluded_rules");
        assert!(
            plan.excluded_profiles.is_empty(),
            "one rule of three was excluded; the profile must stay"
        );
        assert_eq!(plan.warnings.len(), 1, "and the operator must be told");
        let w = &plan.warnings[0];
        assert!(w.contains("com.apple.example.mobileconfig"), "{w}");
        assert!(
            w.contains("os_a"),
            "the warning names what was excluded: {w}"
        );
        assert!(
            w.contains("os_b") && w.contains("os_c"),
            "and what is keeping the profile alive: {w}"
        );
    }

    /// Exclude every rule feeding a domain and the profile goes.
    #[test]
    fn a_fully_excluded_profile_is_dropped_with_its_reason() {
        let all = vec![
            mobileconfig_rule("os_a", "com.apple.example"),
            mobileconfig_rule("os_b", "com.apple.example"),
        ];
        let plan = plan_for(&["os_a", "os_b"], &all, "excluded_rules");
        assert_eq!(plan.excluded_profiles.len(), 1);
        let entry = &plan.excluded_profiles[0];
        assert_eq!(entry.filename, "com.apple.example.mobileconfig");
        assert!(plan.warnings.is_empty(), "nothing partial, nothing to warn");
        // The reason is written into a constraints file that people read
        // later, so it has to say which mechanism asked.
        assert!(
            entry.reason.contains("excluded_rules"),
            "a constraints entry must name its source, not just its rules: {}",
            entry.reason
        );
    }

    /// The source label distinguishes a config setting from a CLI flag.
    #[test]
    fn the_reason_names_which_mechanism_excluded_it() {
        let all = vec![mobileconfig_rule("os_a", "com.apple.example")];
        let from_flag = plan_for(&["os_a"], &all, "--exclude");
        let from_config = plan_for(&["os_a"], &all, "excluded_rules");
        assert!(from_flag.excluded_profiles[0].reason.contains("--exclude"));
        assert!(
            from_config.excluded_profiles[0]
                .reason
                .contains("excluded_rules")
        );
        assert_ne!(
            from_flag.excluded_profiles[0].reason,
            from_config.excluded_profiles[0].reason
        );
    }

    /// Rules with no profile still suppress their scripts.
    ///
    /// Most mSCP rules fix by script, not by profile. An exclusion that only
    /// dropped profiles would leave the remediation running — the setting
    /// would look honoured and the machine would still be changed.
    #[test]
    fn script_only_rules_are_excluded_even_with_no_profile_to_drop() {
        let mut rule = make_test_rule("os_script_only");
        rule.fix = Some("[source,bash]\n----\necho fix\n----".to_string());
        let all = vec![rule];
        let mut plan = CategoryExclusionPlan {
            resolved: vec![ResolvedCategory {
                name: "os_script_only".into(),
                matched_rules: vec!["os_script_only".into()],
                affected_profiles: Vec::new(),
                affected_scripts: vec!["os_script_only".into()],
            }],
            unresolved: Vec::new(),
            excluded_profiles: Vec::new(),
            excluded_scripts: Vec::new(),
            warnings: Vec::new(),
        };
        let ids: HashSet<String> = ["os_script_only".to_string()].into_iter().collect();
        finalize_exclusion_plan(&mut plan, &all, &ids, "excluded_rules");
        assert!(plan.excluded_profiles.is_empty());
        assert_eq!(plan.excluded_scripts.len(), 1);
        assert_eq!(plan.excluded_scripts[0].rule_id, "os_script_only");
    }

    fn make_test_rule(id: &str) -> MscpRule {
        MscpRule {
            id: id.to_string(),
            title: String::new(),
            discussion: String::new(),
            check: None,
            result: None,
            fix: None,
            references: HashMap::new(),
            macos: Vec::new(),
            tags: Vec::new(),
            severity: None,
            mobileconfig: false,
            mobileconfig_info: None,
            ddm_info: None,
            odv: None,
        }
    }
}
