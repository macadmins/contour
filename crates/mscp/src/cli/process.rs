use crate::config::{GitopsGlobConfig, GlobSection, LabelConfig, OutputStructure};
use crate::extractors::{MscpOutputExtractor, RuleExtractor};
use crate::filters::{FleetConflictFilter, JamfConflictFilter};
use crate::generators::{FleetGitOpsGenerator, GlobPlan};
use crate::managers::{
    ConstraintType, Constraints, build_exclusion_plan, build_rule_exclusion_plan,
    discover_categories,
};
use crate::models::Platform;
use crate::output::{CommandResult, OutputMode, print_bar_chart};
use crate::transformers::{
    DdmTransformer, FleetPolicyGenerator, FleetYamlGenerator, JamfOptions, JamfPostprocessor,
    LabelGenerator, MunkiComplianceGenerator, MunkiComplianceOptions, MunkiScriptGenerator,
    MunkiScriptOptions, ProfileOptions, ProfilePostprocessor, ProfileTransformer,
    RuleScriptGenerator, RuleScriptOptions, ScriptMode, ScriptTransformer,
};
use crate::validators::ConflictDetector;
use crate::versioning::{GitInfoExtractor, ManifestStore, ProfileInfo};
use anyhow::Result;
use colored::Colorize;
use std::collections::HashSet;
use std::path::PathBuf;

/// What `--osquery` will do on this run, and why.
///
/// A boolean conjunction of preconditions has one outcome for "no" and no
/// room for a reason: nothing written, nothing said, exit 0. Naming the
/// outcomes gives each one what to tell the operator, and lets the decision
/// be tested without an mSCP checkout.
///
/// `dry_run` is deliberately NOT an input. It decides whether to write, not
/// whether to run: classification and both adapters happen either way, so a
/// dry run reports real counts and fails on the same bad input a real run
/// would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsqueryPlan {
    /// Build the artifacts. Whether they reach disk is `dry_run`'s business.
    Build,
    /// Build nothing, and say why: osquery detection is macOS-only.
    SkipNotMacOs,
    /// Refuse: this output layout has no place to put the artifacts.
    RefuseLayout,
}

/// Decide what `--osquery` does, given the layout and the baseline's platform.
///
/// `is_fleet_output` is the only layout test needed. `effective_structure` is
/// exactly one of Pluggable, Flat or Nested; `is_fleet_output` is the first
/// and `is_jamf_mode` is the other two, so the original `is_fleet_output &&
/// !is_jamf_mode` asked the same question twice and left a reader hunting for
/// the third case.
pub(crate) fn osquery_plan(structure: &OutputStructure, platform: Platform) -> OsqueryPlan {
    if *structure != OutputStructure::Pluggable {
        return OsqueryPlan::RefuseLayout;
    }
    if platform != Platform::MacOS {
        return OsqueryPlan::SkipNotMacOs;
    }
    OsqueryPlan::Build
}

/// Process command - standalone mode
///
/// `glob_config` is the per-baseline Fleet GitOps glob configuration (usually
/// read from `mscp.toml` via `BaselineConfig::gitops_glob`). When `None` or
/// when every section is disabled, output is byte-identical to the legacy
/// per-item `path:` emission.
#[expect(
    clippy::too_many_arguments,
    reason = "legacy signature shaped by CLI flags; refactoring is out of scope for the glob feature"
)]
pub fn process_baseline(
    input_path: PathBuf,
    output_path: PathBuf,
    baseline_name: String,
    mscp_repo_path: Option<PathBuf>,
    profile_options: Option<ProfileOptions>,
    jamf_options: Option<JamfOptions>,
    munki_compliance_options: Option<MunkiComplianceOptions>,
    munki_script_options: Option<MunkiScriptOptions>,
    no_labels: bool,
    fleet_mode: bool,
    jamf_exclude_conflicts: bool,
    dry_run: bool,
    output_mode: OutputMode,
    script_mode: ScriptMode,
    exclude_categories: Option<Vec<String>>,
    // Rule IDs from `[[baselines]] excluded_rules` in mscp.toml. Separate
    // from `exclude_categories` because the two resolve differently — a
    // category matches loosely, a rule ID exactly — and because they come
    // from different places, which the constraints file records.
    excluded_rules: Option<Vec<String>>,
    // Label targeting from `[baselines.labels]` in mscp.toml. Parsed since
    // the config type was written and never read — see where it is applied.
    baseline_labels: Option<LabelConfig>,
    fragment: bool,
    output_structure: OutputStructure,
    glob_config: Option<GitopsGlobConfig>,
    osquery: Option<crate::osquery::OsqueryGenOptions>,
) -> Result<()> {
    tracing::info!(
        "Processing baseline '{}' from: {}",
        baseline_name,
        input_path.display()
    );
    tracing::info!("Output directory: {}", output_path.display());

    // Dry-run warning
    if dry_run && output_mode == OutputMode::Human {
        println!(
            "\n{}",
            "DRY RUN MODE - No files will be written\n".yellow().bold()
        );
    }

    // Initialize result tracking
    let mut result = CommandResult::new("process")
        .with_baseline(&baseline_name)
        .with_output_dir(output_path.to_string_lossy().to_string());

    // Extract mSCP baseline
    let mut extractor = MscpOutputExtractor::new(&input_path, baseline_name.clone());
    if let Some(ref repo_path) = mscp_repo_path {
        extractor = extractor.with_repo_path(repo_path);
    }
    let mut baseline = extractor.extract()?;

    // Detect internal conflicts
    tracing::info!("Checking for internal conflicts...");
    let conflict_report = ConflictDetector::detect_internal_conflicts(&baseline)?;
    if !conflict_report.conflicts.is_empty() {
        tracing::warn!("{}", ConflictDetector::format_report(&conflict_report));
    }

    // Get Git information if repo path provided
    let git_info = if let Some(ref repo_path) = mscp_repo_path {
        match GitInfoExtractor::extract(repo_path) {
            Ok(info) => {
                baseline.mscp_git_hash = Some(info.hash.clone());
                baseline.mscp_git_tag = info.tag.clone();
                Some(info)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to extract Git info: {}. Continuing without version tracking.",
                    e
                );
                None
            }
        }
    } else {
        tracing::info!("No mSCP repo path provided, skipping Git version tracking");
        None
    };

    // Apply rule-level exclusions from `[[baselines]] excluded_rules`.
    //
    // This setting was parsed, counted and printed — "Excluded rules: 1" —
    // and then dropped on the floor: `generate_baseline` had no parameter
    // for it and nothing filtered anything. The template documents it and
    // ships a working example, so an operator had every reason to believe a
    // rule was being held back while it shipped in every artifact. A setting
    // that reports success it did not have is worse than one that is missing.
    // Rule ids whose scripts this run must not ship, from `excluded_rules`
    // and `--exclude` alike. Held here and applied where the scripts are
    // built: the constraints file these plans are also written to was never
    // read back, so "1 script(s) suppressed" was printed while the rule's
    // check and fix stayed in every generated script.
    let mut suppressed_scripts: HashSet<String> = HashSet::new();
    // Every rule id excluded this run. A policy or osquery check for one
    // would report every host failing a rule the operator chose not to apply.
    let mut excluded_rule_ids: HashSet<String> = HashSet::new();
    // The record of those exclusions goes with the baseline's own metadata,
    // mscp/<baseline>/, beside baseline.toml. It was written to the directory
    // the command ran from, so a run from ~ left ~/fleet-constraints.yml. Not
    // the output root either: that is where default.yml and fleets/ live, and
    // a CI glob or a reviewer taking the root's YAML as GitOps would take this
    // for a document Fleet rejects.
    let constraints_dir = output_path.join("mscp").join(&baseline.name);
    let constraints_record = |t: ConstraintType| constraints_dir.join(t.default_filename());

    if let Some(ref rules) = excluded_rules.as_ref().filter(|r| !r.is_empty()) {
        let Some(ref repo_path) = mscp_repo_path else {
            anyhow::bail!(
                "`excluded_rules` needs the mSCP repository to resolve rule IDs against \
                 the baseline, and this run has none. Generate with --mscp-repo (or \
                 [settings] mscp_repo in mscp.toml), or remove the setting — leaving it \
                 in place while nothing applies it is how it spent its first life."
            );
        };
        let plan = build_rule_exclusion_plan(rules, repo_path, &baseline.name)?;

        // An ID that matches nothing is a typo, and excluding nothing is
        // indistinguishable from excluding correctly unless it is said.
        if !plan.unresolved.is_empty() {
            let mut near: Vec<String> = Vec::new();
            if let Ok(all) =
                RuleExtractor::new(repo_path).extract_rules_for_baseline(&baseline.name)
            {
                for missing in &plan.unresolved {
                    let needle = missing.to_lowercase();
                    near.extend(
                        all.iter()
                            .filter(|r| r.id.contains(&needle) || needle.contains(&r.id))
                            .map(|r| r.id.clone()),
                    );
                }
            }
            near.sort_unstable();
            near.dedup();
            let hint = if near.is_empty() {
                format!(
                    "No rule in '{}' has a similar id. `contour mscp schema search <term>` \
                     lists rule ids.",
                    baseline.name
                )
            } else {
                format!("Did you mean: {}", near.join(", "))
            };
            anyhow::bail!(
                "excluded_rules names {} rule(s) that are not in baseline '{}': {}\n{hint}",
                plan.unresolved.len(),
                baseline.name,
                plan.unresolved.join(", ")
            );
        }

        for warning in &plan.warnings {
            tracing::warn!("{}", warning);
        }

        let excluded_filenames: HashSet<String> = plan
            .excluded_profiles
            .iter()
            .map(|p| p.filename.clone())
            .collect();
        let before = baseline.mobileconfigs.len();
        baseline.mobileconfigs.retain(|mc| {
            let filename = mc.path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            !excluded_filenames.contains(filename)
        });
        let removed = before - baseline.mobileconfigs.len();

        // Scripts are suppressed through the constraints file, which is how
        // --exclude does it and the only mechanism downstream honours — the
        // script transformer works from the baseline's compliance script, not
        // from per-rule files. Using the same path means excluded_rules
        // excludes the same things a category would, rather than dropping
        // profiles and quietly leaving the remediation scripts in place.
        let is_jamf = jamf_options.is_some();
        let constraint_type = if jamf_exclude_conflicts || is_jamf {
            ConstraintType::Jamf
        } else {
            ConstraintType::Fleet
        };
        suppressed_scripts.extend(plan.excluded_scripts.iter().map(|s| s.rule_id.clone()));
        excluded_rule_ids.extend(
            plan.resolved
                .iter()
                .flat_map(|c| c.matched_rules.iter().cloned()),
        );
        let mut cm = Constraints::load(constraint_type, Some(constraints_record(constraint_type)))?;
        let merge = cm.merge_category_exclusions(&plan);
        if !dry_run {
            std::fs::create_dir_all(&constraints_dir)?;
            cm.save()?;
        }
        let scripts = merge.scripts_added + merge.scripts_skipped;

        // Said out loud, with what it did rather than what was asked for.
        result.add_warning(format!(
            "excluded_rules: {} rule(s) excluded — {} profile(s) dropped, {} script(s) \
             suppressed{}",
            plan.resolved.len(),
            removed,
            scripts,
            if plan.warnings.is_empty() {
                String::new()
            } else {
                format!(
                    " ({} profile(s) kept because other rules still need them)",
                    plan.warnings.len()
                )
            }
        ));
    }

    // Apply category-based exclusions if --exclude was specified
    if let Some(ref categories) = exclude_categories {
        if let Some(ref repo_path) = mscp_repo_path {
            tracing::info!("Resolving category exclusions...");

            let plan = build_exclusion_plan(categories, repo_path, &baseline.name)?;

            // Report unresolved categories
            if !plan.unresolved.is_empty() {
                let available = discover_categories(repo_path, Some(&baseline.name))?;
                let available_names: Vec<String> =
                    available.iter().map(|c| c.name.clone()).collect();
                anyhow::bail!(
                    "Unknown categories: {}. Available: {}",
                    plan.unresolved.join(", "),
                    available_names.join(", ")
                );
            }

            // Log resolved categories
            for resolved in &plan.resolved {
                tracing::info!(
                    "  {}: {} rules matched ({} profiles, {} scripts)",
                    resolved.name,
                    resolved.matched_rules.len(),
                    resolved.affected_profiles.len(),
                    resolved.affected_scripts.len(),
                );
            }

            // Log warnings for partial profile matches
            for warning in &plan.warnings {
                tracing::warn!("{}", warning);
            }

            // Determine constraint type from mode
            let is_jamf_mode = jamf_options.is_some();
            let constraint_type = if jamf_exclude_conflicts || is_jamf_mode {
                ConstraintType::Jamf
            } else {
                ConstraintType::Fleet
            };

            // Persist to constraint file (merge semantics)
            suppressed_scripts.extend(plan.excluded_scripts.iter().map(|s| s.rule_id.clone()));
            excluded_rule_ids.extend(
                plan.resolved
                    .iter()
                    .flat_map(|c| c.matched_rules.iter().cloned()),
            );
            let mut cm =
                Constraints::load(constraint_type, Some(constraints_record(constraint_type)))?;
            let merge = cm.merge_category_exclusions(&plan);
            if !dry_run {
                std::fs::create_dir_all(&constraints_dir)?;
                cm.save()?;
            }

            // Apply profile exclusions to current baseline
            let excluded_filenames: HashSet<String> = plan
                .excluded_profiles
                .iter()
                .map(|p| p.filename.clone())
                .collect();
            let original_count = baseline.mobileconfigs.len();
            baseline.mobileconfigs.retain(|mc| {
                let filename = mc.path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                !excluded_filenames.contains(filename)
            });
            let profiles_removed = original_count - baseline.mobileconfigs.len();

            // Log summary
            tracing::info!(
                "Category exclusions: {} profiles excluded, {} scripts excluded, saved to {}",
                merge.profiles_added + merge.profiles_skipped,
                merge.scripts_added + merge.scripts_skipped,
                cm.constraints_path().display()
            );
            if merge.profiles_skipped > 0 || merge.scripts_skipped > 0 {
                tracing::info!(
                    "  ({} profiles already existed, {} scripts already existed)",
                    merge.profiles_skipped,
                    merge.scripts_skipped,
                );
            }
            if profiles_removed > 0 {
                tracing::info!(
                    "Removed {} profiles from current baseline due to category exclusions",
                    profiles_removed
                );
            }
        } else {
            anyhow::bail!("--exclude requires --mscp-repo to resolve categories");
        }
    }

    // Apply Fleet conflict filtering if enabled
    if fleet_mode {
        tracing::info!("Fleet conflict filtering enabled");
        let filter = FleetConflictFilter::new();

        // Log exclusions
        tracing::debug!("{}", filter.get_exclusion_summary());

        // Filter out conflicting profiles from baseline
        let original_count = baseline.mobileconfigs.len();
        baseline.mobileconfigs.retain(|mc| {
            let filename = mc.path.file_name().and_then(|s| s.to_str()).unwrap_or("");

            if filter.should_exclude_profile(filename) {
                tracing::info!("Excluding profile due to Fleet conflict: {}", filename);
                false
            } else {
                true
            }
        });

        let excluded_count = original_count - baseline.mobileconfigs.len();
        if excluded_count > 0 {
            tracing::info!(
                "Excluded {} profiles that conflict with Fleet native settings",
                excluded_count
            );
        }
    }

    // Apply Jamf conflict filtering if enabled
    if jamf_exclude_conflicts {
        tracing::info!("Jamf conflict filtering enabled");
        let jamf_filter = JamfConflictFilter::new()?;

        // Log exclusions
        tracing::debug!("{}", jamf_filter.get_exclusion_summary());

        // Filter out conflicting profiles
        let original_count = baseline.mobileconfigs.len();
        baseline.mobileconfigs.retain(|mc| {
            let filename = mc.path.file_name().and_then(|s| s.to_str()).unwrap_or("");

            if jamf_filter.should_exclude_profile(filename) {
                tracing::info!("Excluding profile due to Jamf conflict: {}", filename);
                if let Some(reason) = jamf_filter.get_exclusion_reason(filename) {
                    tracing::debug!("  Reason: {}", reason);
                }
                false
            } else {
                true
            }
        });

        let excluded_count = original_count - baseline.mobileconfigs.len();
        if excluded_count > 0 {
            tracing::info!(
                "Excluded {} profiles that conflict with Jamf",
                excluded_count
            );
        }
    }

    // Resolve effective output structure:
    // 1. Explicit CLI flags override config
    // 2. Config's output.structure used when no explicit flag
    let effective_structure = if jamf_options.is_some() {
        OutputStructure::Flat
    } else if fleet_mode || fragment || no_labels {
        OutputStructure::Pluggable
    } else {
        output_structure
    };

    let is_jamf_mode = matches!(
        effective_structure,
        OutputStructure::Flat | OutputStructure::Nested
    );
    let is_fleet_output = effective_structure == OutputStructure::Pluggable;

    tracing::info!("Output structure: {}", effective_structure);

    // Transform profiles
    tracing::info!("Transforming mobileconfig profiles...");
    let profile_transformer = ProfileTransformer::new(&output_path, is_jamf_mode, is_fleet_output);
    let mut profile_mappings = profile_transformer.transform(&baseline)?;

    if !dry_run {
        profile_transformer.copy_files(&profile_mappings)?;

        // For glob-enabled sections, physically move exception files into
        // their configured subfolders. This is what prevents the flat
        // `*.mobileconfig` glob from matching them on disk.
        if let Some(ref cfg) = glob_config
            && let Some(ref section) = cfg.profiles
        {
            apply_subfolder_placement(&mut profile_mappings, Some(section))?;
        }
    }

    result.profiles_generated = profile_mappings.len();

    // Apply Fleet conflict key stripping if enabled (skip in dry-run)
    if fleet_mode && !dry_run {
        tracing::info!("Stripping conflicting payload keys from profiles...");
        let filter = FleetConflictFilter::new();
        let mut modified_count = 0;

        for (_, dest_path) in &profile_mappings {
            if filter.process_profile(dest_path)? {
                modified_count += 1;
            }
        }

        if modified_count > 0 {
            tracing::info!("Stripped conflicting keys from {} profiles", modified_count);
        } else {
            tracing::info!("No conflicting keys found in profiles");
        }
    }

    // Apply Jamf conflict key stripping if enabled (skip in dry-run)
    if jamf_exclude_conflicts && !dry_run {
        tracing::info!("Stripping Jamf-conflicting keys from profiles...");
        let jamf_filter = JamfConflictFilter::new()?;
        let mut modified_count = 0;

        for (_, dest_path) in &profile_mappings {
            if jamf_filter.process_profile(dest_path)? {
                modified_count += 1;
            }
        }

        if modified_count > 0 {
            tracing::info!(
                "Stripped Jamf-conflicting keys from {} profiles",
                modified_count
            );
        }
    }

    // Apply general profile postprocessing if enabled (skip in dry-run)
    if let Some(ref opts) = profile_options
        && !dry_run
    {
        tracing::info!("Applying profile postprocessing...");
        let profile_processor = ProfilePostprocessor::new(opts.clone());
        for (_, dest_path) in &profile_mappings {
            profile_processor.process_file(dest_path)?;
        }
        tracing::info!("Profile postprocessing complete");
    }

    // Apply Jamf postprocessing if enabled (skip in dry-run)
    if let Some(ref opts) = jamf_options
        && !dry_run
    {
        tracing::info!("Applying Jamf postprocessing...");
        let jamf_processor = JamfPostprocessor::new(opts.clone());
        for (_, dest_path) in &profile_mappings {
            jamf_processor.process_file(dest_path)?;
        }
        tracing::info!("Jamf postprocessing complete");
    }

    // Generate Munki compliance flags nopkg if enabled (skip in dry-run)
    if let Some(ref opts) = munki_compliance_options
        && !dry_run
    {
        tracing::info!("Generating Munki compliance flags nopkg...");
        let munki_generator = MunkiComplianceGenerator::new(opts.clone());

        // Extract PayloadIdentifiers from profiles
        let payload_identifiers: Vec<String> = baseline
            .mobileconfigs
            .iter()
            .filter_map(|mc| mc.payload_identifier.clone())
            .collect();

        // Generate nopkg pkginfo
        let pkginfo =
            munki_generator.generate_flag_writer_pkginfo(&baseline.name, &payload_identifiers)?;

        // Write to munki directory (matches munki-mscp-generator format)
        let munki_dir = output_path.join("munki");
        let pkginfo_path = munki_dir.join("compliance_flags.plist");

        munki_generator.write_pkginfo(&pkginfo, &pkginfo_path)?;
        tracing::info!(
            "Generated Munki compliance flags nopkg at: {}",
            pkginfo_path.display()
        );
    }

    // Generate Munki script nopkg items if enabled
    if let Some(ref opts) = munki_script_options {
        tracing::info!("Generating Munki script nopkg items...");

        // Extract rules from mSCP repository or embedded data
        let mut rules = if let Some(ref repo_path) = mscp_repo_path {
            let rule_extractor = RuleExtractor::new(repo_path);
            rule_extractor.extract_rules_for_baseline(&baseline.name)?
        } else {
            tracing::info!("No mSCP repo path — using embedded rule data");
            crate::extractors::rules_from_embedded(&baseline.name, "macOS")?
        };

        // Rules excluded by `excluded_rules` or `--exclude` ship no script.
        rules.retain(|r| !suppressed_scripts.contains(&r.id));

        // Filter out rules excluded by Fleet constraints
        if fleet_mode {
            let filter = FleetConflictFilter::new();
            let excluded_rules = filter.get_excluded_munki_rules();

            if !excluded_rules.is_empty() {
                let original_count = rules.len();
                rules.retain(|rule| !excluded_rules.contains(&rule.id));

                let filtered_count = original_count - rules.len();
                if filtered_count > 0 {
                    tracing::info!(
                        "Excluded {} Munki script rules managed by Fleet native settings",
                        filtered_count
                    );
                }
            }
        }

        // Filter out rules excluded by Jamf constraints
        if jamf_exclude_conflicts {
            let jamf_filter = JamfConflictFilter::new()?;
            let excluded_rules = jamf_filter.get_excluded_munki_rules();

            if !excluded_rules.is_empty() {
                let original_count = rules.len();
                rules.retain(|rule| !excluded_rules.contains(&rule.id));

                let filtered_count = original_count - rules.len();
                if filtered_count > 0 {
                    tracing::info!(
                        "Excluded {} Munki script rules managed by Jamf native capabilities",
                        filtered_count
                    );
                }
            }
        }

        // Print statistics
        let stats = crate::extractors::RuleStats::from_rules(&rules);
        stats.print_summary(&baseline.name);

        // Generate nopkg items (skip in dry-run)
        // Output to munki/ directory (matches munki-mscp-generator format)
        if !dry_run {
            let munki_script_generator = MunkiScriptGenerator::new(opts.clone());
            let munki_dir = output_path.join("munki");

            let generated_paths =
                munki_script_generator.generate_for_baseline(&rules, &baseline.name, &munki_dir)?;

            tracing::info!(
                "Generated {} Munki script nopkg items in: {}",
                generated_paths.len(),
                munki_dir.display()
            );
        }
    }

    // Transform DDM artifacts
    let _ddm_mappings = if baseline.ddm_artifacts.is_empty() {
        Vec::new()
    } else {
        tracing::info!("Transforming DDM artifacts...");
        let ddm_transformer = DdmTransformer::new(&output_path, is_jamf_mode, is_fleet_output);
        let mappings = ddm_transformer.transform(&baseline)?;

        if !dry_run {
            ddm_transformer.copy_files(&mappings)?;
        }

        result.ddm_artifacts = mappings.len();
        mappings
    };

    // Transform scripts
    let mut script_paths = Vec::new();

    // Combined compliance script (traditional approach)
    // Skip wrapper generation when using bundled/granular scripts — the wrappers reference
    // a sibling compliance script via relative path, which doesn't exist when the script
    // generator writes self-contained categorized scripts. Applies to Fleet and Jamf alike.
    let skip_combined_wrappers = script_mode != ScriptMode::Combined;

    if let Some(ref compliance_script) = baseline.compliance_script {
        // The combined script is mSCP's own, one file for every rule; it
        // cannot drop one. Say so instead of claiming a suppression.
        if !skip_combined_wrappers && !suppressed_scripts.is_empty() {
            let mut ids: Vec<&str> = suppressed_scripts.iter().map(String::as_str).collect();
            ids.sort_unstable();
            result.add_warning(format!(
                "combined script mode wraps mSCP's single compliance script, which still \
                 checks and fixes {} excluded rule(s): {}. Use bundled or granular scripts \
                 to leave them out.",
                ids.len(),
                ids.join(", ")
            ));
        }
        if !dry_run && !skip_combined_wrappers {
            tracing::info!("Transforming combined compliance scripts...");
            let script_transformer =
                ScriptTransformer::new(&output_path, is_jamf_mode, is_fleet_output);
            let (audit, remediate) =
                script_transformer.transform(&baseline.name, compliance_script)?;
            script_paths.push((audit, remediate));
        }
        if !skip_combined_wrappers {
            result.scripts_generated += 1;
        }
    }

    // Categorized per-rule scripts (granular/bundled mode) — platform-agnostic, works for
    // both Fleet and Jamf. Emits self-contained bash scripts grouped by rule category
    // (audit/os/system_settings).
    let should_generate_individual_scripts = script_mode != ScriptMode::Combined;

    if should_generate_individual_scripts {
        let mut rules = if let Some(ref repo_path) = mscp_repo_path {
            let rule_extractor = RuleExtractor::new(repo_path);
            rule_extractor.extract_rules_for_baseline(&baseline.name)?
        } else {
            tracing::info!("No mSCP repo path — using embedded rule data for scripts");
            crate::extractors::rules_from_embedded(&baseline.name, "macOS")?
        };
        rules.retain(|r| !suppressed_scripts.contains(&r.id));

        if dry_run {
            // In dry-run, just count what would be generated
            result.scripts_generated += rules.len();
        } else {
            tracing::info!("Generating scripts in {:?} mode...", script_mode);

            let rule_script_generator = RuleScriptGenerator::new(RuleScriptOptions {
                mode: script_mode,
                ..RuleScriptOptions::default()
            });

            // Use different output directory for Jamf vs Fleet
            let scripts_dir = if is_jamf_mode {
                output_path.join(&baseline.name).join("scripts")
            } else {
                // Fleet v4.83+ GitOps: platforms/macos/scripts/{baseline}/
                let layout = contour_core::fleet_layout::FleetLayout::default();
                output_path
                    .join(layout.macos_scripts_subdir)
                    .join(&baseline.name)
            };

            let generated = rule_script_generator.generate_for_baseline(
                &rules,
                &baseline.name,
                &scripts_dir,
            )?;

            // Add individual scripts to script_paths for team YAML
            for (_rule_id, audit_path, remediate_path) in generated {
                script_paths.push((audit_path, Some(remediate_path)));
            }

            // Move exception script files into subfolders when the scripts
            // glob is enabled so the flat glob can't match them.
            if let Some(ref cfg) = glob_config
                && let Some(ref section) = cfg.scripts
            {
                apply_script_subfolder_placement(&mut script_paths, Some(section))?;
            }

            tracing::info!(
                "Generated {} individual script pairs in {:?} mode",
                script_paths
                    .len()
                    .saturating_sub(usize::from(baseline.compliance_script.is_some())),
                script_mode
            );
        }
    }

    // Generate Fleet policies from mobileconfig rules (macOS only, Fleet mode)
    let mut policy_path: Option<PathBuf> = None;
    if is_fleet_output && !is_jamf_mode && !dry_run && baseline.platform == Platform::MacOS {
        let rules = if let Some(ref repo_path) = mscp_repo_path {
            let rule_extractor = RuleExtractor::new(repo_path);
            rule_extractor.extract_rules_for_baseline(&baseline.name)?
        } else {
            tracing::info!("No mSCP repo path — using embedded rule data for policies");
            crate::extractors::rules_from_embedded(&baseline.name, "macOS")?
        };
        let rules: Vec<_> = rules
            .into_iter()
            .filter(|r| !excluded_rule_ids.contains(&r.id))
            .collect();

        let policy_generator = FleetPolicyGenerator::new(&baseline.name);
        // Fleet v4.83+ GitOps: platforms/macos/policies/{baseline}/
        let layout = contour_core::fleet_layout::FleetLayout::default();
        let policies_dir = output_path
            .join(layout.macos_policies_subdir)
            .join(&baseline.name);

        let (policies, p_path) = policy_generator.generate_for_baseline(
            &rules,
            &baseline.name,
            None, // ODV manager (future: pass from CLI)
            &policies_dir,
        )?;

        if !policies.is_empty() {
            tracing::info!(
                "Generated {} Fleet policies at: {}",
                policies.len(),
                p_path.display()
            );
            policy_path = Some(p_path);
        }
    }

    // `--osquery`: classify rules + emit native-table queries (Tier 1) and a
    // slim/full audit-script → results-plist pattern (Tier 2) for the residual.
    // Reuses the rule set and the FleetPolicyGenerator for managed_policies SQL.
    //
    // Every precondition refuses, or says what was skipped and why, as the
    // org domain below does rather than falling back to a placeholder. There
    // is one layout test: `effective_structure` is exactly one of Pluggable /
    // Flat / Nested, and only Pluggable is a Fleet tree.
    if let Some(oq) = osquery.as_ref() {
        match osquery_plan(&effective_structure, baseline.platform) {
            OsqueryPlan::RefuseLayout => {
                anyhow::bail!(
                    "--osquery writes into a Fleet GitOps tree, and this run emits the \
                     {effective_structure} layout, which has no osquery/ directory.\n\
                     Either drop --osquery, or generate the Fleet layout (--fleet, or \
                     `structure = \"pluggable\"` under [output] in mscp.toml)."
                );
            }
            OsqueryPlan::SkipNotMacOs => {
                // Not an error: `--osquery` is one flag over a run that may
                // cover several baselines, and a non-macOS baseline in that
                // set is ordinary. It is still said out loud, because "no
                // osquery/ directory appeared" is otherwise indistinguishable
                // from a flag that did not work.
                result.add_warning(format!(
                    "--osquery: nothing emitted for '{}' — osquery detection is macOS-only \
                     and this baseline targets {}",
                    baseline.name, baseline.platform
                ));
            }
            OsqueryPlan::Build => {
                let rules = if let Some(ref repo_path) = mscp_repo_path {
                    RuleExtractor::new(repo_path).extract_rules_for_baseline(&baseline.name)?
                } else {
                    crate::extractors::rules_from_embedded(&baseline.name, "macOS")?
                };
                let rules: Vec<_> = rules
                    .into_iter()
                    .filter(|r| !excluded_rule_ids.contains(&r.id))
                    .collect();

                let scope = crate::osquery::AuditScope::parse(&oq.audit)?;
                let fmt = crate::osquery::OsqueryFormat::parse(&oq.format)?;
                // Reverse-domain for the audit results-plist path + launchd label.
                // Required — never fall back to a placeholder org.
                let org_domain = oq.org.as_deref().filter(|o| !o.is_empty()).ok_or_else(|| {
                anyhow::anyhow!(
                    "--osquery requires an organization domain (pass --org, set CONTOUR_ORG, or .contour/config.toml)"
                )
            })?;

                // managed_policies SQL via the existing generator (no duplication).
                let mp_gen = FleetPolicyGenerator::new(&baseline.name);
                let art = crate::osquery::build(&rules, org_domain, &baseline.name, scope, |r| {
                    mp_gen.managed_policies_query(r)
                });

                let oq_dir = output_path.join("osquery").join(&baseline.name);

                // Dry run stops at the writes, not before the work. Classification
                // and both adapters run either way, so a dry run reports the real
                // counts and fails on the same bad input a real run would — which
                // is what a dry run is for.
                if dry_run {
                    result.add_warning(format!(
                        "--osquery (dry run): would write {} queries and an audit covering \
                     {} rules to {}",
                        art.queries.len(),
                        art.audit.covered.len(),
                        oq_dir.display()
                    ));
                } else {
                    std::fs::create_dir_all(&oq_dir)?;
                    std::fs::write(
                        oq_dir.join(format!("{}-audit.sh", baseline.name)),
                        &art.audit.sh,
                    )?;
                    std::fs::write(
                        oq_dir.join(format!(
                            "{org_domain}.{}.audit.launchd.plist",
                            baseline.name
                        )),
                        &art.audit.launchd_plist,
                    )?;
                    std::fs::write(
                        oq_dir.join(format!("{}.osquery-coverage.md", baseline.name)),
                        &art.coverage_md,
                    )?;
                    match fmt {
                        crate::osquery::OsqueryFormat::Pack => {
                            let json = crate::osquery::adapters::pack::to_pack_json(&art);
                            std::fs::write(
                                oq_dir.join(format!("{}.pack.json", baseline.name)),
                                json,
                            )?;
                        }
                        crate::osquery::OsqueryFormat::Fleet => {
                            let policies = crate::osquery::adapters::fleet::to_fleet_policies(&art);
                            let yaml = yaml_serde::to_string(&policies)?;
                            std::fs::write(
                                oq_dir.join(format!("{}.policies.yml", baseline.name)),
                                yaml,
                            )?;

                            // Companion scheduled-query report: surface the audit plist the
                            // bridge's script writes (one row per rule → live compliance
                            // visibility). Lives under platforms/macos/reports/ so the
                            // fleet `reports:` glob picks it up.
                            let reports_dir =
                                output_path.join("platforms").join("macos").join("reports");
                            std::fs::create_dir_all(&reports_dir)?;
                            let compliance = crate::osquery::reports::compliance_report(
                                org_domain,
                                &baseline.name,
                            );
                            let yaml = yaml_serde::to_string(&[compliance])?;
                            std::fs::write(
                                reports_dir
                                    .join(format!("{}-compliance.reports.yml", baseline.name)),
                                yaml,
                            )?;
                            tracing::info!(
                                "osquery bridge: wrote compliance report → {}",
                                reports_dir.display()
                            );
                        }
                    }
                    tracing::info!(
                        "osquery bridge: {} queries, audit covers {} rules → {}",
                        art.queries.len(),
                        art.audit.covered.len(),
                        oq_dir.display()
                    );
                }
            }
        }
    }

    // Baseline-independent macOS security-posture reports (OS version, FileVault,
    // SIP, firewall, Gatekeeper, screen lock). Emitted on every macOS Fleet run —
    // they read live system state, so they need no contour-deployed artifact. The
    // file is overwritten identically each run (idempotent).
    if is_fleet_output && !is_jamf_mode && !dry_run && baseline.platform == Platform::MacOS {
        let reports_dir = output_path.join("platforms").join("macos").join("reports");
        std::fs::create_dir_all(&reports_dir)?;
        // Embedded default, overridable via <repo>/.contour/security-posture.toml.
        let pack = crate::osquery::reports::resolve_security_posture(&output_path)?;
        let yaml = yaml_serde::to_string(&pack)?;
        std::fs::write(reports_dir.join("security-posture.reports.yml"), yaml)?;
        tracing::info!(
            "Wrote {} security-posture reports → {}",
            pack.len(),
            reports_dir.display()
        );
    }

    // Generate Fleet-specific GitOps files (skip for plain mode, Jamf mode, and dry-run)
    if is_fleet_output && !is_jamf_mode && !dry_run {
        let gitops_generator = FleetGitOpsGenerator::new_default(&output_path);
        let profile_dest_paths: Vec<PathBuf> = profile_mappings
            .iter()
            .map(|(_, dest)| dest.clone())
            .collect();

        // Build the glob plan once for both fragment and standard modes so
        // team-YAML emission stays consistent with file placement.
        // `[baselines.labels]` — label targeting for progressive rollout.
        //
        // Only `include_all` can be honoured, and the reason is Fleet's, not
        // ours: an entry takes at most ONE label field, and the generated
        // `mscp-<baseline>` label already occupies `labels_include_all`.
        // Adding to that list narrows the target — "in this baseline AND in
        // the pilot ring" — which is exactly progressive rollout.
        // `include_any` would widen it and `exclude_any` would need a second
        // field; either would mean dropping the baseline label and sending
        // security profiles to a different set of hosts than the baseline
        // describes. That is not a thing to do quietly, so it refuses.
        let extra_include_all: Vec<String> = match baseline_labels.as_ref() {
            None => Vec::new(),
            Some(labels) => {
                let offending: Vec<&str> = [
                    ("include_any", !labels.include_any.is_empty()),
                    ("exclude_any", !labels.exclude_any.is_empty()),
                ]
                .into_iter()
                .filter(|(_, set)| *set)
                .map(|(name, _)| name)
                .collect();
                if !offending.is_empty() {
                    anyhow::bail!(
                        "[baselines.labels] sets {} for '{}', which cannot be emitted.\n\n\
                         Fleet allows one label field per profile entry, and the generated \
                         `mscp-{}` label already uses labels_include_all to scope profiles \
                         to this baseline's hosts. Honouring {} would mean dropping that \
                         label and targeting a different set of machines.\n\n\
                         Use `include_all` to narrow within the baseline — it is added \
                         alongside the baseline label, so every listed label must also \
                         match. For targeting that replaces baseline scoping, set the \
                         labels on the profile entries directly in the generated team YAML.",
                        offending.join(" and "),
                        baseline.name,
                        baseline.name,
                        offending.join("/"),
                    );
                }
                labels.include_all.clone()
            }
        };
        if !extra_include_all.is_empty() {
            result.add_warning(format!(
                "[baselines.labels] include_all: every profile also requires {}",
                extra_include_all.join(", ")
            ));
        }

        // Build the glob plan once for both fragment and standard modes so
        // team-YAML emission stays consistent with file placement.
        let glob_plan = GlobPlan {
            profiles: glob_config.as_ref().and_then(|c| c.profiles.as_ref()),
            scripts: glob_config.as_ref().and_then(|c| c.scripts.as_ref()),
            extra_include_all: &extra_include_all,
        };

        if fragment {
            // Fragment mode: generate minimal structure for merge
            tracing::info!("Fragment mode: generating Fleet fragment...");

            // Generate baseline component (mscp/{baseline}/baseline.toml)
            let fleet_generator = FleetYamlGenerator::new(&output_path);
            let baseline_config = fleet_generator.generate_baseline_component(
                &baseline,
                &profile_dest_paths,
                &script_paths,
            )?;
            let baseline_toml_path = fleet_generator.write_baseline_component(
                &baseline_config,
                &baseline.name,
                baseline.platform,
            )?;
            tracing::info!(
                "Baseline component written to: {}",
                baseline_toml_path.display()
            );

            // Generate team YAML with profile/script content (+ policy reference)
            let fleet_yml_path = gitops_generator.generate_fleet_yml_with_glob_plan(
                &baseline.name,
                &profile_dest_paths,
                &script_paths,
                policy_path.as_deref(),
                &glob_plan,
            )?;
            tracing::info!("Team YAML written to: {}", fleet_yml_path.display());

            // Generate labels (needed for fragment default.yml)
            let layout = contour_core::fleet_layout::FleetLayout::default();
            let mut label_paths = Vec::new();
            if !no_labels {
                let label_generator = LabelGenerator::new(&output_path);
                let labels =
                    label_generator.generate_baseline_labels(&baseline.name, baseline.platform)?;
                let label_path = label_generator.write_labels(&baseline.name, &labels)?;
                tracing::info!("Label definitions written to: {}", label_path.display());
                label_paths.push(format!(
                    "./{}/mscp-{}.labels.yml",
                    layout.labels_dir, baseline.name
                ));
            }

            // Generate fragment-style default.yml (labels only)
            gitops_generator.generate_fragment_default_yml(&label_paths)?;

            // Collect profile entries for fragment.toml
            let profile_entries: Vec<contour_core::fragment::ProfileEntry> = profile_dest_paths
                .iter()
                .map(|p| {
                    let filename = p.file_name().and_then(|s| s.to_str()).unwrap_or_default();
                    let label_name = format!("mscp-{}", baseline.name);
                    contour_core::fragment::ProfileEntry {
                        path: format!(
                            "../{}/{}/{filename}",
                            layout.macos_profiles_subdir, baseline.name
                        ),
                        labels_include_all: Some(vec![label_name]),
                        labels_include_any: None,
                        labels_exclude_any: None,
                        activation: None,
                    }
                })
                .collect();

            let policy_entries: Vec<contour_core::fragment::SimpleEntry> = if let Some(ref p) =
                policy_path
            {
                let policy_filename = p.file_name().and_then(|s| s.to_str()).unwrap_or_default();
                vec![contour_core::fragment::SimpleEntry {
                    path: format!(
                        "../{}/{}/{policy_filename}",
                        layout.macos_policies_subdir, baseline.name
                    ),
                }]
            } else {
                Vec::new()
            };

            // Collect all fragment artifact files (platforms/, mscp/, labels/)
            let fragment_roots = [
                layout.platforms_dir.to_string(),
                "mscp".to_string(),
                layout.labels_dir.to_string(),
            ];
            let lib_files: Vec<String> = fragment_roots
                .iter()
                .flat_map(|root| {
                    let root_dir = output_path.join(root);
                    if !root_dir.exists() {
                        return Vec::new();
                    }
                    walkdir::WalkDir::new(&root_dir)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_type().is_file())
                        .filter_map(|e| {
                            e.path()
                                .strip_prefix(&output_path)
                                .ok()
                                .map(|p| p.to_string_lossy().to_string())
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            // Generate fragment.toml
            gitops_generator.generate_fragment_toml(
                &baseline.name,
                &label_paths,
                &profile_entries,
                &policy_entries,
                &lib_files,
            )?;
            tracing::info!("Fragment manifest written to: fragment.toml");
        } else {
            // Standard mode: full GitOps structure
            // Only generate global files if they don't exist (avoid overwriting on subsequent runs)
            if gitops_generator.default_yml_exists() {
                tracing::info!("Fleet GitOps global structure already exists, skipping");
            } else {
                tracing::info!("Generating Fleet GitOps global structure...");
                gitops_generator.generate_structure()?;
                tracing::info!("Generated default.yml, fleets/unassigned.yml");
            }

            // Generate baseline component (mscp/{baseline}/baseline.toml)
            tracing::info!("Generating baseline component...");
            let fleet_generator = FleetYamlGenerator::new(&output_path);
            let baseline_config = fleet_generator.generate_baseline_component(
                &baseline,
                &profile_dest_paths,
                &script_paths,
            )?;
            let baseline_toml_path = fleet_generator.write_baseline_component(
                &baseline_config,
                &baseline.name,
                baseline.platform,
            )?;

            tracing::info!(
                "Baseline component written to: {}",
                baseline_toml_path.display()
            );

            // Generate team YAML with actual profile/script content (+ policy reference)
            let fleet_yml_path = gitops_generator.generate_fleet_yml_with_glob_plan(
                &baseline.name,
                &profile_dest_paths,
                &script_paths,
                policy_path.as_deref(),
                &glob_plan,
            )?;
            tracing::info!("Team YAML written to: {}", fleet_yml_path.display());

            // Generate label definitions (Fleet-specific)
            if !no_labels {
                tracing::info!("Generating Fleet label definitions...");
                let label_generator = LabelGenerator::new(&output_path);
                let labels =
                    label_generator.generate_baseline_labels(&baseline.name, baseline.platform)?;
                let label_path = label_generator.write_labels(&baseline.name, &labels)?;
                tracing::info!("Label definitions written to: {}", label_path.display());

                // Add label reference to default.yml
                let layout = contour_core::fleet_layout::FleetLayout::default();
                let relative_label_path =
                    format!("./{}/mscp-{}.labels.yml", layout.labels_dir, baseline.name);
                if let Err(e) = gitops_generator.add_label_to_default_yml(&relative_label_path) {
                    tracing::warn!(
                        "Could not add labels to default.yml: {}. Add manually if needed.",
                        e
                    );
                }
            } else {
                tracing::info!("Skipping label generation (--no-labels specified)");
            }
        }
    } else if is_jamf_mode {
        tracing::info!("Skipping Fleet GitOps files (Jamf mode)");
    }

    // Update manifest (Fleet-specific, skip for plain mode, Jamf mode, dry-run, and fragment mode)
    if is_fleet_output && !is_jamf_mode && !dry_run && !fragment {
        if let Some(git_info) = git_info {
            tracing::info!("Updating version manifest...");
            let manifest_manager = ManifestStore::new(&output_path);
            let mut manifest = manifest_manager.load_or_create()?;

            let version_id = GitInfoExtractor::generate_version_id(&git_info);
            let profile_infos: Vec<ProfileInfo> = baseline
                .mobileconfigs
                .iter()
                .map(|mc| ProfileInfo {
                    filename: mc.filename.clone(),
                    payload_identifier: mc.payload_identifier.clone(),
                    hash: mc.hash.clone(),
                })
                .collect();

            manifest_manager.add_baseline(
                &mut manifest,
                &baseline,
                &git_info,
                &version_id,
                profile_infos,
            );
            manifest.update_timestamp();
            let manifest_path = manifest_manager.save(&manifest)?;

            tracing::info!("Manifest updated: {}", manifest_path.display());
            tracing::info!("Version ID: {}", version_id);
        }
    } else if is_jamf_mode {
        tracing::info!("Skipping version manifest (Jamf mode)");
    }

    tracing::info!("✓ Successfully processed baseline '{}'", baseline.name);

    // Output results
    match output_mode {
        OutputMode::Json => {
            crate::output::json::output_result(&result)?;
        }
        OutputMode::Human => {
            // Before the summary, so a skipped surface is read as part of the
            // run rather than as a footnote after the success banner.
            for w in &result.warnings {
                println!("\n{} {w}", "!".yellow().bold());
            }
            if dry_run {
                println!("\n{}", "✓ Dry run complete - no files were written".green());
                println!("  {} {}", "Baseline:".bold(), baseline.name.cyan());
                println!("  {}", "Would generate:".dimmed());
                if result.profiles_generated > 0 {
                    println!(
                        "    {} {} configuration profile{}",
                        "•".cyan(),
                        result.profiles_generated,
                        if result.profiles_generated == 1 {
                            ""
                        } else {
                            "s"
                        }
                    );
                }
                if result.scripts_generated > 0 {
                    println!(
                        "    {} {} script{}",
                        "•".cyan(),
                        result.scripts_generated,
                        if result.scripts_generated == 1 {
                            ""
                        } else {
                            "s"
                        }
                    );
                }
                if result.ddm_artifacts > 0 {
                    println!(
                        "    {} {} DDM artifact{}",
                        "•".cyan(),
                        result.ddm_artifacts,
                        if result.ddm_artifacts == 1 { "" } else { "s" }
                    );
                }
            } else {
                println!("\n{}", "✓ Processing complete!".green().bold());
                println!("  {} {}", "Baseline:".bold(), baseline.name.cyan());
                println!("  {} {}", "Platform:".bold(), baseline.platform);
                println!("  {} {}", "Output:".bold(), output_path.display());

                // Artifact breakdown bar chart
                let mut artifacts: Vec<(&str, usize)> = Vec::new();
                if result.profiles_generated > 0 {
                    artifacts.push(("Profiles", result.profiles_generated));
                }
                if result.scripts_generated > 0 {
                    artifacts.push(("Scripts", result.scripts_generated));
                }
                if result.ddm_artifacts > 0 {
                    artifacts.push(("DDM Artifacts", result.ddm_artifacts));
                }
                if !artifacts.is_empty() {
                    println!();
                    println!("{}", "Artifacts Generated:".bold());
                    artifacts.sort_by(|a, b| b.1.cmp(&a.1));
                    print_bar_chart(&artifacts);
                }
            }
        }
    }

    Ok(())
}

/// Move profile exception files into their configured subfolders and rewrite
/// the destination entries in `mappings` so downstream team-YAML emission
/// references the new locations.
///
/// The subfolder is what physically hides an exception from a flat glob
/// pattern like `../profiles/*.mobileconfig`: the glob matches at one
/// directory depth only, so moving `screensaver.mobileconfig` into
/// `profiles/screensaver/` keeps it off the glob's match list.
fn apply_subfolder_placement(
    mappings: &mut [(PathBuf, PathBuf)],
    section: Option<&GlobSection>,
) -> Result<()> {
    let Some(section) = section.filter(|s| s.enabled) else {
        return Ok(());
    };
    for exc in &section.exceptions {
        let Some(ref subfolder) = exc.subfolder else {
            continue;
        };
        let Some(mapping) = mappings.iter_mut().find(|(_, dest)| {
            dest.file_name().and_then(|s| s.to_str()) == Some(exc.filename.as_str())
        }) else {
            tracing::warn!(
                "glob exception `{}` not found among copied profiles — skipping subfolder move",
                exc.filename
            );
            continue;
        };
        let (_, dest) = mapping;
        let parent = dest
            .parent()
            .ok_or_else(|| anyhow::anyhow!("profile dest has no parent: {}", dest.display()))?;
        let new_parent = parent.join(subfolder);
        std::fs::create_dir_all(&new_parent)?;
        let new_dest = new_parent.join(&exc.filename);
        std::fs::rename(&dest, &new_dest)?;
        tracing::info!(
            "moved glob exception into subfolder: {} -> {}",
            dest.display(),
            new_dest.display()
        );
        *dest = new_dest;
    }
    Ok(())
}

/// Script variant of `apply_subfolder_placement`.
///
/// Scripts are stored as `(audit, Option<remediate>)` pairs, and filename
/// matching happens on whichever element carries the exception's basename.
fn apply_script_subfolder_placement(
    pairs: &mut [(PathBuf, Option<PathBuf>)],
    section: Option<&GlobSection>,
) -> Result<()> {
    let Some(section) = section.filter(|s| s.enabled) else {
        return Ok(());
    };
    let move_into_subfolder = |p: &PathBuf, subfolder: &str| -> Result<PathBuf> {
        let parent = p
            .parent()
            .ok_or_else(|| anyhow::anyhow!("script dest has no parent: {}", p.display()))?;
        let new_parent = parent.join(subfolder);
        std::fs::create_dir_all(&new_parent)?;
        let new_dest = new_parent.join(p.file_name().unwrap_or_default());
        std::fs::rename(p, &new_dest)?;
        Ok(new_dest)
    };

    for exc in &section.exceptions {
        let Some(ref subfolder) = exc.subfolder else {
            continue;
        };
        let mut matched = false;
        for (audit, remediate) in pairs.iter_mut() {
            if audit.file_name().and_then(|s| s.to_str()) == Some(exc.filename.as_str()) {
                *audit = move_into_subfolder(audit, subfolder)?;
                matched = true;
            }
            if let Some(r) = remediate.as_mut()
                && r.file_name().and_then(|s| s.to_str()) == Some(exc.filename.as_str())
            {
                *r = move_into_subfolder(r, subfolder)?;
                matched = true;
            }
        }
        if !matched {
            tracing::warn!(
                "glob exception `{}` not found among generated scripts — skipping subfolder move",
                exc.filename
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod osquery_gate_tests {
    use super::*;

    /// Every non-emitting outcome is distinguishable from every other.
    ///
    /// This is the whole defect in one assertion. Before, all three answers
    /// were the same answer — the conjunction was false, so nothing happened
    /// and nothing was said. A wrong layout and an iOS baseline want opposite
    /// treatment: one is a mistake the operator made and must be told about,
    /// the other is ordinary in a multi-baseline run.
    #[test]
    fn each_reason_for_not_emitting_is_its_own_outcome() {
        assert_eq!(
            osquery_plan(&OutputStructure::Pluggable, Platform::MacOS),
            OsqueryPlan::Build
        );
        assert_eq!(
            osquery_plan(&OutputStructure::Flat, Platform::MacOS),
            OsqueryPlan::RefuseLayout,
            "the Jamf flat layout has no osquery/ tree — this must refuse, not no-op"
        );
        assert_eq!(
            osquery_plan(&OutputStructure::Nested, Platform::MacOS),
            OsqueryPlan::RefuseLayout,
            "the Munki nested layout has no osquery/ tree — this must refuse, not no-op"
        );
        for platform in [Platform::Ios, Platform::VisionOS] {
            assert_eq!(
                osquery_plan(&OutputStructure::Pluggable, platform),
                OsqueryPlan::SkipNotMacOs,
                "{platform:?} is not macOS, so it must skip WITH a reason"
            );
        }
    }

    /// The layout is decided before the platform is looked at.
    ///
    /// Order matters for the message the operator gets. Asked for osquery on
    /// an iOS baseline in a Jamf tree, the useful thing to say is that the
    /// layout is wrong — that is the part they can act on, and it is wrong
    /// for every baseline in the run, not just this one.
    #[test]
    fn a_wrong_layout_is_reported_before_a_wrong_platform() {
        assert_eq!(
            osquery_plan(&OutputStructure::Flat, Platform::Ios),
            OsqueryPlan::RefuseLayout
        );
    }

    /// No layout silently emits nothing.
    ///
    /// `OutputStructure` gains variants over time. A new one must land on a
    /// named outcome, and `RefuseLayout` is the safe default because it is
    /// loud.
    #[test]
    fn every_layout_reaches_a_named_outcome() {
        for structure in [
            OutputStructure::Pluggable,
            OutputStructure::Flat,
            OutputStructure::Nested,
        ] {
            let plan = osquery_plan(&structure, Platform::MacOS);
            assert!(
                matches!(plan, OsqueryPlan::Build | OsqueryPlan::RefuseLayout),
                "{structure:?} produced {plan:?}"
            );
        }
    }
}
