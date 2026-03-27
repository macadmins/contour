use crate::config::OutputStructure;
use crate::extractors::{MscpOutputExtractor, RuleExtractor};
use crate::filters::{FleetConflictFilter, JamfConflictFilter};
use crate::generators::FleetGitOpsGenerator;
use crate::managers::{ConstraintType, Constraints, build_exclusion_plan, discover_categories};
use crate::models::Platform;
use crate::output::{CommandResult, OutputMode, print_bar_chart};
use crate::transformers::{
    DdmTransformer, FleetPolicyGenerator, FleetScriptGenerator, FleetScriptOptions, JamfOptions,
    JamfPostprocessor, LabelGenerator, MunkiComplianceGenerator, MunkiComplianceOptions,
    MunkiScriptGenerator, MunkiScriptOptions, ProfileOptions, ProfilePostprocessor,
    ProfileTransformer, ScriptMode, ScriptTransformer, TeamYamlGenerator,
};
use crate::validators::ConflictDetector;
use crate::versioning::{GitInfoExtractor, ManifestStore, ProfileInfo};
use anyhow::Result;
use colored::Colorize;
use std::collections::HashSet;
use std::path::PathBuf;

/// Process command - standalone mode
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
    fragment: bool,
    output_structure: OutputStructure,
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
            let mut cm = Constraints::load(constraint_type, None)?;
            let merge = cm.merge_category_exclusions(&plan);
            cm.save()?;

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
    let profile_mappings = profile_transformer.transform(&baseline)?;

    if !dry_run {
        profile_transformer.copy_files(&profile_mappings)?;
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
    // Skip wrapper generation in Fleet mode with bundled/granular scripts — the wrappers
    // reference a sibling compliance script via relative path, but Fleet uploads scripts
    // individually (no directory structure), so the wrappers would fail at runtime.
    // The bundled/granular scripts are self-contained and replace this functionality.
    let skip_combined_wrappers = is_fleet_output && script_mode != ScriptMode::Combined;

    if let Some(ref compliance_script) = baseline.compliance_script {
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

    // Individual per-rule scripts (granular/bundled mode)
    // Generate when script_mode is not Combined and we're in Fleet output mode
    // (per-rule scripts are Fleet-specific)
    let should_generate_individual_scripts = is_fleet_output && script_mode != ScriptMode::Combined;

    if should_generate_individual_scripts {
        let rules = if let Some(ref repo_path) = mscp_repo_path {
            let rule_extractor = RuleExtractor::new(repo_path);
            rule_extractor.extract_rules_for_baseline(&baseline.name)?
        } else {
            tracing::info!("No mSCP repo path — using embedded rule data for scripts");
            crate::extractors::rules_from_embedded(&baseline.name, "macOS")?
        };

        if dry_run {
            // In dry-run, just count what would be generated
            result.scripts_generated += rules.len();
        } else {
            tracing::info!("Generating scripts in {:?} mode...", script_mode);

            let fleet_script_generator = FleetScriptGenerator::new(FleetScriptOptions {
                mode: script_mode,
                ..FleetScriptOptions::default()
            });

            // Use different output directory for Jamf vs Fleet
            let scripts_dir = if is_jamf_mode {
                output_path.join(&baseline.name).join("scripts")
            } else {
                output_path
                    .join("lib/mscp")
                    .join(&baseline.name)
                    .join("scripts")
            };

            let generated = fleet_script_generator.generate_for_baseline(
                &rules,
                &baseline.name,
                &scripts_dir,
            )?;

            // Add individual scripts to script_paths for team YAML
            for (_rule_id, audit_path, remediate_path) in generated {
                script_paths.push((audit_path, Some(remediate_path)));
            }

            tracing::info!(
                "Generated {} individual script pairs in {:?} mode",
                script_paths.len() - usize::from(baseline.compliance_script.is_some()),
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

        let policy_generator = FleetPolicyGenerator::new(&baseline.name);
        let policies_dir = output_path
            .join("lib/mscp")
            .join(&baseline.name)
            .join("policies");

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

    // Generate Fleet-specific GitOps files (skip for plain mode, Jamf mode, and dry-run)
    if is_fleet_output && !is_jamf_mode && !dry_run {
        let gitops_generator = FleetGitOpsGenerator::new_default(&output_path);
        let profile_dest_paths: Vec<PathBuf> = profile_mappings
            .iter()
            .map(|(_, dest)| dest.clone())
            .collect();

        if fragment {
            // Fragment mode: generate minimal structure for merge
            tracing::info!("Fragment mode: generating Fleet fragment...");

            // Generate baseline component (lib/mscp/{baseline}/baseline.toml)
            let team_generator = TeamYamlGenerator::new(&output_path);
            let baseline_config = team_generator.generate_baseline_component(
                &baseline,
                &profile_dest_paths,
                &script_paths,
            )?;
            let baseline_toml_path = team_generator.write_baseline_component(
                &baseline_config,
                &baseline.name,
                baseline.platform,
            )?;
            tracing::info!(
                "Baseline component written to: {}",
                baseline_toml_path.display()
            );

            // Generate team YAML with profile/script content (+ policy reference)
            let team_yml_path = gitops_generator.generate_team_yml_with_policies(
                &baseline.name,
                &profile_dest_paths,
                &script_paths,
                policy_path.as_deref(),
            )?;
            tracing::info!("Team YAML written to: {}", team_yml_path.display());

            // Generate labels (needed for fragment default.yml)
            let mut label_paths = Vec::new();
            if !no_labels {
                let label_generator = LabelGenerator::new(&output_path);
                let labels =
                    label_generator.generate_baseline_labels(&baseline.name, baseline.platform)?;
                let label_path = label_generator.write_labels(&baseline.name, &labels)?;
                tracing::info!("Label definitions written to: {}", label_path.display());
                label_paths.push(format!(
                    "./lib/all/labels/mscp-{}.labels.yml",
                    baseline.name
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
                        path: format!("../lib/mscp/{}/profiles/{filename}", baseline.name),
                        labels_include_all: Some(vec![label_name]),
                        labels_include_any: None,
                        labels_exclude_any: None,
                    }
                })
                .collect();

            let policy_entries: Vec<contour_core::fragment::SimpleEntry> = if let Some(ref p) =
                policy_path
            {
                let policy_filename = p.file_name().and_then(|s| s.to_str()).unwrap_or_default();
                vec![contour_core::fragment::SimpleEntry {
                    path: format!("../lib/mscp/{}/policies/{policy_filename}", baseline.name),
                }]
            } else {
                Vec::new()
            };

            // Collect lib files (all files under lib/)
            let lib_dir = output_path.join("lib");
            let lib_files: Vec<String> = if lib_dir.exists() {
                walkdir::WalkDir::new(&lib_dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .filter_map(|e| {
                        e.path()
                            .strip_prefix(&output_path)
                            .ok()
                            .map(|p| p.to_string_lossy().to_string())
                    })
                    .collect()
            } else {
                Vec::new()
            };

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
                tracing::info!("Generated default.yml, lib/agent-options.yml, fleets/no-team.yml");
            }

            // Generate baseline component (lib/mscp/{baseline}/baseline.toml)
            tracing::info!("Generating baseline component...");
            let team_generator = TeamYamlGenerator::new(&output_path);
            let baseline_config = team_generator.generate_baseline_component(
                &baseline,
                &profile_dest_paths,
                &script_paths,
            )?;
            let baseline_toml_path = team_generator.write_baseline_component(
                &baseline_config,
                &baseline.name,
                baseline.platform,
            )?;

            tracing::info!(
                "Baseline component written to: {}",
                baseline_toml_path.display()
            );

            // Generate team YAML with actual profile/script content (+ policy reference)
            let team_yml_path = gitops_generator.generate_team_yml_with_policies(
                &baseline.name,
                &profile_dest_paths,
                &script_paths,
                policy_path.as_deref(),
            )?;
            tracing::info!("Team YAML written to: {}", team_yml_path.display());

            // Generate label definitions (Fleet-specific)
            if !no_labels {
                tracing::info!("Generating Fleet label definitions...");
                let label_generator = LabelGenerator::new(&output_path);
                let labels =
                    label_generator.generate_baseline_labels(&baseline.name, baseline.platform)?;
                let label_path = label_generator.write_labels(&baseline.name, &labels)?;
                tracing::info!("Label definitions written to: {}", label_path.display());

                // Add label reference to default.yml
                let relative_label_path =
                    format!("./lib/all/labels/mscp-{}.labels.yml", baseline.name);
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
