use crate::cli::process_baseline;
use crate::config::{GitopsGlobConfig, OutputStructure};
use crate::managers::BaselineIndex;
use crate::output::{CommandResult, OutputMode, print_bar_chart};
use crate::transformers::{
    JamfOptions, MunkiComplianceOptions, MunkiScriptOptions, ProfileOptions, ScriptMode,
};
use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Python execution method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonMethod {
    /// Use python3 directly
    Python3,
    /// Use uv run with requirements
    Uv,
    /// Use container (Docker or Apple containerization)
    Container,
}

/// Container runtime to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerRuntime {
    /// Docker
    #[default]
    Docker,
    /// Apple containerization (container tool)
    AppleContainer,
}

/// Default mSCP container image
pub const DEFAULT_MSCP_CONTAINER_IMAGE: &str = "ghcr.io/brodjieski/mscp_2.0:latest";

/// In-container path the default mSCP 2.0 image writes its build output to.
/// The 2.0 image checks the project out at `/mscp` (vs the legacy 1.x
/// `/macos_security`), so the host `build/` directory mounts here.
const MSCP_CONTAINER_BUILD_DIR: &str = "/mscp/build";

/// Python version pinned for the `uv run` path.
///
/// mSCP's `requirements.txt` pins packages (e.g. `pillow`, `numpy`) whose
/// wheels lag the newest CPython releases. If `uv` is left to pick the
/// newest interpreter on the host, it lands on a Python with no matching
/// wheel and falls back to compiling from source — which fails without
/// system build deps (`libjpeg` etc.). Pinning to a Python with full
/// wheel coverage keeps the install prebuilt-only. Override by exporting
/// `UV_PYTHON` before running contour.
const MSCP_PYTHON_VERSION: &str = "3.13";

/// mSCP flag that asks `generate_guidance.py` to emit declarative
/// management (DDM) artifacts alongside profiles.
///
/// Both layouts accept the long form `--ddm`, but the short forms differ
/// and the wrong one is silently miscompiled into the wrong feature:
///
/// - mSCP **1.x** (`tahoe` branch): `-D` is `--ddm`.
/// - mSCP **2.0** (`dev_2.0` branch — contour's default since
///   v0.3.0-beta.3): `-D` was repurposed for `--debug` (hidden via
///   `argparse.SUPPRESS`), and `-d`/`--ddm` is the DDM flag. Passing
///   `-D` on 2.0 silently enables debug mode and produces zero DDM
///   artifacts.
///
/// Using the unambiguous long form keeps the call site layout-agnostic.
const MSCP_DDM_FLAG: &str = "--ddm";

/// Generate command - wrapper mode (calls mSCP then processes)
#[expect(
    clippy::too_many_arguments,
    reason = "legacy signature shaped by CLI flags; refactoring is out of scope for the glob feature"
)]
pub fn generate_baseline(
    mscp_repo_path: PathBuf,
    baseline_name: String,
    output_path: PathBuf,
    python_method: Option<PythonMethod>,
    profile_options: Option<ProfileOptions>,
    jamf_options: Option<JamfOptions>,
    munki_compliance_options: Option<MunkiComplianceOptions>,
    munki_script_options: Option<MunkiScriptOptions>,
    no_labels: bool,
    fleet_names: Option<Vec<String>>,
    fleet_glob: bool,
    fleet_mode: bool,
    jamf_exclude_conflicts: bool,
    generate_ddm: bool,
    dry_run: bool,
    output_mode: OutputMode,
    batch_mode: bool, // If true, suppress individual output (used by generate-all)
    script_mode: ScriptMode,
    exclude_categories: Option<Vec<String>>,
    fragment: bool,
    output_structure: OutputStructure,
    glob_config: Option<GitopsGlobConfig>,
    mscp_version: String,
    os: String,
    os_version: Option<String>,
) -> Result<()> {
    tracing::info!(
        "Starting generate workflow for baseline '{}'",
        baseline_name
    );

    // Dry-run warning (skip in JSON mode or batch mode to keep output clean)
    if dry_run && output_mode == OutputMode::Human && !batch_mode {
        println!(
            "\n{}",
            "DRY RUN MODE - No files will be written".yellow().bold()
        );
        println!(
            "{}",
            "NOTE: mSCP generation will still run to determine what would be created\n".dimmed()
        );
    }

    // Determine Python method
    let method = if let Some(m) = python_method {
        // Explicit method specified via CLI flag
        tracing::info!("Using explicitly requested Python method: {:?}", m);
        m
    } else {
        // Auto-detect (will require uv to be installed)
        detect_python_method(&mscp_repo_path)
    };
    tracing::info!("Using Python method: {:?}", method);

    // Step 1: Run mSCP generation (even in dry-run to see what would be generated)
    // Note: mSCP writes to its build directory, but that's acceptable for dry-run
    tracing::info!("Running mSCP baseline generation...");
    let build_subdir = run_mscp_generation(
        &mscp_repo_path,
        &baseline_name,
        method,
        generate_ddm,
        &mscp_version,
        &os,
        os_version.as_deref(),
    )?;

    // Initialize result tracking
    let mut result = CommandResult::new("generate")
        .with_baseline(&baseline_name)
        .with_output_dir(output_path.to_string_lossy().to_string());

    // Step 2: Process the output
    let build_path = mscp_repo_path.join("build").join(&build_subdir);

    if !dry_run && !build_path.exists() {
        anyhow::bail!(
            "mSCP build output not found at: {}. Did the generation succeed?",
            build_path.display()
        );
    }

    tracing::info!("Processing baseline output...");
    if dry_run {
        // In dry-run mode, estimate what would be generated by checking the build path
        if build_path.exists()
            && let Ok(entries) = fs::read_dir(&build_path)
        {
            let mut profile_count = 0;
            let mut script_count = 0;
            let mut ddm_count = 0;

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Some(ext) = path.extension()
                {
                    if ext == "mobileconfig" {
                        profile_count += 1;
                    } else if ext == "sh" {
                        script_count += 1;
                    } else if ext == "json" && path.to_string_lossy().contains("declarative") {
                        ddm_count += 1;
                    }
                }
            }

            if output_mode == OutputMode::Human && !batch_mode {
                println!("Would generate:");
                if profile_count > 0 {
                    println!(
                        "  • {} configuration profile{}",
                        profile_count,
                        if profile_count == 1 { "" } else { "s" }
                    );
                }
                if script_count > 0 {
                    println!(
                        "  • {} script{}",
                        script_count,
                        if script_count == 1 { "" } else { "s" }
                    );
                }
                if ddm_count > 0 {
                    println!(
                        "  • {} DDM artifact{}",
                        ddm_count,
                        if ddm_count == 1 { "" } else { "s" }
                    );
                }

                // Show what transformations would be applied
                if munki_compliance_options.is_some() {
                    println!("  • Munki compliance flags");
                }
                if munki_script_options.is_some() {
                    println!("  • Munki script packaging");
                }
            }

            result.profiles_generated = profile_count;
            result.scripts_generated = script_count;
            result.ddm_artifacts = ddm_count;
        }
    } else {
        // Set baseline in jamf_options for identifier formatting
        let jamf_options = jamf_options.map(|mut opts| {
            opts.baseline = Some(baseline_name.clone());
            opts
        });

        process_baseline(
            build_path.clone(),
            output_path.clone(),
            baseline_name.clone(),
            Some(mscp_repo_path),
            profile_options,
            jamf_options,
            munki_compliance_options.clone(),
            munki_script_options.clone(),
            no_labels,
            fleet_mode,
            jamf_exclude_conflicts,
            false,             // dry_run - always false here since we're in the !dry_run block
            OutputMode::Human, // Use human mode - batch_mode handles JSON at a higher level
            script_mode,
            exclude_categories,
            fragment,
            output_structure,
            glob_config,
        )?;

        // Count what was generated (recursive walk — files are in nested subdirs)
        for entry in walkdir::WalkDir::new(&output_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Some(ext) = entry.path().extension() {
                if ext == "mobileconfig" {
                    result.profiles_generated += 1;
                } else if ext == "sh" {
                    result.scripts_generated += 1;
                } else if ext == "json" && entry.path().to_string_lossy().contains("declarative") {
                    result.ddm_artifacts += 1;
                }
            }
        }
    }

    // Step 3: Update fleet files if requested
    if let Some(teams) = fleet_names {
        // Validate teams upfront before doing any work
        {
            use crate::updaters::FleetUpdater;
            let updater = FleetUpdater::new(&output_path, baseline_name.clone());
            updater.validate_fleets(&teams)?;
        };

        if dry_run {
            if output_mode == OutputMode::Human && !batch_mode {
                println!("\nWould update fleet files:");
                for team in &teams {
                    println!("  • Add baseline to fleet: {team}");
                }
                println!("  • Update default.yml with labels");
            }
        } else {
            tracing::info!("Updating fleet files...");
            use crate::updaters::FleetUpdater;

            let updater =
                FleetUpdater::new(&output_path, baseline_name.clone()).with_glob(fleet_glob);

            // Add labels to default.yml
            updater.add_labels_to_default()?;

            // Add baseline to specified teams
            updater.add_to_fleets(&teams)?;

            if output_mode == OutputMode::Human && !batch_mode {
                println!("{}", "✓ Team files updated successfully".green());
            }
        }
    }

    // Output results (skip if in batch mode - parent will handle output)
    if !batch_mode {
        match output_mode {
            OutputMode::Json => {
                crate::output::json::output_result(&result)?;
            }
            OutputMode::Human => {
                if dry_run {
                    println!("\n{}", "✓ Dry run complete - no files were written".green());
                } else {
                    println!(
                        "\n{}",
                        format!("✓ Baseline '{baseline_name}' generated successfully!")
                            .green()
                            .bold()
                    );

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
    }

    Ok(())
}

/// Detect which Python method to use (prefers uv, requires it if not explicitly overridden)
fn detect_python_method(_mscp_repo_path: &PathBuf) -> PythonMethod {
    // Check if uv is available
    let has_uv = Command::new("uv")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_uv {
        tracing::info!("Using uv for Python execution");
        PythonMethod::Uv
    } else {
        eprintln!("\n⚠️  uv is required but not found.");
        eprintln!();
        eprintln!("Install uv:");
        eprintln!("  Visit: https://docs.astral.sh/uv/getting-started/installation/");
        eprintln!();
        eprintln!("  mise install uv              # via mise");
        eprintln!("  brew install uv              # via Homebrew");
        eprintln!("  curl -LsSf https://astral.sh/uv/install.sh | sh");
        eprintln!();
        eprintln!("Or run: ./scripts/setup-deps.sh");
        eprintln!();
        eprintln!("Alternative: Use --use-python3 flag to use system Python");
        eprintln!("            (not recommended - requires manual dependency installation)");
        eprintln!();

        std::process::exit(1);
    }
}

/// Ensure mSCP repository exists, clone if missing
fn ensure_mscp_repo(mscp_repo_path: &PathBuf) -> Result<()> {
    let script_path = mscp_repo_path.join("scripts/generate_guidance.py");

    if !script_path.exists() {
        tracing::warn!("mSCP repository not found at: {}", mscp_repo_path.display());

        // Check for auto-clone environment variable (for CI/CD)
        let auto_clone = std::env::var("SHAPE_AUTO_CLONE_MSCP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        if auto_clone {
            tracing::info!("SHAPE_AUTO_CLONE_MSCP is set, cloning automatically");
            eprintln!("\n📦 Auto-cloning mSCP repository (SHAPE_AUTO_CLONE_MSCP=1)...");
            clone_mscp_repo(mscp_repo_path)?;
        } else {
            // Offer to clone the repository (interactive)
            eprintln!("\n⚠️  The mSCP repository is required but not found.");
            eprintln!("   Expected location: {}", mscp_repo_path.display());
            eprintln!();
            eprintln!("Would you like to clone it now? (recommended)");
            eprintln!("  Repository: https://github.com/usnistgov/macos_security");
            eprintln!();
            eprint!("Clone mSCP repository? [Y/n]: ");

            use std::io::{self, Write};
            io::stdout().flush()?;

            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            let response = response.trim().to_lowercase();

            if response.is_empty() || response == "y" || response == "yes" {
                clone_mscp_repo(mscp_repo_path)?;
            } else {
                anyhow::bail!(
                    "\nmSCP repository required. Please:\n\
                     1. Clone manually: git clone https://github.com/usnistgov/macos_security {}\n\
                     2. Or run: contour mscp init\n\
                     3. Or specify a different path with --mscp-repo\n\
                     4. Or set SHAPE_AUTO_CLONE_MSCP=1 for automatic cloning",
                    mscp_repo_path.display()
                );
            }
        }
    }

    Ok(())
}

/// Clone the mSCP repository
fn clone_mscp_repo(target_path: &PathBuf) -> Result<()> {
    tracing::info!("Cloning mSCP repository...");

    eprintln!("\n📦 Cloning mSCP repository...");
    eprintln!("   This may take a minute...\n");

    // Create parent directory if it doesn't exist
    if let Some(parent) = target_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .context(format!("Failed to create directory: {}", parent.display()))?;
    }

    // Clone the repository
    let output = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1") // Shallow clone for faster download
        .arg("https://github.com/usnistgov/macos_security.git")
        .arg(target_path)
        .output()
        .context("Failed to execute git clone. Is git installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Git clone failed: {stderr}");
    }

    eprintln!("✅ mSCP repository cloned successfully!\n");
    tracing::info!("mSCP repository cloned to: {}", target_path.display());

    Ok(())
}

/// Pick the highest available OS version for a 2.0 baseline.
///
/// mSCP 2.0 names baseline files `<name>_<os>_<version>.yaml` under
/// `baselines/<os>/`. With no explicit `--os-version`, choose the newest.
fn highest_baseline_version(mscp_repo: &Path, baseline_name: &str, os: &str) -> Result<String> {
    let dir = mscp_repo.join("baselines").join(os);
    let prefix = format!("{baseline_name}_{os}_");
    let mut versions: Vec<(u32, u32, String)> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading mSCP 2.0 baselines directory {}", dir.display()))?
        .filter_map(std::result::Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| {
            let ver = name.strip_prefix(&prefix)?.strip_suffix(".yaml")?;
            let mut parts = ver.split('.');
            let major: u32 = parts.next()?.parse().ok()?;
            let minor: u32 = parts.next().and_then(|m| m.parse().ok()).unwrap_or(0);
            Some((major, minor, ver.to_string()))
        })
        .collect();
    versions.sort();
    versions.pop().map(|(_, _, v)| v).ok_or_else(|| {
        anyhow::anyhow!(
            "no mSCP 2.0 baseline files matching '{prefix}*.yaml' under {}; \
             check --os or pass --os-version",
            dir.display()
        )
    })
}

/// Resolve the repo-relative baseline YAML path to feed the mSCP build,
/// handling both layouts:
/// - 1.x: `baselines/<name>.yaml`
/// - 2.0: `baselines/<os>/<name>_<os>_<version>.yaml`
fn resolve_baseline_yaml(
    mscp_repo: &Path,
    baseline_name: &str,
    mscp_version: &str,
    os: &str,
    os_version: Option<&str>,
) -> Result<String> {
    let layout = crate::layout::MscpLayout::detect_or_from(Some(mscp_version), mscp_repo)
        .with_context(|| format!("detecting mSCP layout in {}", mscp_repo.display()))?;

    let rel = match layout {
        crate::layout::MscpLayout::V1x => format!("baselines/{baseline_name}.yaml"),
        crate::layout::MscpLayout::V2x => {
            let version = match os_version {
                Some(v) => v.to_string(),
                None => highest_baseline_version(mscp_repo, baseline_name, os)?,
            };
            format!("baselines/{os}/{baseline_name}_{os}_{version}.yaml")
        }
    };

    if !mscp_repo.join(&rel).exists() {
        anyhow::bail!(
            "Baseline YAML not found: {} (detected mSCP {} layout)",
            mscp_repo.join(&rel).display(),
            layout
        );
    }
    tracing::info!("Using baseline manifest: {rel} (mSCP {layout})");
    Ok(rel)
}

/// Run mSCP baseline generation. Returns the `build/<subdir>` directory
/// name the build wrote to (`<baseline>` for 1.x, `<baseline>_<os>_<version>`
/// for 2.0).
fn run_mscp_generation(
    mscp_repo_path: &PathBuf,
    baseline_name: &str,
    method: PythonMethod,
    generate_ddm: bool,
    mscp_version: &str,
    os: &str,
    os_version: Option<&str>,
) -> Result<String> {
    // Validate baseline name to prevent path traversal.
    if !baseline_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        || baseline_name.is_empty()
    {
        anyhow::bail!(
            "Invalid baseline name '{baseline_name}': must contain only letters, digits, hyphens, and underscores"
        );
    }

    // Container mode runs mSCP inside the image; the other methods build the
    // local repo, so ensure it is present first.
    if method != PythonMethod::Container {
        ensure_mscp_repo(mscp_repo_path)?;
    }

    // Resolve the baseline YAML path for the repo's mSCP layout. Container
    // mode without a local checkout has nothing to inspect, so it falls
    // back to the 1.x flat path.
    let baseline_yaml_relative =
        if method == PythonMethod::Container && !mscp_repo_path.join("rules").exists() {
            format!("baselines/{baseline_name}.yaml")
        } else {
            resolve_baseline_yaml(mscp_repo_path, baseline_name, mscp_version, os, os_version)?
        };

    // The mSCP build writes to `build/<yaml-stem>`.
    let build_subdir = Path::new(&baseline_yaml_relative)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(baseline_name)
        .to_string();

    // Use relative paths since we set current_dir to mscp_repo_path
    let script_relative = "scripts/generate_guidance.py";

    let output = match method {
        PythonMethod::Python3 => {
            let mut cmd_args = vec!["-p", "-s"];
            if generate_ddm {
                tracing::info!("Adding {MSCP_DDM_FLAG} flag to generate DDM artifacts");
                cmd_args.push(MSCP_DDM_FLAG);
            }

            tracing::info!(
                "Executing: python3 {} {} {} (in {})",
                script_relative,
                cmd_args.join(" "),
                baseline_yaml_relative,
                mscp_repo_path.display()
            );

            let mut cmd = Command::new("python3");
            cmd.arg(script_relative).arg("-p").arg("-s");

            if generate_ddm {
                cmd.arg(MSCP_DDM_FLAG);
            }

            cmd.arg(&baseline_yaml_relative)
                .current_dir(mscp_repo_path)
                .output()
                .context("Failed to execute python3")?
        }
        PythonMethod::Uv => {
            let requirements_relative = "requirements.txt";

            // Pin the interpreter so uv installs prebuilt wheels rather
            // than compiling mSCP's deps from source. Skip the pin when
            // the caller set `UV_PYTHON` — that is the explicit override.
            let pin_python = std::env::var_os("UV_PYTHON").is_none();

            let mut cmd_args = vec!["-p", "-s"];
            if generate_ddm {
                tracing::info!("Adding {MSCP_DDM_FLAG} flag to generate DDM artifacts");
                cmd_args.push(MSCP_DDM_FLAG);
            }

            tracing::info!(
                "Executing: uv run {}--with-requirements {} python {} {} {} (in {})",
                if pin_python {
                    format!("--python {MSCP_PYTHON_VERSION} ")
                } else {
                    String::new()
                },
                requirements_relative,
                script_relative,
                cmd_args.join(" "),
                baseline_yaml_relative,
                mscp_repo_path.display()
            );

            let mut cmd = Command::new("uv");
            cmd.arg("run");
            if pin_python {
                cmd.arg("--python").arg(MSCP_PYTHON_VERSION);
            }
            cmd.arg("--with-requirements")
                .arg(requirements_relative)
                .arg("python")
                .arg(script_relative)
                .arg("-p")
                .arg("-s");

            if generate_ddm {
                cmd.arg(MSCP_DDM_FLAG);
            }

            cmd.arg(&baseline_yaml_relative)
                .current_dir(mscp_repo_path)
                .output()
                .context("Failed to execute uv run")?
        }
        PythonMethod::Container => {
            run_mscp_container(mscp_repo_path, &baseline_yaml_relative, generate_ddm)?;
            return Ok(build_subdir);
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("mSCP generation failed:\n{stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("mSCP output:\n{}", stdout);

    Ok(build_subdir)
}

/// Detect available container runtime
fn detect_container_runtime() -> Option<ContainerRuntime> {
    // Check for Docker first (more reliable for builds)
    if Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        // Also check if Docker daemon is running
        if Command::new("docker")
            .arg("info")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(ContainerRuntime::Docker);
        }
    }

    // Fall back to Apple container tool
    if Command::new("container")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some(ContainerRuntime::AppleContainer);
    }

    None
}

/// Pull the mSCP container image
pub fn pull_mscp_container(image: Option<&str>) -> Result<()> {
    let image = image.unwrap_or(DEFAULT_MSCP_CONTAINER_IMAGE);

    let runtime = detect_container_runtime().ok_or_else(|| {
        anyhow::anyhow!("No container runtime found. Install Docker or Apple container tool.")
    })?;

    tracing::info!("Pulling mSCP container image: {}", image);
    println!("📦 Pulling mSCP container image: {}", image);
    println!("   Using runtime: {:?}", runtime);

    let output = match runtime {
        ContainerRuntime::Docker => Command::new("docker")
            .arg("pull")
            .arg(image)
            .output()
            .context("Failed to execute docker pull")?,
        ContainerRuntime::AppleContainer => Command::new("container")
            .arg("pull")
            .arg(image)
            .output()
            .context("Failed to execute container pull")?,
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to pull container image:\n{stderr}");
    }

    println!("✅ Container image pulled successfully");
    Ok(())
}

/// Dockerfile template for mSCP
const MSCP_DOCKERFILE: &str = r#"# mSCP (macOS Security Compliance Project) Container
# Generated by contour mscp - https://github.com/usnistgov/macos_security
#
# Build: docker build -t mscp:local .
# Run:   docker run --rm -v $(pwd)/build:/macos_security/build mscp:local python3 scripts/generate_guidance.py -p -s baselines/cis_lvl1.yaml

FROM python:3.12-slim

LABEL org.opencontainers.image.title="mSCP - macOS Security Compliance Project"
LABEL org.opencontainers.image.description="Container for generating macOS security baselines"
LABEL org.opencontainers.image.source="https://github.com/usnistgov/macos_security"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /macos_security

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the mSCP repository
COPY . .

# Create build directory
RUN mkdir -p /macos_security/build

# Default command shows help
CMD ["python3", "scripts/generate_guidance.py", "--help"]
"#;

/// Initialize a local mSCP container
pub fn container_init(
    mscp_repo: &std::path::Path,
    branch: &str,
    tag: &str,
    no_build: bool,
    force_docker: bool,
) -> Result<()> {
    let runtime = if force_docker {
        // Check if Docker is available and running
        let docker_running = Command::new("docker")
            .arg("info")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !docker_running {
            anyhow::bail!("Docker is not running. Please start Docker Desktop and try again.");
        }
        ContainerRuntime::Docker
    } else {
        detect_container_runtime().ok_or_else(|| {
            anyhow::anyhow!("No container runtime found. Install Docker or Apple container tool.")
        })?
    };

    println!("🐳 Initializing mSCP container...");
    println!("   Runtime: {:?}", runtime);
    println!("   Repository: {}", mscp_repo.display());
    println!("   Branch: {}", branch);
    println!("   Image tag: {}", tag);
    println!();

    // Clone or update mSCP repository
    if !mscp_repo.exists() {
        println!("📥 Cloning mSCP repository...");
        let output = Command::new("git")
            .arg("clone")
            .arg("--branch")
            .arg(branch)
            .arg("--depth")
            .arg("1")
            .arg("https://github.com/usnistgov/macos_security.git")
            .arg(mscp_repo)
            .output()
            .context("Failed to clone mSCP repository")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to clone mSCP repository:\n{stderr}");
        }
        println!("✅ Repository cloned");
    } else {
        println!("📂 Using existing repository at {}", mscp_repo.display());

        // Check current branch and switch if needed
        let current_branch = Command::new("git")
            .arg("rev-parse")
            .arg("--abbrev-ref")
            .arg("HEAD")
            .current_dir(mscp_repo)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        if current_branch != branch {
            println!("🔀 Switching to branch: {}", branch);
            let output = Command::new("git")
                .arg("checkout")
                .arg(branch)
                .current_dir(mscp_repo)
                .output()
                .context("Failed to switch branch")?;

            if !output.status.success() {
                // Try fetching and checking out
                let _ = Command::new("git")
                    .arg("fetch")
                    .arg("origin")
                    .arg(branch)
                    .current_dir(mscp_repo)
                    .output();

                let output = Command::new("git")
                    .arg("checkout")
                    .arg(branch)
                    .current_dir(mscp_repo)
                    .output()
                    .context("Failed to switch branch")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Failed to switch to branch {branch}:\n{stderr}");
                }
            }
        }
    }

    // Write Dockerfile
    let dockerfile_path = mscp_repo.join("Dockerfile");
    println!("📝 Creating Dockerfile at {}", dockerfile_path.display());
    fs::write(&dockerfile_path, MSCP_DOCKERFILE).context("Failed to write Dockerfile")?;
    println!("✅ Dockerfile created");

    if no_build {
        println!();
        println!("ℹ️  Skipping build (--no-build specified)");
        println!("   To build manually:");
        println!("   cd {} && docker build -t {} .", mscp_repo.display(), tag);
        return Ok(());
    }

    // Build the container with real-time output
    println!();
    println!("🔨 Building container image: {}", tag);
    println!("   This may take a few minutes...");
    println!();

    let status = match runtime {
        ContainerRuntime::Docker => Command::new("docker")
            .arg("build")
            .arg("-t")
            .arg(tag)
            .arg(".")
            .current_dir(mscp_repo)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .context("Failed to build Docker image")?,
        ContainerRuntime::AppleContainer => Command::new("container")
            .arg("build")
            .arg("-t")
            .arg(tag)
            .arg(".")
            .current_dir(mscp_repo)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .context("Failed to build container image")?,
    };

    if !status.success() {
        anyhow::bail!("Failed to build container image");
    }

    println!("✅ Container image built successfully: {}", tag);
    println!();
    println!("🚀 Usage:");
    println!(
        "   contour mscp generate --mscp-repo {} --keyword cis_lvl1 --output ./output --use-container",
        mscp_repo.display()
    );
    println!();
    println!("   Or run directly:");
    match runtime {
        ContainerRuntime::Docker => {
            println!(
                "   docker run --rm -v $(pwd)/build:/macos_security/build {} python3 scripts/generate_guidance.py -p -s baselines/cis_lvl1.yaml",
                tag
            );
        }
        ContainerRuntime::AppleContainer => {
            println!(
                "   container run --rm --volume $(pwd)/build:/macos_security/build {} python3 scripts/generate_guidance.py -p -s baselines/cis_lvl1.yaml",
                tag
            );
        }
    }

    Ok(())
}

/// Check container runtime status
pub fn container_status() -> Result<()> {
    println!("🔍 Checking container runtime status...\n");

    // Check Apple container
    let apple_available = Command::new("container")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if apple_available {
        let version = Command::new("container")
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        println!("✅ Apple container: available ({})", version);
    } else {
        println!("❌ Apple container: not found");
    }

    // Check Docker
    let docker_available = Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if docker_available {
        let version = Command::new("docker")
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        println!("✅ Docker: available ({})", version);
    } else {
        println!("❌ Docker: not found");
    }

    println!();

    if let Some(runtime) = detect_container_runtime() {
        println!("📦 Default runtime: {:?}", runtime);
        println!("   Default image: {}", DEFAULT_MSCP_CONTAINER_IMAGE);
    } else {
        println!("⚠️  No container runtime available");
        println!("   Install Docker: https://docs.docker.com/get-docker/");
        println!("   Or use: brew install container");
    }

    Ok(())
}

/// Test container by running mSCP help
pub fn test_container(image: Option<&str>) -> Result<()> {
    let image = image.unwrap_or(DEFAULT_MSCP_CONTAINER_IMAGE);

    let runtime = detect_container_runtime().ok_or_else(|| {
        anyhow::anyhow!("No container runtime found. Install Docker or Apple container tool.")
    })?;

    println!("🧪 Testing container: {}", image);
    println!("   Runtime: {:?}", runtime);
    println!();

    let output = match runtime {
        ContainerRuntime::Docker => Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg(image)
            .arg("python3")
            .arg("scripts/generate_guidance.py")
            .arg("--help")
            .output()
            .context("Failed to execute docker run")?,
        ContainerRuntime::AppleContainer => Command::new("container")
            .arg("run")
            .arg("--rm")
            .arg(image)
            .arg("python3")
            .arg("scripts/generate_guidance.py")
            .arg("--help")
            .output()
            .context("Failed to execute container run")?,
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Container test failed:\n{stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("✅ Container test successful!\n");
    println!("mSCP generate_guidance.py help output:");
    println!("─────────────────────────────────────");
    println!("{}", stdout);

    Ok(())
}

/// Bail with a clear next-step if the operator's local mSCP repo is on
/// a different layout than the container image expects. The default
/// image (`ghcr.io/brodjieski/mscp_2.0:latest`) bakes in 2.0 scripts
/// that can't read 1.x rule semantics; running them against a 1.x repo
/// fails with a confusing "build output not found" *after* the
/// container exits. Failing fast here surfaces the actual problem and
/// tells the operator how to switch.
///
/// Only enforced when a local repo with a `rules/` directory exists —
/// bare container mode (no local mSCP checkout) still works against
/// the image's baked-in baselines/rules.
fn assert_compatible_layout(mscp_repo_abs: &Path, image: &str) -> Result<()> {
    if !mscp_repo_abs.join("rules").exists() {
        return Ok(());
    }
    let Ok(layout) = crate::layout::MscpLayout::detect(mscp_repo_abs) else {
        // `rules/` exists but layout detection failed — let the script
        // produce its own error rather than guessing here.
        return Ok(());
    };

    if layout == crate::layout::MscpLayout::V1x && image.contains("mscp_2.0") {
        anyhow::bail!(
            "Local mSCP repo at `{repo}` is on the 1.x layout (flat \
             `baselines/<name>.yaml`), but the default container image \
             `{image}` is mSCP 2.0. The image's 2.0 scripts can't read 1.x \
             rules, so the run would fail with a confusing error after the \
             container exits.\n\n\
             Fix by switching the local repo to 2.0:\n  \
             git -C {repo} fetch origin dev_2.0:dev_2.0 && \\\n  \
             git -C {repo} checkout dev_2.0\n\n\
             Or drop `--use-container` and use the local Python interpreter \
             (`--use-uv` / `--use-python3`), which works with either layout.",
            repo = mscp_repo_abs.display(),
            image = image,
        );
    }
    Ok(())
}

/// Run mSCP generation using container.
///
/// Layout-aware: when a local mSCP repo is present, the operator's
/// `rules/`, `baselines/`, `custom/`, and `includes/` subdirectories
/// are bind-mounted over the image's baked-in copies (read-only). The
/// image keeps its Python venv, scripts/, src/, and templates/; the
/// operator's customisations become visible to the script.
///
/// The default image (`mscp_2.0:latest`) bakes in mSCP 2.0 scripts that
/// don't understand 1.x rule semantics. So before mounting, the local
/// repo's layout must match the image's layout — otherwise bail with a
/// clear next-step instead of producing a confusing "build output not
/// found" error after the container runs.
fn run_mscp_container(
    mscp_repo_path: &PathBuf,
    baseline_yaml_relative: &str,
    generate_ddm: bool,
) -> Result<()> {
    let image = DEFAULT_MSCP_CONTAINER_IMAGE;

    // Get absolute path (best effort — if the repo path doesn't exist
    // yet, fall back to the caller's value; we'll re-check after creating
    // build/).
    let mscp_repo_abs = mscp_repo_path
        .canonicalize()
        .unwrap_or_else(|_| mscp_repo_path.clone());

    // Layout safety check first — runs without needing a container
    // runtime, so it fails fast with an actionable message even on a
    // machine without Docker/Apple container.
    assert_compatible_layout(&mscp_repo_abs, image)?;

    let runtime = detect_container_runtime().ok_or_else(|| {
        anyhow::anyhow!("No container runtime found. Install Docker or Apple container tool.")
    })?;

    // Ensure output directory exists (after layout check so we don't
    // create an empty build/ when we're about to bail).
    let build_dir = mscp_repo_path.join("build");
    fs::create_dir_all(&build_dir)?;

    // Build the bind-mount list. `build/` always gets mounted (that's
    // where the script writes its output). The operator-editable
    // subdirs are mounted only when present on disk, read-only to
    // protect them from container-side writes.
    let build_dir_canonical = build_dir
        .canonicalize()
        .unwrap_or_else(|_| build_dir.clone());
    let mut bind_mounts: Vec<(String, String, bool)> = vec![(
        build_dir_canonical.display().to_string(),
        MSCP_CONTAINER_BUILD_DIR.to_string(),
        false, // build/ must be writable — the script writes its output here
    )];
    for sub in ["rules", "baselines", "custom", "includes"] {
        let host_path = mscp_repo_abs.join(sub);
        if host_path.exists() {
            bind_mounts.push((
                host_path.display().to_string(),
                format!("/mscp/{sub}"),
                true, // operator's source is read-only inside the container
            ));
        }
    }

    tracing::info!(
        "Running mSCP generation in container ({:?}): baseline={}, {} bind mount(s)",
        runtime,
        baseline_yaml_relative,
        bind_mounts.len()
    );

    // Both Docker and `container` accept `-v host:target[:ro]`; only
    // the long flag differs ('container' uses `--volume`).
    let (cmd_name, vol_flag) = match runtime {
        ContainerRuntime::Docker => ("docker", "-v"),
        ContainerRuntime::AppleContainer => ("container", "--volume"),
    };

    let mut cmd_args = vec!["-p", "-s"];
    if generate_ddm {
        cmd_args.push(MSCP_DDM_FLAG);
    }

    let output = {
        let mut cmd = Command::new(cmd_name);
        cmd.arg("run").arg("--rm");
        for (host, target, read_only) in &bind_mounts {
            cmd.arg(vol_flag);
            if *read_only {
                cmd.arg(format!("{host}:{target}:ro"));
            } else {
                cmd.arg(format!("{host}:{target}"));
            }
        }
        cmd.arg(image)
            .arg("python3")
            .arg("scripts/generate_guidance.py")
            .arg("-p")
            .arg("-s");

        if generate_ddm {
            cmd.arg(MSCP_DDM_FLAG);
        }

        cmd.arg(baseline_yaml_relative);

        tracing::info!(
            "Executing: {cmd_name} run --rm {mounts} {image} python3 scripts/generate_guidance.py {args} {baseline_yaml_relative}",
            mounts = bind_mounts
                .iter()
                .map(|(h, t, ro)| if *ro {
                    format!("{vol_flag} {h}:{t}:ro")
                } else {
                    format!("{vol_flag} {h}:{t}")
                })
                .collect::<Vec<_>>()
                .join(" "),
            args = cmd_args.join(" "),
        );

        cmd.output()
            .with_context(|| format!("Failed to execute {cmd_name} run"))?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("Container mSCP generation failed:\nstdout: {stdout}\nstderr: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Container mSCP output:\n{}", stdout);

    Ok(())
}

/// Generate all configured baselines
pub fn generate_all_baselines(
    mscp_repo_path: PathBuf,
    baseline_names: Vec<String>,
    output_path: PathBuf,
    python_method: Option<PythonMethod>,
    profile_options: Option<ProfileOptions>,
    jamf_options: Option<crate::transformers::JamfOptions>,
    munki_compliance_options: Option<crate::transformers::MunkiComplianceOptions>,
    munki_script_options: Option<crate::transformers::MunkiScriptOptions>,
    fleet_mode: bool,
    jamf_exclude_conflicts: bool,
    generate_ddm: bool,
    dry_run: bool,
    parallel: bool,
    output_mode: OutputMode,
    script_mode: ScriptMode,
    fragment: bool,
    output_structure: OutputStructure,
) -> Result<()> {
    use crate::output::GenerateAllResult;

    tracing::info!("Generating {} baselines", baseline_names.len());

    // Initialize result tracking
    let mut all_result = GenerateAllResult::new(baseline_names.len());

    if parallel {
        // Parallel processing with rayon — collect outcomes lock-free, then fold
        use rayon::prelude::*;

        let outcomes: Vec<(usize, String, Result<()>)> = baseline_names
            .par_iter()
            .enumerate()
            .map(|(i, baseline_name)| {
                if output_mode == OutputMode::Human {
                    println!(
                        "\n[{}/{}] Generating baseline: {}",
                        i + 1,
                        baseline_names.len(),
                        baseline_name
                    );
                }

                let result = generate_baseline(
                    mscp_repo_path.clone(),
                    baseline_name.clone(),
                    output_path.clone(),
                    python_method,
                    profile_options.clone(),
                    jamf_options.clone(),
                    munki_compliance_options.clone(),
                    munki_script_options.clone(),
                    false, // no_labels (default to generating labels)
                    None,  // fleet_names - not used in generate-all mode
                    false, // fleet_glob - not used in generate-all mode
                    fleet_mode,
                    jamf_exclude_conflicts,
                    generate_ddm,
                    dry_run,
                    OutputMode::Human, // Individual baselines use human mode in batch
                    true,              // batch_mode - suppress individual output
                    script_mode,
                    None, // exclude_categories - not supported in generate-all mode
                    fragment,
                    output_structure.clone(),
                    None, // glob_config - not yet plumbed per-baseline in generate-all
                    "auto".to_string(), // mscp_version — auto-detect layout
                    "macos".to_string(), // os
                    None, // os_version
                );

                (i, baseline_name.clone(), result)
            })
            .collect();

        // Fold outcomes into all_result sequentially (no lock contention)
        for (_i, baseline_name, result) in outcomes {
            match result {
                Ok(()) => {
                    all_result.processed += 1;
                }
                Err(e) => {
                    all_result.failed += 1;
                    all_result.success = false;
                    all_result.add_error(format!("Failed to generate '{baseline_name}': {e}"));
                }
            }
        }
    } else {
        // Sequential processing
        for (i, baseline_name) in baseline_names.iter().enumerate() {
            if output_mode == OutputMode::Human {
                println!(
                    "\n[{}/{}] Generating baseline: {}",
                    i + 1,
                    baseline_names.len(),
                    baseline_name
                );
            }

            match generate_baseline(
                mscp_repo_path.clone(),
                baseline_name.clone(),
                output_path.clone(),
                python_method,
                profile_options.clone(),
                jamf_options.clone(),
                munki_compliance_options.clone(),
                munki_script_options.clone(),
                false, // no_labels (default to generating labels)
                None,  // fleet_names - not used in generate-all mode
                false, // fleet_glob - not used in generate-all mode
                fleet_mode,
                jamf_exclude_conflicts,
                generate_ddm,
                dry_run,
                OutputMode::Human, // Individual baselines use human mode in batch
                true,              // batch_mode - suppress individual output
                script_mode,
                None, // exclude_categories - not supported in generate-all mode
                fragment,
                output_structure.clone(),
                None,               // glob_config - not yet plumbed per-baseline in generate-all
                "auto".to_string(), // mscp_version — auto-detect layout
                "macos".to_string(), // os
                None,               // os_version
            ) {
                Ok(()) => {
                    all_result.processed += 1;
                }
                Err(e) => {
                    all_result.failed += 1;
                    all_result.add_error(format!("Failed to generate '{baseline_name}': {e}"));
                    all_result.success = false;
                }
            }
        }
    }

    // Output results
    match output_mode {
        OutputMode::Json => {
            crate::output::json::output_generate_all_result(&all_result)?;
        }
        OutputMode::Human => {
            if all_result.success {
                println!(
                    "\n{}",
                    "✓ All baselines generated successfully!".green().bold()
                );
                println!(
                    "  {} Processed: {}/{}",
                    "•".cyan(),
                    all_result.processed,
                    all_result.total_baselines
                );
            } else {
                eprintln!("\n{}", "Some baselines failed:".yellow().bold());
                eprintln!("  {} Succeeded: {}", "•".green(), all_result.processed);
                eprintln!("  {} Failed: {}", "•".red(), all_result.failed);
                for error in &all_result.errors {
                    eprintln!("    {} {}", "-".red(), error);
                }
            }
        }
    }

    if !all_result.success {
        anyhow::bail!("Some baselines failed to generate");
    }

    Ok(())
}

/// List all available baselines from mSCP repository
pub fn list_available_baselines(mscp_repo_path: PathBuf, output_mode: OutputMode) -> Result<()> {
    // Check if mSCP repo exists
    if !mscp_repo_path.exists() {
        // In JSON mode (or any non-interactive context), fail fast rather than prompting —
        // a blocking stdin read would hang CI and produce garbled JSON output.
        if output_mode == OutputMode::Json {
            anyhow::bail!(
                "mSCP repository not found at: {}. Run `contour mscp init` to clone.",
                mscp_repo_path.display()
            );
        }

        eprintln!(
            "\n⚠️  mSCP repository not found at: {}",
            mscp_repo_path.display()
        );
        eprintln!();
        eprintln!("Would you like to clone it now?");
        eprint!("Clone mSCP repository? [Y/n]: ");

        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();

        if response.is_empty() || response == "y" || response == "yes" {
            clone_mscp_repo(&mscp_repo_path)?;
        } else {
            anyhow::bail!("Cannot list baselines without mSCP repository");
        }
    }

    // Get current branch
    let current_branch = get_current_branch(&mscp_repo_path)?;
    let (platform, version) = parse_branch_info(&current_branch);

    let baselines_dir = mscp_repo_path.join("baselines");

    if !baselines_dir.exists() {
        anyhow::bail!(
            "Baselines directory not found at: {}. Is this a valid mSCP repo?",
            baselines_dir.display()
        );
    }

    // Read all .yaml files in baselines directory
    let mut baselines = Vec::new();
    for entry in fs::read_dir(&baselines_dir).context(format!(
        "Failed to read baselines directory: {}",
        baselines_dir.display()
    ))? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file()
            && path.extension().and_then(|s| s.to_str()) == Some("yaml")
            && let Some(basename) = path.file_stem().and_then(|s| s.to_str())
        {
            // Skip template/example files
            if !basename.contains("template") && !basename.contains("example") {
                let description = read_baseline_description(&path);
                let platform = detect_baseline_platform(&description);
                baselines.push((basename.to_string(), path, description, platform));
            }
        }
    }

    if output_mode == OutputMode::Json {
        #[derive(serde::Serialize)]
        struct AvailableBaseline<'a> {
            name: &'a str,
            platform: &'a str,
            description: Option<&'a str>,
            path: &'a std::path::Path,
        }
        let json: Vec<AvailableBaseline<'_>> = baselines
            .iter()
            .map(|(name, path, desc, platform)| AvailableBaseline {
                name: name.as_str(),
                platform: platform.as_str(),
                description: desc.as_deref(),
                path: path.as_path(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    if baselines.is_empty() {
        println!("No baselines found in {}", baselines_dir.display());
        return Ok(());
    }

    // Group by platform
    let mut macos_baselines = Vec::new();
    let mut ios_baselines = Vec::new();
    let mut visionos_baselines = Vec::new();
    let mut unknown_baselines = Vec::new();

    for (name, path, desc, platform) in baselines {
        match platform.as_str() {
            "macOS" => macos_baselines.push((name, path, desc)),
            "iOS" => ios_baselines.push((name, path, desc)),
            "visionOS" => visionos_baselines.push((name, path, desc)),
            _ => unknown_baselines.push((name, path, desc)),
        }
    }

    // Sort each group
    macos_baselines.sort_by(|a, b| a.0.cmp(&b.0));
    ios_baselines.sort_by(|a, b| a.0.cmp(&b.0));
    visionos_baselines.sort_by(|a, b| a.0.cmp(&b.0));
    unknown_baselines.sort_by(|a, b| a.0.cmp(&b.0));

    // Display baselines grouped by platform
    println!("\n{}", "Available mSCP Baselines".cyan().bold());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════".dimmed()
    );
    println!(
        "\n{} {} ({} {})",
        "Current Branch:".bold(),
        current_branch.green(),
        if platform.is_empty() {
            "Unknown Platform"
        } else {
            platform.as_str()
        },
        if version.is_empty() {
            ""
        } else {
            version.as_str()
        }
    );
    println!(
        "{}",
        "──────────────────────────────────────────────────────────".dimmed()
    );

    let total = macos_baselines.len()
        + ios_baselines.len()
        + visionos_baselines.len()
        + unknown_baselines.len();

    if !macos_baselines.is_empty() {
        println!(
            "\n{} ({}):",
            "macOS Baselines".cyan().bold(),
            macos_baselines.len()
        );
        println!(
            "{}",
            "──────────────────────────────────────────────────────────".dimmed()
        );
        for (name, _path, desc) in &macos_baselines {
            if let Some(d) = desc {
                // Clean up description to remove platform prefix
                let clean_desc = d.replace("macOS ", "").replace("macOS: ", "");
                println!(
                    "  {} {} - {}",
                    "•".cyan(),
                    name.green(),
                    clean_desc.dimmed()
                );
            } else {
                println!("  {} {}", "•".cyan(), name.green());
            }
        }
    }

    if !ios_baselines.is_empty() {
        println!(
            "\n{} ({}):",
            "iOS/iPadOS Baselines".cyan().bold(),
            ios_baselines.len()
        );
        println!(
            "{}",
            "──────────────────────────────────────────────────────────".dimmed()
        );
        for (name, _path, desc) in &ios_baselines {
            if let Some(d) = desc {
                // Clean up description to remove platform prefix
                let clean_desc = d.replace("iOS/iPadOS ", "").replace("iOS ", "");
                println!(
                    "  {} {} - {}",
                    "•".cyan(),
                    name.green(),
                    clean_desc.dimmed()
                );
            } else {
                println!("  {} {}", "•".cyan(), name.green());
            }
        }
    }

    if !visionos_baselines.is_empty() {
        println!(
            "\n{} ({}):",
            "visionOS Baselines".cyan().bold(),
            visionos_baselines.len()
        );
        println!(
            "{}",
            "──────────────────────────────────────────────────────────".dimmed()
        );
        for (name, _path, desc) in &visionos_baselines {
            if let Some(d) = desc {
                let clean_desc = d.replace("visionOS ", "");
                println!(
                    "  {} {} - {}",
                    "•".cyan(),
                    name.green(),
                    clean_desc.dimmed()
                );
            } else {
                println!("  {} {}", "•".cyan(), name.green());
            }
        }
    }

    if !unknown_baselines.is_empty() {
        println!(
            "\n{} ({}):",
            "Other Baselines".cyan().bold(),
            unknown_baselines.len()
        );
        println!(
            "{}",
            "──────────────────────────────────────────────────────────".dimmed()
        );
        for (name, _path, desc) in &unknown_baselines {
            if let Some(d) = desc {
                println!("  {} {} - {}", "•".cyan(), name.green(), d.dimmed());
            } else {
                println!("  {} {}", "•".cyan(), name.green());
            }
        }
    }

    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════".dimmed()
    );
    println!(
        "{}: {} baseline{}",
        "Total".bold(),
        total,
        if total == 1 { "" } else { "s" }
    );
    println!();
    println!("{}", "Usage:".bold());
    println!(
        "  contour mscp generate --mscp-repo {} --keyword {} --output ./output",
        mscp_repo_path.display(),
        "<NAME>".cyan()
    );
    println!();

    Ok(())
}

/// Get current git branch name
fn get_current_branch(repo_path: &PathBuf) -> Result<String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--abbrev-ref")
        .arg("HEAD")
        .current_dir(repo_path)
        .output()
        .context("Failed to get current git branch")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Git command failed: {stderr}");
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(branch)
}

/// Switch to a specific git branch
pub fn switch_branch(repo_path: &PathBuf, branch_name: &str) -> Result<()> {
    tracing::info!("Switching to branch: {}", branch_name);

    // First, fetch the branch if it's a remote branch
    let output = Command::new("git")
        .arg("fetch")
        .arg("origin")
        .arg(branch_name)
        .current_dir(repo_path)
        .output()
        .context("Failed to fetch branch")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(
            "Git fetch failed (branch may already exist locally): {}",
            stderr
        );
    }

    // Try to checkout the branch
    let output = Command::new("git")
        .arg("checkout")
        .arg(branch_name)
        .current_dir(repo_path)
        .output()
        .context("Failed to checkout branch")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to switch to branch '{branch_name}': {stderr}");
    }

    eprintln!("{}", format!("✓ Switched to branch: {branch_name}").green());
    Ok(())
}

/// Parse platform and version from branch name
/// Examples:
/// - "sequoia" -> ("macOS", "Sequoia")
/// - "`dev_sequoia_stig`" -> ("macOS", "Sequoia")
/// - "`ios_18`" -> ("iOS", "18")
/// - "`dev_ios_18`" -> ("iOS", "18")
pub(crate) fn parse_branch_info(branch: &str) -> (String, String) {
    let branch_lower = branch.to_lowercase();

    // iOS branches
    if branch_lower.contains("ios") {
        // Extract version number
        if let Some(idx) = branch_lower.rfind("ios") {
            let after_ios = &branch_lower[idx + 3..];
            // Look for numbers
            let version_chars: String = after_ios
                .chars()
                .skip_while(|c| *c == '_' || *c == ' ')
                .take_while(|c| c.is_numeric())
                .collect();

            if !version_chars.is_empty() {
                return ("iOS".to_string(), version_chars);
            }
        }
        return ("iOS".to_string(), String::new());
    }

    // visionOS branches
    if branch_lower.contains("vision") {
        return ("visionOS".to_string(), String::new());
    }

    // macOS branches - check for codenames
    let macos_versions = vec![
        ("tahoe", "Tahoe (26.x)"),
        ("sequoia", "Sequoia (15.x)"),
        ("sonoma", "Sonoma (14.x)"),
        ("ventura", "Ventura (13.x)"),
        ("monterey", "Monterey (12.x)"),
        ("big_sur", "Big Sur (11.x)"),
        ("catalina", "Catalina (10.15)"),
    ];

    for (codename, display_name) in macos_versions {
        if branch_lower.contains(codename) {
            return ("macOS".to_string(), display_name.to_string());
        }
    }

    // Default
    ("Unknown".to_string(), String::new())
}

/// Detect baseline platform from description
fn detect_baseline_platform(description: &Option<String>) -> String {
    if let Some(desc) = description {
        let desc_lower = desc.to_lowercase();
        if desc_lower.contains("macos") || desc_lower.contains("mac os") {
            return "macOS".to_string();
        }
        if desc_lower.contains("ios") || desc_lower.contains("ipados") {
            return "iOS".to_string();
        }
        if desc_lower.contains("visionos") || desc_lower.contains("vision os") {
            return "visionOS".to_string();
        }
    }
    "Unknown".to_string()
}

/// Read baseline description from YAML file
fn read_baseline_description(path: &PathBuf) -> Option<String> {
    if let Ok(content) = fs::read_to_string(path) {
        // Simple parsing - look for title or description field
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("title:") {
                return Some(
                    line.strip_prefix("title:")?
                        .trim()
                        .trim_matches('"')
                        .to_string(),
                );
            }
            if line.starts_with("description:") {
                return Some(
                    line.strip_prefix("description:")?
                        .trim()
                        .trim_matches('"')
                        .to_string(),
                );
            }
        }
    }
    None
}

/// List all generated baselines in the output directory
pub fn list_baselines(output: PathBuf, output_mode: OutputMode) -> Result<()> {
    let manager = BaselineIndex::new(output.clone());
    let baselines = manager.list_baselines()?;

    if output_mode == OutputMode::Json {
        println!("{}", serde_json::to_string_pretty(&baselines)?);
        return Ok(());
    }

    if baselines.is_empty() {
        println!("{} {}", "No baselines found in".yellow(), output.display());
        return Ok(());
    }

    println!(
        "\n{} {} baseline(s) in {}:\n",
        "Found".cyan().bold(),
        baselines.len(),
        output.join("mscp").display().to_string().dimmed()
    );

    for baseline in baselines {
        println!("  {} ({})", baseline.name.cyan().bold(), baseline.platform);
        println!("    {} {} profiles", "-".dimmed(), baseline.profile_count);
        println!("    {} {} scripts", "-".dimmed(), baseline.script_count);

        if let Some(generated_at) = baseline.generated_at {
            println!(
                "    {} Generated: {}",
                "-".dimmed(),
                generated_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }

        if baseline.referenced_by.is_empty() {
            println!("    {} Referenced by: {}", "-".dimmed(), "(none)".dimmed());
        } else {
            println!("    {} Referenced by:", "-".dimmed());
            for team_file in &baseline.referenced_by {
                if let Some(filename) = team_file.file_name() {
                    println!(
                        "        {} fleets/{}",
                        "-".dimmed(),
                        filename.to_string_lossy()
                    );
                }
            }
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highest_baseline_version_picks_newest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("baselines/macos");
        fs::create_dir_all(&dir).unwrap();
        for f in [
            "800-53r5_high_macos_15.0.yaml",
            "800-53r5_high_macos_26.0.yaml",
            "800-53r5_high_macos_14.0.yaml",
            "cis_lvl1_macos_26.0.yaml", // different baseline — must be ignored
        ] {
            fs::write(dir.join(f), "x").unwrap();
        }
        let v = highest_baseline_version(tmp.path(), "800-53r5_high", "macos").unwrap();
        assert_eq!(v, "26.0");
    }

    #[test]
    fn test_highest_baseline_version_errors_when_absent() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("baselines/ios")).unwrap();
        let err = highest_baseline_version(tmp.path(), "800-53r5_high", "ios").unwrap_err();
        assert!(err.to_string().contains("no mSCP 2.0 baseline files"));
    }

    /// Build a fake mSCP repo on disk just complete enough for
    /// `MscpLayout::detect` to classify it. The detector keys on
    /// flat `rules/*.yaml` (1.x) vs `rules/<os>/` subdirs (2.0).
    fn fake_repo(tmp: &Path, layout: crate::layout::MscpLayout) -> &Path {
        fs::create_dir_all(tmp.join("rules")).unwrap();
        match layout {
            crate::layout::MscpLayout::V1x => {
                // 1.x: flat rule YAML directly under rules/
                fs::write(
                    tmp.join("rules/os_sample.yaml"),
                    "id: os_sample\ntitle: sample\n",
                )
                .unwrap();
                fs::create_dir_all(tmp.join("baselines")).unwrap();
                fs::write(tmp.join("baselines/cis_lvl1.yaml"), "title: sample\n").unwrap();
            }
            crate::layout::MscpLayout::V2x => {
                // 2.0: the discriminating signal in MscpLayout::detect is
                // the top-level `platforms` key. Per-OS sub-tree layout
                // matters for path resolution; the detect probe only
                // reads the first rule.
                fs::create_dir_all(tmp.join("rules/macos")).unwrap();
                fs::write(
                    tmp.join("rules/macos/os_sample.yaml"),
                    "id: os_sample\ntitle: sample\nplatforms:\n  macos:\n    enforcement_info: {}\n",
                )
                .unwrap();
                fs::create_dir_all(tmp.join("baselines/macos")).unwrap();
                fs::write(
                    tmp.join("baselines/macos/cis_lvl1_macos_26.0.yaml"),
                    "title: sample\n",
                )
                .unwrap();
            }
        }
        tmp
    }

    #[test]
    fn assert_compatible_layout_bails_when_1x_repo_meets_2_0_image() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = fake_repo(tmp.path(), crate::layout::MscpLayout::V1x);

        let err = assert_compatible_layout(repo, "ghcr.io/brodjieski/mscp_2.0:latest")
            .expect_err("1.x repo + 2.0 image must bail");

        let msg = err.to_string();
        assert!(
            msg.contains("1.x layout"),
            "error must name the layout: {msg}"
        );
        assert!(
            msg.contains("dev_2.0"),
            "error must point at the dev_2.0 branch: {msg}"
        );
        assert!(
            msg.contains("--use-uv") || msg.contains("--use-python3"),
            "error must offer the non-container fallback: {msg}"
        );
    }

    #[test]
    fn assert_compatible_layout_passes_when_2_0_repo_meets_2_0_image() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = fake_repo(tmp.path(), crate::layout::MscpLayout::V2x);
        assert_compatible_layout(repo, "ghcr.io/brodjieski/mscp_2.0:latest")
            .expect("2.0 repo + 2.0 image must pass");
    }

    #[test]
    fn assert_compatible_layout_skips_check_when_no_local_repo() {
        // Container-only mode (no local rules/ dir) should pass — the
        // image's baked-in source is the only source of truth.
        let tmp = tempfile::tempdir().unwrap();
        assert_compatible_layout(tmp.path(), "ghcr.io/brodjieski/mscp_2.0:latest")
            .expect("bare container mode must skip the layout check");
    }

    #[test]
    fn assert_compatible_layout_passes_when_image_is_not_2_0() {
        // A 1.x repo paired with a non-2.0 image is the legacy
        // compatible combination and must not be blocked.
        let tmp = tempfile::tempdir().unwrap();
        let repo = fake_repo(tmp.path(), crate::layout::MscpLayout::V1x);
        assert_compatible_layout(repo, "ghcr.io/brodjieski/mscp:latest")
            .expect("1.x repo + non-2.0 image must pass");
    }
}
