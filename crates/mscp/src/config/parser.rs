use crate::config::Config;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Load configuration from TOML file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();

    if !path.exists() {
        anyhow::bail!("Config file not found: {}", path.display());
    }

    let content = fs::read_to_string(path)
        .context(format!("Failed to read config file: {}", path.display()))?;

    let config: Config = toml::from_str(&content)
        .context(format!("Failed to parse config file: {}", path.display()))?;

    tracing::info!("Loaded configuration from: {}", path.display());
    validate_config(&config)?;

    Ok(config)
}

/// Serialize and write `config` to `path`.
///
/// Used by the interactive glob flow to persist user choices back to
/// `mscp.toml` so non-interactive follow-up runs reproduce the same YAML.
pub fn save_config<P: AsRef<Path>>(config: &Config, path: P) -> Result<()> {
    let path = path.as_ref();
    let content = toml::to_string_pretty(config)
        .context(format!("Failed to serialize config for {}", path.display()))?;
    fs::write(path, content).context(format!("Failed to write config to {}", path.display()))?;
    tracing::info!("Saved configuration to: {}", path.display());
    Ok(())
}

/// Load configuration or use defaults if file doesn't exist
#[allow(dead_code, reason = "reserved for future use")]
pub fn load_config_or_default<P: AsRef<Path>>(path: P) -> Config {
    match load_config(path) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!("Could not load config: {}. Using defaults.", e);
            Config::default()
        }
    }
}

/// Validate configuration
fn validate_config(config: &Config) -> Result<()> {
    // Validate python_method
    match config.settings.python_method.as_str() {
        "auto" | "uv" | "python3" => {}
        other => {
            anyhow::bail!("Invalid python_method '{other}'. Must be 'auto', 'uv', or 'python3'");
        }
    }

    // Validate baselines
    for (i, baseline) in config.baselines.iter().enumerate() {
        if baseline.name.is_empty() {
            anyhow::bail!("Baseline {i} has empty name");
        }
    }

    // output.structure is validated by serde deserialization (OutputStructure enum)

    refuse_unimplemented(config)
}

/// Refuse settings that ask for something contour does not do.
///
/// Each of these was parsed and read by nothing — the same failure as
/// `excluded_rules` and `[baselines.labels]` before them: a setting that
/// looks like it works. The generated template wrote three of them, so
/// every config it made asked for diffs, a five-version history and
/// cross-baseline conflict checks that no run performed.
///
/// A value matching what contour already does is accepted: it asks for
/// nothing. Every refusal is reported at once, with the line to delete.
fn refuse_unimplemented(config: &Config) -> Result<()> {
    let mut refused: Vec<String> = Vec::new();
    let o = &config.output;
    if o.separate_baselines == Some(false) {
        refused.push(
            "[output] separate_baselines = false — the layout always puts each baseline in \
             its own directories; this cannot be turned off"
                .to_string(),
        );
    }
    if o.generate_diffs == Some(true) {
        refused.push(
            "[output] generate_diffs = true — generate writes no diff report; compare two \
             outputs with `contour mscp diff`"
                .to_string(),
        );
    }
    if let Some(n) = o.versions_to_keep {
        refused.push(format!(
            "[output] versions_to_keep = {n} — no version history is kept or pruned; the \
             output is rewritten in place, so keep history in git"
        ));
    }
    if config.validation.check_conflicts == Some(true) {
        refused.push(
            "[validation] check_conflicts = true — cross-baseline conflict detection is not \
             implemented; baselines are not compared with each other"
                .to_string(),
        );
    }
    for b in &config.baselines {
        if !b.metadata.is_empty() {
            refused.push(format!(
                "[[baselines]] name = {:?}: metadata — read by nothing and written to no \
                 artifact",
                b.name
            ));
        }
    }
    if refused.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "mscp.toml asks for {} thing(s) contour does not do. Delete these lines:\n  {}\n\n\
         Configs written by earlier `contour mscp init` carry generate_diffs, \
         versions_to_keep and check_conflicts; nothing in them ever ran.",
        refused.len(),
        refused.join("\n  ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_config_invalid_python_method() {
        let mut config = Config::default();
        config.settings.python_method = "invalid".to_string();

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_valid() {
        let config = Config::default();
        validate_config(&config).unwrap();
    }

    fn load_str(toml: &str) -> Result<Config> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mscp.toml");
        std::fs::write(&p, toml).unwrap();
        load_config(&p)
    }

    /// What `mscp init` wrote before these settings were refused. Every one
    /// of them asked for something no run did; all are named at once.
    #[test]
    fn the_old_templates_dead_settings_are_refused_by_name() {
        let err = load_str(
            "[[baselines]]\nname = \"cis_lvl1\"\n\
             [baselines.metadata]\ndescription = \"CIS Level 1\"\n\
             [output]\nstructure = \"pluggable\"\nseparate_baselines = true\n\
             generate_diffs = true\nversions_to_keep = 5\n\
             [validation]\ncheck_conflicts = true\n",
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        for line in [
            "generate_diffs = true",
            "versions_to_keep = 5",
            "check_conflicts = true",
            "metadata",
        ] {
            assert!(msg.contains(line), "{line} must be named: {msg}");
        }
        assert!(
            msg.contains("4 thing(s)"),
            "separate_baselines = true asks for nothing: {msg}"
        );
    }

    /// A value matching what contour already does asks for nothing.
    #[test]
    fn values_that_match_what_contour_does_are_accepted() {
        load_str(
            "[output]\nseparate_baselines = true\ngenerate_diffs = false\n\
             [validation]\ncheck_conflicts = false\n",
        )
        .unwrap();
        let err = load_str("[output]\nseparate_baselines = false\n").unwrap_err();
        assert!(format!("{err:#}").contains("separate_baselines = false"));
    }

    /// What `mscp init` writes now loads, and writes none of them.
    #[test]
    fn a_fresh_template_loads_and_carries_no_dead_setting() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mscp.toml");
        crate::config::template::generate_template(&p).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        for key in [
            "separate_baselines",
            "generate_diffs",
            "versions_to_keep",
            "check_conflicts",
            "metadata",
        ] {
            assert!(!text.contains(key), "the template still writes {key}");
        }
        load_config(&p).unwrap();
    }
}
