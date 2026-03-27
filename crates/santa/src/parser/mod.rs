mod csv_parser;
mod json_parser;
mod yaml_parser;

pub use csv_parser::parse_csv;
pub use json_parser::parse_json;
pub use yaml_parser::parse_yaml;

use crate::bundle::BundleSet;
use crate::models::RuleSet;
use anyhow::{Context, Result};
use std::path::Path;

/// Supported input formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Json,
    Csv,
    Toml,
}

impl Format {
    /// Detect format from file extension
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_lowercase().as_str() {
            "yaml" | "yml" => Some(Format::Yaml),
            "json" => Some(Format::Json),
            "csv" => Some(Format::Csv),
            "toml" => Some(Format::Toml),
            _ => None,
        }
    }
}

/// Parse rules from a file, auto-detecting format
pub fn parse_file(path: &Path) -> Result<RuleSet> {
    let format = Format::from_path(path)
        .with_context(|| format!("Unknown file format: {}", path.display()))?;

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    parse_content(&content, format)
        .with_context(|| format!("Failed to parse file: {}", path.display()))
}

/// Parse rules from content with specified format
pub fn parse_content(content: &str, format: Format) -> Result<RuleSet> {
    match format {
        Format::Yaml => parse_yaml(content),
        Format::Json => parse_json(content),
        Format::Csv => parse_csv(content),
        Format::Toml => parse_toml(content),
    }
}

/// Parse rules from TOML bundles file
pub fn parse_toml(content: &str) -> Result<RuleSet> {
    let bundles: BundleSet =
        toml::from_str(content).context("Failed to parse TOML content as bundles")?;
    Ok(bundles.to_rules())
}

/// Parse multiple files and combine into a single RuleSet
pub fn parse_files(paths: &[impl AsRef<Path>]) -> Result<RuleSet> {
    let mut combined = RuleSet::new();

    for path in paths {
        let rules = parse_file(path.as_ref())?;
        combined.extend(rules);
    }

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_format_from_path() {
        assert_eq!(
            Format::from_path(&PathBuf::from("rules.yaml")),
            Some(Format::Yaml)
        );
        assert_eq!(
            Format::from_path(&PathBuf::from("rules.yml")),
            Some(Format::Yaml)
        );
        assert_eq!(
            Format::from_path(&PathBuf::from("rules.json")),
            Some(Format::Json)
        );
        assert_eq!(
            Format::from_path(&PathBuf::from("rules.csv")),
            Some(Format::Csv)
        );
        assert_eq!(
            Format::from_path(&PathBuf::from("bundles.toml")),
            Some(Format::Toml)
        );
        assert_eq!(Format::from_path(&PathBuf::from("rules.txt")), None);
    }

    #[test]
    fn test_parse_toml_bundles() {
        let toml_content = r#"
[[bundles]]
name = "google"
cel = 'has(app.team_id) && app.team_id == "EQHXZ8M8AV"'
rule_type = "TEAMID"
identifier = "EQHXZ8M8AV"
policy = "ALLOWLIST"
"#;
        let rules = parse_toml(toml_content).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules.rules()[0].identifier, "EQHXZ8M8AV");
    }
}
