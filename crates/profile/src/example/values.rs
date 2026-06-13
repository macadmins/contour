//! Load a find→replace values map from a JSON or TOML file.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Parse a values document into ordered (find, replace) pairs.
pub fn parse_values_str(text: &str, is_toml: bool) -> Result<Vec<(String, String)>> {
    let map: BTreeMap<String, String> = if is_toml {
        toml::from_str(text).context("parsing TOML values")?
    } else {
        serde_json::from_str(text).context("parsing JSON values")?
    };
    Ok(map.into_iter().collect())
}

/// Load a values file (extension decides format).
pub fn load_values(path: &Path) -> Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading values file {}", path.display()))?;
    let is_toml = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
    parse_values_str(&text, is_toml)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_toml_and_json() {
        let pairs = parse_values_str("\"com.example.scanner\" = \"us.zoom.xos\"\n", true).unwrap();
        assert_eq!(
            pairs,
            vec![("com.example.scanner".to_string(), "us.zoom.xos".to_string())]
        );
        let pairs = parse_values_str(r#"{"ABCD1234":"BJ4HAAB9B3"}"#, false).unwrap();
        assert_eq!(pairs.len(), 1);
    }
}
