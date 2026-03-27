//! Schema registry and validation support
//!
//! Note: Some features reserved for future schema-based validation.
#![allow(dead_code, reason = "module under development")]

pub mod jsonschema;
pub mod loader;
pub mod lookup;
pub mod parser;
pub mod plist_parser;
pub mod serializer;
pub mod types;
pub mod yaml_parser;

use anyhow::Result;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

pub use loader::SchemaFormat;
pub use types::{FieldDefinition, FieldType, PayloadManifest};

/// Schema source indicator
#[derive(Debug, Clone)]
pub enum SchemaSource {
    /// Embedded schemas compiled into binary
    Embedded,
    /// External ProfileManifests directory (plist files)
    External(PathBuf),
    /// Apple device-management YAML directory
    Apple(PathBuf),
    /// Combined: embedded + external overrides
    Combined,
}

/// Registry of all payload manifests (schemas)
#[derive(Debug)]
pub struct SchemaRegistry {
    /// Manifests keyed by payload_type
    manifests: HashMap<String, PayloadManifest>,
    /// Schema source indicator
    source: SchemaSource,
    /// Statistics
    stats: RegistryStats,
}

#[derive(Debug, Default)]
pub struct RegistryStats {
    pub apple_count: usize,
    pub apps_count: usize,
    pub prefs_count: usize,
    pub ddm_count: usize,
    pub total: usize,
}

impl SchemaRegistry {
    /// Load embedded schemas (default, fast, no network dependency)
    pub fn embedded() -> Result<Self> {
        let manifests_vec = loader::load_embedded()?;
        Self::from_manifests(manifests_vec, SchemaSource::Embedded)
    }

    /// Load from external ultra-compact directory
    pub fn from_directory(path: &Path) -> Result<Self> {
        let manifests_vec = loader::load_from_directory(path)?;
        Self::from_manifests(manifests_vec, SchemaSource::External(path.to_path_buf()))
    }

    /// Load embedded with external overrides
    /// External manifests override embedded ones with the same payload_type
    pub fn with_overrides(external_path: &Path) -> Result<Self> {
        // Start with embedded
        let mut manifests_vec = loader::load_embedded()?;

        // Load external and override
        let external = loader::load_from_directory(external_path)?;

        // Create a map for deduplication (external wins)
        let mut manifest_map: HashMap<String, PayloadManifest> = manifests_vec
            .into_iter()
            .map(|m| (m.payload_type.clone(), m))
            .collect();

        for m in external {
            manifest_map.insert(m.payload_type.clone(), m);
        }

        manifests_vec = manifest_map.into_values().collect();
        Self::from_manifests(manifests_vec, SchemaSource::Combined)
    }

    /// Load from ProfileManifests directory (plist format)
    /// Path should point to the repository root containing Manifests/ subdirectory
    pub fn from_profile_manifests(path: &Path) -> Result<Self> {
        let manifests_vec = plist_parser::load_from_profile_manifests_dir(path)?;
        Self::from_manifests(manifests_vec, SchemaSource::External(path.to_path_buf()))
    }

    /// Load from Apple device-management directory (YAML format)
    /// Path should point to the repository root containing mdm/profiles/ subdirectory
    pub fn from_apple_dm(path: &Path) -> Result<Self> {
        let manifests_vec = yaml_parser::load_from_apple_dm_dir(path)?;
        Self::from_manifests(manifests_vec, SchemaSource::Apple(path.to_path_buf()))
    }

    /// Load from directory with auto-detected format
    pub fn from_auto_detect(path: &Path) -> Result<Self> {
        let format = loader::detect_directory_format(path)?;
        let manifests_vec = loader::load_from_directory_with_format(path, format)?;

        let source = match format {
            SchemaFormat::AppleYaml => SchemaSource::Apple(path.to_path_buf()),
            _ => SchemaSource::External(path.to_path_buf()),
        };

        Self::from_manifests(manifests_vec, source)
    }

    /// Merge another registry into this one (other's manifests override)
    pub fn merge(&mut self, other: Self) {
        for (payload_type, manifest) in other.manifests {
            // Update stats
            if !self.manifests.contains_key(&payload_type) {
                if manifest.category.starts_with("ddm-") {
                    self.stats.ddm_count += 1;
                } else {
                    match manifest.category.as_str() {
                        "apple" => self.stats.apple_count += 1,
                        "apps" => self.stats.apps_count += 1,
                        "prefs" => self.stats.prefs_count += 1,
                        _ => {}
                    }
                }
                self.stats.total += 1;
            }
            self.manifests.insert(payload_type, manifest);
        }
        self.source = SchemaSource::Combined;
    }

    /// Build registry from a vector of manifests
    fn from_manifests(manifests_vec: Vec<PayloadManifest>, source: SchemaSource) -> Result<Self> {
        let mut stats = RegistryStats::default();

        for m in &manifests_vec {
            if m.category.starts_with("ddm-") {
                stats.ddm_count += 1;
            } else {
                match m.category.as_str() {
                    "apple" => stats.apple_count += 1,
                    "apps" => stats.apps_count += 1,
                    "prefs" => stats.prefs_count += 1,
                    _ => {}
                }
            }
        }
        stats.total = manifests_vec.len();

        let manifests: HashMap<String, PayloadManifest> = manifests_vec
            .into_iter()
            .map(|m| (m.payload_type.clone(), m))
            .collect();

        Ok(Self {
            manifests,
            source,
            stats,
        })
    }

    /// Build a registry from pre-built manifests (for unit tests).
    #[cfg(test)]
    pub fn from_manifests_for_test(manifests_vec: Vec<PayloadManifest>) -> Self {
        let manifests: HashMap<String, PayloadManifest> = manifests_vec
            .into_iter()
            .map(|m| (m.payload_type.clone(), m))
            .collect();
        let total = manifests.len();
        Self {
            manifests,
            source: SchemaSource::Embedded,
            stats: RegistryStats {
                total,
                ..RegistryStats::default()
            },
        }
    }

    /// Get manifest by payload type (exact match)
    pub fn get(&self, payload_type: &str) -> Option<&PayloadManifest> {
        self.manifests.get(payload_type)
    }

    /// Get manifest by short name (e.g., "wifi" -> "com.apple.wifi.managed")
    pub fn get_by_name(&self, name: &str) -> Option<&PayloadManifest> {
        let name_lower = name.to_lowercase();

        // Try exact match first
        if let Some(m) = self.manifests.get(name) {
            return Some(m);
        }

        // Try title match (case-insensitive)
        for m in self.manifests.values() {
            if m.title.to_lowercase() == name_lower {
                return Some(m);
            }
        }

        // Try partial payload_type match
        self.manifests
            .values()
            .find(|&m| m.payload_type.to_lowercase().contains(&name_lower))
            .map(|v| v as _)
    }

    /// List all payload types
    pub fn list(&self) -> Vec<&str> {
        self.manifests
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// List all manifests
    pub fn all(&self) -> impl Iterator<Item = &PayloadManifest> {
        self.manifests.values()
    }

    /// Search manifests by query (matches title, payload_type, description, or field names/descriptions)
    pub fn search(&self, query: &str) -> Vec<&PayloadManifest> {
        let query_lower = query.to_lowercase();

        self.manifests
            .values()
            .filter(|m| {
                // Manifest-level search
                m.title.to_lowercase().contains(&query_lower)
                    || m.payload_type.to_lowercase().contains(&query_lower)
                    || m.description.to_lowercase().contains(&query_lower)
                    // Field-level search (name, title, description)
                    || m.fields.keys().any(|k| k.to_lowercase().contains(&query_lower))
                    || m.fields.values().any(|f| {
                        f.title.to_lowercase().contains(&query_lower)
                            || f.description.to_lowercase().contains(&query_lower)
                    })
            })
            .collect()
    }

    /// Get manifests by category
    pub fn by_category(&self, category: &str) -> Vec<&PayloadManifest> {
        self.manifests
            .values()
            .filter(|m| m.category == category)
            .collect()
    }

    /// Get registry statistics
    pub fn stats(&self) -> &RegistryStats {
        &self.stats
    }

    /// Get schema source
    pub fn source(&self) -> &SchemaSource {
        &self.source
    }

    /// Total number of manifests
    pub fn len(&self) -> usize {
        self.manifests.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.manifests.is_empty()
    }

    /// Write schema catalog for LLM consumption.
    ///
    /// Outputs every payload type with its fields so an LLM can generate
    /// valid MDM profiles without external documentation.
    pub fn write_llm_catalog(&self, writer: &mut impl Write) -> Result<()> {
        let mut buf = String::with_capacity(64 * 1024);

        writeln!(buf, "## Supported payload types")?;
        writeln!(buf)?;
        writeln!(
            buf,
            "{} payload types: {} Apple, {} Apps, {} Prefs, {} DDM",
            self.stats.total,
            self.stats.apple_count,
            self.stats.apps_count,
            self.stats.prefs_count,
            self.stats.ddm_count,
        )?;
        writeln!(buf)?;

        // Collect all categories, sort them
        let mut by_cat: HashMap<String, Vec<&PayloadManifest>> = HashMap::new();
        for m in self.manifests.values() {
            by_cat.entry(m.category.clone()).or_default().push(m);
        }
        // Sort manifests within each category by payload_type
        for manifests in by_cat.values_mut() {
            manifests.sort_by(|a, b| a.payload_type.cmp(&b.payload_type));
        }

        // Output in fixed order: apple, apps, prefs, then ddm-* sorted
        let mut cat_order: Vec<&str> = Vec::new();
        for cat in &["apple", "apps", "prefs"] {
            if by_cat.contains_key(*cat) {
                cat_order.push(cat);
            }
        }
        let mut ddm_cats: Vec<&str> = by_cat
            .keys()
            .filter(|k| k.starts_with("ddm-"))
            .map(|s| s.as_str())
            .collect();
        ddm_cats.sort_unstable();
        cat_order.extend(ddm_cats);

        for cat in &cat_order {
            let manifests = &by_cat[*cat];
            writeln!(buf, "### {} ({})\n", cat, manifests.len())?;

            for m in manifests {
                let platforms = m.platforms.to_vec().join(", ");
                let field_count = m.fields.len();
                writeln!(
                    buf,
                    "#### `{}` — {} [{}]",
                    m.payload_type, m.title, platforms
                )?;
                if !m.description.is_empty() {
                    writeln!(buf, "{}", m.description)?;
                }
                writeln!(buf)?;

                if field_count == 0 {
                    continue;
                }

                // Show fields table
                writeln!(buf, "| Key | Type | Flags | Description |")?;
                writeln!(buf, "|-----|------|-------|-------------|")?;

                for key in &m.field_order {
                    let Some(f) = m.fields.get(key) else {
                        continue;
                    };
                    let mut flags = Vec::new();
                    if f.flags.required {
                        flags.push("required");
                    }
                    if f.flags.supervised {
                        flags.push("supervised");
                    }
                    if f.flags.sensitive {
                        flags.push("sensitive");
                    }
                    let flags_str = if flags.is_empty() {
                        "—".to_string()
                    } else {
                        flags.join(", ")
                    };

                    // Truncate long descriptions for table readability
                    let desc = if f.description.chars().count() > 120 {
                        let truncated: String = f.description.chars().take(117).collect();
                        format!("{truncated}...")
                    } else {
                        f.description.clone()
                    };
                    // Escape pipes in description
                    let desc = desc.replace('|', "\\|");

                    let mut type_str = f.field_type.as_str().to_string();
                    if !f.allowed_values.is_empty() {
                        let vals = f.allowed_values.join(", ");
                        if vals.len() <= 80 {
                            type_str = format!("{} ({})", type_str, vals);
                        }
                    }
                    if let Some(def) = &f.default {
                        type_str = format!("{} [default: {}]", type_str, def);
                    }

                    // Indent nested fields to show hierarchy
                    let indent = "  ".repeat(f.depth as usize);
                    let display_name = format!("{}{}", indent, f.name);

                    writeln!(
                        buf,
                        "| `{}` | {} | {} | {} |",
                        display_name, type_str, flags_str, desc
                    )?;
                }
                writeln!(buf)?;
            }
        }

        writer.write_all(buf.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== SchemaRegistry Basic Tests ==========

    #[test]
    fn test_schema_registry_embedded() {
        let registry = SchemaRegistry::embedded().expect("Failed to load embedded schemas");

        assert!(registry.len() >= 200, "Expected ~219 manifests");
        assert!(registry.stats().apple_count > 0);
        assert!(registry.stats().apps_count > 0);
    }

    #[test]
    fn test_get_by_payload_type() {
        let registry = SchemaRegistry::embedded().unwrap();

        let wifi = registry.get("com.apple.wifi.managed");
        assert!(wifi.is_some());
        assert_eq!(wifi.unwrap().title, "Wi-Fi");
    }

    #[test]
    fn test_get_by_payload_type_not_found() {
        let registry = SchemaRegistry::embedded().unwrap();

        let result = registry.get("com.nonexistent.payload");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_by_name() {
        let registry = SchemaRegistry::embedded().unwrap();

        // By title
        let wifi = registry.get_by_name("WiFi");
        assert!(wifi.is_some());

        // By partial payload type
        let wifi2 = registry.get_by_name("wifi");
        assert!(wifi2.is_some());
    }

    #[test]
    fn test_get_by_name_exact_match() {
        let registry = SchemaRegistry::embedded().unwrap();

        // Exact payload type match should work
        let wifi = registry.get_by_name("com.apple.wifi.managed");
        assert!(wifi.is_some());
        assert_eq!(wifi.unwrap().payload_type, "com.apple.wifi.managed");
    }

    #[test]
    fn test_get_by_name_case_insensitive() {
        let registry = SchemaRegistry::embedded().unwrap();

        let result1 = registry.get_by_name("WIFI");
        let result2 = registry.get_by_name("wifi");
        let result3 = registry.get_by_name("WiFi");

        // All should find the same manifest
        assert!(result1.is_some());
        assert!(result2.is_some());
        assert!(result3.is_some());
    }

    #[test]
    fn test_get_by_name_not_found() {
        let registry = SchemaRegistry::embedded().unwrap();

        let result = registry.get_by_name("nonexistent_manifest_xyz");
        assert!(result.is_none());
    }

    // ========== Search Tests ==========

    #[test]
    fn test_search() {
        let registry = SchemaRegistry::embedded().unwrap();

        // Search for WiFi
        let wifi_results = registry.search("wi-fi");
        assert!(!wifi_results.is_empty(), "Should find Wi-Fi manifests");
        assert!(wifi_results.iter().any(|m| m.title.contains("Wi-Fi")));

        // Search for FileVault
        let fv_results = registry.search("filevault");
        assert!(!fv_results.is_empty(), "Should find FileVault manifests");
    }

    #[test]
    fn test_search_case_insensitive() {
        let registry = SchemaRegistry::embedded().unwrap();

        let results1 = registry.search("WIFI");
        let results2 = registry.search("wifi");
        let results3 = registry.search("WiFi");

        // All searches should find results
        assert!(!results1.is_empty());
        assert!(!results2.is_empty());
        assert!(!results3.is_empty());
    }

    #[test]
    fn test_search_no_results() {
        let registry = SchemaRegistry::embedded().unwrap();

        let results = registry.search("xyznonexistent123");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_description() {
        let registry = SchemaRegistry::embedded().unwrap();

        // WiFi manifest should have "network" in description
        let results = registry.search("network");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_by_field_name() {
        let registry = SchemaRegistry::embedded().unwrap();

        // Search for "SSID" should find WiFi manifest via field name
        let results = registry.search("SSID");
        assert!(!results.is_empty(), "Should find manifests with SSID field");
        assert!(
            results
                .iter()
                .any(|m| m.payload_type == "com.apple.wifi.managed"),
            "WiFi manifest should be found via SSID field"
        );
    }

    #[test]
    fn test_search_by_field_name_osquery() {
        let registry = SchemaRegistry::embedded().unwrap();

        // OSQueryAllowedDomains is a field in com.okta.mobile
        let results = registry.search("osquery");
        assert!(
            !results.is_empty(),
            "Should find manifests with osquery-related fields"
        );
    }

    // ========== Category Tests ==========

    #[test]
    fn test_by_category() {
        let registry = SchemaRegistry::embedded().unwrap();

        let apple = registry.by_category("apple");
        assert!(!apple.is_empty());

        let apps = registry.by_category("apps");
        assert!(!apps.is_empty());
    }

    #[test]
    fn test_by_category_prefs() {
        let registry = SchemaRegistry::embedded().unwrap();

        let prefs = registry.by_category("prefs");
        assert!(!prefs.is_empty());
    }

    #[test]
    fn test_by_category_nonexistent() {
        let registry = SchemaRegistry::embedded().unwrap();

        let results = registry.by_category("nonexistent_category");
        assert!(results.is_empty());
    }

    // ========== Statistics Tests ==========

    #[test]
    fn test_stats() {
        let registry = SchemaRegistry::embedded().unwrap();
        let stats = registry.stats();

        assert!(stats.total > 0);
        assert!(stats.apple_count > 0);
        assert!(stats.apps_count > 0);
        // prefs_count may be 0 if all manifests are categorized as apple or apps
    }

    #[test]
    fn test_stats_total() {
        let registry = SchemaRegistry::embedded().unwrap();
        let stats = registry.stats();

        // Stats total includes all loaded manifests (may be higher than len if duplicates)
        assert!(
            stats.total >= registry.len(),
            "stats.total should be >= registry.len()"
        );
    }

    // ========== Registry Properties Tests ==========

    #[test]
    fn test_len() {
        let registry = SchemaRegistry::embedded().unwrap();
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_is_empty() {
        let registry = SchemaRegistry::embedded().unwrap();
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_all_iterator() {
        let registry = SchemaRegistry::embedded().unwrap();
        let count = registry.all().count();
        assert_eq!(count, registry.len());
    }

    #[test]
    fn test_list() {
        let registry = SchemaRegistry::embedded().unwrap();
        let list = registry.list();

        assert_eq!(list.len(), registry.len());
        assert!(list.contains(&"com.apple.wifi.managed"));
    }

    // ========== SchemaSource Tests ==========

    #[test]
    fn test_source_embedded() {
        let registry = SchemaRegistry::embedded().unwrap();

        match registry.source() {
            SchemaSource::Embedded => {}
            _ => panic!("Expected Embedded source"),
        }
    }

    // ========== RegistryStats Default Tests ==========

    #[test]
    fn test_registry_stats_default() {
        let stats = RegistryStats::default();
        assert_eq!(stats.apple_count, 0);
        assert_eq!(stats.apps_count, 0);
        assert_eq!(stats.prefs_count, 0);
        assert_eq!(stats.total, 0);
    }
}
