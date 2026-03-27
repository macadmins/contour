//! Markdown documentation generator for payload schemas

use crate::schema::{PayloadManifest, SchemaRegistry};
use anyhow::Result;
use std::fmt::Write;
use std::fs;
use std::path::Path;

/// Generate documentation for all (or filtered) manifests
pub fn generate_docs(
    registry: &SchemaRegistry,
    output: &Path,
    filter: Option<&str>,
    category_filter: Option<&str>,
) -> Result<usize> {
    fs::create_dir_all(output)?;

    let mut count = 0;

    for manifest in registry.all() {
        // Apply payload type filter
        if let Some(f) = filter
            && manifest.payload_type != f
        {
            continue;
        }

        // Apply category filter
        if let Some(cat) = category_filter
            && manifest.category != cat
        {
            continue;
        }

        let markdown = generate_payload_doc(manifest)?;
        let filename = format!("{}.md", manifest.payload_type.replace('.', "-"));
        fs::write(output.join(&filename), markdown)?;
        count += 1;
    }

    // Generate index if we generated more than one doc
    if count > 1 {
        generate_index(registry, output, category_filter)?;
    }

    Ok(count)
}

/// Generate markdown documentation for a single payload manifest
pub fn generate_payload_doc(manifest: &PayloadManifest) -> Result<String> {
    let mut doc = String::new();

    // Title
    writeln!(doc, "# {} (`{}`)", manifest.title, manifest.payload_type)?;
    writeln!(doc)?;

    // Description
    if !manifest.description.is_empty() {
        writeln!(doc, "{}", manifest.description)?;
        writeln!(doc)?;
    }

    // Platforms
    writeln!(doc, "## Platforms")?;
    writeln!(doc)?;
    let platforms = manifest.platforms.to_vec();
    if platforms.is_empty() {
        writeln!(doc, "No platform restrictions specified.")?;
    } else {
        for platform in platforms {
            // Check for min version
            let version_note = manifest
                .min_versions
                .iter()
                .find(|(p, _)| p.as_str() == platform)
                .map(|(_, v)| format!(" {v}+"))
                .unwrap_or_default();
            writeln!(doc, "- {platform}{version_note}")?;
        }
    }
    writeln!(doc)?;

    // Category
    writeln!(doc, "## Category")?;
    writeln!(doc)?;
    writeln!(doc, "{}", capitalize(&manifest.category))?;
    writeln!(doc)?;

    // Fields table
    if !manifest.fields.is_empty() {
        writeln!(doc, "## Fields")?;
        writeln!(doc)?;
        writeln!(doc, "| Field | Type | Required | Default | Description |")?;
        writeln!(doc, "|-------|------|----------|---------|-------------|")?;

        // Use field_order for consistent ordering
        for field_name in &manifest.field_order {
            if let Some(field) = manifest.fields.get(field_name) {
                // Skip deeply nested fields (depth > 1) for readability
                if field.depth > 1 {
                    continue;
                }

                let required = if field.flags.required { "Yes" } else { "No" };
                let default_val = field.default.as_deref().unwrap_or("-");
                let field_type = field.field_type.as_str();

                // Clean up description (remove newlines, truncate if too long)
                let desc = field
                    .description
                    .replace('\n', " ")
                    .chars()
                    .take(80)
                    .collect::<String>();

                // Add indent for nested fields
                let name_display = if field.depth > 0 {
                    format!("{}{}", " ".repeat(field.depth as usize * 2), field_name)
                } else {
                    field_name.clone()
                };

                writeln!(
                    doc,
                    "| `{name_display}` | {field_type} | {required} | {default_val} | {desc} |"
                )?;
            }
        }
        writeln!(doc)?;
    }

    // Sensitive fields warning
    let sensitive_fields: Vec<_> = manifest
        .fields
        .iter()
        .filter(|(_, f)| f.flags.sensitive)
        .map(|(n, _)| n.as_str())
        .collect();

    if !sensitive_fields.is_empty() {
        writeln!(doc, "## Sensitive Fields")?;
        writeln!(doc)?;
        writeln!(
            doc,
            "The following fields may contain sensitive data (credentials, certificates):"
        )?;
        writeln!(doc)?;
        for name in sensitive_fields {
            writeln!(doc, "- `{name}`")?;
        }
        writeln!(doc)?;
    }

    // Supervised-only fields
    let supervised_fields: Vec<_> = manifest
        .fields
        .iter()
        .filter(|(_, f)| f.flags.supervised)
        .map(|(n, _)| n.as_str())
        .collect();

    if !supervised_fields.is_empty() {
        writeln!(doc, "## Supervised-Only Fields")?;
        writeln!(doc)?;
        writeln!(doc, "The following fields require iOS Supervised mode:")?;
        writeln!(doc)?;
        for name in supervised_fields {
            writeln!(doc, "- `{name}`")?;
        }
        writeln!(doc)?;
    }

    // Example
    writeln!(doc, "## Example")?;
    writeln!(doc)?;
    writeln!(doc, "```xml")?;
    writeln!(doc, "<dict>")?;
    writeln!(doc, "    <key>PayloadType</key>")?;
    writeln!(doc, "    <string>{}</string>", manifest.payload_type)?;
    writeln!(doc, "    <key>PayloadVersion</key>")?;
    writeln!(doc, "    <integer>1</integer>")?;

    // Add required fields to example
    let required_fields: Vec<_> = manifest
        .required_fields()
        .into_iter()
        .filter(|f| f.depth == 0)
        .take(3) // Limit to first 3
        .collect();

    for field in required_fields {
        writeln!(doc, "    <key>{}</key>", field.name)?;
        match field.field_type.as_str() {
            "String" => writeln!(
                doc,
                "    <string><!-- {} --></string>",
                field.description.chars().take(40).collect::<String>()
            )?,
            "Integer" => writeln!(
                doc,
                "    <integer><!-- {} --></integer>",
                field.description.chars().take(40).collect::<String>()
            )?,
            "Boolean" => writeln!(doc, "    <true/> <!-- or <false/> -->")?,
            "Array" => writeln!(
                doc,
                "    <array><!-- {} --></array>",
                field.description.chars().take(40).collect::<String>()
            )?,
            "Dictionary" => writeln!(
                doc,
                "    <dict><!-- {} --></dict>",
                field.description.chars().take(40).collect::<String>()
            )?,
            "Data" => writeln!(
                doc,
                "    <data><!-- Base64-encoded {} --></data>",
                field.description.chars().take(30).collect::<String>()
            )?,
            _ => writeln!(
                doc,
                "    <!-- {} -->",
                field.description.chars().take(50).collect::<String>()
            )?,
        }
    }

    writeln!(doc, "</dict>")?;
    writeln!(doc, "```")?;

    Ok(doc)
}

/// Generate an index file linking to all generated docs
pub fn generate_index(
    registry: &SchemaRegistry,
    output: &Path,
    category_filter: Option<&str>,
) -> Result<()> {
    let mut doc = String::new();

    writeln!(doc, "# Apple Configuration Profile Payload Reference")?;
    writeln!(doc)?;
    writeln!(
        doc,
        "This documentation covers {} payload types.",
        registry.len()
    )?;
    writeln!(doc)?;

    // Group by category
    let categories = ["apple", "apps", "prefs"];

    for category in categories {
        if let Some(cat_filter) = category_filter
            && category != cat_filter
        {
            continue;
        }

        let manifests: Vec<_> = registry.by_category(category).into_iter().collect();

        if manifests.is_empty() {
            continue;
        }

        writeln!(doc, "## {} ({})", capitalize(category), manifests.len())?;
        writeln!(doc)?;

        for manifest in manifests {
            let filename = format!("{}.md", manifest.payload_type.replace('.', "-"));
            writeln!(
                doc,
                "- [{}]({}) - `{}`",
                manifest.title, filename, manifest.payload_type
            )?;
        }
        writeln!(doc)?;
    }

    fs::write(output.join("README.md"), doc)?;
    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().chain(chars).collect(),
    }
}

/// Construct GitHub URL for DDM declaration source
/// Example: com.apple.configuration.package -> https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/package.yaml
fn get_ddm_github_url(declaration_type: &str, category: &str) -> Option<String> {
    const GITHUB_BASE: &str =
        "https://github.com/apple/device-management/blob/release/declarative/declarations";

    // Map category to directory name
    let dir = match category {
        "ddm-configuration" => "configurations",
        "ddm-activation" => "activations",
        "ddm-asset" => "assets",
        "ddm-management" => "management",
        _ => return None,
    };

    // Extract the filename from declaration type
    // com.apple.configuration.package -> package
    // com.apple.activation.simple -> simple
    // com.apple.asset.credential.acme -> credential.acme
    let prefix = match category {
        "ddm-configuration" => "com.apple.configuration.",
        "ddm-activation" => "com.apple.activation.",
        "ddm-asset" => "com.apple.asset.",
        "ddm-management" => "com.apple.management.",
        _ => return None,
    };

    let filename = declaration_type.strip_prefix(prefix)?;

    // Convert dots to dashes for multi-part names (e.g., credential.acme -> credential.acme)
    // But the file uses dots as-is (e.g., credential.acme.yaml)
    Some(format!("{GITHUB_BASE}/{dir}/{filename}.yaml"))
}

/// Generate documentation from an actual profile, showing configured vs available keys
pub fn generate_profile_doc(
    profile: &crate::profile::ConfigurationProfile,
    registry: &SchemaRegistry,
) -> Result<String> {
    let mut doc = String::new();

    // Profile header
    writeln!(doc, "# Profile: {}", profile.payload_display_name)?;
    writeln!(doc)?;
    writeln!(doc, "- **Identifier**: `{}`", profile.payload_identifier)?;
    writeln!(doc, "- **UUID**: `{}`", profile.payload_uuid)?;
    if let Some(org) = profile.payload_organization() {
        writeln!(doc, "- **Organization**: {org}")?;
    }
    if let Some(desc) = profile.payload_description() {
        writeln!(doc, "- **Description**: {desc}")?;
    }
    writeln!(doc, "- **Payloads**: {}", profile.payload_content.len())?;
    writeln!(doc)?;

    writeln!(doc, "---")?;
    writeln!(doc)?;

    // Process each payload
    for (idx, payload) in profile.payload_content.iter().enumerate() {
        let payload_type = &payload.payload_type;
        let display_name = payload
            .payload_display_name()
            .unwrap_or_else(|| "(unnamed)".to_string());

        writeln!(doc, "## Payload {idx}: {display_name} (`{payload_type}`)")?;
        writeln!(doc)?;

        // Get schema for this payload type
        let manifest = registry.get(payload_type);

        // Section 1: Configured Keys (what's actually in the profile)
        writeln!(doc, "### Configured Keys")?;
        writeln!(doc)?;

        if payload.content.is_empty() {
            writeln!(
                doc,
                "_No custom keys configured (only standard payload envelope fields)._"
            )?;
        } else {
            writeln!(doc, "| Key | Value | Type | Description |")?;
            writeln!(doc, "|-----|-------|------|-------------|")?;

            for (key, value) in &payload.content {
                let value_str = format_plist_value(value);
                let value_display = if value_str.len() > 50 {
                    format!("{}...", &value_str[..47])
                } else {
                    value_str
                };

                let (type_str, desc) = if let Some(m) = manifest {
                    if let Some(field) = m.fields.get(key) {
                        (
                            field.field_type.as_str().to_string(),
                            field
                                .description
                                .replace('\n', " ")
                                .chars()
                                .take(60)
                                .collect::<String>(),
                        )
                    } else {
                        (
                            plist_type_name(value).to_string(),
                            "_Custom/unknown field_".to_string(),
                        )
                    }
                } else {
                    (
                        plist_type_name(value).to_string(),
                        "_No schema available_".to_string(),
                    )
                };

                writeln!(doc, "| `{key}` | `{value_display}` | {type_str} | {desc} |")?;
            }
        }
        writeln!(doc)?;

        // Section 2: Available Keys (from schema, not currently used)
        if let Some(m) = manifest {
            let configured_keys: std::collections::HashSet<_> = payload.content.keys().collect();

            // Skip standard envelope fields
            let envelope_fields = [
                "PayloadType",
                "PayloadVersion",
                "PayloadIdentifier",
                "PayloadUUID",
                "PayloadDisplayName",
                "PayloadDescription",
                "PayloadOrganization",
            ];

            let available_keys: Vec<_> = m
                .field_order
                .iter()
                .filter(|k| !configured_keys.contains(k))
                .filter(|k| !envelope_fields.contains(&k.as_str()))
                .filter(|k| *k != ">>") // Skip comment markers
                .filter_map(|k| m.fields.get(k).map(|f| (k, f)))
                .filter(|(_, f)| f.depth == 0) // Top-level only
                .collect();

            if !available_keys.is_empty() {
                writeln!(doc, "### Available Keys (Not Configured)")?;
                writeln!(doc)?;
                writeln!(
                    doc,
                    "The following keys are available for `{payload_type}` but not currently configured:"
                )?;
                writeln!(doc)?;
                writeln!(doc, "| Key | Type | Required | Default | Description |")?;
                writeln!(doc, "|-----|------|----------|---------|-------------|")?;

                for (key, field) in available_keys {
                    let required = if field.flags.required {
                        "**Yes**"
                    } else {
                        "No"
                    };
                    let default_val = field.default.as_deref().unwrap_or("-");
                    let desc = field
                        .description
                        .replace('\n', " ")
                        .chars()
                        .take(50)
                        .collect::<String>();
                    let sensitive_marker = if field.flags.sensitive { " *" } else { "" };

                    writeln!(
                        doc,
                        "| `{}`{} | {} | {} | {} | {} |",
                        key,
                        sensitive_marker,
                        field.field_type.as_str(),
                        required,
                        default_val,
                        desc
                    )?;
                }
                writeln!(doc)?;
                writeln!(doc, "_* = Sensitive field (may contain credentials)_")?;
            } else {
                writeln!(doc, "### Available Keys")?;
                writeln!(doc)?;
                writeln!(
                    doc,
                    "_All available keys for this payload type are configured._"
                )?;
            }
        } else {
            writeln!(doc, "### Available Keys")?;
            writeln!(doc)?;
            writeln!(
                doc,
                "_No schema available for `{payload_type}`. Cannot determine available keys._"
            )?;
        }

        writeln!(doc)?;
        writeln!(doc, "---")?;
        writeln!(doc)?;
    }

    Ok(doc)
}

fn format_plist_value(value: &plist::Value) -> String {
    format_plist_value_depth(value, 0)
}

fn format_plist_value_depth(value: &plist::Value, depth: usize) -> String {
    // Limit recursion depth to avoid huge outputs
    if depth > 3 {
        return "...".to_string();
    }

    match value {
        plist::Value::String(s) => {
            if s.is_empty() {
                "\"\"".to_string()
            } else if s.len() > 60 && depth == 0 {
                format!("{}...", &s.chars().take(57).collect::<String>())
            } else {
                s.clone()
            }
        }
        plist::Value::Integer(i) => i.to_string(),
        plist::Value::Real(r) => r.to_string(),
        plist::Value::Boolean(b) => b.to_string(),
        plist::Value::Array(arr) => {
            if arr.is_empty() {
                "[]".to_string()
            } else if arr.len() == 1 {
                format!("[{}]", format_plist_value_depth(&arr[0], depth + 1))
            } else if depth > 0 {
                format!("[{} items]", arr.len())
            } else {
                // Show array items on depth 0
                let items: Vec<String> = arr
                    .iter()
                    .take(5)
                    .map(|v| format_plist_value_depth(v, depth + 1))
                    .collect();
                if arr.len() > 5 {
                    format!("[{}, ... +{} more]", items.join(", "), arr.len() - 5)
                } else {
                    format!("[{}]", items.join(", "))
                }
            }
        }
        plist::Value::Dictionary(dict) => {
            if dict.is_empty() {
                "{}".to_string()
            } else if depth > 1 {
                format!("{{...{} keys}}", dict.len())
            } else {
                // Show dict contents
                let items: Vec<String> = dict
                    .iter()
                    .take(5)
                    .map(|(k, v)| format!("{}: {}", k, format_plist_value_depth(v, depth + 1)))
                    .collect();
                if dict.len() > 5 {
                    format!("{{{}, ... +{} more}}", items.join(", "), dict.len() - 5)
                } else {
                    format!("{{{}}}", items.join(", "))
                }
            }
        }
        plist::Value::Data(d) => format!("<data: {} bytes>", d.len()),
        plist::Value::Date(d) => format!("{d:?}"),
        _ => "<unknown>".to_string(),
    }
}

fn plist_type_name(value: &plist::Value) -> &'static str {
    match value {
        plist::Value::String(_) => "String",
        plist::Value::Integer(_) => "Integer",
        plist::Value::Real(_) => "Real",
        plist::Value::Boolean(_) => "Boolean",
        plist::Value::Array(_) => "Array",
        plist::Value::Dictionary(_) => "Dictionary",
        plist::Value::Data(_) => "Data",
        plist::Value::Date(_) => "Date",
        _ => "Unknown",
    }
}

/// Generate documentation for all (or filtered) DDM declaration manifests
pub fn generate_ddm_docs(
    registry: &SchemaRegistry,
    output: &Path,
    filter: Option<&str>,
    category_filter: Option<&str>,
) -> Result<usize> {
    fs::create_dir_all(output)?;

    let mut count = 0;

    for manifest in registry.all() {
        // Only DDM declarations (categories starting with ddm-)
        if !manifest.category.starts_with("ddm-") {
            continue;
        }

        // Apply declaration type filter
        if let Some(f) = filter
            && manifest.payload_type != f
            && !manifest.payload_type.ends_with(f)
        {
            continue;
        }

        // Apply category filter (support both "configuration" and "ddm-configuration")
        if let Some(cat) = category_filter {
            let expected_cat = if cat.starts_with("ddm-") {
                cat.to_string()
            } else {
                format!("ddm-{cat}")
            };
            if manifest.category != expected_cat {
                continue;
            }
        }

        let markdown = generate_ddm_declaration_doc(manifest)?;
        let filename = format!("{}.md", manifest.payload_type.replace('.', "-"));
        fs::write(output.join(&filename), markdown)?;
        count += 1;
    }

    // Generate index if we generated more than one doc
    if count > 1 {
        generate_ddm_index(registry, output, category_filter)?;
    }

    Ok(count)
}

/// Generate markdown documentation for a single DDM declaration manifest
pub fn generate_ddm_declaration_doc(manifest: &PayloadManifest) -> Result<String> {
    let mut doc = String::new();

    // Title
    writeln!(doc, "# {} (`{}`)", manifest.title, manifest.payload_type)?;
    writeln!(doc)?;

    // Source reference - construct GitHub URL from declaration type
    if let Some(github_url) = get_ddm_github_url(&manifest.payload_type, &manifest.category) {
        writeln!(
            doc,
            "> **Source**: [Apple Device Management]({github_url}) on GitHub"
        )?;
        writeln!(doc)?;
    }

    // Description
    if !manifest.description.is_empty() {
        writeln!(doc, "{}", manifest.description)?;
        writeln!(doc)?;
    }

    // Category (strip ddm- prefix for display)
    let category_display = manifest
        .category
        .strip_prefix("ddm-")
        .unwrap_or(&manifest.category);
    writeln!(doc, "## Category")?;
    writeln!(doc)?;
    writeln!(doc, "{}", capitalize(category_display))?;
    writeln!(doc)?;

    // Platforms
    writeln!(doc, "## Platforms")?;
    writeln!(doc)?;
    let platforms = manifest.platforms.to_vec();
    if platforms.is_empty() {
        writeln!(doc, "No platform restrictions specified.")?;
    } else {
        for platform in platforms {
            // Check for min version
            let version_note = manifest
                .min_versions
                .iter()
                .find(|(p, _)| p.as_str() == platform)
                .map(|(_, v)| format!(" {v}+"))
                .unwrap_or_default();
            writeln!(doc, "- {platform}{version_note}")?;
        }
    }
    writeln!(doc)?;

    // Payload Keys table
    if !manifest.fields.is_empty() {
        writeln!(doc, "## Payload Keys")?;
        writeln!(doc)?;
        writeln!(doc, "| Key | Type | Required | Default | Description |")?;
        writeln!(doc, "|-----|------|----------|---------|-------------|")?;

        // Use field_order for consistent ordering
        for field_name in &manifest.field_order {
            if let Some(field) = manifest.fields.get(field_name) {
                // Skip deeply nested fields (depth > 1) for readability
                if field.depth > 1 {
                    continue;
                }

                let required = if field.flags.required { "Yes" } else { "No" };
                let default_val = field.default.as_deref().unwrap_or("-");
                let field_type = field.field_type.as_str();

                // Clean up description (remove newlines, truncate if too long)
                let desc = field
                    .description
                    .replace('\n', " ")
                    .chars()
                    .take(80)
                    .collect::<String>();

                // Add indent for nested fields
                let name_display = if field.depth > 0 {
                    format!("{}{}", " ".repeat(field.depth as usize * 2), field_name)
                } else {
                    field_name.clone()
                };

                writeln!(
                    doc,
                    "| `{name_display}` | {field_type} | {required} | {default_val} | {desc} |"
                )?;
            }
        }
        writeln!(doc)?;
    }

    // Allowed values for enum-like fields
    let enum_fields: Vec<_> = manifest
        .fields
        .iter()
        .filter(|(_, f)| !f.allowed_values.is_empty())
        .collect();

    if !enum_fields.is_empty() {
        writeln!(doc, "## Allowed Values")?;
        writeln!(doc)?;
        for (name, field) in enum_fields {
            writeln!(doc, "### `{name}`")?;
            writeln!(doc)?;
            for value in &field.allowed_values {
                writeln!(doc, "- `{value}`")?;
            }
            writeln!(doc)?;
        }
    }

    // Example JSON
    writeln!(doc, "## Example")?;
    writeln!(doc)?;
    writeln!(doc, "```json")?;
    writeln!(doc, "{{")?;
    writeln!(doc, "    \"Type\": \"{}\",", manifest.payload_type)?;
    writeln!(
        doc,
        "    \"Identifier\": \"com.example.{}\",",
        manifest
            .payload_type
            .split('.')
            .next_back()
            .unwrap_or("declaration")
    )?;
    writeln!(doc, "    \"ServerToken\": \"unique-token-here\",")?;
    writeln!(doc, "    \"Payload\": {{")?;

    // Add required fields to example
    let required_fields: Vec<_> = manifest
        .required_fields()
        .into_iter()
        .filter(|f| f.depth == 0)
        .take(5) // Limit to first 5
        .collect();

    let total_required = required_fields.len();
    for (idx, field) in required_fields.iter().enumerate() {
        let comma = if idx < total_required - 1 { "," } else { "" };
        let example_value = match field.field_type.as_str() {
            "String" => format!("\"{}\"", field.default.as_deref().unwrap_or("")),
            "Integer" => field.default.as_deref().unwrap_or("0").to_string(),
            "Boolean" => field.default.as_deref().unwrap_or("false").to_string(),
            "Array" => "[]".to_string(),
            "Dictionary" => "{}".to_string(),
            _ => "null".to_string(),
        };
        writeln!(
            doc,
            "        \"{}\": {}{}",
            field.name, example_value, comma
        )?;
    }

    writeln!(doc, "    }}")?;
    writeln!(doc, "}}")?;
    writeln!(doc, "```")?;

    Ok(doc)
}

/// Generate an index file linking to all generated DDM docs
pub fn generate_ddm_index(
    registry: &SchemaRegistry,
    output: &Path,
    category_filter: Option<&str>,
) -> Result<()> {
    let mut doc = String::new();

    // Count DDM declarations
    let ddm_count = registry
        .all()
        .filter(|m| m.category.starts_with("ddm-"))
        .count();

    writeln!(doc, "# Declarative Device Management (DDM) Reference")?;
    writeln!(doc)?;
    writeln!(
        doc,
        "This documentation covers {ddm_count} DDM declaration types."
    )?;
    writeln!(doc)?;
    writeln!(
        doc,
        "DDM is Apple's modern approach to device management, using JSON-based declarations"
    )?;
    writeln!(doc, "instead of traditional XML configuration profiles.")?;
    writeln!(doc)?;

    // Group by category
    let categories = [
        "ddm-configuration",
        "ddm-activation",
        "ddm-asset",
        "ddm-management",
    ];

    for category in categories {
        // Check category filter (support both "configuration" and "ddm-configuration")
        if let Some(cat_filter) = category_filter {
            let expected_cat = if cat_filter.starts_with("ddm-") {
                cat_filter.to_string()
            } else {
                format!("ddm-{cat_filter}")
            };
            if category != expected_cat {
                continue;
            }
        }

        let manifests: Vec<_> = registry.by_category(category).into_iter().collect();

        if manifests.is_empty() {
            continue;
        }

        let category_name = category.strip_prefix("ddm-").unwrap_or(category);
        writeln!(
            doc,
            "## {} ({})",
            capitalize(category_name),
            manifests.len()
        )?;
        writeln!(doc)?;

        for manifest in manifests {
            let filename = format!("{}.md", manifest.payload_type.replace('.', "-"));
            writeln!(
                doc,
                "- [{}]({}) - `{}`",
                manifest.title, filename, manifest.payload_type
            )?;
        }
        writeln!(doc)?;
    }

    fs::write(output.join("README.md"), doc)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_payload_doc() {
        let registry = SchemaRegistry::embedded().unwrap();
        let wifi = registry.get("com.apple.wifi.managed").unwrap();
        let doc = generate_payload_doc(wifi).unwrap();

        assert!(doc.contains("# Wi-Fi"));
        assert!(doc.contains("com.apple.wifi.managed"));
        assert!(doc.contains("## Fields"));
        assert!(doc.contains("## Platforms"));
    }

    #[test]
    fn test_generate_docs() {
        let registry = SchemaRegistry::embedded().unwrap();
        let dir = tempdir().unwrap();

        // Generate just one doc
        let count =
            generate_docs(&registry, dir.path(), Some("com.apple.wifi.managed"), None).unwrap();

        assert_eq!(count, 1);
        assert!(dir.path().join("com-apple-wifi-managed.md").exists());
    }

    #[test]
    fn test_generate_ddm_docs() {
        let registry = SchemaRegistry::embedded().unwrap();
        let dir = tempdir().unwrap();

        // Generate DDM docs for configuration category
        let count = generate_ddm_docs(&registry, dir.path(), None, Some("configuration")).unwrap();

        // Should have at least some configuration declarations
        assert!(count > 0);
        // Should have README
        assert!(dir.path().join("README.md").exists());
    }

    #[test]
    fn test_generate_ddm_declaration_doc() {
        let registry = SchemaRegistry::embedded().unwrap();
        // Find a DDM declaration
        let ddm = registry
            .all()
            .find(|m| m.category.starts_with("ddm-"))
            .expect("Should have at least one DDM declaration");

        let doc = generate_ddm_declaration_doc(ddm).unwrap();

        assert!(doc.contains(&format!("# {}", ddm.title)));
        assert!(doc.contains(&ddm.payload_type));
        assert!(doc.contains("## Category"));
        assert!(doc.contains("## Platforms"));
        assert!(doc.contains("## Example"));
        assert!(doc.contains("```json"));
    }
}
