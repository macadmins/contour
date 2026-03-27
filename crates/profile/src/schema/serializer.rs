//! Ultra-compact format serializer
//!

use super::types::{FieldType, PayloadManifest, Platform};
use chrono::Utc;

/// Serialize manifests to ultra-compact format for profile manifests
pub fn to_ultra_compact(manifests: &[PayloadManifest], category: &str) -> String {
    let mut output = String::new();

    // Header
    output.push_str(&format!(
        "# ProfileManifests Ultra-Compact v1.0 - {category}\n"
    ));
    output.push_str(&format!(
        "# Generated: {}\n",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    ));
    output.push_str(&format!("# Category: {category}\n"));
    output.push_str(&format!("# Manifests: {}\n", manifests.len()));
    output.push_str("# Source: contour profile docs generate\n");
    output.push_str("#\n");
    output.push_str("# LEGEND:\n");
    output.push_str("# M=manifest, K=key\n");
    output.push_str("# Types: s=string, i=int, b=bool, a=array, d=dict, x=data, t=date, r=real\n");
    output.push_str("# Platforms: m=macOS, i=iOS, t=tvOS, w=watchOS, v=visionOS, *=all, -=none\n");
    output.push_str("# Flags: R=required, O=optional, S=supervised, X=sensitive\n");
    output.push_str("# Depth: K=top-level, K>=1st nested, K>>=2nd nested, etc.\n");
    output.push_str("#\n");
    output.push_str("# Format:\n");
    output.push_str("# M|domain|title|description|platforms|min_versions|category\n");
    output.push_str("# K|name|type|flags|title|description\n");
    output.push_str("#\n\n");

    // Manifests
    for manifest in manifests {
        output.push_str(&serialize_manifest(manifest, category));
    }

    output
}

/// Serialize manifests to ultra-compact format for DDM declarations
pub fn to_ddm_ultra_compact(manifests: &[PayloadManifest]) -> String {
    let mut output = String::new();

    // Header
    output.push_str("# DDM Declarations Ultra-Compact v1.0\n");
    output.push_str(&format!(
        "# Generated: {}\n",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    ));
    output.push_str(&format!("# Declarations: {}\n", manifests.len()));
    output.push_str("# Source: github.com/apple/device-management\n");
    output.push_str("#\n");
    output.push_str("# LEGEND:\n");
    output.push_str("# D=declaration, K=key\n");
    output.push_str("# Types: s=string, i=int, b=bool, a=array, d=dict, x=data, t=date, r=real\n");
    output.push_str("# Platforms: macOS, iOS, tvOS, watchOS, visionOS\n");
    output.push_str("# Categories: activation, configuration, asset, management\n");
    output.push_str("# Flags: R=required, -=optional\n");
    output.push_str("#\n");
    output.push_str("# Format:\n");
    output.push_str("# D|declarationType|title|description|platforms|category|apply\n");
    output.push_str("# K|name|type|flags|title|description\n");
    output.push_str("#\n\n");

    // Declarations
    for manifest in manifests {
        output.push_str(&serialize_ddm_declaration(manifest));
    }

    output
}

fn serialize_manifest(manifest: &PayloadManifest, category: &str) -> String {
    let mut output = String::new();

    // Platform string
    let platforms = format_platforms(&manifest.platforms);

    // Min versions string
    let min_versions = format_min_versions(&manifest.min_versions);

    // Truncate description
    let desc = truncate_description(&manifest.description, 100);

    // M line
    output.push_str(&format!(
        "M|{}|{}|{}|{}|{}|{}\n",
        manifest.payload_type, manifest.title, desc, platforms, min_versions, category
    ));

    // K lines for fields
    for field_name in &manifest.field_order {
        if let Some(field) = manifest.fields.get(field_name) {
            let type_char = field_type_to_char(&field.field_type);
            let flags = format_field_flags(&field.flags);
            let depth_prefix = match field.depth {
                0 => "K",
                1 => "K>",
                2 => "K>>",
                _ => "K>>>",
            };
            let desc = truncate_description(&field.description, 80);

            output.push_str(&format!(
                "{}|{}|{}|{}|{}|{}\n",
                depth_prefix, field.name, type_char, flags, field.title, desc
            ));
        }
    }

    output.push('\n');
    output
}

fn serialize_ddm_declaration(manifest: &PayloadManifest) -> String {
    let mut output = String::new();

    // Platform string (full names for DDM)
    let platforms = format_platforms_full(&manifest.platforms);

    // Truncate description
    let desc = truncate_description(&manifest.description, 100);

    // D line
    output.push_str(&format!(
        "D|{}|{}|{}|{}|{}|single\n",
        manifest.payload_type, manifest.title, desc, platforms, manifest.category
    ));

    // K lines for fields
    for field_name in &manifest.field_order {
        if let Some(field) = manifest.fields.get(field_name) {
            let type_char = field_type_to_char(&field.field_type);
            let flag = if field.flags.required { "R" } else { "-" };
            let desc = truncate_description(&field.description, 80);

            output.push_str(&format!(
                "K|{}|{}|{}|{}|{}\n",
                field.name, type_char, flag, field.title, desc
            ));
        }
    }

    output.push('\n');
    output
}

fn format_platforms(platforms: &super::types::Platforms) -> String {
    let mut parts = Vec::new();
    if platforms.macos {
        parts.push("m");
    }
    if platforms.ios {
        parts.push("i");
    }
    if platforms.tvos {
        parts.push("t");
    }
    if platforms.watchos {
        parts.push("w");
    }
    if platforms.visionos {
        parts.push("v");
    }

    if parts.is_empty() {
        "-".to_string()
    } else if parts.len() == 5 {
        "*".to_string()
    } else {
        parts.join(",")
    }
}

fn format_platforms_full(platforms: &super::types::Platforms) -> String {
    let mut parts = Vec::new();
    if platforms.ios {
        parts.push("iOS");
    }
    if platforms.macos {
        parts.push("macOS");
    }
    if platforms.tvos {
        parts.push("tvOS");
    }
    if platforms.visionos {
        parts.push("visionOS");
    }
    if platforms.watchos {
        parts.push("watchOS");
    }

    if parts.is_empty() {
        "iOS,macOS".to_string()
    } else {
        parts.join(",")
    }
}

fn format_min_versions(versions: &std::collections::HashMap<Platform, String>) -> String {
    let mut parts = Vec::new();

    if let Some(v) = versions.get(&Platform::MacOS) {
        parts.push(format!("m:{v}"));
    }
    if let Some(v) = versions.get(&Platform::Ios) {
        parts.push(format!("i:{v}"));
    }
    if let Some(v) = versions.get(&Platform::TvOS) {
        parts.push(format!("t:{v}"));
    }
    if let Some(v) = versions.get(&Platform::WatchOS) {
        parts.push(format!("w:{v}"));
    }
    if let Some(v) = versions.get(&Platform::VisionOS) {
        parts.push(format!("v:{v}"));
    }

    parts.join(",")
}

fn format_field_flags(flags: &super::types::FieldFlags) -> String {
    let mut result = String::new();

    if flags.required {
        result.push('R');
    }
    if flags.supervised {
        result.push('S');
    }
    if flags.sensitive {
        result.push('X');
    }

    if result.is_empty() {
        "-".to_string()
    } else {
        result
    }
}

fn field_type_to_char(ft: &FieldType) -> char {
    match ft {
        FieldType::String => 's',
        FieldType::Integer => 'i',
        FieldType::Boolean => 'b',
        FieldType::Array => 'a',
        FieldType::Dictionary => 'd',
        FieldType::Data => 'x',
        FieldType::Date => 't',
        FieldType::Real => 'r',
    }
}

fn truncate_description(desc: &str, max_len: usize) -> String {
    let clean = desc.replace('\n', " ").replace("  ", " ");
    if clean.len() <= max_len {
        clean
    } else {
        format!("{}...", &clean[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::types::Platforms;

    #[test]
    fn test_format_platforms() {
        let mut p = Platforms::default();
        assert_eq!(format_platforms(&p), "-");

        p.macos = true;
        p.ios = true;
        assert_eq!(format_platforms(&p), "m,i");

        p.tvos = true;
        p.watchos = true;
        p.visionos = true;
        assert_eq!(format_platforms(&p), "*");
    }

    #[test]
    fn test_truncate_description() {
        assert_eq!(truncate_description("short", 10), "short");
        assert_eq!(
            truncate_description("this is a very long description", 20),
            "this is a very lo..."
        );
    }
}
