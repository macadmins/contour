//! AI-tool managed-configuration policy schemas with embedded Parquet data.
//!
//! One dataset: `app_policies` — the managed-configuration surface of AI
//! coding tools (Claude Code, Codex, Cursor, Gemini Enterprise mobile), one
//! row per (tool, key), with delivery channels, enum vocabularies, and
//! NIST 800-53 control mappings. Produced by the posture pipeline;
//! deliberately its own crate because the grain is tool × key, not an
//! Apple payload type.

pub mod app_policies;
pub mod types;

pub use types::*;

/// Embedded app policy Parquet data (AI tools' managed-config keys).
pub fn embedded_app_policies() -> &'static [u8] {
    include_bytes!("../data/app_policies.parquet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_app_policies_read_cleanly() {
        let keys = app_policies::read(embedded_app_policies()).expect("read app_policies");
        assert!(
            keys.len() >= 600,
            "expected 600+ policy keys, got {}",
            keys.len()
        );

        // Every published tool is present.
        for tool in ["claude-code", "codex", "cursor"] {
            assert!(
                keys.iter().any(|k| k.tool_id == tool),
                "missing tool '{tool}'"
            );
        }
    }

    /// Claude Code is the largest tool surface and the reason this dataset
    /// exists — pin one well-known managed key end-to-end.
    #[test]
    fn claude_code_managed_key_round_trips() {
        let keys = app_policies::read(embedded_app_policies()).expect("read app_policies");
        let claude: Vec<_> = keys.iter().filter(|k| k.tool_id == "claude-code").collect();
        assert!(
            claude.len() >= 500,
            "expected 500+ Claude Code keys, got {}",
            claude.len()
        );

        let deny = claude
            .iter()
            .find(|k| k.key_path == "permissions.deny")
            .expect("permissions.deny key");
        assert!(deny.channels.macos_plist || deny.channels.json_file);
        assert_eq!(
            deny.macos_domain.as_deref(),
            Some("com.anthropic.claudecode")
        );
    }

    /// Enum vocabularies arrive as real lists, not JSON strings.
    #[test]
    fn allowed_values_lists_are_populated() {
        let keys = app_policies::read(embedded_app_policies()).expect("read app_policies");
        let with_enums = keys
            .iter()
            .filter(|k| k.allowed_values.as_ref().is_some_and(|v| !v.is_empty()))
            .count();
        assert!(
            with_enums > 10,
            "expected 10+ keys with enum vocabularies, got {with_enums}"
        );
    }
}
