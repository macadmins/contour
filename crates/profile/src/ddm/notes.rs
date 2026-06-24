//! Deployment caveats for DDM declaration types — the context a declaration needs
//! to actually *do* something, surfaced by `ddm info` / `ddm generate` so agents
//! don't have to carry tribal knowledge.
//!
//! Two kinds of note:
//! - **Pre-release** — the type exists only in the OS-27 beta seed ([`is_beta_only`]).
//! - **Dependency / composition** — a curated table ([`NOTES`]) plus the generic
//!   rule that any `com.apple.configuration.*` is inert without a
//!   `com.apple.activation.simple` referencing it.

use crate::schema::{Channel, SchemaRegistry};

/// A static deployment note keyed by an exact type or a type prefix.
struct DeploymentNote {
    /// Exact type, or a prefix matched with `starts_with`.
    type_match: &'static str,
    note: &'static str,
}

/// Curated dependency notes — only the types where the declaration alone is
/// inert without a companion app or asset.
const NOTES: &[DeploymentNote] = &[
    DeploymentNote {
        type_match: "com.apple.configuration.webcontent-filter.plugin",
        note: "Inert on its own — needs the companion NetworkExtension content-filter \
               app installed, with a PluginBundleID matching the app's extension. Pair \
               with software deployment for the filter app.",
    },
    DeploymentNote {
        type_match: "com.apple.configuration.network.relay",
        note: "References relay credentials/asset — ensure the relay asset and any \
               required client app are deployed alongside it.",
    },
    DeploymentNote {
        type_match: "com.apple.configuration.network.vpn.vpn-plugin",
        note: "Needs the companion NetworkExtension VPN app installed (PluginBundleID \
               must match the app's extension).",
    },
];

/// True when the declaration type exists only in the beta seed (absent from stable).
pub fn is_beta_only(declaration_type: &str) -> bool {
    let present = |c: Channel| {
        SchemaRegistry::embedded_channel(c)
            .ok()
            .is_some_and(|r| r.get_by_name(declaration_type).is_some())
    };
    present(Channel::Beta) && !present(Channel::Stable)
}

/// Deployment notes for a declaration type: curated dependency notes plus the
/// generic "configuration needs an activation" composition rule.
pub fn notes_for(declaration_type: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = NOTES
        .iter()
        .filter(|n| declaration_type == n.type_match || declaration_type.starts_with(n.type_match))
        .map(|n| n.note)
        .collect();
    if declaration_type.starts_with("com.apple.configuration.") {
        out.push(
            "A configuration declaration is inert alone — pair it with a \
             com.apple.activation.simple that references it. Run \
             `contour profile ddm compose` for a complete deployable bundle.",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_gets_activation_rule() {
        let n = notes_for("com.apple.configuration.passcode.settings");
        assert!(n.iter().any(|s| s.contains("activation.simple")));
    }

    #[test]
    fn webcontent_filter_gets_companion_app_note() {
        let n = notes_for("com.apple.configuration.webcontent-filter.plugin");
        assert!(n.iter().any(|s| s.contains("NetworkExtension")));
        // and still gets the generic activation rule
        assert!(n.iter().any(|s| s.contains("activation.simple")));
    }

    #[test]
    fn non_configuration_has_no_notes() {
        assert!(notes_for("com.apple.activation.simple").is_empty());
        assert!(notes_for("com.apple.management.properties").is_empty());
    }
}
