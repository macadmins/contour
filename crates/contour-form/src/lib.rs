//! `contour-form` — the schema registry and, on top of it, the form contract.
//!
//! Carved out of `crates/profile/src/schema` so that the part of contour a
//! form-driven authoring tool needs — schema bytes in, a render-ready contract
//! out, a declaration or profile back — can be built for
//! `wasm32-unknown-unknown`. The rule, enforced by CI rather than prose:
//!
//! > With `--no-default-features`, this crate names neither `std::fs`,
//! > `std::process`, `std::env`, `std::net` nor `std::time::SystemTime`.
//!
//! Everything that reads a directory, writes a file or asks the clock sits
//! behind the `native` feature. `crates/profile` re-exports this crate under
//! its old `schema` path, so nothing there changed.
#![allow(dead_code, reason = "module under development")]

pub mod annotations;
pub mod composed;
pub mod emit;
pub mod form;
pub mod formspec;
pub mod identity;
pub mod jsonschema;
pub mod loader;
pub mod path;
// gated inside the file: `#![cfg(feature = "native")]`
pub mod lookup;
pub mod parse;
pub mod parser;
pub mod plist_parser;
pub mod scope;
pub mod serializer;
pub mod types;
pub mod validate;
pub mod version;
pub mod yaml_parser;

use anyhow::Result;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write;
#[cfg(feature = "native")]
use std::path::Path;
use std::path::PathBuf;

pub use loader::SchemaFormat;
pub use types::{FieldDefinition, FieldType, OsSupportDetail, PayloadManifest, Platform};

// The contract, at the root. None of these functions takes a path.
pub use annotations::{Annotation, Annotations};
pub use emit::{EmitFormat, EmitOptions, Emitted, emit};
pub use form::{Target, form, form_all, form_all_with, form_with};
pub use formspec::{Document, FormNode, FormSpec};
pub use parse::{Parsed, parse};
pub use validate::{Diagnostic, validate, validate_for, validate_target};

/// Schema channel — selects the stable vs. pre-release (OS seed) dataset.
///
/// Set globally with `--channel <stable|beta>` or per-command with `--beta`.
/// The effective channel is beta if *either* is requested (see dispatch).
///
/// Beta is currently DISABLED: no seed dataset is compiled in, and asking
/// for it refuses rather than returning stable under another name. See
/// [`SchemaRegistry::beta_dataset_is_carried`] — the state is read from the
/// bytes, so beta re-enables itself when a seed dataset ships again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum Channel {
    /// Released Apple schema (the default).
    #[default]
    Stable,
    /// DISABLED — no seed dataset in this build; commands refuse rather than return stable.
    ///
    /// Beta carries Apple's pre-release seed-only declarations and keys when
    /// a seed dataset ships. It is dormant, not removed: the state is read from
    /// the embedded bytes, so it re-enables itself with the next seed.
    Beta,
}

impl Channel {
    /// True when this is the beta (OS seed) channel.
    pub fn is_beta(self) -> bool {
        matches!(self, Channel::Beta)
    }

    /// Combine a global channel with a per-command `--beta` flag: beta wins
    /// if either side asks for it.
    pub fn or_beta(self, beta_flag: bool) -> Self {
        if beta_flag || self.is_beta() {
            Channel::Beta
        } else {
            Channel::Stable
        }
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Channel::Stable => "stable",
            Channel::Beta => "beta",
        })
    }
}

/// On a lookup miss in `current`, check the *other* channel and return an
/// actionable hint — or `None` when the name is absent there too. Suggest-only:
/// this never switches channels, it only tells the caller a retry would work.
///
/// `by_name` uses the short-name resolver ([`SchemaRegistry::get_by_name`]) for
/// DDM-style lookups; otherwise it tries exact [`get`](SchemaRegistry::get) and a
/// substring [`search`](SchemaRegistry::search).
pub fn suggest_other_channel(name: &str, current: Channel, by_name: bool) -> Option<String> {
    let other = match current {
        Channel::Stable => Channel::Beta,
        Channel::Beta => Channel::Stable,
    };
    let reg = SchemaRegistry::embedded_channel(other).ok()?;
    let found = if by_name {
        reg.get_by_name(name).is_some()
    } else {
        reg.get(name).is_some() || !reg.search(name).is_empty()
    };
    if !found {
        return None;
    }
    Some(match other {
        Channel::Beta => format!(
            "'{name}' is not in the released schema but exists in the OS 27 beta seed — \
             re-run with --beta (pre-release: keys may still change)."
        ),
        Channel::Stable => format!(
            "'{name}' is in the released schema — drop --beta to use the stable definition."
        ),
    })
}

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
    /// Which upstream commit each table came from, where the dataset says.
    provenance: Vec<mdm_schema::SourceVersion>,
    /// The channel this registry was loaded for, where one applies.
    channel: Option<Channel>,
}

/// Payload types the ProfileCreator community corpus alone described, which
/// contour no longer carries.
///
/// The names, and only the names. None of the schema survives — that corpus
/// stated no OS availability, was not vendor-authoritative, and described
/// the wrong keys outright for three Apple domains. What survives is the
/// ability to tell an operator that a domain is not described and why,
/// because "unknown payload type" invites an agent to invent keys for it.
///
/// `com.okta.mobile` is deliberately absent: three of its keys are still
/// described, stated by the dataset with the contour recipe that needs each
/// one named beside it.
///
/// This list does not grow. A domain leaves it by acquiring a real schema —
/// an App Schema document built from the vendor's own source.
pub const REMOVED_COMMUNITY_DOMAINS: &[&str] = &[
    "ManagedInstalls",
    "MunkiReport",
    "SupportCompanion",
    "com.1password.1password",
    "com.alectrona.patch-agent",
    "com.alectrona.patch-notifier",
    "com.apple.Enterprise-Connect",
    "com.brave.Browser",
    "com.citrix.receiver.nomas",
    "com.cloudflare.warp",
    "com.crowdstrike.falcon",
    "com.docker.config",
    "com.gilburns.patcher",
    "com.github.macadmins.Nudge",
    "com.github.macadmins.SupportCompanion",
    "com.github.mpanighetti.install-or-defer",
    "com.github.salopensource.sal",
    "com.google.Chrome",
    "com.google.Keystone",
    "com.google.drivefs.settings",
    "com.grahamgilbert.crypt",
    "com.hjuutilainen.MunkiAdmin",
    "com.jamf.connect.shares",
    "com.jamf.connect.sync",
    "com.jamf.connect.verify",
    "com.jamf.setupmanager",
    "com.jamf.trust",
    "com.jigsaw24.Elevate24",
    "com.jigsaw24.Elevate24SecurityExtension",
    "com.keepersecurity.passwordmanager",
    "com.macjutsu.super",
    "com.microsoft.Edge",
    "com.microsoft.Excel",
    "com.microsoft.OneDrive",
    "com.microsoft.Outlook",
    "com.microsoft.Powerpoint",
    "com.microsoft.VSCode",
    "com.microsoft.Word",
    "com.microsoft.autoupdate2",
    "com.microsoft.office",
    "com.microsoft.onenote.mac",
    "com.microsoft.rdc.macos",
    "com.okta.mobile.auth-service-extension",
    "com.papercut.printdeploy.client",
    "com.parallels.desktop.managedprefs",
    "com.secondsonconsulting.baseline",
    "com.secondsonconsulting.renew",
    "com.sentinelone.registration-token",
    "com.sqwarq.DetectX-Swift",
    "com.tinyspeck.slackmacgap",
    "com.trusourcelabs.NoMAD",
    "com.twingate.macos",
    "com.twocanoes.xcreds",
    "com.zscaler.installparams",
    "de.fau.rrze.NetworkShareMounter",
    "dev.firezone.firezone",
    "edu.psu.macoslaps",
    "io.macadmins.Outset",
    "io.tailscale.ipn.macos",
    "io.tailscale.ipn.macsys",
    "menu.nomad.NoMADPro",
    "menu.nomad.login.ad",
    "menu.nomad.login.okta",
    "menu.nomad.shares",
    "uk.co.dataJAR.jamJAR",
    "us.zoom.config",
    "xyz.techitout.appAutoPatch",
];

#[derive(Debug, Default)]
pub struct RegistryStats {
    pub apple_count: usize,
    pub apps_count: usize,
    pub prefs_count: usize,
    pub ddm_count: usize,
    pub total: usize,
}

impl SchemaRegistry {
    /// Load embedded schemas (default, fast, no network dependency).
    pub fn embedded() -> Result<Self> {
        let manifests_vec = loader::load_embedded()?;
        let mut reg = Self::build(manifests_vec, SchemaSource::Embedded)?;
        reg.provenance = mdm_schema::source_versions::read(mdm_schema::embedded_source_versions())?;
        reg.channel = Some(Channel::Stable);
        Ok(reg)
    }

    /// Load embedded schemas from the **beta seed** dataset.
    ///
    /// The pre-release OS seed schema, for `--beta`. Between seeds it is the
    /// released schema byte for byte — see [`mdm_schema::beta_is_retired`] —
    /// and the CLI tells the user so.
    pub fn embedded_beta() -> Result<Self> {
        let manifests_vec = loader::load_embedded_beta()?;
        let mut reg = Self::build(manifests_vec, SchemaSource::Embedded)?;
        reg.provenance = mdm_schema::source_versions::read(mdm_schema::embedded_source_versions())?;
        reg.channel = Some(Channel::Beta);
        Ok(reg)
    }

    /// Load the embedded **Windows CSP** dataset (DDF v2 nodes; categories
    /// `windows-csp` / `windows-admx`). A standalone registry — Windows
    /// nodes are never mixed into the Apple set.
    pub fn embedded_windows() -> Result<Self> {
        let manifests_vec = loader::load_embedded_windows()?;
        Self::build(manifests_vec, SchemaSource::Embedded)
    }

    /// Build a registry from `capabilities.parquet` as bytes, for a host
    /// that carries the dataset as a separate asset. Reported as
    /// [`SchemaSource::Embedded`]: the bytes are the same published table,
    /// just not compiled in.
    pub fn from_parquet(capabilities: &[u8]) -> Result<Self> {
        let manifests_vec = loader::load_from_parquet(capabilities)?;
        Self::build(manifests_vec, SchemaSource::Embedded)
    }

    /// Attach `source_versions.parquet` bytes — for a host that supplied the
    /// schema as bytes and wants `source.upstream_ref` populated too.
    pub fn with_provenance(mut self, source_versions: &[u8]) -> Result<Self> {
        self.provenance = mdm_schema::source_versions::read(source_versions)?;
        Ok(self)
    }

    /// The upstream commit a dataset's rows were read from, by the dataset's
    /// source name (`device-management`, `ProfileManifests`, `mscp`). `None`
    /// when the dataset does not say — never a guess.
    pub fn upstream_revision(&self, source: &str) -> Option<&str> {
        self.provenance
            .iter()
            .find(|v| v.source == source)
            .and_then(|v| v.revision.as_deref())
    }

    /// Every provenance row the dataset carries.
    pub fn provenance(&self) -> &[mdm_schema::SourceVersion] {
        &self.provenance
    }

    /// The channel this registry was loaded for.
    pub fn channel(&self) -> Option<Channel> {
        self.channel
    }

    /// Load the embedded schema for the given [`Channel`].
    pub fn embedded_channel(channel: Channel) -> Result<Self> {
        match channel {
            Channel::Stable => Self::embedded(),
            Channel::Beta if !Self::beta_dataset_is_carried() => {
                anyhow::bail!(Self::beta_unavailable_message())
            }
            Channel::Beta => Self::embedded_beta(),
        }
    }

    /// Is a distinct beta dataset actually compiled into this binary?
    ///
    /// Delegates to [`mdm_schema::beta_dataset_is_carried`], which compares
    /// the embedded beta table to the stable one. Kept as an associated
    /// function because every caller on this side is already holding a
    /// registry; the reasoning lives with the bytes.
    pub fn beta_dataset_is_carried() -> bool {
        mdm_schema::beta_dataset_is_carried()
    }

    /// What to tell someone who asked for beta when it is not carried.
    ///
    /// One text, shared with mSCP's rule queries, because the channel is one
    /// channel — and two surfaces describing it is how this went wrong.
    pub fn beta_unavailable_message() -> String {
        mdm_schema::BETA_DISABLED_MESSAGE.to_string()
    }

    /// Load from external ultra-compact directory
    #[cfg(feature = "native")]
    pub fn from_directory(path: &Path) -> Result<Self> {
        let manifests_vec = loader::load_from_directory(path)?;
        Self::build(manifests_vec, SchemaSource::External(path.to_path_buf()))
    }

    /// Load embedded with external overrides
    /// External manifests override embedded ones with the same payload_type
    #[cfg(feature = "native")]
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
        Self::build(manifests_vec, SchemaSource::Combined)
    }

    /// Load from ProfileManifests directory (plist format)
    /// Path should point to the repository root containing Manifests/ subdirectory
    #[cfg(feature = "native")]
    pub fn from_profile_manifests(path: &Path) -> Result<Self> {
        let manifests_vec = plist_parser::load_from_profile_manifests_dir(path)?;
        Self::build(manifests_vec, SchemaSource::External(path.to_path_buf()))
    }

    /// Load from Apple device-management directory (YAML format)
    /// Path should point to the repository root containing mdm/profiles/ subdirectory
    #[cfg(feature = "native")]
    pub fn from_apple_dm(path: &Path) -> Result<Self> {
        let manifests_vec = yaml_parser::load_from_apple_dm_dir(path)?;
        Self::build(manifests_vec, SchemaSource::Apple(path.to_path_buf()))
    }

    /// Load from directory with auto-detected format
    #[cfg(feature = "native")]
    pub fn from_auto_detect(path: &Path) -> Result<Self> {
        let format = loader::detect_directory_format(path)?;
        let manifests_vec = loader::load_from_directory_with_format(path, format)?;

        let source = match format {
            SchemaFormat::AppleYaml => SchemaSource::Apple(path.to_path_buf()),
            _ => SchemaSource::External(path.to_path_buf()),
        };

        Self::build(manifests_vec, source)
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
    fn build(manifests_vec: Vec<PayloadManifest>, source: SchemaSource) -> Result<Self> {
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
            provenance: Vec::new(),
            channel: None,
        })
    }

    /// Why a payload type is absent, when it is absent on purpose.
    ///
    /// `None` means contour has never heard of it.
    pub fn why_withheld(&self, payload_type: &str) -> Option<String> {
        REMOVED_COMMUNITY_DOMAINS.contains(&payload_type).then(|| {
            format!(
                "'{payload_type}' was described only by the ProfileCreator community \
                     manifests, which contour removed in 0.5.0-beta.3: they stated no OS \
                     availability, were not vendor-authoritative, and described the wrong \
                     keys for three Apple domains. There is no flag that brings them back. \
                     Author the payload by hand, or contribute an App Schema document built \
                     from the vendor's own source."
            )
        })
    }

    /// Build a registry from manifests already in memory — the constructor a
    /// host without a filesystem uses, and the one tests use.
    pub fn from_manifests(manifests_vec: Vec<PayloadManifest>) -> Self {
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
            provenance: Vec::new(),
            channel: None,
        }
    }

    /// Older name of [`Self::from_manifests`]; kept for the callers in
    /// `crates/profile` tests.
    #[doc(hidden)]
    pub fn from_manifests_for_test(manifests_vec: Vec<PayloadManifest>) -> Self {
        Self::from_manifests(manifests_vec)
    }

    /// Get manifest by payload type (exact match)
    pub fn get(&self, payload_type: &str) -> Option<&PayloadManifest> {
        self.manifests.get(payload_type)
    }

    /// Get manifest by short name (e.g., "wifi" -> "com.apple.wifi.managed").
    ///
    /// Matching is **dot-boundary aware and deterministic**: a short name aligns
    /// to dot segments of the payload type, so `intelligence.settings` resolves to
    /// `com.apple.configuration.intelligence.settings` and never to
    /// `com.apple.configuration.external-intelligence.settings` (whose boundary is
    /// `-`, not `.`). When several types match, the shortest (most specific)
    /// enclosing type wins, broken by lexicographic order — so the result does not
    /// depend on `HashMap` iteration order.
    pub fn get_by_name(&self, name: &str) -> Option<&PayloadManifest> {
        let name_lower = name.to_lowercase();

        // 1. Exact key match.
        if let Some(m) = self.manifests.get(name) {
            return Some(m);
        }

        // 2. Title match (case-insensitive).
        for m in self.manifests.values() {
            if m.title.to_lowercase() == name_lower {
                return Some(m);
            }
        }

        // 3. Dot-boundary segment match (deterministic). The name must align to
        //    `.`-delimited segments of the payload type — full type, dot-suffix,
        //    dot-prefix, or a dot-bounded interior run — which excludes substring
        //    collisions like `intelligence.settings` ⊂ `external-intelligence.settings`.
        let mut matches: Vec<&PayloadManifest> = self
            .manifests
            .values()
            .filter(|m| {
                let pt = m.payload_type.to_lowercase();
                pt == name_lower
                    || pt.ends_with(&format!(".{name_lower}"))
                    || pt.starts_with(&format!("{name_lower}."))
                    || pt.contains(&format!(".{name_lower}."))
            })
            .collect();
        matches.sort_by(|a, b| {
            a.payload_type
                .len()
                .cmp(&b.payload_type.len())
                .then_with(|| a.payload_type.cmp(&b.payload_type))
        });
        matches.into_iter().next()
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

    #[test]
    fn channel_or_beta_combines_global_and_local() {
        // Beta wins if either the global channel or the local --beta flag asks.
        assert_eq!(Channel::Stable.or_beta(false), Channel::Stable);
        assert_eq!(Channel::Stable.or_beta(true), Channel::Beta);
        assert_eq!(Channel::Beta.or_beta(false), Channel::Beta);
        assert_eq!(Channel::Beta.or_beta(true), Channel::Beta);
        assert!(!Channel::Stable.is_beta());
        assert!(Channel::Beta.is_beta());
        assert_eq!(Channel::default(), Channel::Stable);
    }

    #[test]
    fn suggest_other_channel_never_points_at_a_disabled_beta() {
        // A hint that names a flag which refuses is worse than no hint: it
        // sends someone to a second error for the same question. While no
        // seed dataset is carried, `embedded_channel(Beta)` bails, so the
        // beta direction yields nothing — and that is asserted rather than
        // left to happen.
        //
        // The reverse direction still works and still matters: someone who
        // passed --beta and missed gets told to drop it.
        if SchemaRegistry::beta_dataset_is_carried() {
            // Beta is back. The hint should work again; pick a seed-only type
            // for the forward direction when that happens.
            let back = suggest_other_channel("com.apple.dock", Channel::Beta, false);
            assert!(back.as_deref().is_some_and(|h| h.contains("drop --beta")));
            return;
        }

        for name in [
            "com.apple.configuration.app.settings",
            "com.apple.dock",
            "com.apple.totally.bogus.xyz",
        ] {
            assert!(
                suggest_other_channel(name, Channel::Stable, true).is_none(),
                "{name}: suggested --beta while the beta channel refuses"
            );
        }

        // From beta towards stable the lookup is of the stable dataset, which
        // is carried, so this arm is unaffected by beta being disabled.
        let back = suggest_other_channel("com.apple.dock", Channel::Beta, false);
        assert!(
            back.as_deref().is_some_and(|h| h.contains("drop --beta")),
            "a stable type queried under beta must still say to drop the flag"
        );

        assert!(
            suggest_other_channel("com.apple.totally.bogus.xyz", Channel::Beta, false).is_none()
        );
    }
    #[test]
    fn embedded_channel_routes_to_dataset() {
        let stable = SchemaRegistry::embedded_channel(Channel::Stable).expect("stable loads");
        assert!(stable.len() > 0);

        // Beta follows the data. Carried: it must be a superset, since the
        // seed adds to the release branch and never subtracts. Not carried:
        // it must REFUSE, because the failure this replaced was beta quietly
        // resolving to the stable dataset — same rows, different name, no
        // way for a caller to tell which question got answered.
        match SchemaRegistry::embedded_channel(Channel::Beta) {
            Ok(beta) => {
                assert!(
                    SchemaRegistry::beta_dataset_is_carried(),
                    "beta loaded while no distinct seed dataset is carried — it is \
                     serving stable under another name"
                );
                assert!(beta.len() >= stable.len());
            }
            Err(e) => {
                assert!(
                    !SchemaRegistry::beta_dataset_is_carried(),
                    "beta refused although a seed dataset IS carried: {e}"
                );
                let msg = e.to_string();
                assert!(msg.contains("disabled"), "{msg}");
            }
        }
    }
    #[test]
    fn test_schema_registry_embedded() {
        let registry = SchemaRegistry::embedded().expect("Failed to load embedded schemas");

        assert!(registry.len() >= 200, "Expected ~219 manifests");
        assert!(registry.stats().apple_count > 0);
        assert!(registry.stats().apps_count > 0);
    }

    /// The Windows CSP registry (`--windows`) is standalone: CSP/ADMX nodes
    /// with `windows-*` categories, the Windows platform flag, and MSFT
    /// AllowedValues surfaced as allowed_values.
    #[test]
    fn test_schema_registry_embedded_windows() {
        let registry = SchemaRegistry::embedded_windows().expect("load Windows registry");

        assert!(registry.len() > 100, "expected 100+ CSPs");

        let bitlocker = registry.get("BitLocker").expect("BitLocker CSP");
        assert_eq!(bitlocker.category, "windows-csp");

        // Every manifest in the Windows registry is Windows-only. An early
        // producer build stamped 83% of rows `platform: macOS`; this pins
        // the fixed labeling so a regression cannot ship silently.
        for m in registry.all() {
            assert!(
                m.platforms.windows && !m.platforms.macos && !m.platforms.ios,
                "'{}' must be Windows-only, got {:?}",
                m.payload_type,
                m.platforms
            );
        }

        assert!(
            registry
                .all()
                .flat_map(|m| m.fields.values())
                .any(|f| !f.allowed_values.is_empty()),
            "MSFT AllowedValues enumerations should reach allowed_values"
        );
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

    #[test]
    fn test_get_by_name_dot_boundary_no_substring_collision() {
        // `intelligence.settings` is a substring of
        // `external-intelligence.settings`: a short name must align to dot
        // boundaries, or a substring match could return the wrong type. Both
        // types are in the stable set; the beta channel is retired and
        // `embedded_beta` returns the same bytes.
        let registry = SchemaRegistry::embedded_beta().unwrap();

        let intel = registry
            .get_by_name("intelligence.settings")
            .expect("intelligence.settings must resolve in the beta registry");
        assert_eq!(
            intel.payload_type, "com.apple.configuration.intelligence.settings",
            "intelligence.settings must NOT resolve to external-intelligence.settings"
        );

        // The other direction still resolves to itself.
        let ext = registry
            .get_by_name("external-intelligence.settings")
            .expect("external-intelligence.settings must resolve");
        assert_eq!(
            ext.payload_type,
            "com.apple.configuration.external-intelligence.settings"
        );
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
    fn test_search_finds_a_field_by_name() {
        // A term the corpus actually carries.
        let registry = SchemaRegistry::embedded().unwrap();

        let results = registry.search("firewall");
        assert!(
            !results.is_empty(),
            "field-name search found nothing for a term Apple's schema carries"
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
pub use path::{FieldPath, PathConflict};
