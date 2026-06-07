//! Track which baselines contour injected into which fleet files.
//!
//! When `--fleets`/`--all-fleets` attaches a baseline to operator-maintained
//! fleet files, contour records each injection in
//! `{repo}/.contour/fleet-injections.toml`. This manifest — not a scan of the
//! YAML — is the load-bearing source of truth for idempotency and removal: a
//! re-run knows exactly which entries it owns, and `--remove` can withdraw them
//! without parsing operator comments. In-file `# contour:<baseline>` markers are
//! human signposts only.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The `.contour/` subdirectory of a GitOps repo and the manifest filename.
const MANIFEST_DIR: &str = ".contour";
const MANIFEST_FILE: &str = "fleet-injections.toml";

/// All contour-managed baseline injections in a repo.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InjectionManifest {
    /// One entry per (fleet, baseline) contour has injected.
    #[serde(default, rename = "injection")]
    injections: Vec<Injection>,
}

/// A single baseline injected into a single fleet, plus the entries contour added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Injection {
    /// Fleet file stem (e.g. `workstations`).
    pub fleet: String,
    /// Baseline name (e.g. `cis_lvl1`).
    pub baseline: String,
    /// Relative paths/globs contour added to the fleet (profiles + scripts), so
    /// a later run can find and withdraw exactly its own additions.
    #[serde(default)]
    pub entries: Vec<String>,
}

impl InjectionManifest {
    /// The manifest path for a repo root.
    fn path(repo: &Path) -> PathBuf {
        repo.join(MANIFEST_DIR).join(MANIFEST_FILE)
    }

    /// Load the manifest for `repo`, or an empty one if none exists yet.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(repo: &Path) -> Result<Self> {
        let path = Self::path(repo);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("Failed to parse {}", path.display()))
    }

    /// Write the manifest to `{repo}/.contour/fleet-injections.toml`, creating
    /// the directory if needed.
    ///
    /// # Errors
    /// Returns an error if the directory or file cannot be written.
    pub fn save(&self, repo: &Path) -> Result<()> {
        let path = Self::path(repo);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let header = "# contour-managed baseline injections. Do not edit by hand —\n\
                      # `contour mscp generate --fleets`/`--all-fleets` maintains it,\n\
                      # and `--remove` uses it to withdraw an injection.\n\n";
        let body = toml::to_string_pretty(self).context("Failed to serialize manifest")?;
        std::fs::write(&path, format!("{header}{body}"))
            .with_context(|| format!("Failed to write {}", path.display()))
    }

    /// Record (upsert) an injection of `baseline` into `fleet` with its `entries`.
    pub fn record(&mut self, fleet: &str, baseline: &str, entries: Vec<String>) {
        if let Some(existing) = self
            .injections
            .iter_mut()
            .find(|i| i.fleet == fleet && i.baseline == baseline)
        {
            existing.entries = entries;
        } else {
            self.injections.push(Injection {
                fleet: fleet.to_string(),
                baseline: baseline.to_string(),
                entries,
            });
        }
    }

    /// The injection of `baseline` into `fleet`, if contour recorded one.
    pub fn find(&self, fleet: &str, baseline: &str) -> Option<&Injection> {
        self.injections
            .iter()
            .find(|i| i.fleet == fleet && i.baseline == baseline)
    }

    /// Remove and return the injection of `baseline` into `fleet`, if present.
    pub fn remove(&mut self, fleet: &str, baseline: &str) -> Option<Injection> {
        let idx = self
            .injections
            .iter()
            .position(|i| i.fleet == fleet && i.baseline == baseline)?;
        Some(self.injections.remove(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_is_upsert_and_find_round_trips() {
        let mut m = InjectionManifest::default();
        m.record("workstations", "cis_lvl1", vec!["a.mobileconfig".into()]);
        m.record(
            "workstations",
            "cis_lvl1",
            vec!["a.mobileconfig".into(), "b.sh".into()],
        );
        // Upsert: still one entry, with the latest content.
        assert_eq!(m.injections.len(), 1);
        assert_eq!(
            m.find("workstations", "cis_lvl1").map(|i| i.entries.len()),
            Some(2)
        );
        assert!(m.find("workstations", "stig").is_none());
    }

    #[test]
    fn remove_returns_the_injection() {
        let mut m = InjectionManifest::default();
        m.record("workstations", "cis_lvl1", vec![]);
        m.record("kiosks", "cis_lvl1", vec![]);
        let removed = m.remove("workstations", "cis_lvl1").unwrap();
        assert_eq!(removed.fleet, "workstations");
        assert!(m.find("workstations", "cis_lvl1").is_none());
        assert!(m.find("kiosks", "cis_lvl1").is_some());
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut m = InjectionManifest::default();
        m.record("workstations", "cis_lvl1", vec!["x/*.mobileconfig".into()]);
        m.save(tmp.path()).unwrap();
        let loaded = InjectionManifest::load(tmp.path()).unwrap();
        assert_eq!(loaded.injections, m.injections);
    }

    #[test]
    fn load_missing_is_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(
            InjectionManifest::load(tmp.path())
                .unwrap()
                .injections
                .is_empty()
        );
    }
}
