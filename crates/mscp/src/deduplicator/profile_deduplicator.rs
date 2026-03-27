use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Represents a profile with its hash and metadata
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    /// Original filename (e.g., "com.apple.security.firewall.mobileconfig")
    pub filename: String,

    /// Full path to the profile
    pub path: PathBuf,

    /// Baseline this profile belongs to
    pub baseline_name: String,

    /// SHA256 hash of the profile content
    pub content_hash: String,

    /// File size in bytes
    pub size: u64,
}

/// Groups profiles by their content hash
#[derive(Debug)]
pub struct ProfileGroup {
    /// Content hash shared by all profiles in this group
    #[allow(dead_code, reason = "reserved for future use")]
    pub content_hash: String,

    /// All profiles with this content hash
    pub profiles: Vec<ProfileEntry>,

    /// Representative filename (shortest/most common)
    pub canonical_filename: String,
}

impl ProfileGroup {
    /// Check if this is a duplicate (used by multiple baselines)
    pub fn is_duplicate(&self) -> bool {
        self.profiles.len() > 1
    }

    /// Get all baseline names that use this profile
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn get_baseline_names(&self) -> Vec<String> {
        self.profiles
            .iter()
            .map(|p| p.baseline_name.clone())
            .collect()
    }

    /// Get unique baseline names (deduplicated)
    pub fn get_unique_baselines(&self) -> HashSet<String> {
        self.profiles
            .iter()
            .map(|p| p.baseline_name.clone())
            .collect()
    }
}

/// Deduplication report
#[derive(Debug)]
pub struct DeduplicationReport {
    /// Total number of profiles scanned
    pub total_profiles: usize,

    /// Number of unique profiles (by content)
    pub unique_profiles: usize,

    /// Number of duplicate profiles
    pub duplicate_profiles: usize,

    /// Profile groups (one per unique content hash)
    pub groups: Vec<ProfileGroup>,

    /// Storage savings in bytes
    pub bytes_saved: u64,
}

impl DeduplicationReport {
    /// Print a summary of the deduplication results
    pub fn print_summary(&self) {
        println!("\n=== Profile Deduplication Report ===");
        println!("Total profiles scanned: {}", self.total_profiles);
        println!("Unique profiles: {}", self.unique_profiles);
        println!("Duplicate profiles: {}", self.duplicate_profiles);
        println!(
            "Storage savings: {:.2} MB",
            self.bytes_saved as f64 / 1024.0 / 1024.0
        );

        if !self.groups.is_empty() {
            println!("\n=== Shared Profiles (used by multiple baselines) ===");
            for group in &self.groups {
                if group.is_duplicate() {
                    let baselines = group.get_unique_baselines();
                    println!("\n{}", group.canonical_filename);
                    println!(
                        "  Baselines: {}",
                        baselines
                            .iter()
                            .map(std::string::String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!("  Instances: {}", group.profiles.len());
                }
            }
        }
    }

    /// Get all shared profiles (used by multiple baselines)
    pub fn get_shared_profiles(&self) -> Vec<&ProfileGroup> {
        self.groups.iter().filter(|g| g.is_duplicate()).collect()
    }

    /// Get all single-use profiles (used by only one baseline)
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn get_single_use_profiles(&self) -> Vec<&ProfileGroup> {
        self.groups.iter().filter(|g| !g.is_duplicate()).collect()
    }
}

/// Profile deduplicator - detects duplicate profiles across baselines
#[derive(Debug)]
pub struct ProfileDeduplicator {
    /// Output base path (e.g., ./London-GitOps)
    output_base: PathBuf,
}

impl ProfileDeduplicator {
    /// Create a new profile deduplicator
    pub fn new<P: AsRef<Path>>(output_base: P) -> Self {
        Self {
            output_base: output_base.as_ref().to_path_buf(),
        }
    }

    /// Scan all baselines and detect duplicates
    pub fn scan_baselines(&self, baseline_names: &[String]) -> Result<DeduplicationReport> {
        tracing::info!(
            "Scanning {} baselines for duplicate profiles",
            baseline_names.len()
        );

        let mut all_profiles = Vec::new();

        // Scan each baseline
        for baseline_name in baseline_names {
            let baseline_profiles = self.scan_baseline(baseline_name)?;
            all_profiles.extend(baseline_profiles);
        }

        // Group by content hash
        let groups = self.group_by_hash(&all_profiles);

        // Calculate statistics
        let total_profiles = all_profiles.len();
        let unique_profiles = groups.len();
        let duplicate_profiles = total_profiles - unique_profiles;

        // Calculate bytes saved
        let bytes_saved: u64 = groups
            .iter()
            .filter(|g| g.is_duplicate())
            .map(|g| {
                // Save (n-1) copies for each duplicate group
                let copies_saved = (g.profiles.len() - 1) as u64;
                g.profiles[0].size * copies_saved
            })
            .sum();

        Ok(DeduplicationReport {
            total_profiles,
            unique_profiles,
            duplicate_profiles,
            groups,
            bytes_saved,
        })
    }

    /// Scan a single baseline for profiles
    fn scan_baseline(&self, baseline_name: &str) -> Result<Vec<ProfileEntry>> {
        let profiles_dir = self
            .output_base
            .join("lib/mscp")
            .join(baseline_name)
            .join("profiles");

        if !profiles_dir.exists() {
            tracing::warn!(
                "Profiles directory not found for baseline '{}': {}",
                baseline_name,
                profiles_dir.display()
            );
            return Ok(Vec::new());
        }

        let mut profiles = Vec::new();

        for entry in std::fs::read_dir(&profiles_dir).with_context(|| {
            format!(
                "Failed to read profiles directory: {}",
                profiles_dir.display()
            )
        })? {
            let entry = entry?;
            let path = entry.path();

            // Only process .mobileconfig files
            if path.extension().and_then(|s| s.to_str()) != Some("mobileconfig") {
                continue;
            }

            let filename = path
                .file_name()
                .and_then(|s| s.to_str())
                .context("Invalid filename")?
                .to_string();

            // Calculate content hash
            let content_hash = self.calculate_hash(&path)?;

            // Get file size
            let metadata = std::fs::metadata(&path)?;
            let size = metadata.len();

            profiles.push(ProfileEntry {
                filename,
                path,
                baseline_name: baseline_name.to_string(),
                content_hash,
                size,
            });
        }

        tracing::info!(
            "Found {} profiles in baseline '{}'",
            profiles.len(),
            baseline_name
        );
        Ok(profiles)
    }

    /// Calculate SHA256 hash of a file
    fn calculate_hash(&self, path: &Path) -> Result<String> {
        let content = std::fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();

        // Convert hash bytes to hex string using fold for efficiency
        use std::fmt::Write as _;
        let hex_string = hash.iter().fold(String::with_capacity(64), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        Ok(hex_string)
    }

    /// Group profiles by content hash
    fn group_by_hash(&self, profiles: &[ProfileEntry]) -> Vec<ProfileGroup> {
        let mut hash_map: HashMap<String, Vec<ProfileEntry>> = HashMap::new();

        for profile in profiles {
            hash_map
                .entry(profile.content_hash.clone())
                .or_default()
                .push(profile.clone());
        }

        hash_map
            .into_iter()
            .map(|(content_hash, profiles)| {
                // Find the canonical filename (shortest one)
                let canonical_filename = profiles
                    .iter()
                    .map(|p| &p.filename)
                    .min_by_key(|f| f.len())
                    .cloned()
                    .unwrap_or_else(|| "unknown.mobileconfig".to_string());

                ProfileGroup {
                    content_hash,
                    profiles,
                    canonical_filename,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_group_is_duplicate() {
        let group = ProfileGroup {
            content_hash: "abc123".to_string(),
            profiles: vec![
                ProfileEntry {
                    filename: "test.mobileconfig".to_string(),
                    path: PathBuf::from("/tmp/test.mobileconfig"),
                    baseline_name: "800-53r5_high".to_string(),
                    content_hash: "abc123".to_string(),
                    size: 1024,
                },
                ProfileEntry {
                    filename: "test.mobileconfig".to_string(),
                    path: PathBuf::from("/tmp/test2.mobileconfig"),
                    baseline_name: "cis_lvl1".to_string(),
                    content_hash: "abc123".to_string(),
                    size: 1024,
                },
            ],
            canonical_filename: "test.mobileconfig".to_string(),
        };

        assert!(group.is_duplicate());
        assert_eq!(group.get_unique_baselines().len(), 2);
    }

    #[test]
    fn test_profile_group_not_duplicate() {
        let group = ProfileGroup {
            content_hash: "abc123".to_string(),
            profiles: vec![ProfileEntry {
                filename: "test.mobileconfig".to_string(),
                path: PathBuf::from("/tmp/test.mobileconfig"),
                baseline_name: "800-53r5_high".to_string(),
                content_hash: "abc123".to_string(),
                size: 1024,
            }],
            canonical_filename: "test.mobileconfig".to_string(),
        };

        assert!(!group.is_duplicate());
        assert_eq!(group.get_unique_baselines().len(), 1);
    }
}
