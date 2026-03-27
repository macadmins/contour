use anyhow::{Context, Result};
use git2::Repository;
use std::path::Path;

/// Get Git information from an mSCP repository
#[derive(Debug)]
pub struct GitInfoExtractor;

impl GitInfoExtractor {
    /// Extract Git hash and tag from a repository
    pub fn extract<P: AsRef<Path>>(repo_path: P) -> Result<GitInfo> {
        let repo = Repository::discover(repo_path.as_ref())
            .context("Failed to open Git repository. Is this a Git repo?")?;

        let head = repo.head().context("Failed to get HEAD reference")?;
        let commit = head.peel_to_commit().context("Failed to get HEAD commit")?;

        let hash = commit.id().to_string();
        let short_hash = hash.chars().take(7).collect();

        // Try to find a tag pointing to this commit
        let tag = Self::find_tag(&repo, &commit.id())?;

        Ok(GitInfo {
            hash,
            short_hash,
            tag,
        })
    }

    /// Find a tag pointing to the given commit
    fn find_tag(repo: &Repository, oid: &git2::Oid) -> Result<Option<String>> {
        let tag_names = repo.tag_names(None)?;

        for tag_name in tag_names.iter().flatten() {
            if let Ok(reference) = repo.find_reference(&format!("refs/tags/{tag_name}"))
                && let Ok(tag_oid) = reference.peel_to_commit()
                && tag_oid.id() == *oid
            {
                return Ok(Some(tag_name.to_string()));
            }
        }

        Ok(None)
    }

    /// Generate a version ID from Git info and timestamp
    /// Format: {short_hash}-{timestamp}
    /// Example: abc123d-20241121T103000Z
    pub fn generate_version_id(git_info: &GitInfo) -> String {
        let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        format!("{}-{}", git_info.short_hash, timestamp)
    }
}

/// Git repository information
#[derive(Debug, Clone)]
pub struct GitInfo {
    /// Full Git commit hash
    pub hash: String,

    /// Short Git commit hash (first 7 chars)
    pub short_hash: String,

    /// Git tag (if exists)
    pub tag: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_id_format() {
        let git_info = GitInfo {
            hash: "abc123def456".to_string(),
            short_hash: "abc123d".to_string(),
            tag: Some("v1.0".to_string()),
        };

        let version_id = GitInfoExtractor::generate_version_id(&git_info);
        assert!(version_id.starts_with("abc123d-"));
        assert!(version_id.contains('T'));
        assert!(version_id.ends_with('Z'));
    }
}
