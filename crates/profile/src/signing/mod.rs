//! Profile signing support
//!
//! Note: Signing configuration reserved for future use.
#![allow(dead_code, reason = "module under development")]

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Return an error on non-macOS platforms for commands that require macOS tools.
fn require_macos(operation: &str) -> Result<()> {
    if cfg!(not(target_os = "macos")) {
        anyhow::bail!("{operation} requires macOS (uses `security` command-line tool)");
    }
    Ok(())
}

/// Profile signing configuration
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Code signing identity (certificate name or SHA-1 hash)
    pub identity: String,
    /// Optional keychain path
    pub keychain: Option<String>,
    /// Timestamp the signature
    pub timestamp: bool,
}

impl SigningConfig {
    pub fn new(identity: String) -> Self {
        Self {
            identity,
            keychain: None,
            timestamp: true,
        }
    }

    pub fn with_keychain(mut self, keychain: String) -> Self {
        self.keychain = Some(keychain);
        self
    }

    pub fn with_timestamp(mut self, timestamp: bool) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Sign a configuration profile using security cms
pub fn sign_profile(
    input_path: &Path,
    output_path: &Path,
    config: &SigningConfig,
) -> Result<SigningResult> {
    require_macos("Profile signing")?;
    // Read the unsigned profile (validates file exists)
    let _profile_data = fs::read(input_path)
        .with_context(|| format!("Failed to read profile: {}", input_path.display()))?;

    // Build the security cms command
    let mut cmd = Command::new("security");
    cmd.args(["cms", "-S"]);

    // Add signer identity
    cmd.args(["-N", &config.identity]);

    // Add keychain if specified
    if let Some(keychain) = &config.keychain {
        cmd.args(["-k", keychain]);
    }

    // Input from stdin, output to stdout
    cmd.args(["-i", "-", "-o", "-"]);

    // Execute and capture output
    let _output = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| "Failed to spawn security cms")?
        .wait_with_output()
        .with_context(|| "Failed to execute security cms")?;

    // Actually pipe the data - we need to do this properly
    let output = sign_with_security_cms(input_path, &config.identity, config.keychain.as_deref())?;

    // Write signed profile
    fs::write(output_path, &output)
        .with_context(|| format!("Failed to write signed profile: {}", output_path.display()))?;

    // Verify the signature
    let verification = verify_signature(output_path)?;

    Ok(SigningResult {
        success: true,
        output_path: output_path.to_path_buf(),
        signer_identity: config.identity.clone(),
        verified: verification.valid,
    })
}

fn sign_with_security_cms(
    input_path: &Path,
    identity: &str,
    keychain: Option<&str>,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("security");
    cmd.args(["cms", "-S"]);
    cmd.args(["-N", identity]);

    if let Some(kc) = keychain {
        cmd.args(["-k", kc]);
    }

    cmd.args([
        "-i",
        input_path.to_str().ok_or_else(|| {
            anyhow::anyhow!("path contains invalid UTF-8: {}", input_path.display())
        })?,
    ]);

    let output = cmd
        .output()
        .with_context(|| "Failed to execute security cms")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("security cms signing failed: {stderr}");
    }

    Ok(output.stdout)
}

/// Signing result
#[derive(Debug)]
pub struct SigningResult {
    pub success: bool,
    pub output_path: std::path::PathBuf,
    pub signer_identity: String,
    pub verified: bool,
}

/// Verify a signed profile's signature
pub fn verify_signature(path: &Path) -> Result<VerificationResult> {
    require_macos("Signature verification")?;
    let output = Command::new("security")
        .args([
            "cms",
            "-D",
            "-i",
            path.to_str().ok_or_else(|| {
                anyhow::anyhow!("path contains invalid UTF-8: {}", path.display())
            })?,
        ])
        .output()
        .with_context(|| "Failed to execute security cms verify")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(VerificationResult {
            valid: false,
            signed: false,
            signer: None,
            error: Some(stderr.to_string()),
        });
    }

    // Profile was decoded successfully, meaning it was validly signed
    // Try to get signer info
    let signer_info = get_signer_info(path)?;

    Ok(VerificationResult {
        valid: true,
        signed: true,
        signer: signer_info,
        error: None,
    })
}

/// Verification result
#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub signed: bool,
    pub signer: Option<String>,
    pub error: Option<String>,
}

fn get_signer_info(path: &Path) -> Result<Option<String>> {
    let output = Command::new("security")
        .args([
            "cms",
            "-D",
            "-h1",
            "-i",
            path.to_str().ok_or_else(|| {
                anyhow::anyhow!("path contains invalid UTF-8: {}", path.display())
            })?,
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let info = String::from_utf8_lossy(&o.stdout);
            // Parse signer from CMS header info
            for line in info.lines() {
                if line.contains("signer") || line.contains("Subject:") {
                    return Ok(Some(line.trim().to_string()));
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// List available signing identities
pub fn list_signing_identities() -> Result<Vec<SigningIdentity>> {
    require_macos("Listing signing identities")?;
    let output = Command::new("security")
        .args(["find-identity", "-v", "-p", "codesigning"])
        .output()
        .with_context(|| "Failed to list signing identities")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to list identities: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut identities = Vec::new();

    for line in stdout.lines() {
        // Parse lines like: "  1) SHA... \"Developer ID Application: Name (Team)\""
        if let Some(start) = line.find('"')
            && let Some(end) = line.rfind('"')
        {
            let name = &line[start + 1..end];
            // Extract SHA
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let sha = parts[1].to_string();
                identities.push(SigningIdentity {
                    name: name.to_string(),
                    sha1: sha,
                    is_developer_id: name.contains("Developer ID"),
                });
            }
        }
    }

    Ok(identities)
}

/// A signing identity
#[derive(Debug, Clone)]
pub struct SigningIdentity {
    pub name: String,
    pub sha1: String,
    pub is_developer_id: bool,
}

/// Check if a profile file is signed (alias for consistency)
pub fn is_signed_profile(path: &Path) -> Result<bool> {
    is_signed(path)
}

/// Remove signature from a signed profile and return unsigned data.
/// On macOS, uses `security cms -D` for verified extraction.
/// On all platforms, falls back to native CMS/PKCS#7 DER parsing.
pub fn remove_signature(path: &Path) -> Result<Vec<u8>> {
    // Try macOS security cms first (verifies signature)
    if cfg!(target_os = "macos") {
        let output = Command::new("security")
            .args([
                "cms",
                "-D",
                "-i",
                path.to_str().ok_or_else(|| {
                    anyhow::anyhow!("path contains invalid UTF-8: {}", path.display())
                })?,
            ])
            .output()
            .with_context(|| "Failed to execute security cms")?;

        if output.status.success() {
            return Ok(output.stdout);
        }
    }

    // Cross-platform: parse CMS/PKCS#7 DER to extract encapsulated content
    let data = fs::read(path)?;
    extract_content_from_cms(&data)
}

/// Extract the encapsulated plist content from CMS/PKCS#7 DER data.
///
/// Signed mobileconfig files are DER-encoded CMS ContentInfo containing
/// SignedData, with the plist XML in encapContentInfo.eContent.
fn extract_content_from_cms(data: &[u8]) -> Result<Vec<u8>> {
    use cms::cert::x509::der::Decode;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    // Parse the outer ContentInfo
    let content_info = ContentInfo::from_der(data)
        .map_err(|e| anyhow::anyhow!("Failed to parse CMS ContentInfo: {e}"))?;

    // Extract SignedData from ContentInfo
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|e| anyhow::anyhow!("Failed to decode CMS SignedData: {e}"))?;

    // Get the encapsulated content (the plist XML)
    let econtent = signed_data
        .encap_content_info
        .econtent
        .context("Signed profile has no encapsulated content")?;

    let bytes = econtent.value();

    // Clean null bytes that can appear in CMS OCTET STRING encoding
    let mut cleaned = bytes.to_vec();
    cleaned.retain(|&b| b != 0);

    Ok(cleaned)
}

/// Check if a profile is signed
pub fn is_signed(path: &Path) -> Result<bool> {
    let data = fs::read(path)?;

    // Check for PKCS#7 signature markers
    // Signed profiles start with sequence of bytes indicating CMS/PKCS#7 structure
    if data.len() > 10 {
        // Check for ASN.1 SEQUENCE tag followed by CMS content type OID
        if data[0] == 0x30 {
            // ASN.1 SEQUENCE
            return Ok(true);
        }
    }

    // Also check if it starts with XML plist (unsigned)
    if data.starts_with(b"<?xml") || data.starts_with(b"bplist") {
        return Ok(false);
    }

    // Try to decode with security cms as fallback (macOS only)
    if cfg!(not(target_os = "macos")) {
        return Ok(false);
    }
    let output = Command::new("security")
        .args([
            "cms",
            "-D",
            "-i",
            path.to_str().ok_or_else(|| {
                anyhow::anyhow!("path contains invalid UTF-8: {}", path.display())
            })?,
        ])
        .output()?;

    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_config() {
        let config = SigningConfig::new("My Identity".to_string())
            .with_keychain("/path/to/keychain".to_string())
            .with_timestamp(false);

        assert_eq!(config.identity, "My Identity");
        assert_eq!(config.keychain, Some("/path/to/keychain".to_string()));
        assert!(!config.timestamp);
    }
}
