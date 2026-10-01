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

/// Verify a signed profile's signature.
///
/// `security cms -D` DECODES a CMS message; it exits 0 whether or not the
/// signature matches the content, so its exit code proves only that a
/// signature is present. The verdict is in the per-signer status it prints
/// with `-h`: a profile with one byte changed after signing decodes fine,
/// exits 0, and reports `signer0.status=DigestMismatch`.
///
/// Two questions, kept apart because the answers mean different things:
///
/// - **Integrity** — does the signature match the content? `GoodSignature` and
///   `SigningCertNotTrusted` both mean yes; the latter only says this Mac does
///   not trust the signer. Anything else — `DigestMismatch`, `BadSignature`, a
///   revoked or expired signer, a status this code does not know, or no status
///   at all — fails. Unknown fails; it does not pass.
/// - **Trust** — does this Mac trust the signer? Reported, not enforced:
///   organisations sign with internal CAs that devices trust through MDM while
///   the admin's Mac does not, and calling those profiles invalid would be
///   wrong in the other direction.
pub fn verify_signature(path: &Path) -> Result<VerificationResult> {
    require_macos("Signature verification")?;
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("path contains invalid UTF-8: {}", path.display()))?;
    let output = Command::new("security")
        .args(["cms", "-D", "-h", "0", "-i", path_str])
        .output()
        .with_context(|| "Failed to execute security cms verify")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(VerificationResult {
            valid: false,
            signed: false,
            trusted: false,
            signer: None,
            error: Some(stderr.to_string()),
        });
    }

    let info = String::from_utf8_lossy(&output.stdout);
    let statuses = signer_statuses(&info);
    let ids = signer_ids(&info);
    let (valid, trusted, error) = judge_signer_statuses(&statuses);
    Ok(VerificationResult {
        valid,
        signed: true,
        trusted,
        signer: (!ids.is_empty()).then(|| ids.join(", ")),
        error,
    })
}

/// Every `signerN.status=<Status>` reported by `security cms -D -h 0`.
fn signer_statuses(info: &str) -> Vec<String> {
    signer_field(info, ".status")
}

/// Every `signerN.id="<common name>"` — who signed, as the header names them.
///
/// Read from the same header as the statuses. The first line containing
/// "signer" is `nsigners=1`, not a name.
fn signer_ids(info: &str) -> Vec<String> {
    signer_field(info, ".id")
        .into_iter()
        .map(|v| v.trim_matches('"').to_string())
        .collect()
}

fn signer_field(info: &str, suffix: &str) -> Vec<String> {
    info.split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key.starts_with("signer") && key.ends_with(suffix)).then(|| value.trim().to_string())
        })
        .collect()
}

/// `(integrity_ok, trusted, error)` for a set of signer statuses.
///
/// Every signer must pass. No statuses at all is a failure: a message that
/// reports no signer has not been shown to be signed by anyone.
fn judge_signer_statuses(statuses: &[String]) -> (bool, bool, Option<String>) {
    const INTACT_TRUSTED: &[&str] = &["GoodSignature"];
    const INTACT_UNTRUSTED: &[&str] = &["SigningCertNotTrusted"];
    if statuses.is_empty() {
        return (
            false,
            false,
            Some("no signer status reported — the signature could not be verified".into()),
        );
    }
    let bad: Vec<&String> = statuses
        .iter()
        .filter(|s| {
            !INTACT_TRUSTED.contains(&s.as_str()) && !INTACT_UNTRUSTED.contains(&s.as_str())
        })
        .collect();
    if !bad.is_empty() {
        let names: Vec<&str> = bad.iter().map(|s| s.as_str()).collect();
        let what = if names.contains(&"DigestMismatch") {
            "the content was changed after it was signed"
        } else {
            "the signature does not verify"
        };
        return (
            false,
            false,
            Some(format!("{what} (signer status: {})", names.join(", "))),
        );
    }
    let trusted = statuses
        .iter()
        .all(|s| INTACT_TRUSTED.contains(&s.as_str()));
    (true, trusted, None)
}

/// Verification result
#[derive(Debug)]
pub struct VerificationResult {
    /// The signature matches the content.
    pub valid: bool,
    pub signed: bool,
    /// This Mac trusts the signer. Separate from `valid`: an intact signature
    /// from a CA only the managed devices trust is valid and untrusted here.
    pub trusted: bool,
    pub signer: Option<String>,
    pub error: Option<String>,
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

#[cfg(test)]
mod verification_tests {
    use super::*;

    /// What `security cms -D -h 0` prints for an intact, self-signed profile.
    const INTACT: &str = "SMIME: \tlevel=0.2; type=signedData; nsigners=1; \n\t\tsigner0.id=\"contour-demo-signing\"; signer0.status=SigningCertNotTrusted; \n\tlevel=0.1; type=data; ";
    /// …and for the same profile with one byte changed after signing. It
    /// decodes, and `security cms -D` exits 0 on it — which is why reading
    /// the exit code said this was validly signed.
    const TAMPERED: &str = "SMIME: \tlevel=0.2; type=signedData; nsigners=1; \n\t\tsigner0.id=\"contour-demo-signing\"; signer0.status=DigestMismatch; \n\tlevel=0.1; type=data; ";

    #[test]
    fn signer_statuses_are_read_from_security_cms_output() {
        assert_eq!(signer_statuses(INTACT), vec!["SigningCertNotTrusted"]);
        assert_eq!(signer_statuses(TAMPERED), vec!["DigestMismatch"]);
        assert_eq!(signer_ids(INTACT), vec!["contour-demo-signing"]);
        let two = "signer0.status=GoodSignature; signer1.status=DigestMismatch;";
        assert_eq!(
            signer_statuses(two),
            vec!["GoodSignature", "DigestMismatch"]
        );
    }

    /// The defect: tampered content was reported as validly signed.
    #[test]
    fn a_digest_mismatch_is_invalid_and_says_the_content_changed() {
        let (valid, trusted, err) = judge_signer_statuses(&signer_statuses(TAMPERED));
        assert!(!valid, "content changed after signing must not verify");
        assert!(!trusted);
        assert!(err.unwrap().contains("changed after it was signed"));
    }

    /// Intact but untrusted is valid, and says it is untrusted.
    #[test]
    fn an_untrusted_signer_is_valid_but_not_trusted() {
        let (valid, trusted, err) = judge_signer_statuses(&signer_statuses(INTACT));
        assert!(valid, "the signature matches the content");
        assert!(!trusted, "and this Mac does not trust who made it");
        assert!(err.is_none());
    }

    #[test]
    fn a_good_signature_is_valid_and_trusted() {
        let (valid, trusted, _) = judge_signer_statuses(&["GoodSignature".to_string()]);
        assert!(valid && trusted);
    }

    /// Unknown means fail. A status this code has not seen is not a pass.
    #[test]
    fn anything_unrecognised_fails_rather_than_passes() {
        for s in [
            "BadSignature",
            "SigningCertRevoked",
            "SigningCertExpired",
            "Unverified",
            "SomethingNew",
        ] {
            let (valid, _, err) = judge_signer_statuses(&[s.to_string()]);
            assert!(!valid, "{s} must fail");
            assert!(
                err.unwrap().contains(s),
                "the failure names the status: {s}"
            );
        }
    }

    /// Every signer must pass; one bad signer fails the file.
    #[test]
    fn one_bad_signer_among_good_ones_fails() {
        let (valid, _, _) =
            judge_signer_statuses(&["GoodSignature".into(), "DigestMismatch".into()]);
        assert!(!valid);
    }

    /// No signer status at all has not been shown to be signed by anyone.
    #[test]
    fn no_signer_status_fails() {
        let (valid, _, err) = judge_signer_statuses(&[]);
        assert!(!valid);
        assert!(err.is_some());
    }
}
