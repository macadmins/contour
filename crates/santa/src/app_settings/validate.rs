//! Validate `app.settings` entries against the schema's `notes` rules.
//!
//! These are semantic constraints Apple states in prose (not expressible as
//! plain schema presence), plus enum/format checks. Structural validation of
//! the assembled declaration against the embedded **beta** schema is the job of
//! `contour profile ddm validate --beta`; this module enforces the rules that
//! schema validation can't:
//!
//! - `AllowedBinaries` ⇒ `CDHash` or `TeamID` present.
//! - `DeniedBinaries` ⇒ `CDHash`, `TeamID`, or `SigningID` present.
//! - identifier formats valid; `TeamID` may be the literal `*APPLE*`.
//! - each Privacy app has a non-empty `OrganizationJustification` and permission
//!   values within their rangelists.

use super::model::{BinaryIdentifier, BinaryPolicy, Permission, PermissionDefault};

/// A rejected entry and why, for reporting (`--strict` fails; default warns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub entry: String,
    pub reason: String,
}

/// The Apple sentinel TeamID for Apple binaries with an empty team identifier.
const APPLE_TEAM_SENTINEL: &str = "*APPLE*";

/// Validate one binary identifier for the list its policy routes it to.
pub fn validate_binary(bi: &BinaryIdentifier, policy: BinaryPolicy) -> Result<(), String> {
    if bi.is_empty() {
        return Err(
            "no identifying field set (need CDHash, TeamID, SigningID, or PathPrefix)".into(),
        );
    }

    // Per-list required-identifier rules from the schema notes.
    match policy {
        BinaryPolicy::Allow => {
            if bi.cdhash.is_none() && bi.team_id.is_none() {
                return Err("AllowedBinaries requires CDHash or TeamID".into());
            }
        }
        BinaryPolicy::Deny => {
            if bi.cdhash.is_none() && bi.team_id.is_none() && bi.signing_id.is_none() {
                return Err("DeniedBinaries requires CDHash, TeamID, or SigningID".into());
            }
        }
    }

    // Format checks for whichever fields are present.
    if let Some(team) = &bi.team_id {
        if team != APPLE_TEAM_SENTINEL && !crate::cel::is_valid_team_id(team) {
            return Err(format!(
                "invalid TeamID '{team}' (expect 10 alphanumerics or *APPLE*)"
            ));
        }
    }
    if let Some(cdhash) = &bi.cdhash {
        if !crate::cel::is_valid_cdhash(cdhash) {
            return Err(format!("invalid CDHash '{cdhash}' (expect 40 hex chars)"));
        }
    }
    if let Some(signing_id) = &bi.signing_id {
        if !crate::cel::is_valid_signing_id(signing_id) {
            return Err(format!("invalid SigningID '{signing_id}'"));
        }
    }

    Ok(())
}

/// Validate one Privacy permission-default entry.
pub fn validate_permission_default(pd: &PermissionDefault) -> Result<(), String> {
    if pd.organization_justification.trim().is_empty() {
        return Err("OrganizationJustification is required and must be non-empty".into());
    }
    for (perm, value) in &pd.permissions {
        if !perm.allowed_values().contains(&value.as_str()) {
            return Err(format!(
                "{} value '{value}' is not one of {:?}",
                perm.key(),
                perm.allowed_values()
            ));
        }
    }
    Ok(())
}

/// Partition binaries into (valid, violations), labelling each entry.
pub fn partition_binaries(
    binaries: Vec<(BinaryIdentifier, BinaryPolicy)>,
) -> (Vec<(BinaryIdentifier, BinaryPolicy)>, Vec<Violation>) {
    let mut valid = Vec::new();
    let mut violations = Vec::new();
    for (bi, policy) in binaries {
        match validate_binary(&bi, policy) {
            Ok(()) => valid.push((bi, policy)),
            Err(reason) => violations.push(Violation {
                entry: label(&bi),
                reason,
            }),
        }
    }
    (valid, violations)
}

/// A short human label for a binary identifier (for violation reports).
fn label(bi: &BinaryIdentifier) -> String {
    bi.signing_id
        .clone()
        .or_else(|| bi.team_id.clone())
        .or_else(|| bi.cdhash.clone())
        .or_else(|| bi.path_prefix.clone())
        .unwrap_or_else(|| "<empty>".to_string())
}

/// True when `Permission` is unavailable on macOS (schema `macOS: n/a`).
pub fn permission_macos_na(perm: Permission) -> bool {
    matches!(perm, Permission::LocationAccuracy)
}

/// True when `Permission` is unavailable on iOS (schema `iOS: n/a`).
pub fn permission_ios_na(perm: Permission) -> bool {
    matches!(perm, Permission::Accessibility)
}

#[cfg(test)]
mod tests {
    use super::super::model::SigningState;
    use super::*;
    use std::collections::BTreeMap;

    fn team(id: &str) -> BinaryIdentifier {
        BinaryIdentifier {
            team_id: Some(id.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn allow_requires_cdhash_or_teamid() {
        // SigningID alone is invalid for allow.
        let only_signing = BinaryIdentifier {
            signing_id: Some("ABCDE12345:com.x".to_string()),
            ..Default::default()
        };
        assert!(validate_binary(&only_signing, BinaryPolicy::Allow).is_err());
        // ...but valid for deny.
        validate_binary(&only_signing, BinaryPolicy::Deny).unwrap();
    }

    #[test]
    fn apple_sentinel_team_id_is_valid() {
        validate_binary(&team("*APPLE*"), BinaryPolicy::Allow).unwrap();
        validate_binary(&team("ABCDE12345"), BinaryPolicy::Allow).unwrap();
        assert!(validate_binary(&team("short"), BinaryPolicy::Allow).is_err());
    }

    #[test]
    fn signing_state_alone_is_not_an_identifier() {
        let only_state = BinaryIdentifier {
            signing_state: Some(SigningState::DeveloperId),
            ..Default::default()
        };
        assert!(validate_binary(&only_state, BinaryPolicy::Deny).is_err());
    }

    #[test]
    fn partition_splits_valid_and_invalid() {
        let entries = vec![
            (team("ABCDE12345"), BinaryPolicy::Allow),
            (BinaryIdentifier::default(), BinaryPolicy::Allow),
        ];
        let (valid, violations) = partition_binaries(entries);
        assert_eq!(valid.len(), 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn permission_default_requires_justification() {
        let mut perms = BTreeMap::new();
        perms.insert(Permission::Camera, "Allow".to_string());
        let mut pd = PermissionDefault {
            app_identifier: "com.x".to_string(),
            organization_justification: String::new(),
            permissions: perms.clone(),
        };
        assert!(validate_permission_default(&pd).is_err());
        pd.organization_justification = "Needed for calls".to_string();
        validate_permission_default(&pd).unwrap();
    }

    #[test]
    fn permission_value_must_be_in_rangelist() {
        let mut perms = BTreeMap::new();
        perms.insert(Permission::Location, "Sometimes".to_string());
        let pd = PermissionDefault {
            app_identifier: "com.x".to_string(),
            organization_justification: "j".to_string(),
            permissions: perms,
        };
        assert!(validate_permission_default(&pd).is_err());
    }
}
