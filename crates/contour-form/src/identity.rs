//! Identifiers: the org-domain rule and deterministic UUIDs.
//!
//! Both exist so that emitting the same document twice yields the same
//! bytes, and so that a placeholder org is refused rather than defaulted.
//! `com.example` is rejected by name: it produces colliding identifiers
//! across every org that forgot to change it.

use sha2::{Digest, Sha256};

/// Why an org domain was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOrg {
    pub domain: String,
}

impl std::fmt::Display for InvalidOrg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid organization domain '{}' — identifiers must be reverse-DNS \
             (lowercase a-z 0-9 with at least one `.`). Examples: `com.acme`, \
             `io.macadmins`. The placeholder `com.example` is also rejected because \
             it produces colliding identifiers across orgs.",
            self.domain
        )
    }
}

impl std::error::Error for InvalidOrg {}

/// The rule `ddm compose` has always applied, in one place so the two
/// emitters cannot disagree about what an org looks like.
pub fn validate_org_domain(domain: &str) -> Result<(), InvalidOrg> {
    let d = domain.trim();
    let valid = !d.is_empty()
        && d.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && d.contains('.')
        && !d.starts_with('.')
        && !d.ends_with('.');
    if !valid || d == "com.example" {
        return Err(InvalidOrg {
            domain: domain.to_string(),
        });
    }
    Ok(())
}

/// Namespace for every UUID this crate derives. Fixed, so the same
/// identifier always yields the same UUID across builds and machines.
pub const UUID_NAMESPACE: &str = "contour-form/v1";

/// A name-based UUID: RFC 9562 version 8, derived from SHA-256.
///
/// Not version 5: v5 is SHA-1, and a SHA-1 dependency is a poor trade for a
/// crate whose only hashing need is "the same name gives the same UUID".
/// Version 8 is the RFC's slot for exactly this — a custom, deterministic
/// derivation — and every consumer that parses UUIDs accepts it.
pub fn name_uuid(name: &str) -> String {
    let mut h = Sha256::new();
    h.update(UUID_NAMESPACE.as_bytes());
    h.update([0u8]);
    h.update(name.as_bytes());
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0F) | 0x80; // version 8
    b[8] = (b[8] & 0x3F) | 0x80; // RFC variant
    let hex: Vec<String> = b.iter().map(|x| format!("{x:02X}")).collect();
    let s = hex.concat();
    format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_rule_matches_compose() {
        validate_org_domain("com.acme").unwrap();
        validate_org_domain("io.mac-admins.x9").unwrap();
        for bad in [
            "",
            "acme",
            "Com.Acme",
            ".com.acme",
            "com.acme.",
            "com.example",
        ] {
            assert!(validate_org_domain(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn uuid_is_deterministic_and_well_formed() {
        let a = name_uuid("com.acme.wifi");
        let b = name_uuid("com.acme.wifi");
        assert_eq!(a, b);
        assert_ne!(a, name_uuid("com.acme.wifi.payload"));
        assert_eq!(a.len(), 36);
        // version nibble 8, variant 10xx
        assert_eq!(&a[14..15], "8");
        assert!(matches!(&a[19..20], "8" | "9" | "A" | "B"));
    }
}
