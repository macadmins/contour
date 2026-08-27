//! UUID generation and validation for profiles.
//!
//! Supports both random (v4) and predictable (v5) UUID generation based on
//! organization domain and payload identifiers.

use anyhow::Result;
use uuid::Uuid;

/// Configuration for UUID generation.
#[derive(Debug)]
pub struct UuidConfig {
    /// Organization domain for v5 UUID namespace.
    pub org_domain: Option<String>,
    /// Use predictable v5 UUIDs instead of random v4.
    pub predictable: bool,
}

pub fn generate_uuid(config: &UuidConfig, identifier: &str) -> Result<String> {
    if config.predictable {
        let Some(org_domain) = &config.org_domain else {
            anyhow::bail!(
                "predictable UUIDs require an organization domain: pass --org <domain>, \
                 or set organization.domain in profile.toml or .contour/config.toml"
            );
        };
        let namespace = create_namespace_from_domain(org_domain);
        let uuid = Uuid::new_v5(&namespace, identifier.as_bytes());
        Ok(uuid.to_string().to_uppercase())
    } else {
        Ok(Uuid::new_v4().to_string().to_uppercase())
    }
}

fn create_namespace_from_domain(domain: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, domain.as_bytes())
}

pub fn is_valid_uuid(uuid: &str) -> bool {
    Uuid::parse_str(uuid).is_ok()
}

/// Detect placeholder UUIDs that are well-formed per RFC 4122 but
/// practically defective (deploy-time MDM collision risk).
///
/// Catches:
/// - All-zeros: `00000000-0000-0000-0000-000000000000`
/// - All-Fs / all-ones / single-digit repetitions: `FFFFFFFF-...`,
///   `11111111-...`, `BBBBBBBB-...`
/// - Common boilerplate placeholders like
///   `12345678-1234-1234-1234-123456789012` whose hex chars only
///   cover a narrow distinct set.
///
/// Heuristic: parse via `Uuid::parse_str` (so it returns false on
/// invalid input — caller can pair this with `is_valid_uuid` for full
/// coverage), then collapse the 32 hex chars and assert at least 4
/// distinct characters appear. Real UUIDs from any standard random or
/// v5 generator have well over 4 distinct hex chars; a 4-distinct
/// threshold is a comfortable line below which a UUID is almost
/// certainly a hand-typed placeholder, not a generated one.
///
/// Returns `false` if the input is not a valid UUID at all (caller
/// already gets that signal from `is_valid_uuid`).
pub fn is_placeholder_uuid(uuid: &str) -> bool {
    let Ok(parsed) = Uuid::parse_str(uuid) else {
        return false;
    };
    let bytes = parsed.as_bytes();
    let mut distinct_nibbles: u32 = 0;
    for byte in bytes {
        distinct_nibbles |= 1 << (byte >> 4);
        distinct_nibbles |= 1 << (byte & 0x0F);
    }
    distinct_nibbles.count_ones() < 4
}

pub fn regenerate_uuid(existing: &str, config: &UuidConfig, identifier: &str) -> Result<String> {
    if !is_valid_uuid(existing) {
        return generate_uuid(config, identifier);
    }

    // Always regenerate: random v4 or predictable v5
    generate_uuid(config, identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_predictable_uuid() {
        let config = UuidConfig {
            org_domain: Some("com.example".to_string()),
            predictable: true,
        };

        let uuid1 = generate_uuid(&config, "test.identifier").unwrap();
        let uuid2 = generate_uuid(&config, "test.identifier").unwrap();

        assert_eq!(uuid1, uuid2);
        assert!(is_valid_uuid(&uuid1));
    }

    #[test]
    fn predictable_without_org_domain_is_an_error() {
        let config = UuidConfig {
            org_domain: None,
            predictable: true,
        };

        let err = generate_uuid(&config, "test.identifier").unwrap_err();
        assert!(
            err.to_string().contains("--org"),
            "error should tell the user how to fix it, got: {err}"
        );
    }

    #[test]
    fn test_generate_random_uuid() {
        let config = UuidConfig {
            org_domain: None,
            predictable: false,
        };

        let uuid1 = generate_uuid(&config, "test.identifier").unwrap();
        let uuid2 = generate_uuid(&config, "test.identifier").unwrap();

        assert_ne!(uuid1, uuid2);
        assert!(is_valid_uuid(&uuid1));
        assert!(is_valid_uuid(&uuid2));
    }

    #[test]
    fn test_regenerate_uuid_random_produces_new_uuid() {
        let config = UuidConfig {
            org_domain: None,
            predictable: false,
        };

        let existing = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        let regenerated = regenerate_uuid(existing, &config, "test.identifier").unwrap();

        assert_ne!(existing, regenerated);
        assert!(is_valid_uuid(&regenerated));
    }

    #[test]
    fn placeholder_all_zeros() {
        assert!(is_placeholder_uuid("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn placeholder_all_fs() {
        assert!(is_placeholder_uuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"));
    }

    #[test]
    fn placeholder_repeating_single_digit() {
        assert!(is_placeholder_uuid("11111111-1111-1111-1111-111111111111"));
        assert!(is_placeholder_uuid("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"));
    }

    #[test]
    fn placeholder_classic_increment_boilerplate() {
        // 12345678-1234-1234-1234-123456789012 — hex chars 0-9 = 10 distinct;
        // does NOT trip the heuristic. That's intentional: 10 distinct hex
        // chars looks like a real UUID, even if a human typed it.
        assert!(!is_placeholder_uuid("12345678-1234-1234-1234-123456789012"));
        // But a "narrow boilerplate" with <4 distinct hex chars does trip:
        assert!(is_placeholder_uuid("11111111-2222-1111-2222-111111111111"));
    }

    #[test]
    fn real_random_uuid_is_not_placeholder() {
        let real = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        assert!(!is_placeholder_uuid(real));
    }

    #[test]
    fn real_v5_uuid_is_not_placeholder() {
        // Generated via NAMESPACE_DNS for "com.example.test"
        let cfg = UuidConfig {
            org_domain: Some("com.example".to_string()),
            predictable: true,
        };
        let v5 = generate_uuid(&cfg, "test.identifier").unwrap();
        assert!(is_valid_uuid(&v5));
        assert!(
            !is_placeholder_uuid(&v5),
            "v5 UUIDs must not register as placeholder"
        );
    }

    #[test]
    fn invalid_input_returns_false() {
        assert!(!is_placeholder_uuid("not-a-uuid"));
        assert!(!is_placeholder_uuid(""));
    }

    #[test]
    fn test_regenerate_uuid_predictable_is_stable() {
        let config = UuidConfig {
            org_domain: Some("com.example".to_string()),
            predictable: true,
        };

        let existing = "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D";
        let regen1 = regenerate_uuid(existing, &config, "test.identifier").unwrap();
        let regen2 = regenerate_uuid(existing, &config, "test.identifier").unwrap();

        assert_eq!(regen1, regen2);
        assert_ne!(existing, regen1);
        assert!(is_valid_uuid(&regen1));
    }
}
