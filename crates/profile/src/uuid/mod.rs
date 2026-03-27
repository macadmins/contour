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
        if let Some(org_domain) = &config.org_domain {
            let namespace = create_namespace_from_domain(org_domain);
            let uuid = Uuid::new_v5(&namespace, identifier.as_bytes());
            Ok(uuid.to_string().to_uppercase())
        } else {
            Ok(Uuid::new_v4().to_string().to_uppercase())
        }
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
