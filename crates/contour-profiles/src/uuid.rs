/// Generate a deterministic UUID v5 from a seed string.
///
/// Uses the DNS namespace as the base UUID, producing the same output
/// for the same input across runs. The result is uppercased.
pub fn deterministic_uuid(seed: &str) -> String {
    ::uuid::Uuid::new_v5(&::uuid::Uuid::NAMESPACE_DNS, seed.as_bytes())
        .to_string()
        .to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let uuid1 = deterministic_uuid("com.example.santa.prep.system-extension");
        let uuid2 = deterministic_uuid("com.example.santa.prep.system-extension");
        assert_eq!(uuid1, uuid2);
    }

    #[test]
    fn test_different_seeds() {
        let uuid1 = deterministic_uuid("com.example.santa.prep.system-extension");
        let uuid2 = deterministic_uuid("com.example.santa.prep.tcc");
        assert_ne!(uuid1, uuid2);
    }

    #[test]
    fn test_uppercase() {
        let uuid = deterministic_uuid("test");
        assert_eq!(uuid, uuid.to_uppercase());
    }
}
