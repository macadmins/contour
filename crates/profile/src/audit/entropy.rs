//! Shannon-entropy heuristic for spotting embedded literal secrets.
//!
//! Used as the last-resort secret detector in the audit: a string field that
//! no schema flag, deploy-variable, or payload-type rule already claimed is
//! handed to [`looks_like_secret`], which decides whether its shape and entropy
//! look like an embedded credential rather than ordinary configuration text.

/// Shannon entropy of `s` in bits per character (0.0 for the empty string).
///
/// Higher values mean less predictable content; random tokens score ~4-6,
/// English prose ~2-3, and a single repeated character scores 0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    let mut total = 0usize;
    for ch in s.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
        total += 1;
    }
    let total = total as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

/// True when `s` is a canonical UUID (8-4-4-4-12 hex with dashes).
///
/// UUIDs are high-entropy but structurally not secrets, so the heuristic
/// excludes them.
pub fn is_uuid(s: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != groups.len() {
        return false;
    }
    parts
        .iter()
        .zip(groups.iter())
        .all(|(part, &len)| part.len() == len && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// True when `s` looks like a hex serial / fingerprint: all hex digits or
/// colon-separated hex byte pairs (e.g. `0A:1B:2C`), length ≥ 8.
///
/// Certificate serials and thumbprints are high-entropy but not secrets.
pub fn is_hex_serial(s: &str) -> bool {
    let stripped: String = s.chars().filter(|&c| c != ':').collect();
    stripped.len() >= 8 && stripped.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when `s` is a reverse-DNS identifier (≥ 3 dot-separated segments, each
/// a non-empty run of letters/digits/`-`/`_`, e.g. `com.acme.wifi`).
///
/// Payload identifiers are excluded so they never trip the secret heuristic.
pub fn is_reverse_dns(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// True when `value` looks like an embedded literal secret.
///
/// This is the tunable policy at the heart of the entropy heuristic: it decides
/// the length floor, the entropy cutoff, and which structural shapes
/// ([`is_uuid`], [`is_hex_serial`], [`is_reverse_dns`]) to exclude as
/// high-entropy-but-not-secret.
pub fn looks_like_secret(value: &str) -> bool {
    // Exclude high-entropy-but-not-secret shapes. UUIDs and reverse-DNS
    // identifiers are never credentials. Colon-formatted hex serials
    // (`0A:1B:2C`) are cert fingerprints — but a *bare* long hex string is left
    // in, since API keys and tokens are often plain hex.
    let is_colon_serial = value.contains(':') && is_hex_serial(value);
    if is_uuid(value) || is_colon_serial || is_reverse_dns(value) {
        return false;
    }

    // Secrets are single contiguous tokens; anything with whitespace is prose
    // or a multi-word label, not an embedded credential.
    if value.chars().any(char::is_whitespace) {
        return false;
    }

    // Length floor of 20 skips ordinary short config tokens. Entropy floor of
    // 3.9 bits/char targets near-random hex/base64 material (hex tops out at
    // 4.0, base64 ~6) while staying above prose and hyphenated identifiers,
    // which sit around 3.6-3.9 even when long.
    value.len() >= 20 && shannon_entropy(value) >= 3.9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_zero_entropy() {
        assert!(shannon_entropy("").abs() < 1e-12);
    }

    #[test]
    fn single_repeated_char_has_zero_entropy() {
        assert!(shannon_entropy("aaaaaaaa").abs() < 1e-12);
    }

    #[test]
    fn random_token_has_high_entropy() {
        // 40 distinct-ish hex chars score well above prose.
        assert!(shannon_entropy("a3f9b2c1d8e7460af1029384756bcdef01928374") > 3.5);
    }

    #[test]
    fn prose_has_low_entropy() {
        assert!(shannon_entropy("Corporate Wi-Fi") < 3.8);
    }

    #[test]
    fn recognizes_canonical_uuid() {
        assert!(is_uuid("550E8400-E29B-41D4-A716-446655440000"));
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn rejects_non_uuid() {
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400e29b41d4a716446655440000"));
    }

    #[test]
    fn recognizes_hex_serial_with_and_without_colons() {
        assert!(is_hex_serial("0A1B2C3D"));
        assert!(is_hex_serial("0A:1B:2C:3D"));
    }

    #[test]
    fn rejects_short_or_nonhex_serial() {
        assert!(!is_hex_serial("0A1B"));
        assert!(!is_hex_serial("hello world"));
    }

    #[test]
    fn recognizes_reverse_dns_identifier() {
        assert!(is_reverse_dns("com.acme.wifi"));
        assert!(is_reverse_dns("com.acme.wifi.payload-1"));
    }

    #[test]
    fn rejects_non_reverse_dns() {
        assert!(!is_reverse_dns("acme"));
        assert!(!is_reverse_dns("two.parts"));
    }

    // --- looks_like_secret: contract the policy must satisfy ---

    #[test]
    fn flags_long_high_entropy_literal() {
        assert!(looks_like_secret(
            "a3f9b2c1d8e7460af1029384756bcdef01928374"
        ));
    }

    #[test]
    fn ignores_short_value() {
        assert!(!looks_like_secret("abc123"));
    }

    #[test]
    fn ignores_uuid_shaped_value() {
        assert!(!looks_like_secret("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn ignores_reverse_dns_identifier() {
        assert!(!looks_like_secret("com.acme.wifi.managed.payload"));
    }

    #[test]
    fn ignores_low_entropy_prose() {
        assert!(!looks_like_secret("Corporate Wireless Network"));
    }

    #[test]
    fn flags_long_base64_token() {
        assert!(looks_like_secret("aGVsbG8gd29ybGQgc2VjcmV0IGtleSE="));
    }

    #[test]
    fn ignores_colon_formatted_serial() {
        assert!(!looks_like_secret("0A:1B:2C:3D:4E:5F:60:71:82:93"));
    }

    #[test]
    fn ignores_long_whitespace_label() {
        // A long, multi-word display name must not be flagged.
        assert!(!looks_like_secret("Acme Corporate Guest Wireless Network"));
    }
}
