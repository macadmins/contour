//! Transform an Apple MDM-profile (.plist / mobileconfig) example into a
//! deployable profile: org-scope PayloadIdentifier(s), regenerate PayloadUUID(s).

use anyhow::Result;

/// Normalize a mobileconfig XML string into a deployable one. `org_domain`
/// prefixes the PayloadIdentifier(s); UUIDs are regenerated (random v4).
pub fn transform_mobileconfig(xml: &str, org_domain: &str) -> Result<String> {
    use crate::profile::{normalizer, parser};
    use crate::uuid::{self, UuidConfig};

    let fr = parser::parse_profile_lenient_from_bytes(xml.as_bytes())?;
    let mut profile = fr.profile;

    normalizer::normalize_profile(
        &mut profile,
        &normalizer::NormalizerConfig {
            org_domain: Some(org_domain.to_string()),
            org_name: None,
            naming_convention: normalizer::NamingConvention::OrgDomainPrefix,
        },
    )?;

    let ucfg = UuidConfig {
        org_domain: Some(org_domain.to_string()),
        predictable: false,
    };
    profile.payload_uuid =
        uuid::regenerate_uuid(&profile.payload_uuid, &ucfg, &profile.payload_identifier)?;
    for c in &mut profile.payload_content {
        c.payload_uuid = uuid::regenerate_uuid(&c.payload_uuid, &ucfg, &c.payload_identifier)?;
    }

    let out = parser::profile_to_xml_string(&profile)?;
    let out = parser::restore_placeholders(out.as_bytes(), &fr.placeholder_mapping);
    let out = String::from_utf8(out)?;
    let out = parser::restore_comments(&out, &fr.comments);
    Ok(out)
}
