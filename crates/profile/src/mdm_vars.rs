//! MDM deploy-time variable catalogues.
//!
//! Tokens like Jamf `$USERNAME` or Fleet `FLEET_VAR_HOST_UUID` are
//! substituted by the MDM server on-device at deploy time — contour
//! passes them through verbatim. This module ships the known token
//! catalogues per MDM so typos can be flagged, plus helpers to extract
//! tokens from a string and check them against a catalogue.

/// Which MDM's variable catalogue to validate against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdmFlavour {
    Fleet,
    Jamf,
    Apple,
}

impl MdmFlavour {
    /// Parse a config `mdm = "..."` value (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fleet" => Some(Self::Fleet),
            "jamf" => Some(Self::Jamf),
            "apple" => Some(Self::Apple),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fleet => "fleet",
            Self::Jamf => "jamf",
            Self::Apple => "apple",
        }
    }
}

/// Fleet exact variable names.
///
/// `FLEET_VAR_HOST_END_USER_EMAIL_IDP` is intentionally excluded — it is
/// a legacy variable Fleet advises against in new configs, so contour
/// flags it as unknown rather than blessing it.
pub const FLEET_EXACT: &[&str] = &[
    "FLEET_VAR_NDES_SCEP_CHALLENGE",
    "FLEET_VAR_NDES_SCEP_PROXY_URL",
    "FLEET_VAR_HOST_HARDWARE_SERIAL",
    "FLEET_VAR_HOST_END_USER_IDP_USERNAME",
    "FLEET_VAR_HOST_END_USER_IDP_USERNAME_LOCAL_PART",
    "FLEET_VAR_HOST_END_USER_IDP_GROUPS",
    "FLEET_VAR_HOST_END_USER_IDP_DEPARTMENT",
    "FLEET_VAR_HOST_UUID",
    "FLEET_VAR_HOST_END_USER_IDP_FULL_NAME",
    "FLEET_VAR_SCEP_RENEWAL_ID",
    "FLEET_VAR_SCEP_WINDOWS_CERTIFICATE_ID",
    "FLEET_VAR_HOST_PLATFORM",
];

/// Fleet prefix variables — a complete token appends a suffix (e.g. a
/// CA name): `FLEET_VAR_DIGICERT_DATA_MyCA`.
pub const FLEET_PREFIXES: &[&str] = &[
    "FLEET_VAR_DIGICERT_DATA_",
    "FLEET_VAR_DIGICERT_PASSWORD_",
    "FLEET_VAR_CUSTOM_SCEP_CHALLENGE_",
    "FLEET_VAR_CUSTOM_SCEP_PROXY_URL_",
    "FLEET_VAR_SMALLSTEP_SCEP_CHALLENGE_",
    "FLEET_VAR_SMALLSTEP_SCEP_PROXY_URL_",
];

/// Jamf Pro configuration-profile payload variables (`$VARIABLE`).
pub const JAMF_VARS: &[&str] = &[
    "$COMPUTERNAME",
    "$DEVICENAME",
    "$ASSETTAG",
    "$UDID",
    "$SERIALNUMBER",
    "$USERNAME",
    "$FULLNAME",
    "$REALNAME",
    "$EMAIL",
    "$PHONE",
    "$POSITION",
    "$DEPARTMENTID",
    "$DEPARTMENTNAME",
    "$BUILDINGID",
    "$BUILDINGNAME",
    "$ROOM",
    "$MACADDRESS",
    "$JSSID",
    "$PROFILEJAMFID",
    "$SITEID",
    "$SITENAME",
    "$IMEI",
    "$MEID",
    "$ICCID",
];

/// Jamf prefix variables — a complete token appends an identifier:
/// `$EXTENSIONATTRIBUTE_<id>`.
pub const JAMF_PREFIXES: &[&str] = &["$EXTENSIONATTRIBUTE_"];

/// Apple in-profile variables. Apple defines no general `$`/`%` payload
/// substitution catalogue; operators declare what they need in the
/// config `[mdm_variables.pool]`.
pub const APPLE_VARS: &[&str] = &[];

/// Whether `token` is a known variable for `flavour`.
pub fn is_known(token: &str, flavour: MdmFlavour) -> bool {
    match flavour {
        MdmFlavour::Fleet => {
            FLEET_EXACT.contains(&token)
                || FLEET_PREFIXES
                    .iter()
                    .any(|p| token.len() > p.len() && token.starts_with(p))
        }
        MdmFlavour::Jamf => {
            JAMF_VARS.contains(&token)
                || JAMF_PREFIXES
                    .iter()
                    .any(|p| token.len() > p.len() && token.starts_with(p))
        }
        MdmFlavour::Apple => APPLE_VARS.contains(&token),
    }
}

/// Extract every MDM variable token of `flavour`'s shape from `s`
/// (e.g. `$USERNAME@acme.com` yields `["$USERNAME"]`).
pub fn extract_tokens(s: &str, flavour: MdmFlavour) -> Vec<String> {
    match flavour {
        MdmFlavour::Fleet => extract_fleet(s),
        MdmFlavour::Jamf => extract_jamf(s),
        // Apple has no recognised token shape — nothing to extract.
        MdmFlavour::Apple => Vec::new(),
    }
}

fn extract_fleet(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = s[search_from..].find("FLEET_VAR_") {
        let start = search_from + rel;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        out.push(s[start..end].to_string());
        search_from = end.max(start + 1);
    }
    out
}

fn extract_jamf(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while let Some(rel) = s[i..].find('$') {
        let start = i + rel;
        let mut end = start + 1;
        // A token is `$` followed by at least one ASCII letter.
        if end < bytes.len() && bytes[end].is_ascii_alphabetic() {
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            out.push(s[start..end].to_string());
            i = end;
        } else {
            i = start + 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavour_parse_is_case_insensitive() {
        assert_eq!(MdmFlavour::parse("Fleet"), Some(MdmFlavour::Fleet));
        assert_eq!(MdmFlavour::parse(" JAMF "), Some(MdmFlavour::Jamf));
        assert_eq!(MdmFlavour::parse("nope"), None);
    }

    #[test]
    fn is_known_fleet_exact_and_prefix() {
        assert!(is_known("FLEET_VAR_HOST_UUID", MdmFlavour::Fleet));
        assert!(is_known("FLEET_VAR_DIGICERT_DATA_MyCA", MdmFlavour::Fleet));
        // Bare prefix with no suffix is not a complete token.
        assert!(!is_known("FLEET_VAR_DIGICERT_DATA_", MdmFlavour::Fleet));
        // Typo.
        assert!(!is_known("FLEET_VAR_HOST_UUDI", MdmFlavour::Fleet));
        // Legacy variable — intentionally not in the catalogue.
        assert!(!is_known(
            "FLEET_VAR_HOST_END_USER_EMAIL_IDP",
            MdmFlavour::Fleet
        ));
    }

    #[test]
    fn is_known_jamf_exact_and_prefix() {
        assert!(is_known("$USERNAME", MdmFlavour::Jamf));
        assert!(is_known("$SERIALNUMBER", MdmFlavour::Jamf));
        assert!(is_known("$EXTENSIONATTRIBUTE_42", MdmFlavour::Jamf));
        assert!(!is_known("$EXTENSIONATTRIBUTE_", MdmFlavour::Jamf));
        assert!(!is_known("$NOTAVAR", MdmFlavour::Jamf));
    }

    #[test]
    fn extract_tokens_jamf_with_static_text() {
        assert_eq!(
            extract_tokens("$USERNAME@acme.com", MdmFlavour::Jamf),
            vec!["$USERNAME".to_string()]
        );
        assert_eq!(
            extract_tokens("$COMPUTERNAME — $FULLNAME", MdmFlavour::Jamf),
            vec!["$COMPUTERNAME".to_string(), "$FULLNAME".to_string()]
        );
    }

    #[test]
    fn extract_tokens_fleet() {
        assert_eq!(
            extract_tokens("url=FLEET_VAR_NDES_SCEP_PROXY_URL/scep", MdmFlavour::Fleet),
            vec!["FLEET_VAR_NDES_SCEP_PROXY_URL".to_string()]
        );
    }
}
