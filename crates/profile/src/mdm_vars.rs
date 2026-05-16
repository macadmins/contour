//! MDM deploy-time variable catalogues.
//!
//! Tokens like Jamf `%Username%` or Fleet `FLEET_VAR_HOST_UUID` are
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
pub const FLEET_EXACT: &[&str] = &[
    "FLEET_VAR_NDES_SCEP_CHALLENGE",
    "FLEET_VAR_NDES_SCEP_PROXY_URL",
    "FLEET_VAR_HOST_END_USER_EMAIL_IDP",
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

/// Jamf payload variables (`%...%`).
pub const JAMF_VARS: &[&str] = &[
    "%Username%",
    "%FullName%",
    "%RealName%",
    "%EmailAddress%",
    "%PhoneNumber%",
    "%Position%",
    "%Department%",
    "%Building%",
    "%Room%",
    "%SerialNumber%",
    "%UDID%",
    "%MACAddress%",
    "%ComputerName%",
    "%AssetTag%",
    "%JSSID%",
    "%ProductName%",
    "%Model%",
    "%ModelIdentifier%",
    "%OSVersion%",
];

/// Apple in-profile variables. Apple defines very few literal
/// substitution tokens; operators extend coverage via the config
/// `[mdm_variables.pool]`.
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
        MdmFlavour::Jamf => JAMF_VARS.contains(&token),
        MdmFlavour::Apple => APPLE_VARS.contains(&token),
    }
}

/// Extract every MDM variable token of `flavour`'s shape from `s`
/// (e.g. `%Username%@acme.com` yields `["%Username%"]`).
pub fn extract_tokens(s: &str, flavour: MdmFlavour) -> Vec<String> {
    match flavour {
        MdmFlavour::Fleet => extract_fleet(s),
        MdmFlavour::Jamf | MdmFlavour::Apple => extract_percent(s),
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

fn extract_percent(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(open) = rest.find('%') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('%') else {
            break;
        };
        let token_end = open + 1 + close + 1;
        let token = &rest[open..token_end];
        let inner = &token[1..token.len() - 1];
        if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric()) {
            out.push(token.to_string());
        }
        rest = &rest[token_end..];
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
    }

    #[test]
    fn is_known_jamf() {
        assert!(is_known("%Username%", MdmFlavour::Jamf));
        assert!(!is_known("%Userrname%", MdmFlavour::Jamf));
    }

    #[test]
    fn extract_tokens_jamf_with_static_text() {
        assert_eq!(
            extract_tokens("%Username%@acme.com", MdmFlavour::Jamf),
            vec!["%Username%".to_string()]
        );
        assert_eq!(
            extract_tokens("%ProductName% of %FullName%", MdmFlavour::Jamf),
            vec!["%ProductName%".to_string(), "%FullName%".to_string()]
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
