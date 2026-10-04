//! What Fleet refuses to accept as a configuration profile or declaration.
//!
//! A GitOps fragment that Fleet rejects at upload has failed as surely as one
//! that never generated, only later and somewhere else. These are Fleet's own
//! server-side rules, carried here so a generator can refuse first, in Fleet's
//! words. Each rule names the Fleet source it mirrors, checked against
//! fleet-v4.92.2 (69c2103f) — the release contour targets; a rule Fleet
//! changes is a change here. One entry is newer than that release and is
//! marked: refusing it keeps a fragment valid on the next one as well.

use plist::Value;

/// One reason Fleet would refuse a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// What Fleet objects to: a PayloadType, identifier, name or declaration type.
    pub subject: String,
    /// Fleet's message, or the substance of it.
    pub reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.subject, self.reason)
    }
}

/// Fleet's message for a profile that touches FileVault, which Fleet manages.
///
/// server/mdm/apple/mobileconfig/mobileconfig.go `DiskEncryptionProfileRestrictionErrMsg`.
pub const FILEVAULT_REFUSAL: &str = "Fleet manages disk encryption itself: the configuration profile can't \
     include FileVault settings (use the fleet's enable_disk_encryption instead)";

/// PayloadTypes Fleet delivers itself (mobileconfig.go `FleetPayloadTypes`).
const FILEVAULT_TYPES: &[&str] = &[
    "com.apple.MCX.FileVault2",
    "com.apple.security.FDERecoveryKeyEscrow",
];
/// No longer supported in macOS 10.13 and later, and refused (`FleetPayloadTypes`).
const UNSUPPORTED_TYPES: &[&str] = &["com.apple.security.FDERecoveryRedirect"];
/// PayloadIdentifiers Fleet owns (mobileconfig.go `FleetPayloadIdentifiers`).
const RESERVED_IDENTIFIERS: &[&str] = &[
    "com.fleetdm.fleet.mdm.filevault",
    "com.fleetdm.fleetd.config",
    "com.fleetdm.caroot",
];
/// Profile names Fleet owns (server/mdm/mdm.go `FleetReservedProfileNames`).
const RESERVED_NAMES: &[&str] = &[
    "Fleetd configuration",
    "Disk encryption",
    "Windows OS Updates",
    "Fleet macOS OS Updates",
    "Fleet iOS OS Updates",
    "Fleet iPadOS OS Updates",
    "Fleet root certificate authority (CA)",
    // Reserved on Fleet main after fleet-v4.92.2 branched; refused here so a
    // fragment also loads on the next release.
    "Fleetd enroll secret",
];

/// Screen a `.mobileconfig` the way Fleet's `Mobileconfig.ScreenPayloads` does.
///
/// Returns every refusal, not only the first. Fleet's `allowCustomFileVault`
/// server option, off by default, is not assumed.
pub fn screen_mobileconfig(bytes: &[u8]) -> anyhow::Result<Vec<Refusal>> {
    let profile: Value = plist::from_bytes(bytes)?;
    let top = profile
        .as_dictionary()
        .ok_or_else(|| anyhow::anyhow!("a .mobileconfig must be a dictionary"))?;
    let mut out = Vec::new();
    let name = |d: &plist::Dictionary| {
        d.get("PayloadDisplayName")
            .and_then(Value::as_string)
            .map(str::to_string)
    };
    if let Some(n) = name(top).filter(|n| RESERVED_NAMES.contains(&n.as_str())) {
        out.push(Refusal {
            subject: n,
            reason: "a profile name Fleet reserves for its own profiles".into(),
        });
    }
    for item in top
        .get("PayloadContent")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(item) = item.as_dictionary() else {
            continue;
        };
        let ty = item
            .get("PayloadType")
            .and_then(Value::as_string)
            .unwrap_or_default();
        if FILEVAULT_TYPES.contains(&ty)
            || (ty == "com.apple.MCX" && item.contains_key("DestroyFVKeyOnStandby"))
        {
            out.push(Refusal {
                subject: ty.to_string(),
                reason: FILEVAULT_REFUSAL.into(),
            });
        }
        if UNSUPPORTED_TYPES.contains(&ty) {
            out.push(Refusal {
                subject: ty.to_string(),
                reason: "a PayloadType Fleet does not accept".into(),
            });
        }
        if let Some(id) = item
            .get("PayloadIdentifier")
            .and_then(Value::as_string)
            .filter(|id| RESERVED_IDENTIFIERS.contains(id))
        {
            out.push(Refusal {
                subject: id.to_string(),
                reason: "a PayloadIdentifier Fleet reserves".into(),
            });
        }
        if let Some(n) = name(item).filter(|n| RESERVED_NAMES.contains(&n.as_str())) {
            out.push(Refusal {
                subject: n,
                reason: "a PayloadDisplayName Fleet reserves".into(),
            });
        }
    }
    Ok(out)
}

/// Declaration types Fleet refuses outright (server/fleet/apple_mdm.go `ForbiddenDeclTypes`).
const FORBIDDEN_DECLARATIONS: &[&str] = &[
    "com.apple.configuration.watch.enrollment",
    "com.apple.configuration.account.google",
    "com.apple.management.server-capabilities",
];
/// Apple's DeclarationBase cap, enforced by Fleet (`MDMAppleDeclarationIdentifierMaxLen`).
pub const DECLARATION_IDENTIFIER_MAX: usize = 64;

/// Screen a declaration the way Fleet's `MDMAppleRawDeclaration.ValidateUserProvided` does.
pub fn screen_declaration(declaration_type: &str, identifier: &str) -> Vec<Refusal> {
    let mut out = Vec::new();
    let refuse = |reason: &str| Refusal {
        subject: declaration_type.to_string(),
        reason: reason.into(),
    };
    if FORBIDDEN_DECLARATIONS.contains(&declaration_type) {
        out.push(refuse("a declaration type Fleet forbids"));
    }
    if declaration_type == "com.apple.configuration.management.status-subscriptions" {
        out.push(refuse(
            "Fleet can't take status subscriptions; it gets host vitals from queries and policies",
        ));
    }
    if declaration_type == "com.apple.configuration.package" {
        out.push(refuse("Fleet can't take software management declarations; software is managed in Fleet's Software tab"));
    }
    if !declaration_type.starts_with("com.apple.configuration.")
        && !declaration_type.starts_with("com.apple.management.")
    {
        out.push(refuse("Fleet takes only configuration (com.apple.configuration.) and management (com.apple.management.) declarations here"));
    }
    if identifier.len() > DECLARATION_IDENTIFIER_MAX {
        out.push(Refusal {
            subject: identifier.to_string(),
            reason: format!(
                "Identifier is {} bytes; Fleet and Apple allow {DECLARATION_IDENTIFIER_MAX}",
                identifier.len()
            ),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(items: &[(&str, &str, &str)], top_name: &str) -> Vec<u8> {
        let mut top = plist::Dictionary::new();
        top.insert("PayloadDisplayName".into(), Value::String(top_name.into()));
        let content = items
            .iter()
            .map(|(ty, id, name)| {
                let mut d = plist::Dictionary::new();
                d.insert("PayloadType".into(), Value::String((*ty).into()));
                d.insert("PayloadIdentifier".into(), Value::String((*id).into()));
                d.insert("PayloadDisplayName".into(), Value::String((*name).into()));
                Value::Dictionary(d)
            })
            .collect();
        top.insert("PayloadContent".into(), Value::Array(content));
        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &Value::Dictionary(top)).unwrap();
        buf
    }

    #[test]
    fn an_ordinary_profile_passes() {
        let p = profile(&[("com.apple.dock", "com.acme.dock", "Dock")], "Acme Dock");
        assert!(screen_mobileconfig(&p).unwrap().is_empty());
    }

    #[test]
    fn filevault_reserved_identifiers_and_names_are_refused() {
        let p = profile(
            &[
                ("com.apple.MCX.FileVault2", "com.acme.fv", "FV"),
                ("com.apple.dock", "com.fleetdm.fleetd.config", "Dock"),
                (
                    "com.apple.security.FDERecoveryRedirect",
                    "com.acme.r",
                    "Disk encryption",
                ),
            ],
            "Fleetd configuration",
        );
        let r = screen_mobileconfig(&p).unwrap();
        let subjects: Vec<&str> = r.iter().map(|x| x.subject.as_str()).collect();
        for want in [
            "com.apple.MCX.FileVault2",
            "com.fleetdm.fleetd.config",
            "com.apple.security.FDERecoveryRedirect",
            "Disk encryption",
            "Fleetd configuration",
        ] {
            assert!(subjects.contains(&want), "missing {want}: {subjects:?}");
        }
    }

    #[test]
    fn mcx_is_refused_only_with_filevault_options() {
        let mut top = plist::Dictionary::new();
        let mut item = plist::Dictionary::new();
        item.insert("PayloadType".into(), Value::String("com.apple.MCX".into()));
        item.insert("DestroyFVKeyOnStandby".into(), Value::Boolean(true));
        top.insert(
            "PayloadContent".into(),
            Value::Array(vec![Value::Dictionary(item)]),
        );
        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &Value::Dictionary(top)).unwrap();
        assert_eq!(screen_mobileconfig(&buf).unwrap().len(), 1);
        let p = profile(
            &[("com.apple.MCX", "com.acme.mcx", "Time server")],
            "Acme MCX",
        );
        assert!(screen_mobileconfig(&p).unwrap().is_empty());
    }

    #[test]
    fn declarations_fleet_refuses() {
        assert!(
            screen_declaration(
                "com.apple.configuration.passcode.settings",
                "com.acme.passcode"
            )
            .is_empty()
        );
        assert!(screen_declaration("com.apple.management.properties", "com.acme.props").is_empty());
        for ty in [
            "com.apple.configuration.management.status-subscriptions",
            "com.apple.configuration.package",
            "com.apple.configuration.watch.enrollment",
            "com.apple.activation.simple",
        ] {
            assert!(
                !screen_declaration(ty, "com.acme.x").is_empty(),
                "{ty} must be refused"
            );
        }
        assert!(
            !screen_declaration("com.apple.configuration.passcode.settings", &"a".repeat(65))
                .is_empty()
        );
    }
}
