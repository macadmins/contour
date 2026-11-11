//! Built-in vendor recipes render the profile the vendor documents.
//!
//! - `fleet-psso`: the payloads of Fleet's
//!   `fleet-sso-extension-example.mobileconfig`, with the domain filled in.
//! - `okta`, `entra-psso`, `entra-psso-password`: the vendor's extension and
//!   the authentication method each recipe is for.
//! - `claude-code`: the payload of Anthropic's
//!   `com.anthropic.claudecode.mobileconfig` example.
//! - `little-snitch`: the content filter and system extension payloads of
//!   Objective Development's `LittleSnitch.mobileconfig`. Its third payload
//!   type is not in Apple's schema and is left out.

use assert_cmd::Command;
use plist::Value;

fn profile(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("profile")
        .unwrap()
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn fleet_psso_is_listed_with_its_variable() {
    let dir = tempfile::tempdir().unwrap();
    let out = profile(dir.path(), &["generate", "--list-recipes", "--json"]);
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let text = json.to_string();
    assert!(text.contains("\"fleet-psso\""), "{text}");
    assert!(text.contains("FLEET_DOMAIN"), "{text}");
}

#[test]
fn fleet_psso_renders_one_profile_with_both_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let out = profile(
        dir.path(),
        &[
            "generate",
            "--recipe",
            "fleet-psso",
            "--set",
            "FLEET_DOMAIN=fleet.example.com",
            "--org",
            "com.acme",
            "-o",
            "out",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // One file: the profile must arrive whole, before Setup Assistant.
    let files: Vec<_> = std::fs::read_dir(dir.path().join("out"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(files, ["fleet-psso.mobileconfig"]);

    let raw = std::fs::read_to_string(dir.path().join("out/fleet-psso.mobileconfig")).unwrap();
    assert!(!raw.contains("{{"), "placeholder left in:\n{raw}");

    let top = Value::from_reader_xml(raw.as_bytes()).unwrap();
    let payloads = top.as_dictionary().unwrap()["PayloadContent"]
        .as_array()
        .unwrap();
    let of = |ty: &str| {
        payloads
            .iter()
            .map(|p| p.as_dictionary().unwrap())
            .find(|p| p["PayloadType"].as_string() == Some(ty))
            .unwrap_or_else(|| panic!("no {ty} payload"))
    };
    let s = |v: &Value| v.as_string().unwrap().to_owned();

    let sso = of("com.apple.extensiblesso");
    assert_eq!(
        s(&sso["ExtensionIdentifier"]),
        "com.fleetdm.fleet-desktop.pssoextension"
    );
    assert_eq!(s(&sso["TeamIdentifier"]), "8VBZ3948LU");
    assert_eq!(s(&sso["Type"]), "Redirect");
    // Fleet's variable passes through untouched.
    assert_eq!(
        s(&sso["RegistrationToken"]),
        "$FLEET_VAR_PSSO_DEVICE_REGISTRATION_TOKEN"
    );
    let ext = sso["ExtensionData"].as_dictionary().unwrap();
    assert_eq!(s(&ext["BaseURL"]), "https://fleet.example.com");
    let psso = sso["PlatformSSO"].as_dictionary().unwrap();
    assert_eq!(s(&psso["AuthenticationMethod"]), "Password");
    assert_eq!(psso["UseSharedDeviceKeys"].as_boolean(), Some(true));
    assert_eq!(
        psso["EnableRegistrationDuringSetup"].as_boolean(),
        Some(true)
    );
    let map = psso["TokenToUserMapping"].as_dictionary().unwrap();
    assert_eq!(s(&map["AccountName"]), "accountName");

    // Both the app and its extension get the authsrv domain.
    let domains = of("com.apple.associated-domains");
    let apps: Vec<(String, String)> = domains["Configuration"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_dictionary().unwrap())
        .map(|c| {
            (
                s(&c["ApplicationIdentifier"]),
                s(&c["AssociatedDomains"].as_array().unwrap()[0]),
            )
        })
        .collect();
    let authsrv = "authsrv:fleet.example.com".to_owned();
    assert_eq!(
        apps,
        [
            (
                "8VBZ3948LU.com.fleetdm.fleet-desktop".to_owned(),
                authsrv.clone()
            ),
            (
                "8VBZ3948LU.com.fleetdm.fleet-desktop.pssoextension".to_owned(),
                authsrv
            ),
        ]
    );
}

#[test]
fn little_snitch_renders_the_filter_and_extension_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let out = profile(
        dir.path(),
        &[
            "generate",
            "--recipe",
            "little-snitch",
            "--org",
            "com.acme",
            "-o",
            "out",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let top = Value::from_file(dir.path().join("out/little-snitch.mobileconfig")).unwrap();
    let payloads = top.as_dictionary().unwrap()["PayloadContent"]
        .as_array()
        .unwrap();
    let of = |ty: &str| {
        payloads
            .iter()
            .map(|p| p.as_dictionary().unwrap())
            .find(|p| p["PayloadType"].as_string() == Some(ty))
            .unwrap_or_else(|| panic!("no {ty} payload"))
    };
    assert_eq!(payloads.len(), 2);

    let ext = "at.obdev.littlesnitch.networkextension";
    let requirement = format!(
        "identifier \"{ext}\" and anchor apple generic and certificate leaf[subject.OU] = MLZF7K7B5R"
    );

    let filter = of("com.apple.webcontent-filter");
    assert_eq!(filter["FilterType"].as_string(), Some("Plugin"));
    assert_eq!(filter["FilterGrade"].as_string(), Some("firewall"));
    assert_eq!(filter["FilterSockets"].as_boolean(), Some(true));
    assert_eq!(
        filter["PluginBundleID"].as_string(),
        Some("at.obdev.littlesnitch")
    );
    assert_eq!(
        filter["FilterDataProviderBundleIdentifier"].as_string(),
        Some(ext)
    );
    assert_eq!(
        filter["FilterDataProviderDesignatedRequirement"].as_string(),
        Some(requirement.as_str())
    );

    let allowed = of("com.apple.system-extension-policy")["AllowedSystemExtensions"]
        .as_dictionary()
        .unwrap();
    let ids = allowed["MLZF7K7B5R"].as_array().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].as_string(), Some(ext));
}

/// The Platform SSO recipes for the IdPs with a native integration: each
/// renders an Extensible SSO payload naming that vendor's extension and the
/// authentication method the recipe is for, with no placeholder left.
#[test]
fn okta_and_entra_psso_recipes_name_their_extension_and_method() {
    // (recipe, --set values, file, ExtensionIdentifier, TeamIdentifier, method)
    let cases: [(&str, &[&str], &str, &str, &str, &str); 3] = [
        (
            "okta",
            &[
                "OKTA_DOMAIN=acme.okta.com",
                "REGISTRATION_TOKEN=tok",
                "SCEP_CHALLENGE=ch",
            ],
            "okta-sso-extension.mobileconfig",
            "com.okta.mobile.auth-service-extension",
            "B7F62B65BN",
            "UserSecureEnclaveKey",
        ),
        (
            "entra-psso",
            &[
                "PSSO_REGISTRATION_TOKEN=tok",
                "PSSO_ACCOUNT_DISPLAY_NAME=Acme",
            ],
            "entra-psso-secure-enclave.mobileconfig",
            "com.microsoft.CompanyPortalMac.ssoextension",
            "UBF8T346G9",
            "UserSecureEnclaveKey",
        ),
        (
            "entra-psso-password",
            &[
                "PSSO_REGISTRATION_TOKEN=tok",
                "PSSO_ACCOUNT_DISPLAY_NAME=Acme",
            ],
            "entra-psso-password.mobileconfig",
            "com.microsoft.CompanyPortalMac.ssoextension",
            "UBF8T346G9",
            "Password",
        ),
    ];

    for (recipe, sets, file, extension, team, method) in cases {
        let dir = tempfile::tempdir().unwrap();
        let mut args = vec![
            "generate", "--recipe", recipe, "--org", "com.acme", "-o", "out",
        ];
        for set in sets {
            args.extend(["--set", set]);
        }
        let out = profile(dir.path(), &args);
        assert!(
            out.status.success(),
            "{recipe}: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let raw = std::fs::read_to_string(dir.path().join("out").join(file))
            .unwrap_or_else(|e| panic!("{recipe}: {file}: {e}"));
        assert!(!raw.contains("{{"), "{recipe}: placeholder left in:\n{raw}");

        let top = Value::from_reader_xml(raw.as_bytes()).unwrap();
        let sso = top.as_dictionary().unwrap()["PayloadContent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_dictionary().unwrap())
            .find(|p| p["PayloadType"].as_string() == Some("com.apple.extensiblesso"))
            .unwrap_or_else(|| panic!("{recipe}: no Extensible SSO payload"));
        assert_eq!(
            sso["ExtensionIdentifier"].as_string(),
            Some(extension),
            "{recipe}"
        );
        assert_eq!(sso["TeamIdentifier"].as_string(), Some(team), "{recipe}");
        let psso = sso["PlatformSSO"].as_dictionary().unwrap();
        assert_eq!(
            psso["AuthenticationMethod"].as_string(),
            Some(method),
            "{recipe}"
        );
        assert_eq!(
            psso["UseSharedDeviceKeys"].as_boolean(),
            Some(true),
            "{recipe}"
        );
    }
}

/// `claude-code` writes managed settings into the `com.anthropic.claudecode`
/// preference domain, forced, as Anthropic's MDM example does.
#[test]
fn claude_code_forces_settings_in_its_preference_domain() {
    let dir = tempfile::tempdir().unwrap();
    let out = profile(
        dir.path(),
        &[
            "generate",
            "--recipe",
            "claude-code",
            "--org",
            "com.acme",
            "-o",
            "out",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let top = Value::from_file(
        dir.path()
            .join("out/claude-code-managed-settings.mobileconfig"),
    )
    .unwrap();
    let payloads = top.as_dictionary().unwrap()["PayloadContent"]
        .as_array()
        .unwrap();
    assert_eq!(payloads.len(), 1);
    let payload = payloads[0].as_dictionary().unwrap();
    assert_eq!(
        payload["PayloadType"].as_string(),
        Some("com.apple.ManagedClient.preferences")
    );
    let forced = payload["PayloadContent"].as_dictionary().unwrap()["com.anthropic.claudecode"]
        .as_dictionary()
        .unwrap()["Forced"]
        .as_array()
        .unwrap();
    let settings = forced[0].as_dictionary().unwrap()["mcx_preference_settings"]
        .as_dictionary()
        .unwrap();
    let permissions = settings["permissions"].as_dictionary().unwrap();
    assert_eq!(
        permissions["disableBypassPermissionsMode"].as_string(),
        Some("disable")
    );
}
