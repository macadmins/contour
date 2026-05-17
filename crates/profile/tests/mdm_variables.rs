//! Integration: `var:` MDM-variable references and unknown-token warnings.

use std::process::Command;

fn contour() -> Command {
    Command::new(env!("CARGO_BIN_EXE_profile"))
}

const CONFIG: &str = r#"[organization]
name = "Test"
domain = "com.test"

[mdm_variables]
mdm = "fleet"

[mdm_variables.pool]
SCEP_CHALLENGE = "FLEET_VAR_NDES_SCEP_CHALLENGE"

[secrets.refs]
NDES = "var:SCEP_CHALLENGE"
"#;

/// A SCEP recipe whose Challenge field references the pooled variable.
const SCEP_RECIPE: &str = r#"[recipe]
name = "scep"
description = "SCEP test"

[[profile]]
filename = "scep.mobileconfig"
payload_type = "com.apple.security.scep"
display_name = "SCEP"
description = ""
removal_disallowed = false

[profile.fields]
"PayloadContent.Challenge" = "VAR_PLACEHOLDER"
"PayloadContent.URL" = "https://scep.example.com"

[profile.extra_fields]
"#;

fn read_all(dir: &std::path::Path) -> String {
    let mut out = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            for e in std::fs::read_dir(&p).unwrap().flatten() {
                stack.push(e.path());
            }
        } else if let Ok(s) = std::fs::read_to_string(&p) {
            out.push_str(&s);
        }
    }
    out
}

/// Write the config + recipe, run generate from `dir`, return stdout
/// plus the concatenated output files.
fn generate(dir: &std::path::Path, recipe_body: &str) -> (String, String) {
    std::fs::create_dir_all(dir.join(".contour")).unwrap();
    std::fs::write(dir.join(".contour/config.toml"), CONFIG).unwrap();
    let recipe = dir.join("r.toml");
    std::fs::write(&recipe, recipe_body).unwrap();
    let out = dir.join("out");
    let result = contour()
        .args([
            "generate",
            "--recipe",
            recipe.to_str().unwrap(),
            "--org",
            "com.test",
            "-o",
            out.to_str().unwrap(),
        ])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(result.status.success(), "generate should succeed");
    (
        String::from_utf8_lossy(&result.stdout).into_owned(),
        read_all(&out),
    )
}

#[test]
fn var_reference_resolves_to_pooled_token() {
    let dir = tempfile::tempdir().unwrap();
    let body = SCEP_RECIPE.replace("VAR_PLACEHOLDER", "var:SCEP_CHALLENGE");
    let (_stdout, content) = generate(dir.path(), &body);
    assert!(
        content.contains("FLEET_VAR_NDES_SCEP_CHALLENGE"),
        "var: should resolve to the pooled MDM token: {content}"
    );
}

#[test]
fn secret_reference_can_reuse_a_pooled_variable() {
    let dir = tempfile::tempdir().unwrap();
    // secret:NDES -> [secrets.refs] NDES = "var:SCEP_CHALLENGE" -> token
    let body = SCEP_RECIPE.replace("VAR_PLACEHOLDER", "secret:NDES");
    let (_stdout, content) = generate(dir.path(), &body);
    assert!(
        content.contains("FLEET_VAR_NDES_SCEP_CHALLENGE"),
        "secret: -> var: chain should reach the MDM token: {content}"
    );
}

#[test]
fn unknown_mdm_variable_is_warned() {
    let dir = tempfile::tempdir().unwrap();
    // A typo'd Fleet token written literally into a field.
    let body = SCEP_RECIPE.replace("VAR_PLACEHOLDER", "FLEET_VAR_HOST_UUDI");
    let (stdout, _content) = generate(dir.path(), &body);
    assert!(
        stdout.contains("Unknown fleet variable: FLEET_VAR_HOST_UUDI"),
        "a typo'd token should be flagged: {stdout}"
    );
}

#[test]
fn legacy_mdm_variable_gets_a_legacy_notice() {
    let dir = tempfile::tempdir().unwrap();
    let body = SCEP_RECIPE.replace("VAR_PLACEHOLDER", "FLEET_VAR_HOST_END_USER_EMAIL_IDP");
    let (stdout, _content) = generate(dir.path(), &body);
    assert!(
        stdout.contains("Legacy fleet variable: FLEET_VAR_HOST_END_USER_EMAIL_IDP"),
        "a legacy token should get a legacy notice, not 'unknown': {stdout}"
    );
    assert!(
        !stdout.contains("Unknown fleet variable: FLEET_VAR_HOST_END_USER_EMAIL_IDP"),
        "a legacy token must not be reported as merely unknown: {stdout}"
    );
}
