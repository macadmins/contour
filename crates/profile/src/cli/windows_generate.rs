//! `profile windows generate` — SyncML from a settings TOML.
//!
//! A subcommand group of its own rather than a flag on `profile generate`:
//! that command carries 19 flags shaped for Apple payloads (`--org`,
//! `--full`, `--recipe`, `--set`), none of which mean anything for a CSP,
//! and `--org` has no Windows analogue at all.
//!
//! ## Input
//!
//! ```toml
//! [[setting]]
//! csp   = "Defender"
//! key   = "EnableNetworkProtection"
//! value = "1"
//!
//! [[setting]]
//! csp      = "Firewall"
//! key      = "EnableFirewall"
//! parent   = "MdmStore.PublicProfile"   # a name repeated under several parents
//! value    = "1"
//!
//! [[setting]]
//! csp      = "ADMX_ActiveXInstallService"
//! key      = "AxISURLZonePolicies"
//! action   = "enable"                    # ADMX-backed
//! [setting.elements]                     # every element, in the form Windows reads
//! InstallTrustedOCX     = "0"            # enum: 0 Don't install, 1 Prompt, 2 Silently
//! InstallSignedOCX      = "1"
//! InstallUnSignedOCX    = "0"
//! IgnoreUnknownCA       = false          # boolean: true or false
//! IgnoreInvalidCN       = false
//! IgnoreInvalidCertDate = false
//! IgnoreWrongCertUsage  = false
//!
//! [[setting]]
//! app      = "chrome"                    # a third-party template, not a CSP
//! key      = "DefaultCookiesSetting"
//! channel  = "user"                      # class Both: device unless asked
//! [setting.elements]
//! DefaultCookiesSetting = "2"
//! ```
//!
//! ## Third-party app policies
//!
//! `app` names a template Windows does not ship — Chrome, Edge, Firefox,
//! Brave, the Microsoft 365 apps, OneDrive, Adobe DC, FSLogix, winget. Those
//! policies do not exist on the device until the template is ingested, so
//! they are delivered in two steps: one `ADMXInstall` command per template,
//! carrying the vendor's ADMX file as its body, then the policies at
//! `…/Policy/Config/{App}~Policy~{category}/{Policy}`. The dataset
//! (`windows_app_policies`) names both URIs; the ADMX XML is not shipped
//! with contour — vendors license their templates — so `--admx-dir` points at
//! the files, and a missing one is an error naming where to fetch it.
//!
//! Windows will not let MDM ingest a policy that writes under
//! `Software\Policies\Microsoft\` (and two other roots) unless the location
//! is on Microsoft's allow-list. Such a policy is accepted by the device and
//! silently dropped. The dataset carries that verdict per policy with the
//! document it rests on, and this command refuses those rather than emit
//! them. Where Windows already ships the same template natively
//! (`in_box_area`), it warns: ingestion is the wrong route.
//!
//! ## Why every problem is reported, not just the first
//!
//! A settings file is edited as a whole. Failing on setting 1 of 30, being
//! fixed, then failing on setting 2 turns one review into thirty. Every
//! setting is resolved and validated, and the refusals are reported
//! together.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::windows::syncml::{
    Channel, Operation, WindowsError, admx_element_values, apply_instance, atomic_wrap, build_path,
    csp_for_key, decode_admx, deprecation_warning, find_admx_policy, find_app_policy,
    find_node_detail, find_setting, instance_placeholder, render, render_admx_install,
    resolve_channel, syncml_format, validate_value,
};

/// Default filename, matching `pppc.toml` / `btm.toml` / `app-privacy.toml`.
pub const DEFAULT_POLICY_FILE: &str = "windows.toml";

/// `windows.toml`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct WindowsFile {
    #[serde(default, rename = "setting")]
    pub settings: Vec<SettingEntry>,
}

/// One setting to deliver.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SettingEntry {
    /// CSP / policy area, e.g. `Defender`, `ADMX_WindowsExplorer`. Empty
    /// when `app` names a third-party template instead.
    #[serde(default)]
    pub csp: String,
    /// A third-party app template — `chrome`, `edge`, `firefox`, `office`,
    /// … — whose policy `key` is. Mutually exclusive with `csp`.
    #[serde(default)]
    pub app: Option<String>,

    /// Setting name within that CSP.
    pub key: String,

    /// Dot-path parent, required only when a CSP repeats a key name under
    /// several parents (`Firewall`'s three `EnableFirewall` nodes).
    #[serde(default)]
    pub parent: Option<String>,

    /// The value. Omitted for `action = "delete"` and for ADMX enable/disable.
    #[serde(default)]
    pub value: Option<toml::Value>,

    /// `device` or `user`. Omitted picks the setting's only channel, or
    /// device when it offers both.
    #[serde(default)]
    pub channel: Option<String>,

    /// Name to substitute for an instance placeholder such as `{ProfileName}`.
    #[serde(default)]
    pub instance: Option<String>,

    /// `set` (default), `delete`, `enable`, `disable`.
    #[serde(default)]
    pub action: Option<String>,

    /// ADMX element values, by element id. A boolean, a number, a string,
    /// or — for `multiText` and `list` — an array of strings.
    #[serde(default)]
    pub elements: Option<BTreeMap<String, toml::Value>>,
}

impl SettingEntry {
    fn label(&self) -> String {
        if let Some(app) = &self.app {
            return format!("{app}/{}", self.key);
        }
        match &self.parent {
            Some(p) => format!("{}/{}/{}", self.csp, p.replace('.', "/"), self.key),
            None => format!("{}/{}", self.csp, self.key),
        }
    }

    /// The TOML value as the string that goes on the wire.
    ///
    /// TOML distinguishes `1` from `"1"` and `true` from `"true"`; Windows
    /// does not — both arrive as text in `<Data>`. Normalising here means an
    /// author can write whichever reads better.
    fn value_string(&self) -> Option<String> {
        self.value.as_ref().map(|v| match v {
            toml::Value::String(s) => s.clone(),
            toml::Value::Integer(i) => i.to_string(),
            // NOT normalised to 1/0 here: the key's declared enum decides
            // the spelling, and validate_value applies it.
            toml::Value::Boolean(b) => b.to_string(),
            other => other.to_string(),
        })
    }
}

/// One resolved command, ready to render.
#[derive(Debug)]
pub struct Resolved {
    pub label: String,
    pub path: String,
    pub xml: String,
    pub warnings: Vec<String>,
    /// For a third-party policy: the template that must be ingested first.
    pub template: Option<TemplateRef>,
    /// The DDF marks this node `AtomicRequired`: it travels inside an
    /// `<Atomic>` with its siblings under the same instance.
    pub atomic: bool,
    /// Nodes the DDF says this one applies only alongside. Checked against
    /// the whole file in `resolve_all`, since one entry cannot see the rest.
    pub depends_on: Vec<windows_schema::NodeDependency>,
    /// The wire value, when this entry sets a plain value.
    pub value: Option<String>,
    /// This entry deletes its node rather than setting it.
    pub deletes: bool,
}

/// The LocURI prefix that names one instance — `…/ActiveSync/Accounts/acct1`,
/// `…/VPNv2/Corp` — so every Atomic node under it lands in the same
/// `<Atomic>`. Six components reach the CSP's top node, seven the instance
/// segment after it.
fn atomic_group_key(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let n = parts.len().min(7);
    parts[..n].join("/")
}

/// Commands in delivery order, with Atomic nodes grouped one `<Atomic>` per
/// instance at the position of the group's first member. Everything else is
/// emitted as it stands. Returns the commands and `(prefix, count)` per
/// group for the summary.
pub fn assemble(resolved: &[Resolved]) -> (Vec<String>, Vec<(String, usize)>) {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    // Ok(group index) | Err(plain command)
    let mut order: Vec<Result<usize, String>> = Vec::new();
    for r in resolved {
        if r.atomic {
            let key = atomic_group_key(&r.path);
            match groups.iter().position(|(k, _)| *k == key) {
                Some(i) => groups[i].1.push(r.xml.clone()),
                None => {
                    groups.push((key, vec![r.xml.clone()]));
                    order.push(Ok(groups.len() - 1));
                }
            }
        } else {
            order.push(Err(r.xml.clone()));
        }
    }
    let commands = order
        .into_iter()
        .map(|o| match o {
            Ok(i) => atomic_wrap(&groups[i].1),
            Err(xml) => xml,
        })
        .collect();
    let summary = groups.into_iter().map(|(k, v)| (k, v.len())).collect();
    (commands, summary)
}

/// One template to ingest: the file, the URI it is installed at, and where
/// an operator fetches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRef {
    pub app: String,
    pub admx_file: String,
    pub install_loc_uri: String,
    pub source_url: String,
}

/// Resolve and validate every setting, collecting refusals rather than
/// stopping at the first.
pub fn resolve_all(file: &WindowsFile) -> (Vec<Resolved>, Vec<String>, Vec<String>) {
    let caps = match mdm_schema::capabilities::read(mdm_schema::embedded_windows_capabilities()) {
        Ok(c) => c,
        Err(e) => {
            return (
                Vec::new(),
                vec![format!("reading windows schema: {e}")],
                Vec::new(),
            );
        }
    };
    let policies =
        windows_schema::admx_policies::read(windows_schema::embedded_windows_admx_policies())
            .unwrap_or_default();
    let app_policies =
        windows_schema::app_policies::read(windows_schema::embedded_windows_app_policies())
            .unwrap_or_default();
    let details =
        windows_schema::node_details::read(windows_schema::embedded_windows_node_details())
            .unwrap_or_default();

    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for entry in &file.settings {
        let resolved = match &entry.app {
            Some(app) => resolve_app_policy(entry, app, &app_policies),
            None => resolve_one(entry, &caps, &policies, &details),
        };
        match resolved {
            Ok(r) => out.push(r),
            Err(e) => errors.push(format!("{}: {e}", entry.label())),
        }
    }

    // Dependencies need the whole file: the node a setting depends on is
    // usually another entry in it.
    let unmet: Vec<Vec<String>> = out.iter().map(|r| unmet_dependencies(r, &out)).collect();
    for (r, extra) in out.iter_mut().zip(unmet) {
        r.warnings.extend(extra);
        warnings.extend(r.warnings.clone());
    }
    (out, errors, warnings)
}

/// A LocURI reduced to what identifies the node: the DDF writes
/// `Device/Vendor/MSFT/Bitlocker/…` where generation emits
/// `./Device/Vendor/MSFT/BitLocker/…`, and Firewall has no `Device/` at all.
fn node_key(uri: &str) -> String {
    let lower = uri.trim_start_matches("./").to_ascii_lowercase();
    lower
        .strip_prefix("device/")
        .map_or(lower.clone(), str::to_string)
}

/// Warnings for the dependencies of `r` the file does not satisfy.
///
/// Absent from the file: the node's own state on the device decides, which
/// is worth saying. Set to another value: the setting does nothing, which
/// is worth saying louder. Set to an allowed value, or set through an ADMX
/// body contour does not read back: nothing to say.
fn unmet_dependencies(r: &Resolved, all: &[Resolved]) -> Vec<String> {
    let allowed = |dep: &windows_schema::NodeDependency, v: &str| {
        dep.values.iter().any(|a| {
            a.trim_matches(|c| c == '[' || c == ']' || c == ' ')
                .eq_ignore_ascii_case(v)
        })
    };
    r.depends_on
        .iter()
        .filter_map(|dep| {
            let want = node_key(&dep.uri);
            let found = all.iter().find(|o| !o.deletes && node_key(&o.path) == want);
            let values = dep.values.join(" or ");
            match found.map(|o| o.value.as_deref()) {
                None => Some(format!(
                    "{}: applies only while {} is {values} (DDF {}), and this file does not set it",
                    r.label, dep.uri, dep.kind
                )),
                Some(Some(v)) if !allowed(dep, v) => Some(format!(
                    "{}: has no effect as written — it applies only while {} is {values} \
                     (DDF {}), and this file sets it to {v}",
                    r.label, dep.uri, dep.kind
                )),
                Some(_) => None,
            }
        })
        .collect()
}

/// A third-party app policy: the dataset already holds both LocURIs, so
/// there is no path to build — only a channel to pick, a verdict to honour,
/// and a body to render.
fn resolve_app_policy(
    entry: &SettingEntry,
    app: &str,
    app_policies: &[windows_schema::WindowsAppPolicy],
) -> Result<Resolved, WindowsError> {
    let policy = find_app_policy(app_policies, app, &entry.key).ok_or_else(|| {
        WindowsError::UnknownAppPolicy {
            app: app.to_string(),
            key: entry.key.clone(),
        }
    })?;
    // Windows already ships this template as a native Policy CSP area: the
    // ingested copy is not the route, and the dataset marks it as such.
    // Refuse with the pointer, which is the useful part.
    if let Some(native) = &policy.in_box_area {
        return Err(WindowsError::ShippedNatively {
            app: app.to_string(),
            key: entry.key.clone(),
            native: native.clone(),
        });
    }
    if !policy.ingestable {
        return Err(WindowsError::NotIngestable {
            app: app.to_string(),
            key: entry.key.clone(),
            reason: policy
                .ingest_reason
                .clone()
                .unwrap_or_else(|| "writes where Windows blocks MDM ingestion".into()),
            evidence: policy.ingest_evidence.clone(),
        });
    }
    let warnings = Vec::new();
    // Class decides the tree. `Both` takes the requested channel, device
    // by default, like an in-box node that offers both.
    let requested = entry.channel.as_deref().and_then(Channel::parse);
    let channel = match (policy.class.as_str(), requested) {
        ("Machine", Some(Channel::User)) | ("User", Some(Channel::Device)) => {
            return Err(WindowsError::ChannelMismatch {
                path: policy.device_loc_uri.clone(),
                requested: requested.unwrap_or(Channel::Device),
                available: format!("{} only", policy.class.to_ascii_lowercase()),
            });
        }
        ("User", _) => Channel::User,
        (_, Some(Channel::User)) => Channel::User,
        _ => Channel::Device,
    };
    let path = match channel {
        Channel::User => policy.user_loc_uri.clone(),
        _ => policy.device_loc_uri.clone(),
    };
    let action = entry.action.as_deref().unwrap_or("enable");
    let xml = match action {
        "delete" => render(Operation::Delete, &path, "", None),
        "disable" => render(
            Operation::Replace,
            &path,
            "chr",
            Some(&policy.disabled_payload()),
        ),
        _ => {
            let values =
                admx_element_values(&entry.key, &policy.elements, entry.elements.as_ref())?;
            render(
                Operation::Replace,
                &path,
                "chr",
                Some(&policy.payload(Some(&values))),
            )
        }
    };
    Ok(Resolved {
        label: entry.label(),
        path,
        xml,
        warnings,
        template: Some(TemplateRef {
            app: policy.app_name.clone(),
            admx_file: policy.admx_file.clone(),
            install_loc_uri: policy.admx_install_loc_uri.clone(),
            source_url: policy.source_url.clone(),
        }),
        depends_on: Vec::new(),
        value: None,
        deletes: false,
        atomic: false,
    })
}

/// The ADMXInstall commands for every template the resolved settings use,
/// one each, in first-use order — or the error that says which file is
/// missing and where to get it. Nothing is emitted for a partial set: an
/// ingested template with a missing sibling is a half-configured device.
pub fn ingestion_commands(
    resolved: &[Resolved],
    admx_dir: Option<&std::path::Path>,
) -> Result<Vec<(TemplateRef, String)>, WindowsError> {
    let mut seen: Vec<&TemplateRef> = Vec::new();
    for t in resolved.iter().filter_map(|r| r.template.as_ref()) {
        if !seen.iter().any(|s| s.install_loc_uri == t.install_loc_uri) {
            seen.push(t);
        }
    }
    let mut out = Vec::new();
    for t in seen {
        let Some(dir) = admx_dir else {
            return Err(WindowsError::TemplateMissing {
                admx_file: t.admx_file.clone(),
                app: t.app.clone(),
                source_url: t.source_url.clone(),
                dir: None,
            });
        };
        // Exact name first; then the same name in any case, since vendors
        // and archives disagree about it.
        let exact = dir.join(&t.admx_file);
        let found = if exact.is_file() {
            Some(exact)
        } else {
            std::fs::read_dir(dir).ok().and_then(|rd| {
                rd.flatten().map(|e| e.path()).find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.eq_ignore_ascii_case(&t.admx_file))
                })
            })
        };
        let Some(path) = found else {
            return Err(WindowsError::TemplateMissing {
                admx_file: t.admx_file.clone(),
                app: t.app.clone(),
                source_url: t.source_url.clone(),
                dir: Some(dir.display().to_string()),
            });
        };
        let bytes = std::fs::read(&path).map_err(|e| WindowsError::TemplateUnreadable {
            path: path.display().to_string(),
            why: e.to_string(),
        })?;
        let xml = decode_admx(&bytes).map_err(|why| WindowsError::TemplateUnreadable {
            path: path.display().to_string(),
            why,
        })?;
        out.push((t.clone(), render_admx_install(&t.install_loc_uri, &xml)));
    }
    Ok(out)
}

fn resolve_one(
    entry: &SettingEntry,
    caps: &[mdm_schema::types::Capability],
    policies: &[windows_schema::AdmxPolicy],
    details: &[windows_schema::NodeDetail],
) -> Result<Resolved, WindowsError> {
    if entry.csp.is_empty() {
        return Err(WindowsError::UnknownSetting {
            csp: "(none)".into(),
            key: entry.key.clone(),
        });
    }
    let (cap, key) = find_setting(caps, &entry.csp, &entry.key, entry.parent.as_deref())?;

    let requested = entry.channel.as_deref().and_then(Channel::parse);
    let provisional = build_path(
        &cap.payload_type,
        csp_for_key(cap, key),
        key.parent_key.as_deref(),
        &key.name,
        Channel::Device,
    );
    let channel = resolve_channel(cap, key, requested, &provisional)?;

    let mut path = build_path(
        &cap.payload_type,
        csp_for_key(cap, key),
        key.parent_key.as_deref(),
        &key.name,
        channel,
    );

    // An instance placeholder left in the path names no node on the device.
    if let Some(placeholder) = instance_placeholder(&path) {
        match &entry.instance {
            Some(name) => path = apply_instance(&path, name),
            None => {
                return Err(WindowsError::InstanceRequired {
                    path: path.clone(),
                    placeholder,
                });
            }
        }
    }

    let mut warnings = Vec::new();
    if let Some(w) = deprecation_warning(key) {
        warnings.push(format!("{}: {w}", entry.label()));
    }
    // What the DDF says beyond the type: a node that only applies while
    // another holds a given value is worth saying so about.
    let key_path = match key.parent_key.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => format!("{p}.{}", key.name),
        None => key.name.clone(),
    };
    let detail = find_node_detail(details, &cap.payload_type, &key_path);
    let atomic = detail.is_some_and(|d| d.atomic_required);
    let depends_on = detail.map(|d| d.dependencies.clone()).unwrap_or_default();

    let action = entry.action.as_deref().unwrap_or("set");

    // Delete names a node to remove and carries no value or format.
    if action == "delete" {
        return Ok(Resolved {
            label: entry.label(),
            path: path.clone(),
            xml: render(Operation::Delete, &path, "", None),
            warnings,
            template: None,
            atomic,
            // A node being removed needs nothing else in place.
            depends_on: Vec::new(),
            value: None,
            deletes: true,
        });
    }

    let format = syncml_format(&key.data_type).ok_or(WindowsError::ActionOnly {
        key: key.name.clone(),
    })?;

    // ADMX-backed settings carry a policy body rather than a bare value.
    if let Some(policy) = find_admx_policy(policies, &cap.payload_type, &key.name) {
        let body = if action == "disable" {
            policy.disabled_payload()
        } else {
            let values = admx_element_values(&key.name, &policy.elements, entry.elements.as_ref())?;
            policy.payload(Some(&values))
        };
        return Ok(Resolved {
            label: entry.label(),
            path: path.clone(),
            xml: render(Operation::Replace, &path, format, Some(&body)),
            warnings,
            template: None,
            atomic,
            depends_on,
            value: None,
            deletes: false,
        });
    }

    if action == "disable" || action == "enable" {
        return Err(WindowsError::NotAdmx {
            key: key.name.clone(),
        });
    }

    let raw = entry.value_string().ok_or(WindowsError::MissingValue {
        key: key.name.clone(),
    })?;
    // validate_value returns the wire text, so the declared enum spelling
    // survives: a TOML `true` becomes `True`, `true` or `1` depending on the
    // setting. See its docs.
    let wire = validate_value(key, &raw).map_err(|e| match e {
        // The DDF says what each allowed value means; a refusal that only
        // lists the values leaves the author guessing which one they wanted.
        WindowsError::NotInEnum {
            key: k,
            value,
            allowed,
        } if detail.is_some_and(|d| !d.value_descriptions.is_empty()) => {
            let meanings = detail
                .map(|d| {
                    d.value_descriptions
                        .iter()
                        .map(|v| format!("{} ({})", v.value, v.description.trim_end_matches('.')))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or(allowed);
            WindowsError::NotInEnum {
                key: k,
                value,
                allowed: meanings,
            }
        }
        other => other,
    })?;

    Ok(Resolved {
        label: entry.label(),
        path: path.clone(),
        xml: render(Operation::Replace, &path, format, Some(&wire)),
        warnings,
        template: None,
        atomic,
        depends_on,
        value: Some(wire),
        deletes: false,
    })
}

/// `profile windows generate`
/// The provenance comment every generated file opens with: which contour
/// and which Windows dataset checked the settings. A reader that finds it
/// knows every node, value and channel below was resolved against that
/// pin; a file without it was authored by hand and checked by nothing.
/// After the XML declaration when there is one, first line otherwise.
pub fn stamp_comment() -> String {
    let pin = windows_schema::dataset_pin();
    // `release v… sha256 <64 hex>` reads better with the hash shortened.
    let pin = match pin.split_once(" sha256 ") {
        Some((head, hex)) => format!("{head} sha256 {}", &hex[..12.min(hex.len())]),
        None => pin.to_string(),
    };
    format!(
        "<!-- generated by contour {} · windows-schema {pin} · every LocURI, value and channel \
         below was resolved against that dataset -->",
        env!("CARGO_PKG_VERSION")
    )
}

fn stamp(body: &str) -> String {
    let comment = stamp_comment();
    match body.strip_prefix("<?xml") {
        Some(rest) => match rest.find('\n') {
            Some(i) => format!("<?xml{}\n{comment}{}", &rest[..i], &rest[i..]),
            None => format!("{body}\n{comment}"),
        },
        None => format!("{comment}\n{body}"),
    }
}

pub fn handle_generate(
    input: &str,
    output: Option<&str>,
    envelope: bool,
    write: bool,
    admx_dir: Option<&str>,
    json: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(input).with_context(|| format!("reading {input}"))?;
    let file: WindowsFile = toml::from_str(&text).with_context(|| format!("parsing {input}"))?;
    if file.settings.is_empty() {
        bail!("no [[setting]] entries in {input} — nothing to generate");
    }

    let (resolved, errors, warnings) = resolve_all(&file);

    if !errors.is_empty() {
        // Every refusal at once: a settings file is edited as a whole.
        bail!(
            "{} of {} setting(s) refused:\n  {}",
            errors.len(),
            file.settings.len(),
            errors.join("\n  ")
        );
    }

    // Templates first: a policy under an area that does not exist yet is
    // accepted and ignored, so the ADMXInstall commands lead.
    let ingestion = ingestion_commands(&resolved, admx_dir.map(std::path::Path::new))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut commands: Vec<String> = ingestion.iter().map(|(_, xml)| xml.clone()).collect();
    let (settings, atomic_groups) = assemble(&resolved);
    commands.extend(settings);
    let body = if envelope {
        crate::windows::syncml::envelope(&commands)
    } else {
        commands.join("\n")
    };
    let body = stamp(&body);

    let dest = output.map(PathBuf::from);
    // Naming an output file is asking for it to be written.
    let write = write || dest.is_some();
    if write {
        let path = dest
            .clone()
            .unwrap_or_else(|| PathBuf::from("windows-profile.xml"));
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, &body).with_context(|| format!("writing {}", path.display()))?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "written": write,
                "dataset_pin": windows_schema::dataset_pin(),
                "settings": resolved.len(),
                "envelope": envelope,
                "ingested_templates": ingestion.iter().map(|(t, _)| serde_json::json!({
                    "app": t.app, "admx_file": t.admx_file, "loc_uri": t.install_loc_uri,
                })).collect::<Vec<_>>(),
                "paths": resolved.iter().map(|r| &r.path).collect::<Vec<_>>(),
                "atomic_groups": atomic_groups.iter().map(|(k, n)| serde_json::json!({"prefix": k, "settings": n})).collect::<Vec<_>>(),
                "warnings": warnings,
            }))?
        );
        return Ok(());
    }

    for w in &warnings {
        println!("{} {w}", "!".yellow());
    }

    if write {
        println!(
            "{} {} setting(s) -> {}",
            "✓".green(),
            resolved.len(),
            dest.unwrap_or_else(|| PathBuf::from("windows-profile.xml"))
                .display()
        );
        for (t, _) in &ingestion {
            println!(
                "  {} ← {}  {}",
                "ingest".cyan(),
                t.admx_file,
                t.install_loc_uri.dimmed()
            );
        }
        for r in &resolved {
            // Both: the label is what the author wrote, the path is what the
            // device sees. Showing only one leaves the reader translating.
            println!("  {}  {}", r.label, r.path.dimmed());
        }
        for (k, n) in &atomic_groups {
            println!("  {} {n} setting(s) under {}", "atomic".cyan(), k.dimmed());
        }
    } else {
        println!("{body}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(toml_text: &str) -> (Vec<Resolved>, Vec<String>, Vec<String>) {
        let file: WindowsFile = toml::from_str(toml_text).expect("parse");
        resolve_all(&file)
    }

    /// The provenance stamp leads every file, names the dataset pin, and
    /// sits after the XML declaration when an envelope has one.
    #[test]
    fn generated_files_open_with_the_dataset_stamp() {
        let comment = stamp_comment();
        assert!(comment.starts_with("<!-- generated by contour "));
        assert!(comment.contains("windows-schema "));
        assert!(!comment.contains("unstamped"), "the build must have stamped data/: {comment}");

        let bare = stamp("<Replace>…</Replace>");
        assert!(bare.starts_with(&comment), "{bare}");
        assert!(bare.ends_with("<Replace>…</Replace>"));

        let enveloped = stamp("<?xml version=\"1.0\"?>\n<SyncML>…</SyncML>");
        let mut lines = enveloped.lines();
        assert!(lines.next().unwrap().starts_with("<?xml"));
        assert_eq!(lines.next().unwrap(), comment);
        assert_eq!(lines.next().unwrap(), "<SyncML>…</SyncML>");
    }

    #[test]
    fn generates_a_plain_int_setting() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
csp = "Defender"
key = "EnableNetworkProtection"
value = 1
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert_eq!(ok.len(), 1);
        assert_eq!(
            ok[0].path,
            "./Device/Vendor/MSFT/Policy/Config/Defender/EnableNetworkProtection"
        );
        assert!(
            ok[0]
                .xml
                .contains("<Format xmlns=\"syncml:metinf\">int</Format>")
        );
        assert!(ok[0].xml.contains("<Data>1</Data>"));
    }

    #[test]
    fn a_repeated_key_name_needs_its_parent() {
        // Firewall carries three EnableFirewall nodes. Naming one without a
        // parent is ambiguous; with it, the path is exact.
        let (ok, err, _) = resolve(
            r#"
[[setting]]
csp = "Firewall"
key = "EnableFirewall"
parent = "MdmStore.PublicProfile"
value = true
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert_eq!(
            ok[0].path,
            "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableFirewall"
        );
    }

    #[test]
    fn enum_violations_are_refused_with_the_allowed_set() {
        let (_, err, _) = resolve(
            r#"
[[setting]]
csp = "Defender"
key = "PUAProtection"
value = 99
"#,
        );
        assert_eq!(err.len(), 1, "{err:?}");
        assert!(
            err[0].contains("99") && err[0].contains("not one of"),
            "must name the value and the allowed set: {}",
            err[0]
        );
    }

    #[test]
    fn an_unknown_setting_is_refused() {
        let (_, err, _) = resolve(
            r#"
[[setting]]
csp = "Defender"
key = "NoSuchSettingAnywhere"
value = 1
"#,
        );
        assert_eq!(err.len(), 1);
        assert!(err[0].contains("NoSuchSettingAnywhere"), "{}", err[0]);
    }

    #[test]
    fn every_refusal_is_reported_not_just_the_first() {
        let (_, err, _) = resolve(
            r#"
[[setting]]
csp = "Defender"
key = "NopeOne"
value = 1

[[setting]]
csp = "Defender"
key = "NopeTwo"
value = 1
"#,
        );
        assert_eq!(err.len(), 2, "a whole file is edited at once: {err:?}");
    }

    #[test]
    fn delete_emits_no_value() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
csp = "Defender"
key = "EnableNetworkProtection"
action = "delete"
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert!(ok[0].xml.starts_with("<Delete>"));
        assert!(!ok[0].xml.contains("<Data>"));
    }

    #[test]
    fn toml_scalars_normalise_to_wire_text() {
        let e = SettingEntry {
            value: Some(toml::Value::Boolean(true)),
            ..Default::default()
        };
        // Left as the word: the setting's enum decides 1 vs true vs True.
        assert_eq!(e.value_string().as_deref(), Some("true"));
        let e = SettingEntry {
            value: Some(toml::Value::Integer(7)),
            ..Default::default()
        };
        assert_eq!(e.value_string().as_deref(), Some("7"));
    }

    // ── third-party app policies ──────────────────────────────────────────

    fn app_data_present(err: &[String]) {
        assert!(
            !err.iter()
                .any(|e| e.contains("no policy") && e.contains("chrome")),
            "no Chrome policies — the dataset predates windows_app_policies; \
             republish, do not skip: {err:?}"
        );
    }

    /// A Chrome policy resolves to the LocURI the dataset states — under
    /// `Chrome~Policy~googlechrome…`, as Google documents — with the
    /// `<enabled/>` body an ingested policy takes, and names its template.
    #[test]
    fn an_app_policy_resolves_to_its_dataset_loc_uri() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
app = "chrome"
key = "HomepageIsNewTabPage"
"#,
        );
        app_data_present(&err);
        assert!(err.is_empty(), "{err:?}");
        assert!(
            ok[0]
                .path
                .starts_with("./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome"),
            "{}",
            ok[0].path
        );
        assert!(ok[0].path.ends_with("/HomepageIsNewTabPage"));
        assert!(
            ok[0]
                .xml
                .contains("<Format xmlns=\"syncml:metinf\">chr</Format>")
        );
        assert!(
            ok[0].xml.contains("<![CDATA[<enabled/>]]>"),
            "{}",
            ok[0].xml
        );
        let t = ok[0].template.as_ref().expect("names its template");
        assert_eq!(t.admx_file, "chrome.admx");
        assert_eq!(
            t.install_loc_uri,
            "./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/Chrome/Policy/chrome"
        );
        assert!(t.source_url.starts_with("https://"));
    }

    /// An element value goes into `<data id value/>`; class Both goes to the
    /// user tree when asked.
    #[test]
    fn an_app_policy_element_and_channel_are_honoured() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
app = "Chrome"
key = "DefaultCookiesSetting"
channel = "user"
[setting.elements]
DefaultCookiesSetting = "2"
"#,
        );
        app_data_present(&err);
        assert!(err.is_empty(), "{err:?}");
        assert!(
            ok[0]
                .path
                .starts_with("./User/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome"),
            "{}",
            ok[0].path
        );
        assert!(
            ok[0]
                .xml
                .contains("<data id=\"DefaultCookiesSetting\" value=\"2\"/>"),
            "{}",
            ok[0].xml
        );
    }

    /// Windows blocks MDM ingestion under Software\Policies\Microsoft\: an
    /// EdgeUpdate policy is accepted by the device and silently dropped. It is
    /// refused here, with the reason and Microsoft's document.
    #[test]
    fn a_policy_windows_will_not_ingest_is_refused_with_evidence() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
app = "edge-update"
key = "Pol_AutoUpdateCheckPeriod"
"#,
        );
        app_data_present(&err);
        assert!(ok.is_empty());
        assert_eq!(err.len(), 1, "{err:?}");
        assert!(err[0].contains("MDM ingestion blocks"), "{}", err[0]);
        assert!(
            err[0].contains("https://learn.microsoft.com/"),
            "{}",
            err[0]
        );
        assert!(err[0].contains("silently dropped"), "{}", err[0]);
    }

    /// Windows ships winget's template natively as the DesktopAppInstaller
    /// area: the ingested copy is not the route, and the refusal says which
    /// `csp = ` to write instead.
    #[test]
    fn a_template_windows_ships_natively_is_refused_naming_the_native_area() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
app = "winget"
key = "EnableAppInstaller"
"#,
        );
        app_data_present(&err);
        assert!(ok.is_empty());
        assert_eq!(err.len(), 1, "{err:?}");
        assert!(
            err[0].contains("`DesktopAppInstaller`")
                && err[0].contains("csp = \"DesktopAppInstaller\""),
            "{}",
            err[0]
        );
    }

    #[test]
    fn an_unknown_app_policy_is_refused() {
        let (_, err, _) = resolve(
            r#"
[[setting]]
app = "chrome"
key = "NoSuchPolicyAnywhere"
"#,
        );
        assert_eq!(err.len(), 1);
        assert!(
            err[0].contains("no policy 'NoSuchPolicyAnywhere' in the chrome template"),
            "{}",
            err[0]
        );
    }

    /// The template is the payload of the first step, and it is not shipped:
    /// without --admx-dir the error says which file and where to fetch it;
    /// with the file present, one ADMXInstall command per template, ahead of
    /// the policies.
    #[test]
    fn ingestion_needs_the_vendor_template_and_emits_it_once() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
app = "chrome"
key = "HomepageIsNewTabPage"

[[setting]]
app = "chrome"
key = "IncognitoModeAvailability"
[setting.elements]
IncognitoModeAvailability = "1"
"#,
        );
        app_data_present(&err);
        assert!(err.is_empty(), "{err:?}");

        let missing = ingestion_commands(&ok, None).unwrap_err().to_string();
        assert!(
            missing.contains("chrome.admx")
                && missing.contains("--admx-dir")
                && missing.contains("https://"),
            "{missing}"
        );

        let dir = std::env::temp_dir().join(format!("contour-admx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wrong_dir = ingestion_commands(&ok, Some(&dir)).unwrap_err().to_string();
        assert!(
            wrong_dir.contains("is not in") && wrong_dir.contains("chrome.admx"),
            "{wrong_dir}"
        );

        std::fs::write(
            dir.join("Chrome.ADMX"),
            "<policyDefinitions revision=\"1.0\"/>",
        )
        .unwrap();
        let cmds = ingestion_commands(&ok, Some(&dir)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            cmds.len(),
            1,
            "two Chrome policies, one template, one ingest"
        );
        let (t, xml) = &cmds[0];
        assert_eq!(t.admx_file, "chrome.admx");
        assert!(xml.contains("<LocURI>./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/Chrome/Policy/chrome</LocURI>"), "{xml}");
        assert!(
            xml.contains("<![CDATA[<policyDefinitions revision=\"1.0\"/>]]>"),
            "the template XML is the body: {xml}"
        );
    }

    /// Vendors ship UTF-16 LE with a BOM (Chrome, Edge, Office, Brave), UTF-8
    /// with a BOM, or plain UTF-8 (Firefox, OneDrive). All three are the
    /// payload; the declaration stops claiming utf-16 once the bytes are not.
    #[test]
    fn a_template_in_any_vendor_encoding_becomes_the_ingestion_body() {
        use crate::windows::syncml::decode_admx;
        let xml =
            "<?xml version=\"1.0\" encoding=\"utf-16\"?><policyDefinitions revision=\"1.0\"/>";
        let mut utf16 = vec![0xFF, 0xFE];
        for u in xml.encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        let decoded = decode_admx(&utf16).unwrap();
        assert!(
            decoded.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"),
            "{decoded}"
        );
        assert!(decoded.ends_with("<policyDefinitions revision=\"1.0\"/>"));

        let mut bom8 = vec![0xEF, 0xBB, 0xBF];
        bom8.extend_from_slice(b"<?xml version=\"1.0\" ?><policyDefinitions/>");
        assert_eq!(
            decode_admx(&bom8).unwrap(),
            "<?xml version=\"1.0\" ?><policyDefinitions/>"
        );

        assert_eq!(
            decode_admx(b"<policyDefinitions/>").unwrap(),
            "<policyDefinitions/>"
        );

        let err = decode_admx(&[0x00, 0x01, 0x02, 0xFF]).unwrap_err();
        assert!(err.contains("not UTF-8"), "{err}");

        // And through the whole path: a UTF-16 chrome.admx on disk.
        let (ok, err, _) =
            resolve("[[setting]]\napp = \"chrome\"\nkey = \"HomepageIsNewTabPage\"\n");
        app_data_present(&err);
        let dir = std::env::temp_dir().join(format!("contour-admx16-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("chrome.admx"), &utf16).unwrap();
        let cmds = ingestion_commands(&ok, Some(&dir)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            cmds[0]
                .1
                .contains("<![CDATA[<?xml version=\"1.0\" encoding=\"utf-8\"?><policyDefinitions"),
            "{}",
            cmds[0].1
        );
    }

    // ── Atomic ────────────────────────────────────────────────────────────

    /// The DDF says an ActiveSync account's nodes travel inside one Atomic.
    /// Two settings of one account become one `<Atomic>` with both Replaces;
    /// a plain Defender setting stays outside it.
    #[test]
    fn atomic_required_nodes_of_one_instance_share_one_atomic() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
csp = "ActiveSync"
key = "EmailAddress"
instance = "acct1"
value = "user@example.com"

[[setting]]
csp = "Defender"
key = "EnableNetworkProtection"
value = 1

[[setting]]
csp = "ActiveSync"
key = "ServerName"
instance = "acct1"
value = "mail.example.com"
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert_eq!(ok.len(), 3);
        assert!(
            ok[0].atomic && ok[2].atomic,
            "ActiveSync account nodes are AtomicRequired"
        );
        assert!(!ok[1].atomic, "Defender policy nodes are not");
        let (commands, groups) = assemble(&ok);
        assert_eq!(
            commands.len(),
            2,
            "one Atomic at the first member's position, one plain: {commands:?}"
        );
        assert!(commands[0].starts_with("<Atomic>"), "{}", commands[0]);
        assert!(commands[0].contains("/ActiveSync/Accounts/acct1/EmailAddress</LocURI>"));
        assert!(commands[0].contains("/ActiveSync/Accounts/acct1/ServerName</LocURI>"));
        assert!(commands[0].trim_end().ends_with("</Atomic>"));
        assert!(
            commands[1].contains("/Defender/EnableNetworkProtection</LocURI>")
                && !commands[1].contains("Atomic")
        );
        assert_eq!(groups.len(), 1);
        assert!(
            groups[0].0.ends_with("/ActiveSync/Accounts/acct1"),
            "{}",
            groups[0].0
        );
        assert_eq!(groups[0].1, 2);
    }

    /// Two accounts are two Atomics: all-or-nothing is per instance.
    #[test]
    fn different_instances_get_different_atomics() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
csp = "ActiveSync"
key = "EmailAddress"
instance = "a"
value = "a@example.com"

[[setting]]
csp = "ActiveSync"
key = "EmailAddress"
instance = "b"
value = "b@example.com"
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        let (commands, groups) = assemble(&ok);
        assert_eq!(commands.len(), 2);
        assert_eq!(groups.len(), 2);
    }

    // ── node details in refusals and warnings ─────────────────────────────

    /// The DDF says what 0 and 1 mean; a refusal that lists only the numbers
    /// leaves the author guessing.
    #[test]
    fn an_enum_refusal_names_what_each_value_means() {
        let (_, err, _) = resolve(
            r#"
[[setting]]
csp = "AboveLock"
key = "AllowActionCenterNotifications"
value = 7
"#,
        );
        assert_eq!(err.len(), 1, "{err:?}");
        assert!(
            err[0].contains("Allowed") && err[0].contains("Not allowed"),
            "{}",
            err[0]
        );
    }

    /// A node that only applies while another holds a value says so.
    #[test]
    fn a_dependency_stated_by_the_ddf_is_a_warning() {
        let (ok, err, warn) = resolve(
            r#"
[[setting]]
csp = "BitLocker"
key = "AllowStandardUserEncryption"
value = 1
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert_eq!(ok.len(), 1);
        assert!(
            warn.iter().any(|w| w.contains("applies only while")
                && w.contains("AllowWarningForOtherDiskEncryption")),
            "{warn:?}"
        );
    }

    /// A dependency the same file sets to an allowed value is met: no warning.
    #[test]
    fn a_dependency_the_file_satisfies_is_not_a_warning() {
        let (ok, err, warn) = resolve(
            r#"
[[setting]]
csp = "BitLocker"
key = "AllowStandardUserEncryption"
value = 1

[[setting]]
csp = "BitLocker"
key = "AllowWarningForOtherDiskEncryption"
value = 0
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert_eq!(ok.len(), 2);
        assert!(
            !warn.iter().any(|w| w.contains("applies only while")),
            "the dependency is in the file: {warn:?}"
        );
    }

    /// A dependency the file sets to a value that switches the setting off
    /// is worse than an absent one, and says so.
    #[test]
    fn a_dependency_set_to_another_value_is_a_warning() {
        let (_, err, warn) = resolve(
            r#"
[[setting]]
csp = "BitLocker"
key = "AllowStandardUserEncryption"
value = 1

[[setting]]
csp = "BitLocker"
key = "AllowWarningForOtherDiskEncryption"
value = 1
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert!(
            warn.iter()
                .any(|w| w.contains("has no effect") && w.contains("sets it to 1")),
            "{warn:?}"
        );
    }

    /// A key under several parents with none named is refused, listing the
    /// parents — the first match is the Domain profile, not a safe guess.
    #[test]
    fn an_ambiguous_key_without_a_parent_is_refused() {
        let (ok, err, _) = resolve(
            r#"
[[setting]]
csp = "Firewall"
key = "EnableFirewall"
value = true
"#,
        );
        assert!(ok.is_empty(), "{ok:?}");
        assert_eq!(err.len(), 1, "{err:?}");
        assert!(
            err[0].contains("MdmStore.DomainProfile") && err[0].contains("MdmStore.PublicProfile"),
            "the refusal must name the candidates: {}",
            err[0]
        );

        let (ok, err, _) = resolve(
            r#"
[[setting]]
csp = "Firewall"
key = "EnableFirewall"
parent = "MdmStore.PublicProfile"
value = true
"#,
        );
        assert!(err.is_empty(), "{err:?}");
        assert!(
            ok[0]
                .path
                .ends_with("/MdmStore/PublicProfile/EnableFirewall"),
            "{}",
            ok[0].path
        );
    }

    /// `-o` alone writes the file; `--write` is not also needed.
    #[test]
    fn an_output_path_writes_without_write_flag() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("windows.toml");
        std::fs::write(
            &input,
            r#"
[[setting]]
csp = "Defender"
key = "AllowRealtimeMonitoring"
value = 1
"#,
        )
        .unwrap();
        let out = dir.path().join("sub/out.xml");
        handle_generate(
            input.to_str().unwrap(),
            Some(out.to_str().unwrap()),
            false,
            false,
            None,
            true,
        )
        .unwrap();
        let xml = std::fs::read_to_string(&out).expect("-o must write the file");
        assert!(xml.contains("AllowRealtimeMonitoring"), "{xml}");
    }
}
