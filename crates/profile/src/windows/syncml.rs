//! SyncML generation for Windows CSP settings.
//!
//! Turns a setting name and a value into the `<Replace>` fragment an MDM
//! delivers.
//!
//! ## The path rule
//!
//! [`build_path`] mirrors the dataset's DDF ingest, where the rule is
//! verified to rebuild every LocURI in Microsoft's DDF drop exactly. It is
//! reproduced, not reinvented:
//!
//! ```text
//! ./{Device|User}/Vendor/MSFT/[Policy/Config/]<payload_type>/<parent_key>/<key>
//! ```
//!
//! with `Policy/Config/` inserted only when `csp_name` is `Policy` and the
//! payload type is not — the Policy CSP itself is standalone — and
//! `parent_key`'s dots becoming slashes. Settings that name no channel are
//! rooted at `./Vendor/MSFT/…`, except `DMAcc` (`./SyncML/…`) and
//! `DevDetail` / `DevInfo` (`./`).
//!
//! ## Why the output shape is not invented here
//!
//! `fleet_stigs.enforcement_xml` in `windows-schema` carries 648 working
//! fragments produced by a different toolchain. Those are the oracle: the
//! renderer matches them, and `tests/windows_oracle.rs`
//! (`oracle_generated_syncml_matches_fleet_stigs`) compares generated
//! output against them setting by setting. A disagreement
//! there is real information, not a restatement of this module's own
//! assumptions.

use std::fmt;

use mdm_schema::types::{Capability, PayloadKey};

/// CSPs whose settings carry no channel and are not rooted at
/// `./Vendor/MSFT` — see the module docs.
const SYNCML_ROOTED: &str = "DMAcc";
const BARE_ROOTED: [&str; 2] = ["DevDetail", "DevInfo"];

/// Delivery channel for a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Device,
    User,
    /// The setting names no channel; the path carries no `Device`/`User`
    /// segment at all.
    Unscoped,
}

impl Channel {
    pub fn parse(s: &str) -> Option<Channel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "device" => Some(Channel::Device),
            "user" => Some(Channel::User),
            _ => None,
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Channel::Device => "device",
            Channel::User => "user",
            Channel::Unscoped => "unscoped",
        })
    }
}

/// SyncML `<Format>` value.
///
/// The mapping is confirmed against the oracle: every `boolean` row there
/// renders `bool`, every `integer` `int`, every `string` `chr` — ADMX-backed
/// settings included, since an ADMX body is a string payload.
pub fn syncml_format(data_type: &str) -> Option<&'static str> {
    match data_type {
        "string" => Some("chr"),
        "integer" => Some("int"),
        "boolean" => Some("bool"),
        "base64" => Some("b64"),
        "xml" => Some("xml"),
        "datetime" => Some("chr"),
        "binary" => Some("bin"),
        // "null" is an action-only node: it takes no value at all.
        _ => None,
    }
}

/// Everything generation refuses, each one a silent failure on a device.
#[derive(Debug, Clone, PartialEq)]
pub enum WindowsError {
    UnknownSetting {
        csp: String,
        key: String,
    },
    /// The key name exists under several parents and none was given.
    AmbiguousKey {
        csp: String,
        key: String,
        parents: Vec<String>,
    },
    /// The setting exists but not on the channel asked for.
    ChannelMismatch {
        path: String,
        requested: Channel,
        available: String,
    },
    /// Value outside `key_rangelist`.
    NotInEnum {
        key: String,
        value: String,
        allowed: String,
    },
    /// Value outside `key_range_min`/`key_range_max`.
    OutOfRange {
        key: String,
        value: String,
        min: Option<f64>,
        max: Option<f64>,
    },
    /// Value is not the kind the setting takes.
    WrongType {
        key: String,
        value: String,
        data_type: String,
    },
    /// The node is an action (`key_data_type = "null"`); it carries no value.
    ActionOnly {
        key: String,
    },
    /// The path contains an instance placeholder and none was supplied.
    InstanceRequired {
        path: String,
        placeholder: String,
    },
    /// enable/disable was asked for on a setting that is not ADMX-backed.
    NotAdmx {
        key: String,
    },
    /// A value is required and none was given.
    MissingValue {
        key: String,
    },
    /// No such policy in that app's template.
    UnknownAppPolicy {
        app: String,
        key: String,
    },
    /// Windows will not let MDM ingest where this policy writes.
    NotIngestable {
        app: String,
        key: String,
        reason: String,
        evidence: String,
    },
    /// Windows ships this template natively; the ingested copy is not the
    /// route.
    ShippedNatively {
        app: String,
        key: String,
        native: String,
    },
    /// The template file is there but cannot be turned into text.
    TemplateUnreadable {
        path: String,
        why: String,
    },
    /// ADMX element values that do not fit the policy's element schema.
    /// Every problem, not the first.
    BadElements {
        key: String,
        problems: Vec<String>,
    },
    /// An `app` entry with no `--admx-dir`, or a directory without the
    /// template file the policy needs.
    TemplateMissing {
        admx_file: String,
        app: String,
        source_url: String,
        dir: Option<String>,
    },
}

impl fmt::Display for WindowsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WindowsError::UnknownSetting { csp, key } => write!(
                f,
                "no setting '{key}' in CSP '{csp}'. A LocURI the device does not \
                 recognise is accepted and ignored, so this is refused rather than emitted"
            ),
            WindowsError::AmbiguousKey { csp, key, parents } => write!(
                f,
                "'{key}' exists under {} parents in CSP '{csp}', and each is a different \
                 node on the device. Name the one you mean with parent = \"…\": {}",
                parents.len(),
                parents.join(", ")
            ),
            WindowsError::ChannelMismatch {
                path,
                requested,
                available,
            } => write!(
                f,
                "{path} is not available on the {requested} channel (it is {available}). \
                 Delivering it on the wrong channel silently does nothing"
            ),
            WindowsError::NotInEnum {
                key,
                value,
                allowed,
            } => write!(f, "{key}: '{value}' is not one of {allowed}"),
            WindowsError::OutOfRange {
                key,
                value,
                min,
                max,
            } => {
                let lo = min.map(|v| v.to_string()).unwrap_or_else(|| "-∞".into());
                let hi = max.map(|v| v.to_string()).unwrap_or_else(|| "∞".into());
                write!(f, "{key}: {value} is outside [{lo}, {hi}]")
            }
            WindowsError::WrongType {
                key,
                value,
                data_type,
            } => write!(f, "{key}: '{value}' is not a valid {data_type}"),
            WindowsError::ActionOnly { key } => write!(
                f,
                "{key} is an action node — it executes rather than holding a value, \
                 so it cannot be set"
            ),
            WindowsError::InstanceRequired { path, placeholder } => write!(
                f,
                "{path} addresses an instance: supply a name for '{placeholder}'. \
                 Without one the LocURI names no node"
            ),
            WindowsError::NotAdmx { key } => write!(
                f,
                "{key} is not ADMX-backed, so it has no enable/disable form — \
                 give it a value instead"
            ),
            WindowsError::MissingValue { key } => write!(
                f,
                "{key} needs a value (or action = \"delete\" to remove it)"
            ),
            WindowsError::UnknownAppPolicy { app, key } => write!(
                f,
                "no policy '{key}' in the {app} template. An ingested LocURI the template does \
                 not define is accepted by the device and does nothing, so this is refused"
            ),
            WindowsError::NotIngestable {
                app,
                key,
                reason,
                evidence,
            } => write!(
                f,
                "{app}/{key} cannot be delivered by MDM: it {reason}. An ingested policy that \
                 writes there is accepted and silently dropped by Windows, so it is refused \
                 here rather than shipped. Evidence: {evidence}"
            ),
            WindowsError::ShippedNatively { app, key, native } => write!(
                f,
                "{app}/{key}: Windows ships this template natively as the `{native}` Policy CSP \
                 area, and blocks ingesting a copy. Write it as csp = \"{native}\", key = \
                 \"{key}\" — no ADMXInstall step needed"
            ),
            WindowsError::BadElements { key, problems } => write!(
                f,
                "'{key}' element values do not fit its template:\n    {}\n  \
                 Windows applies an ADMX policy only with every element it displays, in \
                 the form it declares; `profile windows apps show` or `profile info` lists them",
                problems.join("\n    ")
            ),
            WindowsError::TemplateUnreadable { path, why } => write!(
                f,
                "{path} could not be read as an ADMX template: {why}. Vendors ship these as \
                 UTF-16 LE with a byte-order mark, UTF-8 with one, or plain UTF-8, all of \
                 which are accepted; anything else is not a template file"
            ),
            WindowsError::TemplateMissing {
                admx_file,
                app,
                source_url,
                dir,
            } => match dir {
                Some(d) => write!(
                    f,
                    "{admx_file} is not in {d}. The {app} policies need their template \
                     ingested first, and the template itself is the payload: fetch it from \
                     {source_url} and place {admx_file} in that directory"
                ),
                None => write!(
                    f,
                    "{app} policies need {admx_file} ingested before they apply, and the \
                     template's own XML is that payload. Pass --admx-dir <dir> holding \
                     {admx_file} (from {source_url})"
                ),
            },
        }
    }
}

impl std::error::Error for WindowsError {}

/// Build the LocURI for one setting.
///
/// `channel` picks between the Device and User trees; pass
/// [`Channel::Unscoped`] for a setting that names neither.
pub fn build_path(
    payload_type: &str,
    csp_name: Option<&str>,
    parent_key: Option<&str>,
    key: &str,
    channel: Channel,
) -> String {
    // parent_key is dot-separated in the data and slash-separated in a path.
    let mut tail = String::new();
    if let Some(parent) = parent_key.filter(|p| !p.is_empty()) {
        tail.push_str(&parent.replace('.', "/"));
        tail.push('/');
    }
    tail.push_str(key);

    // The Policy CSP hosts its areas under Policy/Config; the CSP itself does
    // not nest inside itself.
    let policy_prefix = if csp_name == Some("Policy") && payload_type != "Policy" {
        "Policy/Config/"
    } else {
        ""
    };

    match channel {
        Channel::Device => format!("./Device/Vendor/MSFT/{policy_prefix}{payload_type}/{tail}"),
        Channel::User => format!("./User/Vendor/MSFT/{policy_prefix}{payload_type}/{tail}"),
        Channel::Unscoped => {
            if payload_type == SYNCML_ROOTED {
                format!("./SyncML/{payload_type}/{tail}")
            } else if BARE_ROOTED.contains(&payload_type) {
                format!("./{payload_type}/{tail}")
            } else {
                format!("./Vendor/MSFT/{policy_prefix}{payload_type}/{tail}")
            }
        }
    }
}

/// Find the instance placeholder in a path, if any.
///
/// 678 settings sit under a node like `{UniqueName}`. A LocURI still carrying
/// the placeholder addresses nothing, so generation refuses it.
pub fn instance_placeholder(path: &str) -> Option<String> {
    let start = path.find('{')?;
    let end = path[start..].find('}')? + start;
    Some(path[start..=end].to_string())
}

/// Substitute the instance placeholder with a caller-supplied name.
pub fn apply_instance(path: &str, instance: &str) -> String {
    match instance_placeholder(path) {
        Some(ph) => path.replace(&ph, instance),
        None => path.to_string(),
    }
}

/// Check a value against the key's declared constraints and return the exact
/// text to put on the wire.
///
/// Validation and normalisation are one step because they disagree otherwise.
/// Booleans are the case in point: 152 of the 192 boolean settings declare an
/// enum, and the spellings differ between settings — `["true","false"]`,
/// `["True","False"]`, `["0","1"]`. **The declared enum wins**, so a TOML
/// `true` becomes `True` for one setting and `1` for another. Emitting `1`
/// for every boolean, which is the obvious implementation, is wrong for
/// those 152. Only the 40 booleans with no enum use the 0/1 convention.
///
/// Verified against the oracle: `Firewall/EnableFirewall` declares
/// `["false","true"]` and `fleet_stigs` sends the word `true`.
pub fn validate_value(key: &PayloadKey, value: &str) -> Result<String, WindowsError> {
    if key.data_type == "null" {
        return Err(WindowsError::ActionOnly {
            key: key.name.clone(),
        });
    }

    let want = value.trim();

    if let Some(list) = key.range_list.as_ref().filter(|l| !l.is_empty()) {
        // Accept any spelling the author used, emit the declared one.
        if let Some(canonical) = list.iter().find(|v| v.eq_ignore_ascii_case(want)) {
            return Ok(canonical.clone());
        }
        // A TOML `true` against an enum of ["1","0"] is a fair thing to write.
        let alias = match want.to_ascii_lowercase().as_str() {
            "true" => Some("1"),
            "false" => Some("0"),
            "1" => Some("true"),
            "0" => Some("false"),
            _ => None,
        };
        if let Some(alias) = alias {
            if let Some(canonical) = list.iter().find(|v| v.eq_ignore_ascii_case(alias)) {
                return Ok(canonical.clone());
            }
        }
        return Err(WindowsError::NotInEnum {
            key: key.name.clone(),
            value: want.to_string(),
            allowed: list.join(", "),
        });
    }

    match key.data_type.as_str() {
        "integer" => {
            let n: f64 = want.parse().map_err(|_parse| WindowsError::WrongType {
                key: key.name.clone(),
                value: want.to_string(),
                data_type: key.data_type.clone(),
            })?;
            let below = key.range_min.is_some_and(|min| n < min);
            let above = key.range_max.is_some_and(|max| n > max);
            if below || above {
                return Err(WindowsError::OutOfRange {
                    key: key.name.clone(),
                    value: want.to_string(),
                    min: key.range_min,
                    max: key.range_max,
                });
            }
            Ok(want.to_string())
        }
        // No enum: the 0/1 convention applies.
        "boolean" => match want.to_ascii_lowercase().as_str() {
            "1" | "true" => Ok("1".to_string()),
            "0" | "false" => Ok("0".to_string()),
            _ => Err(WindowsError::WrongType {
                key: key.name.clone(),
                value: want.to_string(),
                data_type: key.data_type.clone(),
            }),
        },
        _ => Ok(want.to_string()),
    }
}

/// What to do with a setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Set a value.
    Replace,
    /// Remove the setting from the device.
    Delete,
}

/// Render one SyncML command.
///
/// The layout — four-space indents, `syncml:metinf` on `<Format>`, CDATA only
/// where the payload is itself XML — matches `fleet_stigs.enforcement_xml`
/// byte for byte. `<Delete>` carries no `<Meta>` or `<Data>`: it names a node
/// to remove, and a format for a value that is not being sent is noise.
pub fn render(op: Operation, path: &str, format: &str, data: Option<&str>) -> String {
    // CDATA iff the format is `chr`. Verified against the oracle: 415 of 415
    // chr fragments use CDATA, 0 of 233 int/bool fragments do. `chr` is
    // arbitrary character data that may contain & or <; int and bool cannot.
    // Deciding it here rather than taking it from the caller removes the
    // only way to get it wrong, and it subsumes ADMX bodies, which are chr.
    let cdata = format == "chr";
    if op == Operation::Delete {
        return format!(
            "<Delete>\n    <Item>\n        <Target>\n            \
             <LocURI>{path}</LocURI>\n        </Target>\n    </Item>\n</Delete>"
        );
    }

    let body = match data {
        Some(d) if cdata => format!("<Data><![CDATA[{d}]]></Data>"),
        Some(d) => format!("<Data>{}</Data>", xml_escape(d)),
        None => String::new(),
    };

    format!(
        "<Replace>\n    <Item>\n        <Meta>\n            \
         <Format xmlns=\"syncml:metinf\">{format}</Format>\n        </Meta>\n        \
         <Target>\n            <LocURI>{path}</LocURI>\n        </Target>\n        \
         {body}\n    </Item>\n</Replace>"
    )
}

/// Wrap commands in a full `<SyncML>` envelope for a DM session.
///
/// Fleet and most GitOps flows want the bare fragments; a DM session wants
/// this. Two forms, not five — everything else is a presentation choice a
/// caller can make from these.
pub fn envelope(commands: &[String]) -> String {
    let mut out = String::from("<SyncML xmlns=\"SYNCML:SYNCML1.2\">\n  <SyncBody>\n");
    // CmdID must be unique and 1-based within a SyncBody — and an <Atomic>
    // is a command too: it takes an id of its own, and each command inside
    // it takes the next, so a two-setting Atomic consumes three ids.
    let mut id = 0usize;
    for cmd in commands {
        let indented: String = cmd
            .lines()
            .map(|l| format!("    {l}"))
            .collect::<Vec<_>>()
            .join("\n");
        let numbered = if cmd.starts_with("<Atomic>") {
            id += 1;
            let mut s = indented.replacen(
                "<Atomic>",
                &format!("<Atomic>\n        <CmdID>{id}</CmdID>"),
                1,
            );
            while let Some(pos) = s.find("<Item>") {
                id += 1;
                // Mark this <Item> so the next search moves past it.
                s.replace_range(
                    pos..pos + 6,
                    &format!("<CmdID>{id}</CmdID>\n            <ITEM_>"),
                );
            }
            s.replace("<ITEM_>", "<Item>")
        } else {
            id += 1;
            indented.replacen("<Item>", &format!("<CmdID>{id}</CmdID>\n        <Item>"), 1)
        };
        out.push_str(&numbered);
        out.push('\n');
    }
    out.push_str("    <Final/>\n  </SyncBody>\n</SyncML>");
    out
}

/// Enclose commands in one `<Atomic>`, which the device applies all or
/// nothing. The DDF marks 231 nodes `AtomicRequired` — "this node and all
/// children nodes should be enclosed by an Atomic tag when being sent to
/// the client": an ActiveSync account, a VPNv2 profile, a SCEP request, a
/// firewall rule. Delivering those as independent Replaces is accepted and
/// leaves a half-written instance when one fails.
pub fn atomic_wrap(commands: &[String]) -> String {
    let mut out = String::from("<Atomic>\n");
    for cmd in commands {
        for line in cmd.lines() {
            out.push_str("    ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str("</Atomic>");
    out
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Locate a setting in the Windows capability data.
///
/// A CSP may repeat a key name under several parents — Firewall has
/// `EnableFirewall` under each of its profiles. With a parent given, match
/// it exactly (`""` names a top-level key). Without one, a name that exists
/// under more than one parent is refused with the candidates: taking the
/// first would configure the Domain profile for someone who meant Public.
pub fn find_setting<'a>(
    caps: &'a [Capability],
    csp: &str,
    key: &str,
    parent: Option<&str>,
) -> Result<(&'a Capability, &'a PayloadKey), WindowsError> {
    let parent_of = |k: &PayloadKey| k.parent_key.clone().unwrap_or_default();
    let matches: Vec<(&Capability, &PayloadKey)> = caps
        .iter()
        .filter(|c| c.payload_type.eq_ignore_ascii_case(csp))
        .flat_map(|c| c.keys.iter().map(move |k| (c, k)))
        .filter(|(_, k)| k.name.eq_ignore_ascii_case(key))
        .filter(|(_, k)| parent.is_none_or(|p| parent_of(k) == p))
        .collect();

    let mut parents: Vec<String> = matches.iter().map(|(_, k)| parent_of(k)).collect();
    parents.sort();
    parents.dedup();
    match (matches.first(), parents.len()) {
        (None, _) => Err(WindowsError::UnknownSetting {
            csp: csp.to_string(),
            key: key.to_string(),
        }),
        // One parent, possibly listed more than once in the data.
        (Some(&m), 1) => Ok(m),
        (Some(_), _) => Err(WindowsError::AmbiguousKey {
            csp: csp.to_string(),
            key: key.to_string(),
            parents: parents
                .into_iter()
                .map(|p| {
                    if p.is_empty() {
                        "\"\" (top level)".into()
                    } else {
                        p
                    }
                })
                .collect(),
        }),
    }
}

/// Which channels a KEY is addressable on.
///
/// Per key, never per capability: `ADMX_AppCompat` holds 8 device-only keys
/// and 1 user-only one, so a capability-level answer mislabels one group.
/// Falling back to the capability only when the key carries nothing keeps
/// older parquets working.
pub fn channels_for_key(cap: &Capability, key: &PayloadKey) -> (bool, bool) {
    if key.device_channel.is_some() || key.user_channel.is_some() {
        return (
            key.device_channel.unwrap_or(false),
            key.user_channel.unwrap_or(false),
        );
    }
    cap.supported_os
        .iter()
        .find_map(|os| {
            let d = os.device_channel.unwrap_or(false);
            let u = os.user_channel.unwrap_or(false);
            (d || u).then_some((d, u))
        })
        .unwrap_or((false, false))
}

/// The CSP a key is addressed under.
///
/// `Defender` and `CloudDesktop` each exist both as a standalone CSP and as
/// a Policy area, so the capability-level `csp_name` describes only one of
/// the two key sets. The key's own value wins when the data carries it.
pub fn csp_for_key<'a>(cap: &'a Capability, key: &'a PayloadKey) -> Option<&'a str> {
    key.csp_name.as_deref().or(cap.csp_name.as_deref())
}

/// Resolve the channel to emit on, refusing a contradiction.
pub fn resolve_channel(
    cap: &Capability,
    key: &PayloadKey,
    requested: Option<Channel>,
    path_hint: &str,
) -> Result<Channel, WindowsError> {
    let (device, user) = channels_for_key(cap, key);

    match requested {
        Some(Channel::Device) if device => Ok(Channel::Device),
        Some(Channel::User) if user => Ok(Channel::User),
        Some(req @ (Channel::Device | Channel::User)) => Err(WindowsError::ChannelMismatch {
            path: path_hint.to_string(),
            requested: req,
            available: match (device, user) {
                (true, true) => "device and user".to_string(),
                (true, false) => "device only".to_string(),
                (false, true) => "user only".to_string(),
                (false, false) => "neither — the setting names no channel".to_string(),
            },
        }),
        // No explicit request: device wins when both are offered, because a
        // CSP setting delivered per-device is the common intent.
        _ => Ok(if device {
            Channel::Device
        } else if user {
            Channel::User
        } else {
            Channel::Unscoped
        }),
    }
}

/// Deprecation notice for a key, if the data records one.
///
/// A warning, never a refusal: a deprecated setting still applies on the
/// builds that predate its removal, which is exactly when an admin needs it.
pub fn deprecation_warning(key: &PayloadKey) -> Option<String> {
    key.deprecated.values().next().map(|build| {
        format!(
            "{} is deprecated as of build {build} — it still applies on earlier builds",
            key.name
        )
    })
}

/// Find the ADMX policy backing a setting, if any.
///
/// Returns the policy rather than its rendered body: the caller then picks
/// between [`windows_schema::AdmxPolicy::payload`] (with element values) and
/// [`windows_schema::AdmxPolicy::disabled_payload`], and a wrapper around
/// both would only re-state their signatures.
pub fn find_admx_policy<'a>(
    policies: &'a [windows_schema::AdmxPolicy],
    payload_type: &str,
    key: &str,
) -> Option<&'a windows_schema::AdmxPolicy> {
    policies
        .iter()
        .find(|p| p.payload_type == payload_type && p.policy_name == key)
}

/// A third-party app policy by template (`chrome`) or app name (`Chrome`),
/// either spelling case-insensitively, and policy name.
pub fn find_app_policy<'a>(
    policies: &'a [windows_schema::WindowsAppPolicy],
    app: &str,
    key: &str,
) -> Option<&'a windows_schema::WindowsAppPolicy> {
    policies.iter().find(|p| {
        (p.template.eq_ignore_ascii_case(app) || p.app_name.eq_ignore_ascii_case(app))
            && p.policy_name == key
    })
}

/// The DDF's word on one node, when the dataset carries it.
pub fn find_node_detail<'a>(
    details: &'a [windows_schema::NodeDetail],
    payload_type: &str,
    key_path: &str,
) -> Option<&'a windows_schema::NodeDetail> {
    details
        .iter()
        .find(|d| d.payload_type == payload_type && d.key_path == key_path)
}

/// The ADMXInstall command: the template's own XML, sent once, at the URI
/// the dataset names for it. `chr`, so it travels in CDATA like every other
/// XML-bearing body.
pub fn render_admx_install(install_loc_uri: &str, admx_xml: &str) -> String {
    render(Operation::Replace, install_loc_uri, "chr", Some(admx_xml))
}

/// An ADMX file's bytes as the text an ADMXInstall body carries.
///
/// Chrome, Edge, Brave and the Microsoft 365 templates are UTF-16 LE with a
/// byte-order mark; Firefox and OneDrive are plain UTF-8. The BOM decides.
/// Once decoded, an XML declaration that still says `encoding="utf-16"`
/// would describe bytes that are no longer there — the body travels inside
/// a UTF-8 SyncML document — so it is rewritten to `utf-8`. A declaration
/// with no encoding, which is what Google writes, is left alone.
pub fn decode_admx(bytes: &[u8]) -> Result<String, String> {
    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).map_err(|e| format!("invalid UTF-16 LE: {e}"))?
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).map_err(|e| format!("invalid UTF-16 BE: {e}"))?
    } else {
        let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        String::from_utf8(body.to_vec()).map_err(|e| format!("not UTF-8: {e}"))?
    };
    // Nothing may sit between `<![CDATA[` and `<?xml`: a line break or a
    // space there makes ADMXInstall fail with status 500 (Fleet, 2026-10).
    // Vendors do ship files with a blank first line, so the body starts at
    // the first `<`.
    let text = text.trim_start().to_string();
    if !text.starts_with("<?xml") && !text.starts_with('<') {
        return Err("does not begin with XML".into());
    }
    // Only the declaration, only the encoding attribute.
    if let Some(end) = text.find("?>") {
        let (decl, rest) = text.split_at(end);
        let lower = decl.to_ascii_lowercase();
        if let Some(i) = lower.find("encoding=") {
            let quote = decl.as_bytes().get(i + 9).copied();
            if let Some(q) = quote.filter(|q| *q == b'"' || *q == b'\'') {
                let start = i + 10;
                if let Some(len) = decl[start..].find(q as char) {
                    let mut fixed = String::with_capacity(text.len());
                    fixed.push_str(&decl[..start]);
                    fixed.push_str("utf-8");
                    fixed.push_str(&decl[start + len..]);
                    fixed.push_str(rest);
                    return Ok(fixed);
                }
            }
        }
    }
    Ok(text)
}

/// The U+F000 separator Windows reads between the strings of a `multiText`
/// or `list` element.
pub const ADMX_LIST_SEPARATOR: char = '\u{F000}';

/// Check `[setting.elements]` against an ADMX policy's elements and return
/// each element's wire value, by id.
///
/// What goes on the wire is Microsoft's, from "Understanding ADMX policies":
/// a `boolean` is `true` or `false` — not the registry value the template
/// writes — an `enum` is the chosen item's value, a `decimal` its number, and
/// the strings of a `multiText` or `list` are joined by U+F000. A TOML array
/// is accepted for those two and joined here, so nobody has to type the
/// separator.
///
/// Every element must be given. Microsoft: "Any data entry field that is
/// displayed in the Group Policy page of the Group Policy Editor must be
/// supplied." Filling a missing one in — an enum's first choice, a number's
/// minimum, a boolean's "on" — would deploy a decision contour made. Unknown
/// ids, values outside an enum or range, over-long text and the wrong kind
/// are refused too.
pub fn admx_element_values(
    key: &str,
    elements: &[windows_schema::types::AdmxElement],
    given: Option<&std::collections::BTreeMap<String, toml::Value>>,
) -> Result<std::collections::HashMap<String, String>, WindowsError> {
    let empty = std::collections::BTreeMap::new();
    let given = given.unwrap_or(&empty);
    let mut problems = Vec::new();
    let mut out = std::collections::HashMap::new();

    for id in given.keys() {
        if !elements.iter().any(|e| &e.id == id) {
            let known: Vec<&str> = elements.iter().map(|e| e.id.as_str()).collect();
            problems.push(if known.is_empty() {
                format!("{id}: this policy takes no elements")
            } else {
                format!("{id}: no such element; it takes {}", known.join(", "))
            });
        }
    }

    for e in elements {
        let Some(v) = given.get(&e.id) else {
            problems.push(format!("{}: missing — {}", e.id, describe(e)));
            continue;
        };
        match admx_wire_value(e, v) {
            Ok(w) => {
                out.insert(e.id.clone(), w);
            }
            Err(why) => problems.push(format!("{}: {why}", e.id)),
        }
    }

    if problems.is_empty() {
        Ok(out)
    } else {
        Err(WindowsError::BadElements {
            key: key.to_string(),
            problems,
        })
    }
}

/// The bounds an element really has. An ADMX that states no `minValue`,
/// `maxValue` or `maxLength` still has one: the ADMX schema defaults them to
/// 0, 9999 and 1023 (decimal, longDecimal and text elements, Microsoft's
/// PolicyDefinitions reference). The dataset records only what the template
/// states — 66 decimals across the app templates state no minimum — so the
/// defaults are applied here, where the value is judged.
fn numeric_bounds(e: &windows_schema::types::AdmxElement) -> (f64, f64) {
    (e.min.unwrap_or(0.0), e.max.unwrap_or(9999.0))
}

fn text_max_length(e: &windows_schema::types::AdmxElement) -> u32 {
    e.max_length.unwrap_or(1023)
}

/// What an element takes, for a refusal to say.
fn describe(e: &windows_schema::types::AdmxElement) -> String {
    match e.kind.as_str() {
        "boolean" => "a boolean, true or false".into(),
        "enum" => format!(
            "one of {}",
            e.items
                .iter()
                .map(|i| format!("{} ({})", i.value, i.display))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "decimal" | "longDecimal" => {
            let (lo, hi) = numeric_bounds(e);
            format!("a whole number, {lo}..={hi}")
        }
        "multiText" => "a list of strings".into(),
        "list" if e.explicit_value == Some(true) => {
            "a list of name, value, name, value … strings".into()
        }
        "list" => "a list of strings".into(),
        _ => format!("a string of at most {} characters", text_max_length(e)),
    }
}

fn admx_wire_value(
    e: &windows_schema::types::AdmxElement,
    v: &toml::Value,
) -> Result<String, String> {
    let scalar = || match v {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        _ => None,
    };
    let strings = || -> Option<Vec<String>> {
        match v {
            toml::Value::Array(a) => a.iter().map(|x| x.as_str().map(str::to_string)).collect(),
            toml::Value::String(s) => {
                Some(s.split(ADMX_LIST_SEPARATOR).map(str::to_string).collect())
            }
            _ => None,
        }
    };
    match e.kind.as_str() {
        "boolean" => match v {
            toml::Value::Boolean(b) => Ok(b.to_string()),
            toml::Value::String(s) if s.eq_ignore_ascii_case("true") => Ok("true".into()),
            toml::Value::String(s) if s.eq_ignore_ascii_case("false") => Ok("false".into()),
            other => Err(format!(
                "{other} is not a boolean. Windows takes true or false here — not the \
                 registry value ({}) the template writes",
                e.true_value.as_deref().unwrap_or("1")
            )),
        },
        "enum" => {
            let s = scalar().ok_or_else(|| format!("not a value; {}", describe(e)))?;
            if e.items.iter().any(|i| i.value == s) {
                Ok(s)
            } else if let Some(i) = e.items.iter().find(|i| i.display.eq_ignore_ascii_case(&s)) {
                Err(format!("\"{s}\" is a label; the value is {}", i.value))
            } else {
                Err(format!("{s} is not {}", describe(e)))
            }
        }
        "decimal" | "longDecimal" => {
            let s = scalar().ok_or_else(|| format!("not a number; {}", describe(e)))?;
            let n: i64 = s
                .trim()
                .parse()
                .map_err(|_| format!("{s} is not {}", describe(e)))?;
            let x = n as f64;
            let (lo, hi) = numeric_bounds(e);
            if x < lo || x > hi {
                return Err(format!("{n} is outside {}", describe(e)));
            }
            Ok(n.to_string())
        }
        "multiText" | "list" => {
            let parts = strings().ok_or_else(|| format!("not {}", describe(e)))?;
            if e.kind == "list" && e.explicit_value == Some(true) && parts.len() % 2 != 0 {
                return Err(format!(
                    "{} string(s); this list takes name, value pairs",
                    parts.len()
                ));
            }
            Ok(parts.join(&ADMX_LIST_SEPARATOR.to_string()))
        }
        _ => {
            let s = scalar().ok_or_else(|| format!("not {}", describe(e)))?;
            let n = text_max_length(e);
            if s.chars().count() > n as usize {
                return Err(format!("{} characters; at most {n}", s.chars().count()));
            }
            if e.required == Some(true) && s.is_empty() {
                return Err("empty, and the template requires a value".into());
            }
            Ok(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rule_matches_posture() {
        // Policy areas nest under Policy/Config.
        assert_eq!(
            build_path(
                "Defender",
                Some("Policy"),
                None,
                "EnableNetworkProtection",
                Channel::Device
            ),
            "./Device/Vendor/MSFT/Policy/Config/Defender/EnableNetworkProtection"
        );
        // The Policy CSP itself does not nest inside itself.
        assert_eq!(
            build_path("Policy", Some("Policy"), None, "Setting", Channel::Device),
            "./Device/Vendor/MSFT/Policy/Setting"
        );
        // A standalone CSP.
        assert_eq!(
            build_path(
                "BitLocker",
                Some("BitLocker"),
                None,
                "RequireDeviceEncryption",
                Channel::Device
            ),
            "./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption"
        );
        // parent_key dots become slashes.
        assert_eq!(
            build_path("Foo", Some("Foo"), Some("A.B"), "C", Channel::User),
            "./User/Vendor/MSFT/Foo/A/B/C"
        );
        // Unscoped roots.
        assert_eq!(
            build_path("DMAcc", Some("DMAcc"), None, "X", Channel::Unscoped),
            "./SyncML/DMAcc/X"
        );
        assert_eq!(
            build_path("DevDetail", Some("DevDetail"), None, "X", Channel::Unscoped),
            "./DevDetail/X"
        );
        assert_eq!(
            build_path("Other", Some("Other"), None, "X", Channel::Unscoped),
            "./Vendor/MSFT/Other/X"
        );
    }

    #[test]
    fn replace_matches_the_oracle_layout() {
        // Byte-for-byte against fleet_stigs.enforcement_xml for
        // Defender/EnableNetworkProtection.
        let got = render(
            Operation::Replace,
            "./Device/Vendor/MSFT/Policy/Config/Defender/EnableNetworkProtection",
            "int",
            Some("1"),
        );
        let want = "<Replace>\n    <Item>\n        <Meta>\n            \
                    <Format xmlns=\"syncml:metinf\">int</Format>\n        </Meta>\n        \
                    <Target>\n            <LocURI>./Device/Vendor/MSFT/Policy/Config/Defender/\
                    EnableNetworkProtection</LocURI>\n        </Target>\n        \
                    <Data>1</Data>\n    </Item>\n</Replace>";
        assert_eq!(got, want);
    }

    #[test]
    fn admx_bodies_go_in_cdata() {
        let got = render(
            Operation::Replace,
            "./Device/Vendor/MSFT/Policy/Config/ADMX_X/Y",
            "chr",
            Some("<enabled/>"),
        );
        assert!(
            got.contains("<Data><![CDATA[<enabled/>]]></Data>"),
            "ADMX payloads are XML and must not be escaped into unreadability: {got}"
        );
    }

    #[test]
    fn delete_carries_no_meta_or_data() {
        let got = render(
            Operation::Delete,
            "./Device/Vendor/MSFT/X/Y",
            "int",
            Some("1"),
        );
        assert!(got.starts_with("<Delete>"));
        assert!(!got.contains("<Meta>"), "a Delete sends no value: {got}");
        assert!(!got.contains("<Data>"), "a Delete sends no value: {got}");
        assert!(got.contains("<LocURI>./Device/Vendor/MSFT/X/Y</LocURI>"));
    }

    #[test]
    fn instance_placeholders_are_detected_and_filled() {
        let p = "./Device/Vendor/MSFT/VPNv2/{ProfileName}/TrafficFilterList";
        assert_eq!(instance_placeholder(p).as_deref(), Some("{ProfileName}"));
        assert_eq!(
            apply_instance(p, "Corp"),
            "./Device/Vendor/MSFT/VPNv2/Corp/TrafficFilterList"
        );
        assert_eq!(instance_placeholder("./Device/Vendor/MSFT/X/Y"), None);
    }

    #[test]
    fn format_mapping_covers_every_type_in_the_data() {
        // Confirmed against the oracle for the three it exercises.
        assert_eq!(syncml_format("string"), Some("chr"));
        assert_eq!(syncml_format("integer"), Some("int"));
        assert_eq!(syncml_format("boolean"), Some("bool"));
        assert_eq!(syncml_format("base64"), Some("b64"));
        assert_eq!(syncml_format("xml"), Some("xml"));
        // Action-only nodes have no format because they carry no value.
        assert_eq!(syncml_format("null"), None);
    }

    /// An Atomic is a command: it gets an id, and its members get the next
    /// ones, so what follows continues the count.
    #[test]
    fn envelope_gives_an_atomic_and_its_members_their_own_ids() {
        let atomic = atomic_wrap(&[
            render(Operation::Replace, "./A/x/1", "chr", Some("a")),
            render(Operation::Replace, "./A/x/2", "chr", Some("b")),
        ]);
        let plain = render(Operation::Replace, "./B", "int", Some("2"));
        let env = envelope(&[atomic, plain]);
        let ids: Vec<&str> = env.matches("<CmdID>").collect();
        assert_eq!(ids.len(), 4, "{env}");
        let a = env.find("<Atomic>").unwrap();
        let one = env.find("<CmdID>1</CmdID>").unwrap();
        let two = env.find("<CmdID>2</CmdID>").unwrap();
        let three = env.find("<CmdID>3</CmdID>").unwrap();
        let close = env.find("</Atomic>").unwrap();
        let four = env.find("<CmdID>4</CmdID>").unwrap();
        assert!(
            a < one && one < two && two < three && three < close && close < four,
            "{env}"
        );
        assert!(!env.contains("<ITEM_>"));
    }

    #[test]
    fn envelope_numbers_commands_from_one() {
        let cmds = vec![
            render(Operation::Replace, "./A", "int", Some("1")),
            render(Operation::Replace, "./B", "int", Some("2")),
        ];
        let env = envelope(&cmds);
        assert!(env.starts_with("<SyncML"));
        assert!(env.contains("<CmdID>1</CmdID>"));
        assert!(env.contains("<CmdID>2</CmdID>"));
        assert!(env.contains("<Final/>"), "a DM session needs Final");
    }

    fn el(id: &str, kind: &str) -> windows_schema::types::AdmxElement {
        windows_schema::types::AdmxElement {
            id: id.into(),
            kind: kind.into(),
            label: None,
            required: None,
            min: None,
            max: None,
            max_length: None,
            true_value: Some("1".into()),
            false_value: Some("0".into()),
            explicit_value: None,
            items: vec![],
            value_name: None,
            key: None,
        }
    }

    fn given(t: &str) -> std::collections::BTreeMap<String, toml::Value> {
        toml::from_str(t).unwrap()
    }

    fn problems(r: Result<std::collections::HashMap<String, String>, WindowsError>) -> String {
        r.unwrap_err().to_string()
    }

    /// Microsoft: a boolean element is `value="true"`, not the registry
    /// trueValue the template writes.
    #[test]
    fn a_boolean_element_is_true_or_false_on_the_wire() {
        let els = [el("B", "boolean")];
        let ok = admx_element_values("P", &els, Some(&given("B = true"))).unwrap();
        assert_eq!(ok["B"], "true");
        let ok = admx_element_values("P", &els, Some(&given("B = \"False\""))).unwrap();
        assert_eq!(ok["B"], "false");
        let e = problems(admx_element_values("P", &els, Some(&given("B = \"1\""))));
        assert!(e.contains("not the registry value"), "{e}");
    }

    /// Nothing is filled in: an element left out is named, with what it takes.
    #[test]
    fn a_missing_element_is_refused_not_defaulted() {
        let mut e = el("E", "enum");
        e.items = vec![
            windows_schema::types::AdmxEnumItem {
                display: "Allow".into(),
                value: "1".into(),
            },
            windows_schema::types::AdmxEnumItem {
                display: "Block".into(),
                value: "2".into(),
            },
        ];
        let msg = problems(admx_element_values("P", &[e.clone()], None));
        assert!(
            msg.contains("E: missing") && msg.contains("1 (Allow)"),
            "{msg}"
        );
        // A label is not the value, and the refusal says which value it is.
        let msg = problems(admx_element_values(
            "P",
            &[e.clone()],
            Some(&given("E = \"Block\"")),
        ));
        assert!(msg.contains("the value is 2"), "{msg}");
        let msg = problems(admx_element_values("P", &[e], Some(&given("E = \"3\""))));
        assert!(msg.contains("3 is not one of"), "{msg}");
    }

    #[test]
    fn unknown_ids_ranges_and_lengths_are_refused_together() {
        let mut d = el("D", "decimal");
        d.min = Some(0.0);
        d.max = Some(10.0);
        let mut t = el("T", "text");
        t.max_length = Some(3);
        let msg = problems(admx_element_values(
            "P",
            &[d, t],
            Some(&given("D = 11\nT = \"four\"\nTypo = 1")),
        ));
        assert!(
            msg.contains("Typo: no such element; it takes D, T"),
            "{msg}"
        );
        assert!(msg.contains("11 is outside"), "{msg}");
        assert!(msg.contains("4 characters; at most 3"), "{msg}");
    }

    /// An ADMX that states no bounds still has the schema's: 0..=9999 for a
    /// decimal, 1023 characters for text.
    #[test]
    fn unstated_bounds_are_the_admx_schema_defaults() {
        let els = [el("D", "decimal"), el("T", "text")];
        let long = "x".repeat(1024);
        let msg = problems(admx_element_values(
            "P",
            &els,
            Some(&given(&format!("D = -1\nT = {long:?}"))),
        ));
        assert!(
            msg.contains("-1 is outside a whole number, 0..=9999"),
            "{msg}"
        );
        assert!(msg.contains("1024 characters; at most 1023"), "{msg}");
        assert!(admx_element_values("P", &els, Some(&given("D = 9999\nT = \"ok\""))).is_ok());
    }

    /// A TOML array is joined with the U+F000 separator Windows reads, and a
    /// name/value list must come in pairs.
    #[test]
    fn list_elements_take_an_array_joined_by_u_f000() {
        let ok = admx_element_values(
            "P",
            &[el("M", "multiText")],
            Some(&given("M = [\"a.exe\", \"b.exe\"]")),
        )
        .unwrap();
        assert_eq!(ok["M"], "a.exe\u{F000}b.exe");
        let mut l = el("L", "list");
        l.explicit_value = Some(true);
        let msg = problems(admx_element_values(
            "P",
            &[l],
            Some(&given("L = [\"1\", \"a\", \"2\"]")),
        ));
        assert!(msg.contains("name, value pairs"), "{msg}");
    }
}
