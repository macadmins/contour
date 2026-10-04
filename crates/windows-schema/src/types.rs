//! Domain types for the Windows STIG compliance datasets.

/// One registry-backed Windows STIG check (from MITRE's InSpec baseline).
///
/// Joins to the Windows rules (`windows_rules.parquet`) on `rule_id`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct StigRegistryCheck {
    /// STIG rule id (e.g. `V-253260`).
    pub rule_id: String,
    /// Registry hive (e.g. `HKEY_LOCAL_MACHINE`).
    pub hive: String,
    /// Registry key path under the hive.
    pub path: String,
    /// Value name to check.
    pub value_name: String,
    /// Registry value type (`REG_DWORD`, `REG_SZ`, …).
    pub value_type: String,
    /// Expected value, as the STIG states it.
    pub expected_value: String,
    /// Generated osquery query for the check — usable directly as a
    /// Fleet compliance policy.
    pub osquery_sql: String,
}

/// One Fleet-deployable STIG policy: the CSP enforcement (SyncML) plus
/// the osquery compliance check.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FleetStig {
    /// STIG profile this policy belongs to.
    pub stig_profile: String,
    /// OMA-URI / LocURI of the CSP node being enforced.
    pub oma_uri: String,
    /// Whether enforcement is available/blocked for this policy.
    pub enforcement_status: String,
    /// Whether a compliance check is available for this policy.
    pub compliance_status: String,
    /// SyncML fragment that enforces the policy (`<Replace>…`).
    pub enforcement_xml: Option<String>,
    /// SyncML `Format` of the enforcement data (`int`, `chr`, …).
    pub enforcement_format: Option<String>,
    /// The enforcement `Data` value.
    pub enforcement_data: Option<String>,
    /// osquery query verifying compliance.
    pub compliance_query: Option<String>,
    /// Human-readable policy name.
    pub policy_name: String,
    /// Policy tags.
    pub policy_tags: Vec<String>,
    /// CSP policy area (e.g. `Update`, `Defender`).
    pub csp_area: Option<String>,
    /// True when the policy is ADMX-backed (CDATA `<enabled/><data/>` payload).
    pub is_admx: bool,
    /// Why enforcement is blocked, when it is.
    pub block_reason: Option<String>,
}

/// One value an ADMX `enum` element offers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdmxEnumItem {
    /// English label from the template's strings.
    pub display: String,
    /// Value written into the `<data>` payload.
    pub value: String,
}

/// An input an ADMX policy takes when enabled.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmxElement {
    /// `id` attribute, used as `<data id=…>`.
    pub id: String,
    /// `boolean`, `decimal`, `longDecimal`, `text`, `multiText`, `enum` or `list`.
    pub kind: String,
    /// Label from the policy's presentation, when the template has one.
    pub label: Option<String>,
    /// Whether the element must be supplied.
    pub required: Option<bool>,
    /// Lowest accepted number.
    pub min: Option<f64>,
    /// Highest accepted number.
    pub max: Option<f64>,
    /// Longest accepted string.
    pub max_length: Option<u32>,
    /// Value a `boolean` element writes when on.
    pub true_value: Option<String>,
    /// Value a `boolean` element writes when off.
    pub false_value: Option<String>,
    /// Whether a `list` element carries its own value names.
    pub explicit_value: Option<bool>,
    /// Choices for an `enum` element, in document order.
    pub items: Vec<AdmxEnumItem>,
    /// The registry value this element writes (`valueName` in the ADMX).
    /// `None` on a dataset without the column, and for a
    /// `list`, which writes under a prefix.
    pub value_name: Option<String>,
    /// An element-level registry key overriding the policy's, when the ADMX
    /// states one.
    pub key: Option<String>,
}

impl AdmxElement {
    /// A value that satisfies this element, for scaffolding a payload.
    ///
    /// Booleans take `true`, numbers their minimum, enums their first
    /// choice. Free-text elements have no sensible stand-in and return
    /// `None` — the admin has to supply those.
    ///
    /// A boolean is `true` on the wire, not its `trueValue`: that is the
    /// registry value the template writes, and Microsoft's example sends
    /// `value="true"` for an element whose trueValue is decimal 1. This
    /// returned the trueValue.
    pub fn example_value(&self) -> Option<String> {
        match self.kind.as_str() {
            "boolean" => Some("true".to_string()),
            "decimal" | "longDecimal" => Some(self.min.unwrap_or(0.0).trunc().to_string()),
            "enum" => self.items.first().map(|i| i.value.clone()),
            _ => None,
        }
    }
}

/// An ADMX policy behind a Windows CSP node, with its element schema.
///
/// Joins `windows_capabilities` on `(payload_type, key_name)`.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmxPolicy {
    /// CSP area the node belongs to (e.g. `ADMX_AppCompat`).
    pub payload_type: String,
    /// CSP node name.
    pub key_name: String,
    /// Template file the policy is defined in.
    pub admx_file: String,
    /// Area path inside the template.
    pub admx_area: String,
    /// Policy `name` attribute.
    pub policy_name: String,
    /// `Machine`, `User` or `Both`.
    pub class: String,
    /// Registry key the policy writes under.
    pub registry_key: Option<String>,
    /// Registry value the policy itself writes.
    pub registry_value: Option<String>,
    /// Value written when enabled.
    pub enabled_value: Option<String>,
    /// Value written when disabled.
    pub disabled_value: Option<String>,
    /// English title.
    pub display_name: Option<String>,
    /// English explanation.
    pub explain_text: Option<String>,
    /// Elements the policy takes when enabled, in document order.
    pub elements: Vec<AdmxElement>,
}

impl AdmxPolicy {
    /// Build the `<Data>` payload for this policy.
    ///
    /// `values` supplies element ids; anything missing falls back to
    /// [`AdmxElement::example_value`], and an element with neither is left
    /// out so the caller can see what still needs a value. Pass `None` for
    /// `values` to scaffold. The result is unescaped — a SyncML `<Data>`
    /// element must XML-escape it.
    pub fn payload(&self, values: Option<&std::collections::HashMap<String, String>>) -> String {
        admx_payload(&self.elements, values)
    }

    /// The payload that turns this policy off.
    pub fn disabled_payload(&self) -> String {
        "<disabled/>".to_string()
    }
}

/// The body an ADMX-backed policy takes when enabled: `<enabled/>` and one
/// `<data id value/>` per element. Shared by in-box CSP policies and
/// ingested third-party ones — the wire format does not know the
/// difference.
pub fn admx_payload(
    elements: &[AdmxElement],
    values: Option<&std::collections::HashMap<String, String>>,
) -> String {
    let mut out = String::from("<enabled/>");
    for element in elements {
        let value = values
            .and_then(|v| v.get(&element.id).cloned())
            .or_else(|| element.example_value());
        if let Some(value) = value {
            out.push_str(&format!(
                "<data id=\"{}\" value=\"{}\"/>",
                xml_escape(&element.id),
                xml_escape(&value)
            ));
        }
    }
    out
}

/// A policy from a third-party app's Administrative Template — Chrome, Edge,
/// Firefox, Office and other vendor templates.
///
/// Delivered in two steps: ingest the template once at
/// `admx_install_loc_uri` (the ADMX file's own XML as the body), then set the
/// policy at `device_loc_uri` or `user_loc_uri`, whose area is
/// `{app_name}~Policy~{category_path}`. `ingestable` is Windows' rule on
/// whether MDM may write where this policy writes — an ingested policy under
/// `Software\Policies\Microsoft\` is silently dropped unless the location
/// is on Microsoft's allow-list — with the document that verdict rests on.
///
/// Joins nothing in `windows_capabilities`: these areas do not exist until
/// the template is ingested. `in_box_area` names the native Policy CSP area
/// when Windows already ships the same template, in which case ingestion is
/// the wrong route.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowsAppPolicy {
    /// Source key in the dataset's template manifest (`chrome`, `edge`,
    /// `office`, …).
    pub template: String,
    /// `{AppName}` of the ADMXInstall URI; first segment of the area.
    pub app_name: String,
    pub vendor: String,
    /// `published` (the vendor ships it) or `community`.
    pub provenance: String,
    pub source_label: String,
    /// Where the template was fetched from — where an operator fetches it
    /// too, since the XML itself is not shipped here.
    pub source_url: String,
    pub admx_file: String,
    pub policy_name: String,
    /// `Machine`, `User` or `Both`.
    pub class: String,
    pub category_path: String,
    /// `{app_name}~Policy~{category_path}`.
    pub area: String,
    pub device_loc_uri: String,
    pub user_loc_uri: String,
    pub admx_install_loc_uri: String,
    pub supported_on: Option<String>,
    pub registry_key: Option<String>,
    pub registry_value: Option<String>,
    pub enabled_value: Option<String>,
    pub disabled_value: Option<String>,
    pub display_name: Option<String>,
    pub explain_text: Option<String>,
    pub ingestable: bool,
    pub ingest_reason: Option<String>,
    pub ingest_evidence: String,
    pub in_box_area: Option<String>,
    pub elements: Vec<AdmxElement>,
}

impl WindowsAppPolicy {
    /// The enabling payload, with element values by id where given.
    pub fn payload(&self, values: Option<&std::collections::HashMap<String, String>>) -> String {
        admx_payload(&self.elements, values)
    }

    /// The payload that turns this policy off.
    pub fn disabled_payload(&self) -> String {
        "<disabled/>".to_string()
    }
}

/// What the DDF says about a CSP node beyond its type: the meaning of each
/// allowed value, the nodes it depends on, and whether it must be delivered
/// inside `<Atomic>`. Joins `windows_capabilities` on
/// `(payload_type, key_path)`.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeDetail {
    pub payload_type: String,
    pub key_path: String,
    pub key_name: String,
    pub csp_version: Option<String>,
    pub editions: Option<String>,
    pub home_supported: Option<bool>,
    pub pro_supported: Option<bool>,
    pub value_descriptions: Vec<ValueDescription>,
    pub dependencies: Vec<NodeDependency>,
    pub atomic_required: bool,
}

/// One allowed value and what Microsoft says it means.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ValueDescription {
    pub value: String,
    pub description: String,
}

/// A `DependencyBehavior` from the DDF: this node applies only when `uri`
/// holds one of `values`.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct NodeDependency {
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub uri: String,
    #[serde(default)]
    pub value_type: String,
    #[serde(default)]
    pub values: Vec<String>,
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
