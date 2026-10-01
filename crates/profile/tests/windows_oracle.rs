//! Oracle test: generated SyncML vs `fleet_stigs.enforcement_xml`.
//!
//! `fleet_stigs` carries 648 working enforcement fragments produced by a
//! different toolchain from a different source. Comparing contour's generator
//! against them is the one test here that is not a restatement of the
//! generator's own assumptions — a disagreement is genuine information about
//! which side is wrong.
//!
//! Two things are checked, and they fail for different reasons:
//!
//! 1. **Coverage** — every oracle LocURI must be reconstructible from the
//!    embedded capability data by [`build_path`]. A miss means the path rule
//!    or the capability data has drifted from Microsoft's DDF.
//! 2. **Exactness** — for each of those, the rendered fragment must equal the
//!    oracle's, byte for byte after trimming. A miss means the format mapping
//!    or the SyncML layout is wrong.

use std::collections::HashMap;

use profile::windows::syncml::{Channel, Operation, build_path, render, syncml_format};

/// Reconstruct every LocURI the capability data can address, mapped to the
/// key's declared data type.
fn path_index() -> HashMap<String, String> {
    let caps = mdm_schema::capabilities::read(mdm_schema::embedded_windows_capabilities())
        .expect("read embedded windows capabilities");

    let mut index = HashMap::new();
    for cap in &caps {
        for key in &cap.keys {
            let (device, user) = profile::windows::syncml::channels_for_key(cap, key);
            let mut channels = Vec::new();
            if device {
                channels.push(Channel::Device);
            }
            if user {
                channels.push(Channel::User);
            }
            if channels.is_empty() {
                channels.push(Channel::Unscoped);
            }
            for channel in channels {
                let path = build_path(
                    &cap.payload_type,
                    profile::windows::syncml::csp_for_key(cap, key),
                    key.parent_key.as_deref(),
                    &key.name,
                    channel,
                );
                index.insert(path, key.data_type.clone());
            }
        }
    }
    index
}

/// One usable oracle row.
struct OracleRow {
    uri: String,
    format: String,
    data: String,
    xml: String,
    is_admx: bool,
}

fn oracle_rows() -> Vec<OracleRow> {
    let stigs = windows_schema::fleet_stigs::read(windows_schema::embedded_fleet_stigs())
        .expect("read embedded fleet_stigs");

    stigs
        .into_iter()
        .filter_map(|s| {
            // Rows without a format are blocked upstream (Fleet refuses the
            // CSP, or the definition had no DDF match). They carry no
            // fragment to compare against.
            let format = s.enforcement_format?;
            let xml = s.enforcement_xml?;
            if format.is_empty() || xml.is_empty() {
                return None;
            }
            Some(OracleRow {
                uri: s.oma_uri,
                format,
                data: s.enforcement_data.unwrap_or_default(),
                xml,
                is_admx: s.is_admx,
            })
        })
        .collect()
}

#[test]
fn oracle_every_fragment_path_is_reconstructible() {
    let index = path_index();
    let rows = oracle_rows();
    assert!(
        rows.len() > 600,
        "expected the full oracle set, got {} rows — did fleet_stigs shrink?",
        rows.len()
    );

    let missing: Vec<&str> = rows
        .iter()
        .map(|r| r.uri.as_str())
        .filter(|uri| !index.contains_key(*uri))
        .collect();

    assert!(
        missing.is_empty(),
        "{} of {} oracle LocURIs cannot be rebuilt from the capability data. \
         The path rule or the DDF ingest has drifted. First few:\n  {}",
        missing.len(),
        rows.len(),
        missing
            .iter()
            .take(5)
            .copied()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn oracle_generated_syncml_matches_fleet_stigs() {
    let index = path_index();
    let rows = oracle_rows();

    let mut format_disagreements = Vec::new();
    let mut render_disagreements = Vec::new();
    let mut compared = 0;

    for row in &rows {
        let Some(data_type) = index.get(&row.uri) else {
            continue; // coverage is the other test's business
        };

        // The format contour would choose from the declared data type, vs the
        // one the oracle shipped.
        let Some(ours) = syncml_format(data_type) else {
            format_disagreements.push(format!(
                "{}: data_type '{}' yields no format, oracle says '{}'",
                row.uri, data_type, row.format
            ));
            continue;
        };
        if ours != row.format {
            format_disagreements.push(format!(
                "{}: data_type '{}' -> contour '{}', oracle '{}'",
                row.uri, data_type, ours, row.format
            ));
            continue;
        }

        let generated = render(Operation::Replace, &row.uri, ours, Some(&row.data));

        compared += 1;
        if generated.trim() != row.xml.trim() {
            if render_disagreements.len() < 3 {
                render_disagreements.push(format!(
                    "--- {}\n  admx={}\n  contour:\n{}\n  oracle:\n{}",
                    row.uri, row.is_admx, generated, row.xml
                ));
            }
        }
    }

    assert!(
        format_disagreements.is_empty(),
        "{} format disagreement(s) between contour and the oracle:\n  {}",
        format_disagreements.len(),
        format_disagreements
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    assert!(
        compared > 600,
        "only {compared} fragments compared — the oracle set shrank unexpectedly"
    );

    assert!(
        render_disagreements.is_empty(),
        "generated SyncML differs from the oracle. Work out which side is \
         right before changing either.\n{}",
        render_disagreements.join("\n")
    );
}
