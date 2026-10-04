//! The `variant` and `key_path` columns.
//!
//! Both are read as optional, so a parquet predating them still loads —
//! these tests assert the behaviour when they ARE present.

/// One payload type is not always one payload.
///
/// `com.apple.MCX` is the managed-preferences container and Apple describes
/// six surfaces through it, naming each in the filename —
/// `com.apple.MCX(WiFi).yaml`, `(EnergySaver)`, `(Accounts)`, `(Mobility)`,
/// `(TimeServer)`, `(FileVault2)`. Keyed on payload type alone they merge into
/// one capability wearing six titles.
#[test]
fn mcx_reads_as_six_capabilities_not_one() {
    let caps = mdm_schema::capabilities::read(mdm_schema::embedded_capabilities())
        .expect("read capabilities");
    let mcx: Vec<_> = caps
        .iter()
        .filter(|c| c.payload_type == "com.apple.MCX")
        .collect();
    if mcx.iter().all(|c| c.variant.is_none()) {
        return; // dataset predates the column
    }
    let variants: std::collections::BTreeSet<_> =
        mcx.iter().filter_map(|c| c.variant.as_deref()).collect();
    for expected in [
        "wifi",
        "energysaver",
        "accounts",
        "mobility",
        "timeserver",
        "filevault2",
    ] {
        assert!(
            variants.contains(expected),
            "missing MCX variant {expected:?}: {variants:?}"
        );
    }
    for c in &mcx {
        assert!(!c.title.is_empty(), "{:?} has no title", c.variant);
    }
}

/// `key_path` survives a dot inside a segment, which `parent_key` cannot.
///
/// Apple ships `com.apple.EnergySaver.desktop.ACPower` as a single key name.
#[test]
fn key_path_escapes_dots_inside_a_segment() {
    let caps = mdm_schema::capabilities::read(mdm_schema::embedded_capabilities())
        .expect("read capabilities");
    let mut checked = 0;
    for cap in &caps {
        for key in &cap.keys {
            let Some(path) = &key.key_path else { continue };
            if !key.name.contains('.') {
                continue;
            }
            checked += 1;
            assert!(
                path.contains("\\."),
                "{}: key {:?} contains a dot but its key_path {:?} is unescaped",
                cap.payload_type,
                key.name,
                path
            );
        }
    }
    assert!(
        checked > 0,
        "no dotted key names found — dataset may predate key_path"
    );
}

/// A capability with no keys occupies a row with an empty `key_name`.
/// Read literally that becomes a key with no name; it is not a key.
#[test]
fn placeholder_rows_do_not_become_keys() {
    let caps = mdm_schema::capabilities::read(mdm_schema::embedded_capabilities())
        .expect("read capabilities");
    let nameless: Vec<&str> = caps
        .iter()
        .flat_map(|c| c.keys.iter().map(move |k| (c.payload_type.as_str(), k)))
        .filter(|(_, k)| k.name.is_empty())
        .map(|(t, _)| t)
        .collect();
    assert!(
        nameless.is_empty(),
        "capabilities carry nameless keys: {nameless:?}"
    );
}
