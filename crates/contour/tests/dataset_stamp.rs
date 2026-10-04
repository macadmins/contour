//! The rule that decides whether a pin bump reaches the binary.
//!
//! A file existing in `data/` says nothing about which dataset it is, so the
//! build compares `data/.dataset-pin` with what the checkout asks for; this
//! holds that comparison. The rule lives in its own file so it can
//! be included here — build scripts run no tests.

include!("../../../build-support/dataset_stamp.rs");

const PINNED: &str = "release v2026.09.27-2 sha256 d2420e31";

#[test]
fn the_pinned_dataset_stamped_and_complete_is_used() {
    assert_eq!(
        decide_data_action(Some(PINNED), PINNED, true, false),
        DataAction::Use
    );
    // A trailing newline, as the stamp is written, is the same stamp.
    assert_eq!(
        decide_data_action(Some(&format!("{PINNED}\n")), PINNED, true, false),
        DataAction::Use
    );
}

/// The defect: data/ from the previous pin, complete, looked finished.
#[test]
fn a_previous_pin_is_fetched_again_even_when_every_file_is_there() {
    let old = "release v2026.09.27-1 sha256 eba9a259";
    match decide_data_action(Some(old), PINNED, true, false) {
        DataAction::Fetch(why) => assert!(why.contains(old) && why.contains(PINNED), "{why}"),
        other => panic!("{other:?}"),
    }
}

/// Every checkout from before stamps: nothing vouches for what it holds.
#[test]
fn an_unstamped_data_dir_is_fetched() {
    assert!(matches!(
        decide_data_action(None, PINNED, true, false),
        DataAction::Fetch(why) if why.contains("no stamp")
    ));
    assert!(matches!(
        decide_data_action(Some("  "), PINNED, true, false),
        DataAction::Fetch(_)
    ));
}

/// A local dataset build leaves `local …`; the next pinned build replaces it.
#[test]
fn a_local_build_does_not_outlive_the_variable() {
    let local = dataset_stamp("local", "/tmp/dataset/out");
    assert!(matches!(
        decide_data_action(Some(&local), PINNED, true, false),
        DataAction::Fetch(_)
    ));
}

#[test]
fn the_right_stamp_with_files_missing_is_fetched() {
    assert!(matches!(
        decide_data_action(Some(PINNED), PINNED, false, false),
        DataAction::Fetch(why) if why.contains("missing")
    ));
}

/// Offline builds keep working, and say they are not the pin.
#[test]
fn skip_download_keeps_a_mismatch_but_never_silently() {
    let old = "release v2026.09.27-1 sha256 eba9a259";
    assert!(matches!(
        decide_data_action(Some(old), PINNED, true, true),
        DataAction::KeepWithWarning(why) if why.contains(old)
    ));
    // A match needs no warning, offline or not.
    assert_eq!(
        decide_data_action(Some(PINNED), PINNED, true, true),
        DataAction::Use
    );
}
