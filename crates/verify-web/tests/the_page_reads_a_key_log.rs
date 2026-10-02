//! The page takes a copy of the key log the reader holds, as the command line does.
//!
//! The page reads the file here and never fetches one, so the only two things to hold are that a log
//! it cannot read stops the check and says so, and that a log it can read reaches the same step the
//! command line answers.

use std::path::Path;

use timewitness_verify_web::{json_for, json_with_key_log};

fn the_real_receipt() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("crates/verify/tests/data/a-real-stamp/receipt.cbor");
    std::fs::read(path).expect("the committed real receipt")
}

#[test]
fn a_file_that_is_not_a_key_log_stops_the_check_and_says_so() {
    let json = json_with_key_log(&the_real_receipt(), None, Some(b"not a key log\n"));
    assert!(json.contains("\"key_log_error\""), "{json}");
    assert!(!json.contains("\"steps\""), "nothing was checked: {json}");
}

#[test]
fn a_key_log_reaches_the_step_that_asks_whose_key_it_is() {
    let log = b"timewitness-key-log v1\n";
    let with = json_with_key_log(&the_real_receipt(), None, Some(log));
    assert!(with.contains("list nobody has put their name to"), "{with}");
    let without = json_with_key_log(&the_real_receipt(), None, None);
    assert_eq!(without, json_for(&the_real_receipt(), None));
    assert!(
        !with.contains("\"certificate\""),
        "no cutoff ships, so no grade: {with}"
    );
}
