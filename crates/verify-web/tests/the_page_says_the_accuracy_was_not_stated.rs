//! The same sentence on the page as on the command line, taken through the page's own JSON.
//!
//! The page shows every line in `checks` for each piece of evidence, and this crate is where those
//! lines reach it. So the test builds the JSON the page is handed, rather than asserting about a
//! string somewhere behind it. Until 2026-09-19 the line read "to a stated accuracy of 0 ns" for a
//! token that stated no accuracy at all, on the page and on the command line alike, because both
//! read the one implementation.

use std::path::Path;

use timewitness_verify_web::json_for;

fn the_real_receipt() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("crates/verify/tests/data/a-real-stamp/receipt.cbor");
    std::fs::read(path).expect("the committed real receipt")
}

#[test]
fn the_checks_the_page_prints_say_the_accuracy_was_not_stated() {
    let json = json_for(&the_real_receipt(), None);

    assert!(
        json.contains("accuracy not stated"),
        "the page is not told the authority stated no accuracy:\n{json}"
    );
    assert!(
        !json.contains("accuracy of 0 ns"),
        "the page is still shown a figure the authority did not write:\n{json}"
    );
}
