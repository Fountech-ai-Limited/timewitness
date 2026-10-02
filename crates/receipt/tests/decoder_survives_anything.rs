//! The decoder against input chosen to break it.
//!
//! Every receipt that reaches `open()` goes through `cbor::decode`, and the free public verifier is
//! the surface it will be reached on. A verifier a stranger can crash with nine bytes is not a
//! verifier they will trust, so the property this file asserts is the blunt one: no input of any
//! length, of any shape, from anybody, makes the decoder panic. It refuses, and it says why.
//!
//! Two halves. Four inputs that were watched panicking a release build, kept as named regressions
//! because a named case says what went wrong and a fuzzer does not. Then a deterministic fuzzer over
//! random bytes and over damaged copies of a real receipt, which is where the cases nobody thought
//! of come from.
//!
//! The fuzzer is in the tree and seeded rather than run through `cargo-fuzz`. It needs no nightly
//! toolchain and no extra dependency, it runs on every push in CI alongside everything else, and a
//! failure reproduces from the seed in the message. What it gives up against a coverage-guided
//! fuzzer is depth, and that trade is worth restating whenever this file is read: it is a floor, not
//! a proof.

use timewitness_receipt::{cbor, open};

/// The declared length that overflowed the bounds check, in the four shapes it reaches.
///
/// Each is a CBOR head announcing a length of very nearly 2^64 with nothing behind it. The check
/// was `at + n > len`, which wrapped, so the guard passed and the slice index went out the other
/// side. In a release build that is a panic and not an error.
const WATCHED_PANICKING: [(&str, &[u8]); 4] = [
    (
        "a byte string claiming 2^64-1 bytes",
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ),
    (
        "a text string claiming 2^64-1 bytes",
        &[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ),
    (
        "a byte string claiming 2^64-8 bytes, so the wrap lands inside the buffer",
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8],
    ),
    (
        "the same byte string one level down, inside an array",
        &[0x81, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ),
];

#[test]
fn the_four_inputs_that_panicked_the_decoder_are_refused() {
    for (what, bytes) in WATCHED_PANICKING {
        let outcome = cbor::decode(bytes);
        assert!(
            outcome.is_err(),
            "{what} was accepted, and it is {} bytes of nothing",
            bytes.len()
        );
    }
}

#[test]
fn the_same_inputs_are_refused_through_the_front_door_as_well() {
    // `open` is what a verifier calls. The decoder sits under it and this is the path a stranger's
    // bytes actually take.
    for (what, bytes) in WATCHED_PANICKING {
        assert!(open(bytes).is_err(), "{what} got past open()");
    }
}

#[test]
fn a_declared_length_longer_than_the_input_is_refused_at_every_width() {
    // The same lie told in the four widths CBOR allows for a length argument. None of these
    // overflows; they are here so the fix is a bounds check rather than an overflow check alone.
    let cases: [&[u8]; 4] = [
        &[0x58, 0xff],                   // one byte of length, 255 claimed
        &[0x59, 0xff, 0xff],             // two bytes, 65535 claimed
        &[0x5a, 0x7f, 0xff, 0xff, 0xff], // four bytes
        &[0x5b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00], // eight bytes, 4 GB claimed
    ];
    for bytes in cases {
        assert!(
            cbor::decode(bytes).is_err(),
            "a length longer than the input was accepted"
        );
    }
}

#[test]
fn a_collection_claiming_more_members_than_there_are_bytes_is_refused_without_reading_them() {
    // An array or a map announcing four billion members has to be refused on the announcement. Every
    // member costs at least one byte, so a count past the bytes remaining cannot be satisfied, and
    // finding that out by trying is a loop a stranger controls the length of.
    let cases: [&[u8]; 2] = [
        &[0x9a, 0xff, 0xff, 0xff, 0xff], // an array of 4,294,967,295 things
        &[0xba, 0xff, 0xff, 0xff, 0xff], // a map of the same
    ];
    for bytes in cases {
        assert!(
            cbor::decode(bytes).is_err(),
            "a collection larger than the input was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// The fuzzer
// ---------------------------------------------------------------------------

/// A seeded generator, so a failure is reproducible from the seed printed with it.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64. Good enough to produce varied bytes and small enough to read.
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn no_run_of_random_bytes_makes_the_decoder_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..200_000 {
        let len = rng.below(64);
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(rng.byte());
        }
        // There is no assertion here and there does not need to be one. The property is that these
        // two lines return at all, so the test passes by reaching the end of the loop.
        let _ = cbor::decode(&bytes);
        let _ = open(&bytes);
    }
}

#[test]
fn no_head_byte_followed_by_rubbish_makes_the_decoder_panic() {
    // Every one of the 256 possible first bytes, each given eight lengths of arbitrary tail. The
    // first byte is what decides how the rest is read, so this is the shallow part of the space
    // swept exhaustively rather than sampled.
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for head in 0u16..=255 {
        for tail_len in [0usize, 1, 2, 4, 8, 9, 16, 33] {
            let mut bytes = vec![head as u8];
            for _ in 0..tail_len {
                bytes.push(rng.byte());
            }
            let _ = cbor::decode(&bytes);
        }
    }
}

#[test]
fn no_damaged_copy_of_a_real_receipt_makes_the_decoder_panic() {
    // Random bytes almost never reach the deeper parts of the parser, because they fail at the
    // first head byte. Damaging something that was valid does, and it is closer to what actually
    // arrives: a receipt that was truncated in transit, or altered on purpose.
    let good = cbor::encode(&sample_value());
    let mut rng = Rng(0xdead_beef_cafe_f00d);

    for _ in 0..50_000 {
        let mut bytes = good.clone();
        match rng.below(4) {
            // Flip a byte.
            0 => {
                let i = rng.below(bytes.len());
                bytes[i] ^= rng.byte();
            }
            // Truncate.
            1 => {
                let keep = rng.below(bytes.len());
                bytes.truncate(keep);
            }
            // Splice in a length that is a lie.
            2 => {
                let i = rng.below(bytes.len());
                bytes.splice(i..i, [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            }
            // Append rubbish.
            _ => {
                for _ in 0..rng.below(16) {
                    bytes.push(rng.byte());
                }
            }
        }
        let _ = cbor::decode(&bytes);
        let _ = open(&bytes);
    }
}

/// A value with one of everything the format allows, so damaging it reaches every branch.
fn sample_value() -> timewitness_receipt::value::Value {
    use timewitness_receipt::value::Value;
    Value::map([
        ("version", Value::Int(0)),
        ("sequence", Value::Int(1)),
        ("negative", Value::Int(-4_200_000_000)),
        ("blob", Value::Bytes(vec![0xa1; 96])),
        ("text", Value::text("an authenticated corridor")),
        ("yes", Value::Bool(true)),
        ("no", Value::Bool(false)),
        ("nothing", Value::Null),
        (
            "list",
            Value::Array(vec![
                Value::Int(1),
                Value::text("two"),
                Value::Bytes(vec![3, 3, 3]),
                Value::map([("nested", Value::Int(4))]),
            ]),
        ),
    ])
}
