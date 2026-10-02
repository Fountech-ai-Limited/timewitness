//! Deterministic CBOR, encoder and a strict decoder.
//!
//! Deterministic means the same logical receipt always produces the same bytes. That matters more
//! here than it does in most places, because the bytes are what gets hashed, what gets signed, and
//! what a verifier compares. A format with two valid spellings of the same value gives an attacker
//! room to produce a second receipt that means the same thing and hashes differently, or a
//! signature that covers one spelling while a reader sees another.
//!
//! The rules, which are RFC 8949's core deterministic encoding:
//!
//! - definite lengths everywhere, never indefinite;
//! - the shortest form of every integer argument;
//! - map keys sorted by their own encoded bytes, and never repeated;
//! - no floating point at all, which is stricter than the specification and is deliberate, because
//!   every quantity in a receipt is a whole number.
//!
//! The decoder rejects anything that is not encoded that way rather than accepting it quietly. It
//! also re-encodes what it decoded and compares the bytes, so a spelling this file has not thought
//! of still cannot get through.

use crate::error::ReceiptError;
use crate::value::Value;

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

/// Encode a value as deterministic CBOR.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

fn write_head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if argument < 24 {
        out.push(m | argument as u8);
    } else if argument <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(argument as u8);
    } else if argument <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

fn write_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(i) => {
            if *i >= 0 {
                write_head(MAJOR_UINT, clamp_u64(*i), out);
            } else {
                // A negative integer is encoded as its own magnitude less one.
                let magnitude = (-1 - *i) as u128;
                write_head(MAJOR_NINT, clamp_u64_from_u128(magnitude), out);
            }
        }
        Value::Bytes(b) => {
            write_head(MAJOR_BYTES, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            let bytes = t.as_bytes();
            write_head(MAJOR_TEXT, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Array(items) => {
            write_head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                write_value(item, out);
            }
        }
        Value::Map(pairs) => {
            // Sorted by the encoded bytes of the key, which is what makes two maps carrying the
            // same entries in a different order produce the same receipt.
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> =
                pairs.iter().map(|(k, v)| (encode(k), encode(v))).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            write_head(MAJOR_MAP, encoded.len() as u64, out);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(b) => {
            out.push((MAJOR_SIMPLE << 5) | if *b { SIMPLE_TRUE } else { SIMPLE_FALSE });
        }
        Value::Null => {
            out.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL);
        }
    }
}

fn clamp_u64(i: i128) -> u64 {
    u64::try_from(i).unwrap_or(u64::MAX)
}

fn clamp_u64_from_u128(u: u128) -> u64 {
    u64::try_from(u).unwrap_or(u64::MAX)
}

/// Decode deterministic CBOR, refusing anything that is not encoded canonically.
///
/// Every input this accepts re-encodes to exactly the bytes it came from. That property is checked
/// rather than assumed.
pub fn decode(bytes: &[u8]) -> Result<Value, ReceiptError> {
    let mut cursor = Cursor { bytes, at: 0 };
    let value = read_value(&mut cursor, 0)?;
    if cursor.at != bytes.len() {
        return Err(ReceiptError::Encoding(format!(
            "{} trailing bytes after the value",
            bytes.len() - cursor.at
        )));
    }
    if encode(&value) != bytes {
        return Err(ReceiptError::Encoding(
            "the receipt is not in the one spelling this format allows".to_string(),
        ));
    }
    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    /// How many bytes are left to read.
    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// A length or a count off the wire, held to what is left before it becomes a size. Each item
    /// costs at least `per` bytes, so more than the bytes left can carry is a receipt that ends part
    /// way through a value. Held as a 64-bit number first, so the answer is the same on a machine
    /// whose sizes are 32 bits wide, which is what the verifier page runs on, as on one whose are 64.
    fn announced(&self, argument: u64, per: usize) -> Result<usize, ReceiptError> {
        let room = u64::try_from(self.remaining() / per).unwrap_or(u64::MAX);
        if argument > room {
            return Err(ReceiptError::Encoding(
                "the receipt ends part way through a value".into(),
            ));
        }
        // At most what is left, which is itself a size, so this cannot fail.
        Ok(usize::try_from(argument).unwrap_or(usize::MAX))
    }

    fn take(&mut self, n: usize) -> Result<&[u8], ReceiptError> {
        // Compared rather than added. `n` is a length argument off the wire and may be anything up
        // to 2^64-1, so `self.at + n` wraps in a release build, the guard passes on a number that
        // came out the other side of zero, and the slice index below panics. Nine bytes did it:
        // a byte string announcing 2^64-1 bytes and carrying none. Every receipt a stranger sends
        // comes through here, so a panic here is the whole verifier going down on nine bytes.
        if n > self.remaining() {
            return Err(ReceiptError::Encoding(
                "the receipt ends part way through a value".into(),
            ));
        }
        let slice = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, ReceiptError> {
        Ok(self.take(1)?[0])
    }
}

/// How deeply a receipt may nest. Enough for the shape this format defines and small enough that a
/// hostile input cannot exhaust the stack.
const MAX_DEPTH: usize = 16;

fn read_head(cursor: &mut Cursor) -> Result<(u8, u64), ReceiptError> {
    let initial = cursor.byte()?;
    let major = initial >> 5;
    let info = initial & 0x1f;
    let argument = match info {
        0..=23 => u64::from(info),
        24 => u64::from(cursor.byte()?),
        25 => {
            let b = cursor.take(2)?;
            u64::from(u16::from_be_bytes([b[0], b[1]]))
        }
        26 => {
            let b = cursor.take(4)?;
            u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }
        27 => {
            let b = cursor.take(8)?;
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        }
        31 => {
            return Err(ReceiptError::Encoding(
                "indefinite lengths are not allowed in a receipt".into(),
            ))
        }
        other => {
            return Err(ReceiptError::Encoding(format!(
                "the value at byte {} is not a shape this format allows ({other})",
                cursor.at - 1
            )))
        }
    };
    Ok((major, argument))
}

fn read_value(cursor: &mut Cursor, depth: usize) -> Result<Value, ReceiptError> {
    if depth > MAX_DEPTH {
        return Err(ReceiptError::Encoding(
            "the receipt nests too deeply".into(),
        ));
    }
    let (major, argument) = read_head(cursor)?;
    match major {
        MAJOR_UINT => Ok(Value::Int(i128::from(argument))),
        MAJOR_NINT => Ok(Value::Int(-1 - i128::from(argument))),
        MAJOR_BYTES => {
            let n = cursor.announced(argument, 1)?;
            Ok(Value::Bytes(cursor.take(n)?.to_vec()))
        }
        MAJOR_TEXT => {
            let n = cursor.announced(argument, 1)?;
            let raw = cursor.take(n)?;
            let text = core::str::from_utf8(raw)
                .map_err(|_| ReceiptError::Encoding("a text field is not valid UTF-8".into()))?;
            Ok(Value::Text(text.to_string()))
        }
        MAJOR_ARRAY => {
            // Refused on the announcement rather than by trying. Every member costs at least one
            // byte, so a count past what is left cannot be satisfied, and finding that out by
            // looping is a loop whose length a stranger chose.
            let n = cursor.announced(argument, 1)?;
            let mut items = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                items.push(read_value(cursor, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        MAJOR_MAP => {
            // A pair costs at least two bytes, so half of what is left is the most a map can hold.
            let n = cursor.announced(argument, 2)?;
            let mut pairs = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                let k = read_value(cursor, depth + 1)?;
                let v = read_value(cursor, depth + 1)?;
                pairs.push((k, v));
            }
            let mut keys: Vec<Vec<u8>> = pairs.iter().map(|(k, _)| encode(k)).collect();
            keys.sort();
            for pair in keys.windows(2) {
                if pair[0] == pair[1] {
                    return Err(ReceiptError::Encoding(
                        "the same key appears twice in one map".into(),
                    ));
                }
            }
            Ok(Value::Map(pairs))
        }
        MAJOR_SIMPLE => match argument {
            a if a == u64::from(SIMPLE_FALSE) => Ok(Value::Bool(false)),
            a if a == u64::from(SIMPLE_TRUE) => Ok(Value::Bool(true)),
            a if a == u64::from(SIMPLE_NULL) => Ok(Value::Null),
            other => Err(ReceiptError::Encoding(format!(
                "a receipt may not carry the simple value {other}, and floating point is not \
                 allowed at all"
            ))),
        },
        other => Err(ReceiptError::Encoding(format!(
            "a receipt may not carry a value of major type {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: Value) {
        let bytes = encode(&v);
        let back = decode(&bytes).expect("what this encoder produces, this decoder accepts");
        assert_eq!(back, v);
    }

    #[test]
    fn whole_numbers_round_trip_at_every_size() {
        for i in [
            0i128,
            1,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            4_294_967_295,
            4_294_967_296,
        ] {
            round_trip(Value::Int(i));
            round_trip(Value::Int(-i - 1));
        }
    }

    #[test]
    fn small_numbers_use_one_byte() {
        assert_eq!(encode(&Value::Int(0)), vec![0x00]);
        assert_eq!(encode(&Value::Int(23)), vec![0x17]);
        assert_eq!(encode(&Value::Int(24)), vec![0x18, 0x18]);
        assert_eq!(encode(&Value::Int(-1)), vec![0x20]);
    }

    #[test]
    fn text_bytes_lists_and_maps_round_trip() {
        round_trip(Value::text("bounded, never accurate"));
        round_trip(Value::Bytes(vec![0, 1, 2, 250]));
        round_trip(Value::Array(vec![Value::Int(1), Value::text("a")]));
        round_trip(Value::map([("b", Value::Int(2)), ("a", Value::Int(1))]));
        round_trip(Value::Bool(true));
        round_trip(Value::Null);
    }

    #[test]
    fn two_maps_with_the_same_entries_encode_to_the_same_bytes() {
        let one = Value::map([("zulu", Value::Int(1)), ("alpha", Value::Int(2))]);
        let other = Value::map([("alpha", Value::Int(2)), ("zulu", Value::Int(1))]);
        assert_eq!(encode(&one), encode(&other));
    }

    #[test]
    fn keys_are_ordered_by_their_encoded_bytes() {
        // Shorter keys sort before longer ones, whatever the alphabet says.
        let v = Value::map([("zz", Value::Int(1)), ("a", Value::Int(2))]);
        let bytes = encode(&v);
        // map(2), then text(1) "a", then 2, then text(2) "zz", then 1.
        assert_eq!(bytes, vec![0xa2, 0x61, b'a', 0x02, 0x62, b'z', b'z', 0x01]);
    }

    #[test]
    fn a_number_written_the_long_way_is_refused() {
        // Zero, written with a one byte argument instead of inline.
        assert!(decode(&[0x18, 0x00]).is_err());
    }

    #[test]
    fn an_indefinite_length_is_refused() {
        // An indefinite length array.
        assert!(decode(&[0x9f, 0x01, 0xff]).is_err());
    }

    #[test]
    fn a_map_with_its_keys_out_of_order_is_refused() {
        // The same two entries as the ordering test, written the wrong way round.
        assert!(decode(&[0xa2, 0x62, b'z', b'z', 0x01, 0x61, b'a', 0x02]).is_err());
    }

    #[test]
    fn a_repeated_key_is_refused() {
        assert!(decode(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]).is_err());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = encode(&Value::Int(1));
        bytes.push(0x00);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn floating_point_is_refused_outright() {
        // A half precision float, which ordinary CBOR would accept.
        assert!(decode(&[0xf9, 0x00, 0x00]).is_err());
    }

    #[test]
    fn a_truncated_receipt_is_refused() {
        assert!(decode(&[0x62, b'a']).is_err());
    }

    #[test]
    fn text_that_is_not_utf8_is_refused() {
        assert!(decode(&[0x61, 0xff]).is_err());
    }

    /// A length that cannot be satisfied is said the same way on every machine. Until 2026-09-25 a
    /// text file whose first byte announces an eight-byte length was "larger than this machine can
    /// hold" in the browser, where a length is 32 bits wide, and "ends part way through a value" on
    /// the command line, where it is 64. Same bytes, two reasons, and the page's read as a fault of
    /// the reader's machine. The length is now held to what is left before it is ever made a size.
    #[test]
    fn a_length_past_the_end_is_the_same_refusal_however_wide_the_machine() {
        let said = |bytes: &[u8]| match decode(bytes) {
            Err(ReceiptError::Encoding(why)) => why,
            other => panic!("{other:?}"),
        };
        let text_file = b"{\"receipt\":\"not really\"}
";
        assert_eq!(text_file.len(), 25);
        assert_eq!(said(text_file), "the receipt ends part way through a value");

        // Past what a 32-bit length holds, which is where the browser's answer used to differ.
        for major in [0x5b_u8, 0x7b, 0x9b, 0xbb] {
            let mut bytes = vec![major];
            bytes.extend_from_slice(&(u64::from(u32::MAX) + 1).to_be_bytes());
            assert_eq!(
                said(&bytes),
                "the receipt ends part way through a value",
                "major byte {major:#x}"
            );
        }
    }
}
