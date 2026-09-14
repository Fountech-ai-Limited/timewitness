//! Just enough DER to read a timestamp token, and not one byte more.
//!
//! A timestamp token is the only thing in this product encoded this way, and it arrives from
//! outside, so this reader is written the way the CBOR decoder next door is: it checks every length
//! against the bytes in hand rather than against the number the encoding claims, it refuses
//! everything it has not been taught, and it never allocates from a field it has not validated.
//!
//! Two rules it enforces that a permissive reader would not, both of which matter because the bytes
//! get hashed and compared:
//!
//! - **No indefinite lengths.** They are legal in BER and forbidden in DER, and accepting one means
//!   accepting two encodings of the same document.
//! - **No unread trailing bytes inside a value.** A sequence with something after its last element
//!   is a place to hide a second document, so reading one asks for the remainder to be empty.

use super::EvidenceError;

/// How deep this reader will follow a nesting before deciding the input is hostile.
///
/// A timestamp token nests about eight deep. Sixteen is room to spare and still refuses a document
/// built to run a parser out of stack.
const MAX_DEPTH: usize = 16;

/// One tag, length and value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier octet, class and constructed bit included.
    pub tag: u8,
    /// The content, without the tag or the length.
    pub value: &'a [u8],
    /// The tag, length and content together, which is what gets hashed or signed.
    pub whole: &'a [u8],
}

/// A cursor over a run of DER elements.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

fn malformed(what: impl Into<String>) -> EvidenceError {
    EvidenceError::Malformed(what.into())
}

impl<'a> Reader<'a> {
    /// A reader over some bytes.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            depth: 0,
        }
    }

    /// Whether everything has been read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    /// What is left unread.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at.min(self.bytes.len())..]
    }

    /// Read the next element, whatever it is.
    pub fn take(&mut self) -> Result<Tlv<'a>, EvidenceError> {
        if self.depth > MAX_DEPTH {
            return Err(malformed("a document nested deeper than any token is"));
        }
        let start = self.at;
        let tag = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| malformed("an element with no tag"))?;
        self.at += 1;

        // High tag numbers are a multi-byte form nothing in a timestamp token uses.
        if tag & 0x1f == 0x1f {
            return Err(malformed("a multi-byte tag, which no part of a token uses"));
        }

        let first = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| malformed("an element with no length"))?;
        self.at += 1;

        let length = if first < 0x80 {
            usize::from(first)
        } else if first == 0x80 {
            return Err(malformed(
                "an indefinite length, which is not allowed in this encoding",
            ));
        } else if first == 0xff {
            return Err(malformed("a reserved length form"));
        } else {
            let count = usize::from(first & 0x7f);
            if count > 4 {
                return Err(malformed(
                    "a length longer than any real document, expressed in more than four bytes",
                ));
            }
            // The long form is written with no leading zero. Allowing one gives every length a
            // second spelling, and a padded length is the easy half of it: 82 00 81 and 81 81 are
            // both one hundred and twenty-nine, so two byte strings that differ describe the same
            // document. The two checks together, this one and the one below, are the whole of the
            // shortest-form rule for a length.
            if self.bytes.get(self.at) == Some(&0) {
                return Err(malformed(
                    "a length padded with a leading zero, which this encoding forbids",
                ));
            }
            let mut value = 0usize;
            for _ in 0..count {
                let byte = *self
                    .bytes
                    .get(self.at)
                    .ok_or_else(|| malformed("a length that runs off the end"))?;
                self.at += 1;
                value = (value << 8) | usize::from(byte);
            }
            // And a length under 128 has a one byte form, so writing it long is the other half of
            // the same second spelling.
            if value < 0x80 {
                return Err(malformed(
                    "a short length written in the long form, which this encoding forbids",
                ));
            }
            value
        };

        let end = self
            .at
            .checked_add(length)
            .ok_or_else(|| malformed("a length that overflows a length"))?;
        if end > self.bytes.len() {
            return Err(malformed(format!(
                "an element claiming {length} bytes with {} left",
                self.bytes.len() - self.at
            )));
        }
        let value = &self.bytes[self.at..end];
        let whole = &self.bytes[start..end];
        self.at = end;
        Ok(Tlv { tag, value, whole })
    }

    /// Read the next element and require its tag.
    pub fn expect(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>, EvidenceError> {
        let element = self.take()?;
        if element.tag != tag {
            return Err(malformed(format!(
                "{what} should be tagged {tag:#04x} and is tagged {:#04x}",
                element.tag
            )));
        }
        Ok(element)
    }

    /// Read the next element, require it to be a sequence, and return a reader over its contents.
    pub fn sequence(&mut self, what: &str) -> Result<Reader<'a>, EvidenceError> {
        let element = self.expect(TAG_SEQUENCE, what)?;
        Ok(self.inner(element.value))
    }

    /// The same for a set.
    pub fn set(&mut self, what: &str) -> Result<Reader<'a>, EvidenceError> {
        let element = self.expect(TAG_SET, what)?;
        Ok(self.inner(element.value))
    }

    /// A reader over the contents of an element already in hand, one level deeper.
    #[must_use]
    pub fn inner(&self, bytes: &'a [u8]) -> Reader<'a> {
        Reader {
            bytes,
            at: 0,
            depth: self.depth + 1,
        }
    }

    /// Read an object identifier and return its encoded body.
    pub fn oid(&mut self, what: &str) -> Result<&'a [u8], EvidenceError> {
        Ok(self.expect(TAG_OID, what)?.value)
    }

    /// Read an integer and return its bytes, with any leading zero pad removed.
    pub fn integer(&mut self, what: &str) -> Result<&'a [u8], EvidenceError> {
        let element = self.expect(TAG_INTEGER, what)?;
        let mut bytes = element.value;
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes = &bytes[1..];
        }
        Ok(bytes)
    }

    /// Read an octet string.
    pub fn octets(&mut self, what: &str) -> Result<&'a [u8], EvidenceError> {
        Ok(self.expect(TAG_OCTET_STRING, what)?.value)
    }

    /// Peek at the tag of the next element without consuming it.
    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// Require that nothing is left.
    pub fn finished(&self, what: &str) -> Result<(), EvidenceError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(malformed(format!(
                "{what} has {} bytes after its last element",
                self.bytes.len() - self.at
            )))
        }
    }
}

/// A sequence.
pub const TAG_SEQUENCE: u8 = 0x30;
/// A set.
pub const TAG_SET: u8 = 0x31;
/// An object identifier.
pub const TAG_OID: u8 = 0x06;
/// An integer.
pub const TAG_INTEGER: u8 = 0x02;
/// An octet string.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// A boolean.
pub const TAG_BOOLEAN: u8 = 0x01;
/// A null.
pub const TAG_NULL: u8 = 0x05;
/// A bit string.
pub const TAG_BIT_STRING: u8 = 0x03;
/// A generalized time.
pub const TAG_GENERALIZED_TIME: u8 = 0x18;

/// The tag for a context-specific element, constructed.
#[must_use]
pub const fn context(number: u8) -> u8 {
    0xa0 | number
}

/// The tag for a context-specific element that is not constructed.
#[must_use]
pub const fn context_primitive(number: u8) -> u8 {
    0x80 | number
}

/// Read the body of a DER INTEGER as the signed number it is.
///
/// DER integers are two's complement and big-endian, and the top bit of the first byte is the sign.
/// A reader folding the body as a magnitude gets two different wrong answers out of the same
/// encoding of minus one: two hundred and fifty five from one byte, and minus one from sixteen,
/// because that many shifts run into the sign bit of an `i128` by accident. Both were reachable,
/// and the second is how an authority could state a negative accuracy and be believed.
///
/// Refuses an empty body, which DER does not allow, and one wider than an `i128` holds, rather than
/// silently taking the low bytes of it.
pub fn signed_value(body: &[u8]) -> Result<i128, EvidenceError> {
    let Some(first) = body.first() else {
        return Err(malformed("an integer with no bytes in it"));
    };
    if body.len() > 16 {
        return Err(malformed(format!(
            "an integer {} bytes wide, which is wider than any value this code reads",
            body.len()
        )));
    }
    // Sign extension, done by padding rather than by shifting, so the widest legal body cannot
    // overflow the shift that assembles it.
    let mut buffer = if first & 0x80 != 0 {
        [0xffu8; 16]
    } else {
        [0u8; 16]
    };
    buffer[16 - body.len()..].copy_from_slice(body);
    Ok(i128::from_be_bytes(buffer))
}

/// Write a tag, a length and a value.
///
/// The only thing this product ever encodes in DER is the little structure an RSA signature is
/// actually made over, which has to be rebuilt from the algorithm the token names rather than
/// looked up in a table of byte strings nobody can check by reading.
#[must_use]
pub fn encode(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = value.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let used = &bytes[first..];
        out.push(0x80 | used.len() as u8);
        out.extend_from_slice(used);
    }
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_der_integer_is_read_as_the_signed_number_it_is() {
        // The two answers a magnitude fold gave for the same number. One byte of 0xff read as two
        // hundred and fifty five; sixteen bytes of it read as minus one, because that many shifts
        // reach the sign bit of an i128 by accident.
        assert_eq!(signed_value(&[0xff]).unwrap(), -1);
        assert_eq!(signed_value(&[0xffu8; 16]).unwrap(), -1);
        assert_eq!(signed_value(&[0x00, 0xff]).unwrap(), 255);
        assert_eq!(signed_value(&[0x80]).unwrap(), -128);
        assert_eq!(signed_value(&[0x7f]).unwrap(), 127);
        assert_eq!(signed_value(&[0x00]).unwrap(), 0);
        assert_eq!(signed_value(&[0x01, 0x00]).unwrap(), 256);
    }

    #[test]
    fn a_length_has_one_spelling_and_the_others_are_refused() {
        // One hundred and twenty-nine bytes, written the one way the encoding allows.
        let body = vec![7u8; 129];
        let proper = encode(TAG_OCTET_STRING, &body);
        assert_eq!(proper[1..3], [0x81, 0x81]);
        assert_eq!(
            Reader::new(&proper).take().unwrap().value.len(),
            129,
            "the shortest form should read"
        );

        // The same length with a zero byte in front of it, which is a second byte string saying
        // the same thing. Two spellings of one document is what the rule exists to stop.
        let mut padded = vec![TAG_OCTET_STRING, 0x82, 0x00, 0x81];
        padded.extend_from_slice(&body);
        assert!(
            Reader::new(&padded).take().is_err(),
            "a length padded with a leading zero was accepted"
        );

        // And the half that was already refused: a short length written in the long form.
        let short_written_long = [TAG_OCTET_STRING, 0x81, 0x02, 1, 2];
        assert!(Reader::new(&short_written_long).take().is_err());
    }

    #[test]
    fn an_integer_with_no_bytes_or_too_many_is_refused_rather_than_truncated() {
        assert!(signed_value(&[]).is_err());
        assert!(signed_value(&[0u8; 17]).is_err());
        // The widest one an i128 holds is still read rather than refused.
        let mut widest = vec![0x7fu8];
        widest.extend([0xffu8; 15]);
        assert_eq!(signed_value(&widest).unwrap(), i128::MAX);
    }

    #[test]
    fn a_short_sequence_reads_back() {
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x2a];
        let mut reader = Reader::new(&bytes);
        let mut inner = reader.sequence("a sequence").expect("a sequence");
        assert_eq!(inner.integer("a number").expect("a number"), &[0x2a]);
        inner.finished("the sequence").expect("nothing left over");
        reader.finished("the document").expect("nothing left over");
    }

    #[test]
    fn an_indefinite_length_is_refused() {
        let bytes = [0x30, 0x80, 0x02, 0x01, 0x2a, 0x00, 0x00];
        assert!(Reader::new(&bytes).take().is_err());
    }

    #[test]
    fn a_length_written_longer_than_it_needs_is_refused() {
        // Three, written as a one byte long form. Legal in BER, a second spelling in DER.
        let bytes = [0x30, 0x81, 0x03, 0x02, 0x01, 0x2a];
        assert!(Reader::new(&bytes).take().is_err());
    }

    #[test]
    fn an_element_longer_than_the_bytes_it_sits_in_is_refused() {
        let bytes = [0x30, 0x40, 0x02, 0x01, 0x2a];
        assert!(Reader::new(&bytes).take().is_err());
    }

    #[test]
    fn trailing_bytes_inside_a_sequence_are_refused_when_asked_about() {
        let bytes = [0x30, 0x06, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x2b];
        let mut reader = Reader::new(&bytes);
        let mut inner = reader.sequence("a sequence").expect("a sequence");
        let _ = inner.integer("the first").expect("the first");
        assert!(inner.finished("the sequence").is_err());
    }

    #[test]
    fn leading_zero_padding_comes_off_an_integer() {
        let bytes = [0x02, 0x02, 0x00, 0xff];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.integer("a number").expect("a number"), &[0xff]);
    }

    #[test]
    fn what_encode_writes_is_what_the_reader_reads() {
        for length in [0usize, 1, 127, 128, 300, 70_000] {
            let value = vec![0x41u8; length];
            let written = encode(TAG_OCTET_STRING, &value);
            let mut reader = Reader::new(&written);
            let element = reader
                .expect(TAG_OCTET_STRING, "an octet string")
                .expect("reads");
            assert_eq!(element.value.len(), length);
            reader.finished("the document").expect("nothing left over");
        }
    }

    #[test]
    fn no_input_of_any_length_takes_the_reader_down() {
        let mut seed = 0x2026_0907_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for length in 0..400usize {
            let bytes: Vec<u8> = (0..length).map(|_| (next() & 0xff) as u8).collect();
            let mut reader = Reader::new(&bytes);
            // Walk the whole thing, following into every sequence, the way a real parse does.
            let mut budget = 200;
            while budget > 0 {
                budget -= 1;
                match reader.take() {
                    Ok(element) => {
                        if element.tag & 0x20 != 0 {
                            let mut child = reader.inner(element.value);
                            while child.take().is_ok() {}
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}
