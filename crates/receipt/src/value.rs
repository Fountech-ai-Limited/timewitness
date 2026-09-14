//! The one data shape the wire format and the human view are both written over.
//!
//! Keeping a single tree means the bytes a verifier checks and the text a person reads are the same
//! thing rendered twice, rather than two encoders that can drift apart. A receipt whose JSON says
//! something its CBOR does not would be the worst kind of bug in this product, because the person
//! reviewing it would be reading the wrong one.

use core::fmt;

/// A CBOR value, in the subset this format uses.
///
/// There is no floating point here on purpose. Every quantity in a receipt is a whole number of
/// nanoseconds or a count, and a float would introduce a value that does not round-trip.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    /// A whole number, positive or negative.
    Int(i128),
    /// A string of bytes.
    Bytes(Vec<u8>),
    /// A string of text.
    Text(String),
    /// An ordered list.
    Array(Vec<Value>),
    /// A map. Held as pairs so the encoder controls the ordering rather than a hash table.
    Map(Vec<(Value, Value)>),
    /// True or false.
    Bool(bool),
    /// Nothing.
    Null,
}

impl Value {
    /// A text value from anything string-like.
    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    /// A map from a list of pairs whose keys are text.
    ///
    /// The pairs are put into the order the wire format uses as they are built, so a map is equal
    /// to another map with the same entries whatever order the two were written in. Without that,
    /// a value that has been through the encoder and back would not compare equal to the one it
    /// came from, and every round-trip check in this crate would be testing the wrong thing.
    pub fn map(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Self {
        let mut pairs: Vec<(Value, Value)> = pairs
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect();
        pairs.sort_by_cached_key(|(k, _)| crate::cbor::encode(k));
        Value::Map(pairs)
    }

    /// The value under a text key, if this is a map that has one.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// Whether this is a map carrying a text key of that name.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// This value as a whole number.
    #[must_use]
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// This value as text.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// This value as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// This value as a list.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// This value as a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// A short name for the kind of value this is, for an error message.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Value::Int(_) => "a whole number",
            Value::Bytes(_) => "a byte string",
            Value::Text(_) => "text",
            Value::Array(_) => "a list",
            Value::Map(_) => "a map",
            Value::Bool(_) => "a boolean",
            Value::Null => "nothing",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", crate::json::render(self))
    }
}

/// Bytes as lower case hexadecimal.
///
/// Hexadecimal rather than base64 because it has one spelling, and a receipt printed for a person to
/// compare against another receipt should not depend on which base64 alphabet somebody used.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    s
}

/// Hexadecimal back to bytes.
#[must_use]
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for pair in chars.chunks(2) {
        let hi = pair[0].to_digit(16)?;
        let lo = pair[1].to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_can_be_read_by_key() {
        let v = Value::map([("a", Value::Int(1)), ("b", Value::text("two"))]);
        assert_eq!(v.get("a").and_then(Value::as_int), Some(1));
        assert_eq!(v.get("b").and_then(Value::as_text), Some("two"));
        assert!(v.get("c").is_none());
        assert!(v.has("a"));
        assert!(!v.has("c"));
    }

    #[test]
    fn hexadecimal_round_trips() {
        let bytes = vec![0x00, 0x0f, 0xff, 0xa5, 0x10];
        let hex = to_hex(&bytes);
        assert_eq!(hex, "000fffa510");
        assert_eq!(from_hex(&hex), Some(bytes));
    }

    #[test]
    fn bad_hexadecimal_is_refused() {
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }
}
