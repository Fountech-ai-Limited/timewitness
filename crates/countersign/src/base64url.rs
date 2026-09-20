//! base64url without padding, RFC 4648 section 5, written here rather than taken from a crate.
//!
//! It is forty lines and it sits on the path a stranger's bytes take into this product, which is
//! the one place where a dependency costs more than it saves. The decoder refuses anything that is
//! not the exact spelling it would have emitted: no padding, no line breaks, no whitespace, no
//! standard-alphabet `+` or `/`, and no trailing bits set in the last character. A decoder that
//! accepts two spellings of one value hands an attacker a second header that means the same thing
//! and hashes differently, which is the fault deterministic CBOR is chosen to avoid one layer up.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as base64url with no padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = chunk.len() + 1;
        for i in 0..take {
            let index = ((n >> (18 - 6 * i)) & 0x3f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    out
}

/// Decode base64url with no padding, or `None` where the text is not exactly that.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        // One character left over cannot be the tail of anything.
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        ALPHABET
            .iter()
            .position(|&a| a == c)
            .map(|p| u32::try_from(p).unwrap_or(0))
    };

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        for i in 0..produced {
            out.push(((n >> (16 - 8 * i)) & 0xff) as u8);
        }
        // Whatever is left in the last character below the bits that became bytes has to be zero,
        // or the same bytes have more than one spelling. Two characters carry twelve bits and
        // produce one byte, so four bits are left over; three carry eighteen and produce two, so
        // two are left over. Four carry twenty-four and produce three, so none is.
        let leftover_mask: u32 = match chunk.len() {
            2 => 0x00_f000,
            3 => 0x00_00c0,
            _ => 0,
        };
        if n & leftover_mask != 0 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_round_trips_every_length_up_to_a_few_blocks() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
            let text = encode(&bytes);
            assert_eq!(
                decode(&text).as_deref(),
                Some(bytes.as_slice()),
                "at {len} bytes"
            );
        }
    }

    #[test]
    fn it_never_emits_padding_or_the_standard_alphabet() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (255 - i) as u8).collect();
            let text = encode(&bytes);
            assert!(!text.contains('='), "padding in {text}");
            assert!(!text.contains('+'), "standard alphabet in {text}");
            assert!(!text.contains('/'), "standard alphabet in {text}");
        }
    }

    #[test]
    fn a_second_spelling_of_the_same_bytes_is_refused() {
        // `AQ` is one byte. `AR` decodes to the same byte with a bit set in the part that becomes
        // nothing, so it is a second spelling and it is refused rather than accepted.
        assert_eq!(decode("AQ"), Some(vec![0x01]));
        assert_eq!(decode("AR"), None);
        // The same at the two-byte tail.
        assert_eq!(decode("AQI"), Some(vec![0x01, 0x02]));
        assert_eq!(decode("AQJ"), None);
    }

    #[test]
    fn padding_line_breaks_and_the_standard_alphabet_are_all_refused() {
        assert_eq!(decode("AQ=="), None);
        assert_eq!(decode("AQ I"), None);
        assert_eq!(decode("AQ\nI"), None);
        assert_eq!(decode("+w"), None);
        assert_eq!(decode("/w"), None);
        assert_eq!(decode("A"), None);
    }

    #[test]
    fn the_url_safe_characters_are_the_ones_it_uses() {
        // 0xff 0xff 0xff is all ones, which is the last character of the alphabet four times.
        assert_eq!(encode(&[0xff, 0xff, 0xff]), "____");
        // 0xfb 0xff 0xbf exercises the other url-safe character.
        assert_eq!(decode("-_-_").unwrap(), vec![0xfb, 0xff, 0xbf]);
    }
}
