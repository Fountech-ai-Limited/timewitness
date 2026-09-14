//! The human view.
//!
//! The wire format is CBOR because a receipt has to be small, deterministic and signable. Nobody
//! reads CBOR, so the same value tree renders as JSON for a person. It is a view and never a
//! format: nothing is ever parsed back from it, nothing is signed over it, and a verifier that
//! read this instead of the bytes would be checking the wrong thing.
//!
//! Byte strings come out as lower case hexadecimal, because base64 has several alphabets and a
//! person comparing two receipts by eye should not have to work out which one was used.

use crate::value::{to_hex, Value};

/// Render a value as indented JSON.
#[must_use]
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    write(value, 0, &mut out);
    out
}

fn write(value: &Value, indent: usize, out: &mut String) {
    match value {
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
        Value::Text(t) => write_string(t, out),
        Value::Bytes(b) => write_string(&to_hex(b), out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                pad(indent + 1, out);
                write(item, indent + 1, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(indent, out);
            out.push(']');
        }
        Value::Map(pairs) => {
            if pairs.is_empty() {
                out.push_str("{}");
                return;
            }
            // Rendered in the same order the wire format uses, so a person comparing the two is
            // reading the same sequence of fields.
            let mut sorted: Vec<&(Value, Value)> = pairs.iter().collect();
            sorted.sort_by_key(|(k, _)| crate::cbor::encode(k));

            out.push_str("{\n");
            for (i, (k, v)) in sorted.iter().enumerate() {
                pad(indent + 1, out);
                match k {
                    Value::Text(t) => write_string(t, out),
                    other => write_string(&render_key(other), out),
                }
                out.push_str(": ");
                write(v, indent + 1, out);
                if i + 1 < sorted.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(indent, out);
            out.push('}');
        }
    }
}

fn render_key(value: &Value) -> String {
    match value {
        Value::Int(i) => i.to_string(),
        Value::Bytes(b) => to_hex(b),
        other => format!("{other:?}"),
    }
}

fn pad(indent: usize, out: &mut String) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_renders_in_the_order_the_wire_format_uses() {
        let v = Value::map([("zz", Value::Int(1)), ("a", Value::Int(2))]);
        let rendered = render(&v);
        assert!(rendered.find("\"a\"").unwrap() < rendered.find("\"zz\"").unwrap());
    }

    #[test]
    fn bytes_render_as_hexadecimal() {
        let v = Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(render(&v), "\"deadbeef\"");
    }

    #[test]
    fn text_with_quotes_and_newlines_is_escaped() {
        let v = Value::text("a \"quoted\"\nline");
        assert_eq!(render(&v), "\"a \\\"quoted\\\"\\nline\"");
    }

    #[test]
    fn an_empty_list_and_an_empty_map_render_compactly() {
        assert_eq!(render(&Value::Array(vec![])), "[]");
        assert_eq!(render(&Value::Map(vec![])), "{}");
    }
}
