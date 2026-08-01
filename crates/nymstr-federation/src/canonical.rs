//! RFC 8785 (JCS) canonical JSON serialization, restricted to the subset the
//! federation protocol actually uses: objects, arrays, strings, booleans,
//! null, and integers within the IEEE-754 safe range (|n| <= 2^53 - 1).
//!
//! Floats are rejected outright (`FederationError::NonCanonicalNumber`): no
//! protocol structure contains one, and rejecting them removes the entire
//! ECMAScript number-formatting corner of RFC 8785.

use super::FederationError;
use serde_json::Value;

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const MIN_SAFE_INTEGER: i64 = -((1_i64 << 53) - 1);

/// Serialize a JSON value to its canonical (JCS) string form.
pub fn to_canonical_json(value: &Value) -> Result<String, FederationError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Canonical form of any serializable structure.
pub fn canonicalize<T: serde::Serialize>(value: &T) -> Result<String, FederationError> {
    let json = serde_json::to_value(value).map_err(|_| FederationError::NonCanonicalNumber)?;
    to_canonical_json(&json)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), FederationError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(FederationError::NonCanonicalNumber);
                }
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                if i < MIN_SAFE_INTEGER {
                    return Err(FederationError::NonCanonicalNumber);
                }
                out.push_str(&i.to_string());
            } else {
                return Err(FederationError::NonCanonicalNumber);
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: sort property names by their UTF-16 code units.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a16: Vec<u16> = a.encode_utf16().collect();
                let b16: Vec<u16> = b.encode_utf16().collect();
                a16.cmp(&b16)
            });
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2 string serialization: only the mandatory escapes, with
/// the short forms where they exist.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v: Value =
            serde_json::from_str(r#"{ "b": 2, "a": 1, "c": [1, 2, {"z": null, "y": true}] }"#)
                .unwrap();
        assert_eq!(
            to_canonical_json(&v).unwrap(),
            r#"{"a":1,"b":2,"c":[1,2,{"y":true,"z":null}]}"#
        );
    }

    #[test]
    fn escapes_control_characters() {
        let v = json!({"s": "a\"b\\c\nd\te\u{0001}f"});
        assert_eq!(
            to_canonical_json(&v).unwrap(),
            r#"{"s":"a\"b\\c\nd\te\u0001f"}"#
        );
    }

    #[test]
    fn preserves_unicode_literally() {
        let v = json!({"emoji": "€𝄞ü"});
        assert_eq!(to_canonical_json(&v).unwrap(), "{\"emoji\":\"€𝄞ü\"}");
    }

    #[test]
    fn rfc8785_utf16_key_ordering() {
        // Keys sort by UTF-16 code units (RFC 8785 §3.2.3), which diverges
        // from code-point order for supplementary-plane characters:
        // U+10000 encodes as the surrogate pair [D800, DC00], and D800 <
        // E000, so U+10000 sorts BEFORE U+E000 despite the larger code point.
        let v = json!({"\u{E000}": 1, "\u{10000}": 2});
        let canon = to_canonical_json(&v).unwrap();
        let idx_supp = canon.find('\u{10000}').unwrap();
        let idx_e000 = canon.find('\u{E000}').unwrap();
        assert!(
            idx_supp < idx_e000,
            "UTF-16 ordering must place U+10000 before U+E000: {canon}"
        );
    }

    #[test]
    fn rejects_floats_and_unsafe_integers() {
        assert!(to_canonical_json(&json!({"x": 1.5})).is_err());
        assert!(to_canonical_json(&json!({"x": u64::MAX})).is_err());
        assert!(to_canonical_json(&json!({"x": 9007199254740991_u64})).is_ok());
        assert!(to_canonical_json(&json!({"x": -9007199254740991_i64})).is_ok());
    }

    #[test]
    fn deterministic_across_input_orderings() {
        let a: Value = serde_json::from_str(r#"{"x":1,"y":{"b":2,"a":3}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"y":{"a":3,"b":2},"x":1}"#).unwrap();
        assert_eq!(
            to_canonical_json(&a).unwrap(),
            to_canonical_json(&b).unwrap()
        );
    }
}
