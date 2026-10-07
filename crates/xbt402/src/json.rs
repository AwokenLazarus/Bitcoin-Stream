//! JSON exactly as Python's `json.dumps` writes it (key order kept, `ensure_ascii`), so a header
//! built here is byte-identical to the reference implementation's, plus the loose readers the
//! reference's `int(...)`/`str(...)` conversions amount to.
//!
//! Integers beyond i64/u64 (routed amsat prices and meters, which B1 writes as Python ints) are
//! kept exactly without serde_json's `arbitrary_precision` feature, which Cargo feature
//! unification would force on every crate linked with this one (AGP-035). [`parse`] reads them into
//! a reserved one-key object `{"$xbt402::int": "<decimal>"}` ([`big_int`]), and the writers here
//! emit that object as the bare integer again, so a quote signed by Python re-canonicalises byte for
//! byte. Floats are parsed with Rust's correctly rounded `f64` parser and written as Python's
//! `repr`. Always read xbt402 JSON with [`parse`] and write it with [`dumps`]/[`dumps_compact`]:
//! `serde_json::to_string` would print the reserved object as an object.
use serde_json::{Map, Number, Value};

/// The reserved key of a big-integer value (see the module docs).
pub const BIG_INT_KEY: &str = "$xbt402::int";
/// Floats in flight between the pre-scan and the fix-up walk of [`parse`]; never in a result.
const FLOAT_KEY: &str = "$xbt402::float";

/// A JSON integer of any size: a plain number when it fits i64/u64, else the reserved object.
pub fn big_int(n: i128) -> Value {
    if let Ok(u) = u64::try_from(n) {
        Value::from(u)
    } else if let Ok(i) = i64::try_from(n) {
        Value::from(i)
    } else {
        big_int_digits(&n.to_string())
    }
}

/// [`big_int`] for a u128 (amsat).
pub fn big_uint(n: u128) -> Value {
    match i128::try_from(n) {
        Ok(i) => big_int(i),
        Err(_) => big_int_digits(&n.to_string()),
    }
}

fn big_int_digits(d: &str) -> Value {
    let mut m = Map::with_capacity(1);
    m.insert(BIG_INT_KEY.into(), Value::String(d.into()));
    Value::Object(m)
}

/// The decimal text of a big integer ([`big_int`]), or None.
pub fn as_big_int(v: &Value) -> Option<&str> {
    match v {
        Value::Object(m) if m.len() == 1 => m.get(BIG_INT_KEY).and_then(Value::as_str),
        _ => None,
    }
}

/// The integer text of a JSON integer of any size (a plain integer or [`big_int`]), or None.
pub fn int_text(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) if !n.is_f64() => Some(n.to_string()),
        _ => as_big_int(v).map(str::to_string),
    }
}

fn de_err(msg: &str) -> serde_json::Error {
    <serde_json::Error as serde::de::Error>::custom(msg)
}

/// The JSON number token at `b[0..]` (RFC 8259 grammar): (length, is an integer), or None.
fn number_token(b: &[u8]) -> Option<(usize, bool)> {
    let digits = |i: usize| b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut i = usize::from(b.first() == Some(&b'-'));
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => i += digits(i),
        _ => return None,
    }
    let mut int = true;
    if b.get(i) == Some(&b'.') {
        let n = digits(i + 1);
        if n == 0 {
            return None;
        }
        i += 1 + n;
        int = false;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        let s = usize::from(matches!(b.get(i + 1), Some(b'+' | b'-')));
        let n = digits(i + 1 + s);
        if n == 0 {
            return None;
        }
        i += 1 + s + n;
        int = false;
    }
    Some((i, int))
}

/// Parse JSON losslessly (see the module docs): integers of any size, correctly rounded floats.
/// Otherwise exactly serde_json's parse (with `preserve_order`), whose errors it returns. A
/// document that itself contains the reserved key is refused.
pub fn parse(s: &str) -> serde_json::Result<Value> {
    // Pre-scan: outside strings, rewrite every float and every integer beyond i64/u64 as a
    // reserved one-key object holding its token, so serde_json never rounds it through f64.
    let b = s.as_bytes();
    let (mut out, mut last, mut i) = (String::new(), 0, 0);
    let (mut in_str, mut esc) = (false, false);
    let (mut n_int, mut n_float) = (0usize, 0usize);
    while i < b.len() {
        let c = b[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
        } else if c == b'"' {
            in_str = true;
            i += 1;
        } else if c == b'-' || c.is_ascii_digit() {
            let Some((len, int)) = number_token(&b[i..]) else {
                i += 1;
                continue;
            };
            let tok = &s[i..i + len];
            let key = if !int {
                n_float += 1;
                Some(FLOAT_KEY)
            } else if tok.parse::<i64>().is_err() && tok.parse::<u64>().is_err() {
                n_int += 1;
                Some(BIG_INT_KEY)
            } else {
                None
            };
            if let Some(key) = key {
                out.push_str(&s[last..i]);
                out.push_str(&format!("{{\"{key}\":\"{tok}\"}}"));
                last = i + len;
            }
            i += len;
        } else {
            i += 1;
        }
    }
    if last == 0 {
        return check_reserved(serde_json::from_str(s)?, 0, 0);
    }
    out.push_str(&s[last..]);
    check_reserved(serde_json::from_str(&out)?, n_int, n_float)
}

/// [`parse`] over bytes (UTF-8, as serde_json requires).
pub fn parse_slice(b: &[u8]) -> serde_json::Result<Value> {
    parse(std::str::from_utf8(b).map_err(|_| de_err("invalid UTF-8"))?)
}

/// Turn the float objects back into numbers and check that the reserved objects are exactly the
/// ones the pre-scan wrote.
fn check_reserved(mut v: Value, n_int: usize, n_float: usize) -> serde_json::Result<Value> {
    fn walk(v: &mut Value, ints: &mut usize, floats: &mut usize) -> serde_json::Result<()> {
        match v {
            Value::Array(a) => a.iter_mut().try_for_each(|x| walk(x, ints, floats)),
            Value::Object(m) => {
                if m.len() == 1 {
                    if let Some(Value::String(t)) = m.get(FLOAT_KEY) {
                        let f: f64 = t.parse().map_err(|_| de_err("bad float"))?;
                        *v = Value::Number(Number::from_f64(f).ok_or_else(|| de_err("number out of range"))?);
                        *floats += 1;
                        return Ok(());
                    }
                    if let Some(Value::String(_)) = m.get(BIG_INT_KEY) {
                        *ints += 1;
                        return Ok(());
                    }
                }
                if m.contains_key(FLOAT_KEY) || m.contains_key(BIG_INT_KEY) {
                    return Err(de_err("reserved key"));
                }
                m.values_mut().try_for_each(|x| walk(x, ints, floats))
            }
            _ => Ok(()),
        }
    }
    let (mut ints, mut floats) = (0, 0);
    walk(&mut v, &mut ints, &mut floats)?;
    if ints != n_int || floats != n_float {
        return Err(de_err("reserved key"));
    }
    Ok(v)
}

/// Python's `repr(float)`: shortest round-trip digits, `1.0` for integral values, exponent form
/// (`1e-05`, `1e+16`) outside [1e-4, 1e16).
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let s = format!("{f:?}");
    match s.find('e') {
        None => s,
        Some(i) => {
            let (mant, exp) = (&s[..i], &s[i + 1..]);
            let (sign, digits) = if let Some(d) = exp.strip_prefix('-') { ("-", d) } else { ("+", exp) };
            let mant = mant.strip_suffix(".0").unwrap_or(mant);
            format!("{mant}e{sign}{digits:0>2}")
        }
    }
}

fn write_num(out: &mut String, n: &Number) {
    match n.as_f64() {
        Some(f) if n.is_f64() => out.push_str(&py_float(f)),
        _ => out.push_str(&n.to_string()),
    }
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(out: &mut String, v: &Value, item_sep: &str, key_sep: &str) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_num(out, n),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write(out, x, item_sep, key_sep);
            }
            out.push(']');
        }
        Value::Object(_) if as_big_int(v).is_some() => out.push_str(as_big_int(v).unwrap_or("0")),
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write_str(out, k);
                out.push_str(key_sep);
                write(out, x, item_sep, key_sep);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(v)`: separators `", "` and `": "`.
pub fn dumps(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, ", ", ": ");
    s
}

/// `json.dumps(v, separators=(",", ":"))`.
pub fn dumps_compact(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, ",", ":");
    s
}

/// Python's `str(x)` of a JSON value, as the reference formats values into signed messages:
/// strings as themselves, integers in decimal, `None`/`True`/`False`.
pub fn py_str(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".into(),
        Some(Value::Bool(true)) => "True".into(),
        Some(Value::Bool(false)) => "False".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => {
            let mut s = String::new();
            write_num(&mut s, n);
            s
        }
        Some(other) => as_big_int(other).map(str::to_string).unwrap_or_else(|| dumps(other)),
    }
}

/// Python's `int(x)` of a JSON value: an integer, or a string of decimal digits (optional sign,
/// surrounding whitespace). None for anything else.
pub fn py_int(v: Option<&Value>) -> Option<i128> {
    match v? {
        Value::Number(n) => n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)),
        v @ Value::Object(_) => as_big_int(v)?.parse().ok(),
        Value::Bool(b) => Some(*b as i128),
        Value::String(s) => {
            let t = s.trim();
            let (neg, digits) = match t.as_bytes().first() {
                Some(b'-') => (true, &t[1..]),
                Some(b'+') => (false, &t[1..]),
                _ => (false, t),
            };
            if digits.is_empty() || digits.len() > 30 || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let n: i128 = digits.parse().ok()?;
            Some(if neg { -n } else { n })
        }
        _ => None,
    }
}

/// `py_int` narrowed to a non-negative u64.
pub fn py_u64(v: Option<&Value>) -> Option<u64> {
    py_int(v).and_then(|n| u64::try_from(n).ok())
}

/// Python truthiness of an optional JSON value (`pl.get("sig")` in an `if`).
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Build an ordered JSON object from `(key, value)` pairs.
pub fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    let mut m = Map::with_capacity(N);
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python() {
        let v = json!({"b": 1, "a": [true, null, "x\u{e9}\n"], "c": {"d": "\u{1F600}"}});
        assert_eq!(dumps(&v), "{\"b\": 1, \"a\": [true, null, \"x\\u00e9\\n\"], \"c\": {\"d\": \"\\ud83d\\ude00\"}}");
        assert_eq!(dumps_compact(&v), "{\"b\":1,\"a\":[true,null,\"x\\u00e9\\n\"],\"c\":{\"d\":\"\\ud83d\\ude00\"}}");
        assert_eq!(py_str(Some(&json!(5))), "5");
        assert_eq!(py_str(None), "None");
        assert_eq!(py_int(Some(&json!(" 12 "))), Some(12));
        assert_eq!(py_int(Some(&json!("1.5"))), None);
    }

    #[test]
    fn lossless_parse() {
        // integers beyond u64/i64 survive exactly, both signs, anywhere in the tree
        let src = r#"{"a": 813000000000123456789, "b": [-99999999999999999999, 18446744073709551615, -9223372036854775808], "s": "1.5 \" 123456789012345678901234"}"#;
        let v = parse(src).unwrap();
        assert_eq!(dumps(&v), src);
        assert_eq!(as_big_int(&v["a"]), Some("813000000000123456789"));
        assert_eq!(py_int(Some(&v["b"][0])), Some(-99_999_999_999_999_999_999));
        assert_eq!(v["b"][1], json!(u64::MAX));
        assert_eq!(v["b"][2], json!(i64::MIN));
        assert_eq!(v["s"], json!("1.5 \" 123456789012345678901234"));
        assert_eq!(py_str(Some(&v["a"])), "813000000000123456789");
        assert_eq!(big_uint(813_000_000_000_123_456_789), v["a"]);
        assert_eq!(big_int(5), json!(5));
        // floats: correctly rounded, written as Python's repr
        let f = parse(r#"[1727550000.123, 1.0, 1e16, 1.5E-7, 0.0001, -0.0, 1e22, 5e-324]"#).unwrap();
        assert!(f.as_array().unwrap().iter().all(|x| x.as_f64().is_some()));
        assert_eq!(dumps(&f), "[1727550000.123, 1.0, 1e+16, 1.5e-07, 0.0001, -0.0, 1e+22, 5e-324]");
        // the reserved keys cannot be smuggled in, and malformed numbers stay errors
        assert!(parse(r#"{"$xbt402::int": "5"}"#).is_err());
        assert!(parse(r#"{"x": {"$xbt402::float": "5", "y": 1}}"#).is_err());
        assert!(parse(r#"{"x": {"$xbt402::int": "5"}}"#).is_err());
        for bad in ["[01]", "[1.]", "[1e]", "[-]", "[1e400]", "{\"a\": 1,}", "[1 2]"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        // everything else parses exactly as serde_json does
        for ok in ["{}", "[]", "0", "-1", "\"x\"", "true", "null", r#"{"k": [1, "a\\\"b", {"z": null}], "k": 2}"#] {
            assert_eq!(parse(ok).unwrap(), serde_json::from_str::<Value>(ok).unwrap(), "{ok}");
        }
    }
}