//! JSON as B2 (Python) writes it: `json.dumps(v, sort_keys=True, separators=(",", ":"))` for the
//! hash-chained logs, `indent=N` for the state files, and Python's float repr for timestamps.
//! A Rust signer's files open in the Python signer and the reverse; the hash-chained logs hash
//! the exact bytes written, so both implementations produce lines of the same shape.
use serde_json::{Map, Value};

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
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
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

fn write_num(out: &mut String, n: &serde_json::Number) {
    if n.is_f64() {
        out.push_str(&py_float(n.as_f64().unwrap_or(0.0)));
    } else {
        out.push_str(&n.to_string());
    }
}

fn sorted(m: &Map<String, Value>, sort: bool) -> Vec<(&String, &Value)> {
    let mut v: Vec<_> = m.iter().collect();
    if sort {
        // Python sorts str keys by code point; for these ASCII keys that is byte order
        v.sort_by(|a, b| a.0.cmp(b.0));
    }
    v
}

fn write_compact(out: &mut String, v: &Value, sort: bool, item: &str, key: &str) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_num(out, n),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item);
                }
                write_compact(out, x, sort, item, key);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in sorted(m, sort).into_iter().enumerate() {
                if i > 0 {
                    out.push_str(item);
                }
                write_str(out, k);
                out.push_str(key);
                write_compact(out, x, sort, item, key);
            }
            out.push('}');
        }
    }
}

fn write_indent(out: &mut String, v: &Value, sort: bool, indent: usize, level: usize) {
    let pad = |n: usize| " ".repeat(indent * n);
    match v {
        Value::Array(a) if !a.is_empty() => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                out.push_str(if i > 0 { ",\n" } else { "\n" });
                out.push_str(&pad(level + 1));
                write_indent(out, x, sort, indent, level + 1);
            }
            out.push('\n');
            out.push_str(&pad(level));
            out.push(']');
        }
        Value::Object(m) if !m.is_empty() => {
            out.push('{');
            for (i, (k, x)) in sorted(m, sort).into_iter().enumerate() {
                out.push_str(if i > 0 { ",\n" } else { "\n" });
                out.push_str(&pad(level + 1));
                write_str(out, k);
                out.push_str(": ");
                write_indent(out, x, sort, indent, level + 1);
            }
            out.push('\n');
            out.push_str(&pad(level));
            out.push('}');
        }
        other => write_compact(out, other, sort, ", ", ": "),
    }
}

/// `json.dumps(v, sort_keys=True, separators=(",", ":"))`: the hash-chained log lines.
pub fn dumps_sorted_compact(v: &Value) -> String {
    let mut s = String::new();
    write_compact(&mut s, v, true, ",", ":");
    s
}

/// `json.dumps(v)` (key order kept, `", "` / `": "`).
pub fn dumps(v: &Value) -> String {
    let mut s = String::new();
    write_compact(&mut s, v, false, ", ", ": ");
    s
}

/// `json.dumps(v, indent=indent, sort_keys=sort)`.
pub fn dumps_indent(v: &Value, indent: usize, sort: bool) -> String {
    let mut s = String::new();
    write_indent(&mut s, v, sort, indent, 0);
    s
}

/// `round(time.time(), 3)` as a JSON number.
pub fn now_ts() -> Value {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    ts_value((t * 1000.0).round() / 1000.0)
}

/// A float timestamp as a JSON number.
pub fn ts_value(t: f64) -> Value {
    serde_json::Number::from_f64(t).map(Value::Number).unwrap_or(Value::Null)
}

/// `time.time()`.
pub fn now_f64() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Python's `int(x)` over a JSON value: an integer, an integral string, or a float (truncated).
pub fn py_int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_u64().map(|u| u as i64)).or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

/// Python truthiness of a JSON value (`None`, `0`, `""`, `[]`, `{}` and `False` are false).
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

/// `params.get(k) or ""` as a string (non-strings are formatted as JSON).
pub fn str_or_empty(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(v) if truthy(Some(v)) => v.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_like_python() {
        assert_eq!(py_float(1.0), "1.0");
        assert_eq!(py_float(1727540000.123), "1727540000.123");
        assert_eq!(py_float(1e-5), "1e-05");
        assert_eq!(py_float(1e16), "1e+16");
        assert_eq!(py_float(0.5), "0.5");
        assert_eq!(py_float(1.5e-7), "1.5e-07");
    }

    #[test]
    fn sorted_compact_like_python() {
        let v = json!({"b": 1, "a": [1, "x\u{e9}"], "c": {"z": null, "y": 1.0}});
        assert_eq!(dumps_sorted_compact(&v), "{\"a\":[1,\"x\\u00e9\"],\"b\":1,\"c\":{\"y\":1.0,\"z\":null}}");
        assert_eq!(dumps_indent(&json!({"a": [], "b": {"c": 1}}), 2, true), "{\n  \"a\": [],\n  \"b\": {\n    \"c\": 1\n  }\n}");
    }
}
