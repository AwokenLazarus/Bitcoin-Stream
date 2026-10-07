//! Python's `repr` of a JSON value, as pydantic prints `input_value` in a validation error, and the
//! Python type name it prints as `input_type`. B2's MCP answers a bad argument with pydantic's text,
//! so this server prints the same.
use serde_json::Value;
use xbt402::json::{as_big_int, py_float};

/// Python's `str.isprintable()` for the characters an agent realistically sends: control
/// characters, separators other than the space, and the invisible format characters are not.
fn printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(c as u32, 0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E
        | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0xD800..=0xDFFF | 0xE000..=0xF8FF | 0xFFFE | 0xFFFF)
}

/// `repr(s)` for a Python str.
pub fn str_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if printable(c) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(q);
    out
}

/// `repr(v)` of the Python value `json.loads` gives for `v`.
pub fn repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) if n.is_f64() => py_float(n.as_f64().unwrap_or(0.0)),
        Value::Number(n) => n.to_string(),
        Value::String(s) => str_repr(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(_) if as_big_int(v).is_some() => as_big_int(v).unwrap_or("0").to_string(),
        Value::Object(m) => format!("{{{}}}", m.iter().map(|(k, x)| format!("{}: {}", str_repr(k), repr(x))).collect::<Vec<_>>().join(", ")),
    }
}

/// pydantic's `input_value=`: the repr, cut to its first 25 and last 24 characters past 50.
pub fn input_value(v: &Value) -> String {
    let r = repr(v);
    let cs: Vec<char> = r.chars().collect();
    if cs.len() <= 50 {
        return r;
    }
    format!("{}...{}", cs[..25].iter().collect::<String>(), cs[cs.len() - 24..].iter().collect::<String>())
}

/// pydantic's `input_type=`: the Python type name.
pub fn input_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) if as_big_int(v).is_some() => "int",
        Value::Object(_) => "dict",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reprs_like_python() {
        assert_eq!(repr(&json!({"a": "b'c"})), "{'a': \"b'c\"}");
        assert_eq!(repr(&json!([1, 2.5, null, true, "x"])), "[1, 2.5, None, True, 'x']");
        assert_eq!(repr(&json!(1e20)), "1e+20");
        assert_eq!(str_repr("\u{e9}\n\u{1}it's"), "\"\u{e9}\\n\\x01it's\"");
        assert_eq!(str_repr("a'\"b"), "'a\\'\"b'");
        assert_eq!(str_repr("\u{2028}"), "'\\u2028'");
        assert_eq!(input_value(&json!("a".repeat(80))), format!("'{}...{}'", "a".repeat(24), "a".repeat(23)));
        assert_eq!(input_type(&json!({})), "dict");
    }
}
