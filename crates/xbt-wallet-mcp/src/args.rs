//! The ten tools' arguments, validated as B2's MCP (pydantic 2 in lax mode, through the Python SDK's
//! `MCPServer`) validates them: the same coercions (`"7"` and `7.0` are the integer 7, `true` is 1,
//! `"1_000"` is 1000, `"inf"` is a float), the same refusals, and pydantic's error text word for word.
use serde_json::{Map, Value};
use xbt402::json::{as_big_int, big_int, BIG_INT_KEY};

use crate::pyrepr::{input_type, input_value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ty {
    Str,
    Float,
    Int,
}

/// One argument: its name, type and default (`None`: required).
pub struct Arg {
    pub name: &'static str,
    pub ty: Ty,
    pub default: Option<fn() -> Value>,
}

const fn req(name: &'static str, ty: Ty) -> Arg {
    Arg { name, ty, default: None }
}

const fn opt(name: &'static str, ty: Ty, default: fn() -> Value) -> Arg {
    Arg { name, ty, default: Some(default) }
}

fn empty() -> Value {
    Value::String(String::new())
}

/// The arguments of each tool, in B2's order (`mcp_server.py` at b2 `b4f2fe5`).
pub fn spec(tool: &str) -> Option<&'static [Arg]> {
    static PAYMENT: [Arg; 3] = [req("to", Ty::Str), req("amount_xbt", Ty::Float), opt("memo", Ty::Str, empty)];
    static HISTORY: [Arg; 1] = [opt("limit", Ty::Int, || Value::from(20))];
    static XBT402_PAY: [Arg; 4] = [req("url", Ty::Str), opt("method", Ty::Str, || Value::from("GET")), opt("body", Ty::Str, empty),
                                   opt("max_sats", Ty::Int, || Value::from(1000))];
    static COUNTERPARTY: [Arg; 1] = [req("counterparty", Ty::Str)];
    static TXID: [Arg; 1] = [req("txid", Ty::Str)];
    // AGP-082: amount_sats, for a BOLT 12 offer that names no amount (0: not given)
    static LN_PAY: [Arg; 4] = [req("invoice", Ty::Str), req("max_sats", Ty::Int), opt("description", Ty::Str, empty),
                               opt("amount_sats", Ty::Int, || Value::from(0))];
    Some(match tool {
        "balance" | "channels" | "forward_status" => &[],
        "quote_payment" | "pay" => &PAYMENT,
        "history" => &HISTORY,
        "xbt402_pay" => &XBT402_PAY,
        "close_channel" | "xbt402_refund" => &COUNTERPARTY,
        "forward_recover" => &TXID,
        // AGP-048 (not B2's)
        "ln_pay" => &LN_PAY,
        "ln_status" => &[],
        _ => return None,
    })
}

struct Issue {
    field: String,
    kind: &'static str,
    msg: &'static str,
    value: String,
    vtype: &'static str,
}

/// Python's `str.strip()`.
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Digits with single underscores between them (Python's numeric literal rule), underscores removed.
fn digits_underscored(s: &str) -> Option<String> {
    if s.is_empty() || s.starts_with('_') || s.ends_with('_') || s.contains("__") {
        return None;
    }
    let d: String = s.chars().filter(|c| *c != '_').collect();
    d.bytes().all(|b| b.is_ascii_digit()).then_some(d)
}

/// An integer from a string as pydantic parses one: sign, ASCII digits (underscores between them), an
/// optional `.000` tail. Any size.
fn int_from_str(s: &str) -> Option<Value> {
    let s = py_strip(s);
    let (neg, rest) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let int_part = match rest.split_once('.') {
        Some((i, frac)) if frac.bytes().all(|b| b == b'0') => i,
        Some(_) => return None,
        None => rest,
    };
    let d = digits_underscored(int_part)?;
    let d = d.trim_start_matches('0');
    if d.is_empty() {
        return Some(Value::from(0));
    }
    let text = if neg { format!("-{d}") } else { d.to_string() };
    Some(match text.parse::<i128>() {
        Ok(n) => big_int(n),
        Err(_) => {
            let mut m = Map::new();
            m.insert(BIG_INT_KEY.into(), Value::String(text));
            Value::Object(m)
        }
    })
}

/// Python's `float(s)`: optional sign, `inf`/`infinity`/`nan`, or a decimal literal whose digit
/// groups may hold single underscores.
fn float_from_str(s: &str) -> Option<f64> {
    let s = py_strip(s);
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    let l = body.to_ascii_lowercase();
    if matches!(l.as_str(), "inf" | "infinity" | "nan") {
        return s.to_ascii_lowercase().replace("infinity", "inf").parse::<f64>().ok();
    }
    if s.contains('_') {
        // every underscore sits between two digits
        let b = s.as_bytes();
        for (i, c) in b.iter().enumerate() {
            if *c == b'_' && !(i > 0 && b[i - 1].is_ascii_digit() && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
                return None;
            }
        }
    }
    let t: String = s.chars().filter(|c| *c != '_').collect();
    if !t.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E')) || t.is_empty() {
        return None;
    }
    t.parse::<f64>().ok()
}

/// A float argument as the JSON the signer receives; a non-finite one as Python's `json.dumps` writes it.
fn float_value(f: f64) -> Value {
    match serde_json::Number::from_f64(f) {
        Some(n) => Value::Number(n),
        None => {
            let mut m = Map::new();
            let t = if f.is_nan() { "NaN" } else if f > 0.0 { "Infinity" } else { "-Infinity" };
            m.insert(BIG_INT_KEY.into(), Value::String(t.into()));
            Value::Object(m)
        }
    }
}

fn coerce(ty: Ty, v: &Value) -> Result<Value, (&'static str, &'static str)> {
    match (ty, v) {
        (Ty::Str, Value::String(_)) => Ok(v.clone()),
        (Ty::Str, _) => Err(("string_type", "Input should be a valid string")),
        (Ty::Int, Value::Bool(b)) => Ok(Value::from(*b as u8)),
        (Ty::Int, Value::Number(n)) if !n.is_f64() => Ok(v.clone()),
        (Ty::Int, Value::Number(n)) => {
            let f = n.as_f64().unwrap_or(0.0);
            if f.fract() != 0.0 {
                Err(("int_from_float", "Input should be a valid integer, got a number with a fractional part"))
            } else if f.abs() >= i64::MAX as f64 {
                Err(("int_parsing_size", "Unable to parse input string as an integer, exceeded maximum size"))
            } else {
                Ok(Value::from(f as i64))
            }
        }
        (Ty::Int, Value::Object(_)) if as_big_int(v).is_some() => Ok(v.clone()),
        (Ty::Int, Value::String(s)) => int_from_str(s).ok_or(("int_parsing", "Input should be a valid integer, unable to parse string as an integer")),
        (Ty::Int, _) => Err(("int_type", "Input should be a valid integer")),
        (Ty::Float, Value::Bool(b)) => Ok(float_value(*b as u8 as f64)),
        (Ty::Float, Value::Number(n)) => Ok(float_value(n.as_f64().unwrap_or(0.0))),
        (Ty::Float, Value::Object(_)) if as_big_int(v).is_some() => {
            Ok(float_value(as_big_int(v).and_then(|t| t.parse::<f64>().ok()).unwrap_or(f64::NAN)))
        }
        (Ty::Float, Value::String(s)) => float_from_str(s).map(float_value)
            .ok_or(("float_parsing", "Input should be a valid number, unable to parse string as a number")),
        (Ty::Float, _) => Err(("float_type", "Input should be a valid number")),
    }
}

/// Validate `args` (the `arguments` object; `None` is `{}`) for `tool`. Ok: the signer's params, every
/// argument present with its default filled in; extra keys are ignored, as pydantic ignores them.
/// Err: pydantic's `ValidationError` text.
pub fn validate(tool: &str, args: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let spec = spec(tool).unwrap_or(&[]);
    let mut out = Map::new();
    let mut issues = vec![];
    for a in spec {
        match args.get(a.name) {
            None => match a.default {
                Some(d) => {
                    out.insert(a.name.into(), d());
                }
                None => issues.push(Issue { field: a.name.into(), kind: "missing", msg: "Field required",
                                            value: input_value(&Value::Object(args.clone())), vtype: "dict" }),
            },
            Some(v) => match coerce(a.ty, v) {
                Ok(x) => {
                    out.insert(a.name.into(), x);
                }
                Err((kind, msg)) => issues.push(Issue { field: a.name.into(), kind, msg, value: input_value(v), vtype: input_type(v) }),
            },
        }
    }
    if issues.is_empty() {
        return Ok(out);
    }
    let n = issues.len();
    let mut s = format!("{n} validation error{} for {tool}Arguments", if n == 1 { "" } else { "s" });
    for i in issues {
        s.push_str(&format!("\n{}\n  {} [type={}, input_value={}, input_type={}]\n    For further information visit https://errors.pydantic.dev/2.13/v/{}",
                            i.field, i.msg, i.kind, i.value, i.vtype, i.kind));
    }
    Err(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(tool: &str, a: Value) -> Result<Value, String> {
        validate(tool, a.as_object().unwrap()).map(Value::Object)
    }

    #[test]
    fn coercions_like_pydantic() {
        assert_eq!(v("history", json!({"limit": " 12 "})).unwrap(), json!({"limit": 12}));
        assert_eq!(v("history", json!({"limit": "1_000"})).unwrap(), json!({"limit": 1000}));
        assert_eq!(v("history", json!({"limit": "5.0"})).unwrap(), json!({"limit": 5}));
        assert_eq!(v("history", json!({"limit": true})).unwrap(), json!({"limit": 1}));
        assert_eq!(v("history", json!({"limit": 1e3})).unwrap(), json!({"limit": 1000}));
        assert_eq!(v("history", json!({})).unwrap(), json!({"limit": 20}));
        assert_eq!(v("quote_payment", json!({"to": "x", "amount_xbt": "1_0"})).unwrap(), json!({"to": "x", "amount_xbt": 10.0, "memo": ""}));
        assert_eq!(v("quote_payment", json!({"to": "x", "amount_xbt": " 1e3 ", "zz": 1})).unwrap(), json!({"to": "x", "amount_xbt": 1000.0, "memo": ""}));
        assert_eq!(v("xbt402_pay", json!({"url": "u", "max_sats": 5.0})).unwrap(), json!({"url": "u", "method": "GET", "body": "", "max_sats": 5}));
        let big = xbt402::json::parse(r#"{"limit": "100000000000000000000000"}"#).unwrap();
        assert_eq!(xbt402::json::dumps(&v("history", big).unwrap()), r#"{"limit": 100000000000000000000000}"#);
    }

    #[test]
    fn errors_word_for_word() {
        assert_eq!(v("history", json!({"limit": 5.5})).unwrap_err(),
            "1 validation error for historyArguments\nlimit\n  Input should be a valid integer, got a number with a fractional part [type=int_from_float, input_value=5.5, input_type=float]\n    For further information visit https://errors.pydantic.dev/2.13/v/int_from_float");
        assert_eq!(v("quote_payment", json!({})).unwrap_err(),
            "2 validation errors for quote_paymentArguments\nto\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing\namount_xbt\n  Field required [type=missing, input_value={}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/missing");
        assert!(v("history", json!({"limit": 1e20})).unwrap_err().contains("[type=int_parsing_size, input_value=1e+20, input_type=float]"));
        assert!(v("xbt402_pay", json!({"url": "u", "max_sats": "0x10"})).unwrap_err().contains("[type=int_parsing, input_value='0x10', input_type=str]"));
        assert!(v("history", json!({"limit": "\u{663}"})).unwrap_err().contains("type=int_parsing"));
        assert!(v("quote_payment", json!({"to": 1.5, "amount_xbt": []})).unwrap_err().contains("input_value=[], input_type=list"));
    }
}
