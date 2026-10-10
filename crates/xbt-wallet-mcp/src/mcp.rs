//! The MCP protocol (JSON-RPC 2.0), answered as B2's MCP answers it (Python SDK `mcp` 2.2.0,
//! `MCPServer`): the same handshake and version negotiation, tool list, results
//! (`content` text + `structuredContent.result`) and errors. Transport-independent: [`Server::handle`]
//! takes one message and returns the reply, if any.
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::args;
use crate::wallet::Wallet;

/// The server name B2 announces (agents' tool names are `mcp__<config key>__<tool>`).
pub const SERVER_NAME: &str = "xbt-agent-wallet";
/// The versions B2's SDK negotiates; any other request gets [`LATEST`].
pub const SUPPORTED: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
pub const LATEST: &str = "2025-11-25";

/// The exact MCP surface (B2 `MCP_TOOL_NAMES`).
pub const TOOL_NAMES: [&str; 10] = ["balance", "quote_payment", "pay", "history", "channels", "xbt402_pay", "close_channel",
                                    "xbt402_refund", "forward_status", "forward_recover"];
/// AGP-048 `rail=ln`: listed and callable only when the operator turns the rail on (`XBT_MCP_LN=1`),
/// so a wallet without a Lightning node keeps B2's exact surface.
pub const LN_TOOL_NAMES: [&str; 2] = ["ln_pay", "ln_status"];
/// Never tools: a model cannot approve its own payments or move the hot key (B2 `FORBIDDEN_MCP_TOOLS`),
/// nor reach the web UI's methods (AGP-039): the policy, the human key, the signed rotation, the backup.
pub const FORBIDDEN: [&str; 12] = ["approve", "recover_vault", "recover_treasury", "sweep_hot", "rotate_hot_key", "deny_approval", "policy_prepare",
                                   "policy_set", "human_key_enroll", "human_key_rotate", "rotate_hot_key_signed", "backup_export"];

/// B2's `tools/list` result, verbatim (names, descriptions, input and output schemas).
pub fn tools() -> Value {
    static TOOLS: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    TOOLS.get_or_init(|| serde_json::from_str(include_str!("tools.json")).expect("tools.json")).clone()
}

/// `tools/list` with the Lightning tools appended when `ln` is on.
pub fn tools_for(ln: bool) -> Value {
    let mut t = tools();
    if ln {
        let extra: Value = serde_json::from_str(include_str!("tools_ln.json")).expect("tools_ln.json");
        if let (Some(a), Value::Array(x)) = (t.get_mut("tools").and_then(Value::as_array_mut), extra) {
            a.extend(x);
        }
    }
    t
}

/// Per-connection state: whether `initialize` has been answered, and the version agreed.
#[derive(Default, Clone, Debug)]
pub struct Session {
    pub initialized: bool,
    pub version: String,
}

pub struct Server {
    pub wallet: Arc<Wallet>,
}

fn ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: &Value, code: i64, message: &str, data: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message, "data": data}})
}

fn invalid_params(id: &Value) -> Value {
    error(id, -32602, "Invalid request parameters", "".into())
}

/// A tool result that reaches the model as an error (`isError: true`).
fn tool_error(text: String) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": true})
}

impl Server {
    pub fn new(wallet: Arc<Wallet>) -> Self {
        Self { wallet }
    }

    /// Whether `msg` is a request that may take long (a tool call): transports run those off the
    /// reading thread, as B2's SDK runs requests concurrently.
    pub fn is_slow(msg: &Value) -> bool {
        msg.get("method").and_then(Value::as_str) == Some("tools/call") && msg.get("id").is_some()
    }

    /// One incoming message. `None`: nothing to send (a notification, a response, or a message that
    /// is not JSON-RPC 2.0, which B2's SDK also drops).
    pub fn handle(&self, sess: &mut Session, msg: &Value) -> Option<Value> {
        let m = msg.as_object()?;
        if m.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return None;
        }
        let method = m.get("method").and_then(Value::as_str)?;
        // B2's SDK drops a request whose id is not a string or an integer, or whose params are
        // present but not an object
        let id = m.get("id").filter(|i| i.is_string() || i.is_i64() || i.is_u64())?;
        let params = match m.get("params") {
            None | Some(Value::Null) => None,
            Some(p @ Value::Object(_)) => Some(p),
            Some(_) => return None,
        };
        if method == "initialize" {
            let Some(p) = params.and_then(Value::as_object) else { return Some(invalid_params(id)) };
            let (Some(v), Some(_), Some(ci)) = (p.get("protocolVersion").and_then(Value::as_str), p.get("capabilities").and_then(Value::as_object),
                                                 p.get("clientInfo").and_then(Value::as_object)) else {
                return Some(invalid_params(id));
            };
            if !ci.get("name").is_some_and(Value::is_string) || !ci.get("version").is_some_and(Value::is_string) {
                return Some(invalid_params(id));
            }
            let version = if SUPPORTED.contains(&v) { v } else { LATEST };
            sess.initialized = true;
            sess.version = version.into();
            return Some(ok(id, json!({
                "protocolVersion": version,
                "capabilities": {"experimental": {}, "prompts": {"listChanged": false},
                                 "resources": {"subscribe": false, "listChanged": false}, "tools": {"listChanged": false}},
                "serverInfo": {"name": SERVER_NAME, "version": ""},
            })));
        }
        if method == "ping" {
            return Some(ok(id, json!({})));
        }
        if !sess.initialized {
            return Some(invalid_params(id));
        }
        Some(match method {
            "tools/list" => ok(id, tools_for(self.wallet.ln_tools)),
            "resources/list" => ok(id, json!({"resources": []})),
            "resources/templates/list" => ok(id, json!({"resourceTemplates": []})),
            "prompts/list" => ok(id, json!({"prompts": []})),
            "resources/read" => match params.and_then(|p| p.get("uri")).and_then(Value::as_str) {
                Some(uri) => error(id, -32602, &format!("Unknown resource: {uri}"), json!({"uri": uri})),
                None => invalid_params(id),
            },
            "prompts/get" => match params.and_then(|p| p.get("name")).and_then(Value::as_str) {
                Some(name) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": 0, "message": format!("Unknown prompt: {name}")}}),
                None => invalid_params(id),
            },
            "completion/complete" if !params.is_some_and(|p| p.get("ref").is_some_and(Value::is_object) && p.get("argument").is_some_and(Value::is_object)) => {
                invalid_params(id)
            }
            "tools/call" => {
                let Some(p) = params.and_then(Value::as_object) else { return Some(invalid_params(id)) };
                let Some(name) = p.get("name").and_then(Value::as_str) else { return Some(invalid_params(id)) };
                let args = match p.get("arguments") {
                    None | Some(Value::Null) => Map::new(),
                    Some(Value::Object(a)) => a.clone(),
                    Some(_) => return Some(invalid_params(id)),
                };
                ok(id, self.call_tool(name, &args))
            }
            _ => error(id, -32601, "Method not found", method.into()),
        })
    }

    /// `tools/call`'s result for one tool.
    pub fn call_tool(&self, name: &str, args: &Map<String, Value>) -> Value {
        if !TOOL_NAMES.contains(&name) && !(self.wallet.ln_tools && LN_TOOL_NAMES.contains(&name)) {
            return tool_error(format!("Unknown tool: {name}"));
        }
        let params = match args::validate(name, args) {
            Ok(p) => p,
            Err(e) => return tool_error(format!("Error executing tool {name}: {e}")),
        };
        match self.wallet.call_tool(name, params) {
            Ok(text) => json!({"content": [{"type": "text", "text": text}], "structuredContent": {"result": text}, "isError": false}),
            Err(e) => {
                // B2's SDK keeps a crashed tool's reason on the server and tells the model only this
                eprintln!("xbt-wallet-mcp: tool {name} failed: {e}");
                tool_error(format!("Error executing tool {name}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ln_tools_only_when_on() {
        let names = |v: Value| v["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(names(tools_for(false)), TOOL_NAMES);
        let on = names(tools_for(true));
        assert_eq!(on.len(), 12);
        assert_eq!(on[10..], LN_TOOL_NAMES);
        for n in LN_TOOL_NAMES {
            assert!(crate::args::spec(n).is_some() && !FORBIDDEN.contains(&n));
        }
        // AGP-082: the published schema of each LN tool names exactly the arguments the server takes
        let listed = tools_for(true);
        for t in listed["tools"].as_array().unwrap().iter().filter(|t| LN_TOOL_NAMES.contains(&t["name"].as_str().unwrap())) {
            let spec = crate::args::spec(t["name"].as_str().unwrap()).unwrap();
            let mut props: Vec<&str> = t["inputSchema"]["properties"].as_object().unwrap().keys().map(String::as_str).collect();
            let mut args: Vec<&str> = spec.iter().map(|a| a.name).collect();
            props.sort_unstable();
            args.sort_unstable();
            assert_eq!(props, args, "{}", t["name"]);
            let required: Vec<&str> = spec.iter().filter(|a| a.default.is_none()).map(|a| a.name).collect();
            let listed: Vec<&str> = t["inputSchema"].get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
            assert_eq!(required, listed, "{}", t["name"]);
        }
        let ln_pay = &listed["tools"][10];
        assert!(ln_pay["description"].as_str().unwrap().contains("ln-offer:<offer id>"));
        assert_eq!(ln_pay["inputSchema"]["properties"]["amount_sats"]["default"], 0);
    }
}
