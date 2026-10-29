//! Nullhawk MCP server — exposes Nullhawk's capabilities to AI agents over the Model
//! Context Protocol (JSON-RPC 2.0 over stdio, newline-delimited).
//!
//! The tools here are deliberately the *safe* ones to start with: offline transforms and
//! reads of a project a human already captured and scoped. Nothing here sends traffic or
//! bypasses a guardrail — an agent driving Nullhawk through this server is still bound by
//! what the project's scope and licence allow, the same as the GUI and the CLI. Active and
//! destructive capabilities (scanning, authz replay, cracking) are intentionally not
//! exposed yet; when they are, they go through the same scope + licence gates, and the
//! evidence-first, human-in-the-loop model stays the contract.

use std::io::{self, BufRead, Write};
use std::path::Path;

use serde_json::{json, Value};

const VERSION: &str = "0.1.0";
const PROTOCOL: &str = "2024-11-05";

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        match method {
            "initialize" => respond(
                &mut out,
                id,
                json!({
                    "protocolVersion": PROTOCOL,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "nullhawk", "version": VERSION }
                }),
            ),
            // Notifications carry no id and expect no response.
            m if m.starts_with("notifications/") => {}
            "tools/list" => respond(&mut out, id, json!({ "tools": tool_schemas() })),
            "tools/call" => {
                let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                match call_tool(name, &args) {
                    Ok(text) => respond(
                        &mut out,
                        id,
                        json!({ "content": [{ "type": "text", "text": text }] }),
                    ),
                    Err(e) => respond(
                        &mut out,
                        id,
                        json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
                    ),
                }
            }
            "ping" => respond(&mut out, id, json!({})),
            _ => {
                if id.is_some() {
                    respond_error(&mut out, id, -32601, "method not found");
                }
            }
        }
    }
}

fn respond(out: &mut impl Write, id: Option<Value>, result: Value) {
    let msg = json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result });
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

fn respond_error(out: &mut impl Write, id: Option<Value>, code: i64, message: &str) {
    let msg =
        json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "error": { "code": code, "message": message } });
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

fn tool_schemas() -> Value {
    json!([
        {
            "name": "jwt_decode",
            "description": "Decode a JSON Web Token's header and payload (offline; no signature is checked).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": { "type": "string", "description": "The JWT, with or without a 'Bearer ' prefix." }
                },
                "required": ["token"]
            }
        },
        {
            "name": "findings",
            "description": "List the security findings recorded in a Nullhawk project, worst first. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Path to the Nullhawk project directory." },
                    "limit": { "type": "integer", "description": "Maximum findings to return (default 50)." }
                },
                "required": ["project"]
            }
        }
    ])
}

fn call_tool(name: &str, args: &Value) -> Result<String, String> {
    match name {
        "jwt_decode" => tool_jwt_decode(args),
        "findings" => tool_findings(args),
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn tool_jwt_decode(args: &Value) -> Result<String, String> {
    let token = args
        .get("token")
        .and_then(Value::as_str)
        .ok_or("`token` is required")?;
    let jwt =
        nullhawk_types::jwt::Jwt::parse(token).map_err(|e| format!("not a JWT: {e}"))?;
    Ok(pretty(&json!({
        "header": jwt.header,
        "payload": jwt.payload,
        "algorithm": jwt.algorithm(),
        "signature_bytes": jwt.signature.len(),
        "unsigned": jwt.signature.is_empty(),
    })))
}

fn tool_findings(args: &Value) -> Result<String, String> {
    let path = args
        .get("project")
        .and_then(Value::as_str)
        .ok_or("`project` is required")?;
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as u32;

    let project = nullhawk_storage::Project::open(Path::new(path)).map_err(|e| e.to_string())?;
    let filter = nullhawk_storage::FindingFilter {
        min_severity: None,
        status: None,
        target: None,
        actionable_only: false,
    };
    let page = project
        .findings()
        .list(&filter, None, nullhawk_storage::repository::Limit::new(limit))
        .map_err(|e| e.to_string())?;

    let items: Vec<Value> = page
        .items
        .iter()
        .map(|f| {
            json!({
                "id": f.id.to_string(),
                "title": f.title,
                "severity": f.severity.as_str(),
                "confidence": format!("{:?}", f.confidence).to_lowercase(),
            })
        })
        .collect();
    Ok(pretty(&json!({ "count": items.len(), "findings": items })))
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}
