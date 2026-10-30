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
        },
        {
            "name": "history",
            "description": "List captured HTTP exchanges (method, URL, status) from a Nullhawk project, newest first. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Path to the Nullhawk project directory." },
                    "limit": { "type": "integer", "description": "Maximum exchanges to return (default 50)." }
                },
                "required": ["project"]
            }
        },
        {
            "name": "decode",
            "description": "Decode a value through a chain of codecs (offline). Each codec is applied left to right.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "input": { "type": "string", "description": "The value to decode." },
                    "codecs": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["base64", "base64url", "url", "hex"] },
                        "description": "Codecs to apply in order, e.g. [\"base64\",\"url\"]."
                    }
                },
                "required": ["input", "codecs"]
            }
        },
        {
            "name": "fingerprint",
            "description": "Name the stack behind each host (server, language, framework, CDN, WAF) from captured response signals. Read-only; sends nothing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Path to the Nullhawk project directory." },
                    "host": { "type": "string", "description": "Optional: only this host (bare host or host:port)." }
                },
                "required": ["project"]
            }
        },
        {
            "name": "sitemap",
            "description": "The host -> path coverage the project has captured (methods and statuses per path). Read-only; sends nothing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": { "type": "string", "description": "Path to the Nullhawk project directory." },
                    "host": { "type": "string", "description": "Optional: only paths whose URL contains this host." }
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
        "history" => tool_history(args),
        "decode" => tool_decode(args),
        "fingerprint" => tool_fingerprint(args),
        "sitemap" => tool_sitemap(args),
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

fn tool_history(args: &Value) -> Result<String, String> {
    let path = args
        .get("project")
        .and_then(Value::as_str)
        .ok_or("`project` is required")?;
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as u32;

    let project = nullhawk_storage::Project::open(Path::new(path)).map_err(|e| e.to_string())?;
    let store = project.traffic();
    let total = store.count().map_err(|e| e.to_string())?;
    let page = store
        .history(None, nullhawk_storage::repository::Limit::new(limit))
        .map_err(|e| e.to_string())?;
    let rows: Vec<Value> = page
        .items
        .iter()
        .map(|t| json!({ "method": t.method, "url": t.url, "status": t.status }))
        .collect();
    Ok(pretty(
        &json!({ "total": total, "returned": rows.len(), "exchanges": rows }),
    ))
}

fn tool_decode(args: &Value) -> Result<String, String> {
    let input = args
        .get("input")
        .and_then(Value::as_str)
        .ok_or("`input` is required")?;
    let codecs: Vec<String> = args
        .get("codecs")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if codecs.is_empty() {
        return Err("`codecs` must list at least one codec".into());
    }

    let mut bytes = input.as_bytes().to_vec();
    for codec in &codecs {
        bytes = apply_decode(codec, &bytes)?;
    }
    Ok(match String::from_utf8(bytes.clone()) {
        Ok(s) => s,
        Err(_) => format!("(binary) {}", hex_encode(&bytes)),
    })
}

fn apply_decode(codec: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| format!("the value is binary, not text, before `{codec}`"))?;
    match codec {
        "base64" | "base64url" | "b64" => {
            let norm = s
                .trim()
                .replace('+', "-")
                .replace('/', "_")
                .trim_end_matches('=')
                .to_string();
            nullhawk_types::jwt::base64url_decode(&norm).ok_or_else(|| "invalid base64".to_string())
        }
        "url" | "urldecode" => Ok(url_decode(s)),
        "hex" => hex_decode(s),
        other => Err(format!("unknown codec: {other}")),
    }
}

fn url_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("hex input has an odd number of digits".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| "invalid hex".to_string()))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn tool_fingerprint(args: &Value) -> Result<String, String> {
    let path = args
        .get("project")
        .and_then(Value::as_str)
        .ok_or("`project` is required")?;
    let host = args.get("host").and_then(Value::as_str);
    let project = nullhawk_storage::Project::open(Path::new(path)).map_err(|e| e.to_string())?;
    let store = project.traffic();
    let report = nullhawk_recon::fingerprint::analyze(&store, host).map_err(|e| e.to_string())?;
    let value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    Ok(pretty(&value))
}

fn tool_sitemap(args: &Value) -> Result<String, String> {
    let path = args
        .get("project")
        .and_then(Value::as_str)
        .ok_or("`project` is required")?;
    let host = args.get("host").and_then(Value::as_str).map(str::to_string);
    let project = nullhawk_storage::Project::open(Path::new(path)).map_err(|e| e.to_string())?;
    let scope = project.settings().scope().map_err(|e| e.to_string())?;
    let store = project.traffic();

    let mut pages = Vec::new();
    let mut cursor: Option<nullhawk_storage::repository::Cursor> = None;
    loop {
        let page = store
            .history(cursor.as_ref(), nullhawk_storage::repository::Limit::new(500))
            .map_err(|e| e.to_string())?;
        for item in &page.items {
            if let Some(h) = &host {
                if !item.url.contains(h.as_str()) {
                    continue;
                }
            }
            pages.push(nullhawk_crawl::CapturedPage {
                url: item.url.clone(),
                method: item.method.clone(),
                status: item.status,
                identity: item.identity.clone(),
                content_type: String::new(),
                body: Vec::new(),
            });
        }
        match page.next {
            Some(n) => cursor = Some(n),
            None => break,
        }
    }

    let map = nullhawk_crawl::SiteMap::build(pages, &scope);
    let hosts: Vec<Value> = map
        .hosts
        .iter()
        .map(|h| {
            json!({
                "host": h.host,
                "secure": h.secure,
                "paths": h
                    .paths
                    .iter()
                    .map(|p| json!({ "path": p.path, "methods": p.methods, "statuses": p.statuses }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(pretty(&json!({ "hosts": hosts })))
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}
