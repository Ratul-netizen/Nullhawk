//! `nullhawk upload` — test a file-upload endpoint for weak validation.
//!
//! An upload form that accepts whatever it is sent is how a web shell, a stored-XSS SVG,
//! or an HTML page under the application's origin gets onto a server. This sends a battery
//! of files — a web shell, a double-extension `shell.php.jpg`, an SVG and an HTML page
//! carrying script, a `GIF89a` polyglot — alongside one plainly-benign control, and
//! reports which dangerous ones the endpoint accepted the same way it accepted the control.
//!
//! The control is the whole method: it establishes what *accepted* looks like for this
//! endpoint, so a dangerous file that comes back the same way was not filtered, while one
//! that comes back differently (a `415`, an error page the control did not get) was. That
//! turns "the server returned 200" — which it may do for a rejection too — into a
//! comparison that means something.
//!
//! Acceptance is a lead, not a confirmed shell: whether an accepted `.php` actually
//! executes depends on where it is stored and how it is served, which is the tester's next
//! step. This sends state-changing `POST`s, so it is a tool a person runs against an
//! endpoint they are authorized to test; it asks before sending.

use std::sync::Arc;
use std::time::Duration;

use nullhawk_engine::guard::ScopeGuard;
use nullhawk_engine::transport::{HttpTransport, Origin, SendOptions};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_types::http::{HttpRequest, HttpService};
use nullhawk_types::scope::{Scope, ScopeRule};
use nullhawk_types::{NullhawkError, Result};

pub struct Args<'a> {
    pub url: &'a str,
    /// The multipart field name the file goes in (default "file").
    pub field: &'a str,
    pub method: Option<&'a str>,
    pub headers: &'a [String],
    pub insecure: bool,
    pub yes: bool,
    pub json: bool,
}

/// One file in the battery.
struct Upload {
    label: &'static str,
    filename: &'static str,
    content_type: &'static str,
    body: &'static str,
    /// Why accepting it matters. `None` marks the benign control.
    risk: Option<&'static str>,
}

fn battery() -> Vec<Upload> {
    vec![
        Upload {
            label: "benign control",
            filename: "nullhawk.txt",
            content_type: "text/plain",
            body: "nullhawk benign upload",
            risk: None,
        },
        Upload {
            label: "PHP web shell",
            filename: "nullhawk.php",
            content_type: "application/x-php",
            body: "<?php echo 'NHUP'; ?>",
            risk: Some("a server-side script under the app's origin — remote code execution if it executes"),
        },
        Upload {
            label: "double extension",
            filename: "nullhawk.php.jpg",
            content_type: "image/jpeg",
            body: "<?php echo 'NHUP'; ?>",
            risk: Some("script content behind an image extension — bypasses an extension-only check"),
        },
        Upload {
            label: "alternate PHP extension",
            filename: "nullhawk.phtml",
            content_type: "application/octet-stream",
            body: "<?php echo 'NHUP'; ?>",
            risk: Some("a PHP handler extension a denylist of `.php` often misses"),
        },
        Upload {
            label: "SVG with script",
            filename: "nullhawk.svg",
            content_type: "image/svg+xml",
            body: "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('NHUP')</script></svg>",
            risk: Some("stored XSS when served inline — an image that runs script"),
        },
        Upload {
            label: "HTML with script",
            filename: "nullhawk.html",
            content_type: "text/html",
            body: "<html><body><script>alert('NHUP')</script></body></html>",
            risk: Some("stored XSS: an HTML page under the application's origin"),
        },
        Upload {
            label: "GIF-magic polyglot",
            filename: "nullhawk.php",
            content_type: "image/gif",
            body: "GIF89a;\n<?php echo 'NHUP'; ?>",
            risk: Some("script behind a valid image magic number — bypasses a content-sniff check"),
        },
    ]
}

pub fn run(args: Args<'_>) -> Result<()> {
    let (service, path) = HttpService::parse_url(args.url)?;
    let method = args.method.unwrap_or("POST").to_string();
    let battery = battery();

    if !args.json {
        println!("File-upload validation test");
        println!("  target:  {method} {}", args.url);
        println!("  field:   {}", args.field);
        println!(
            "  files:   {} ({} dangerous + 1 control)",
            battery.len(),
            battery.len() - 1
        );
        println!();
        println!(
            "This sends {} multipart {method} upload(s). Only test an endpoint you are authorized \
             to, and that you are willing to have receive these files.",
            battery.len()
        );
        if !args.yes && !crate::proxy::confirm("Send the uploads?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(NullhawkError::invalid_input(
            "--yes",
            "an upload test sends traffic, and --json cannot ask; pass --yes to confirm",
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

    let send_one = |upload: &Upload| {
        let boundary = "----nullhawkUploadBoundary7MA4YWxkTrZu0gW";
        let body = multipart(boundary, args.field, upload);
        let mut request = HttpRequest::get(service.clone(), path.clone());
        request.method = method.clone();
        request.headers.set(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        );
        for (name, value) in &extra {
            request.headers.set(name, value.clone());
        }
        request
            .headers
            .set("Content-Length", body.len().to_string());
        request.body = bytes::Bytes::from(body);
        request
    };

    let results = runtime()?.block_on(async {
        let mut results: Vec<(usize, Option<(u16, String)>)> = Vec::new();
        for (index, upload) in battery.iter().enumerate() {
            let answer = match guard.send(send_one(upload), options.clone()).await {
                Ok(exchange) => Some((
                    exchange.response.status,
                    String::from_utf8_lossy(&exchange.response.body).into_owned(),
                )),
                Err(_) => None,
            };
            results.push((index, answer));
            // One upload at a time, with a short pause, rather than a burst.
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        results
    });

    report(&args, &battery, &results);
    Ok(())
}

fn report(args: &Args<'_>, battery: &[Upload], results: &[(usize, Option<(u16, String)>)]) {
    // The control establishes what "accepted" looks like here.
    let control = results
        .iter()
        .find(|(i, _)| battery[*i].risk.is_none())
        .and_then(|(_, answer)| answer.clone());

    let mut accepted: Vec<(&Upload, u16)> = Vec::new();
    let mut rejected: Vec<&Upload> = Vec::new();
    let mut inconclusive: Vec<&Upload> = Vec::new();

    for (index, answer) in results {
        let upload = &battery[*index];
        if upload.risk.is_none() {
            continue;
        }
        match (&control, answer) {
            (Some((control_status, control_body)), Some((status, body))) => {
                if is_accepted(*control_status, control_body, *status, body) {
                    accepted.push((upload, *status));
                } else {
                    rejected.push(upload);
                }
            }
            _ => inconclusive.push(upload),
        }
    }

    if args.json {
        let payload = serde_json::json!({
            "target": args.url,
            "control": control.as_ref().map(|(s, _)| *s),
            "accepted": accepted.iter().map(|(u, s)| serde_json::json!({
                "file": u.filename, "label": u.label, "status": s, "risk": u.risk,
            })).collect::<Vec<_>>(),
            "rejected": rejected.iter().map(|u| u.filename).collect::<Vec<_>>(),
            "inconclusive": inconclusive.iter().map(|u| u.filename).collect::<Vec<_>>(),
        });
        println!("{payload}");
        return;
    }

    println!();
    match &control {
        Some((status, _)) => println!(
            "The benign control was accepted with status {status}; comparing the rest to it.\n"
        ),
        None => {
            println!(
                "The benign control could not be sent, so there is no baseline to compare against."
            );
            println!("Without it, a status alone cannot tell acceptance from a rejection page.");
            return;
        }
    }

    if accepted.is_empty() {
        println!("No dangerous file was accepted the way the control was — the endpoint filtered");
        println!("every one tried. That is bounded by this battery, not proof it is airtight.");
    } else {
        println!("DANGEROUS UPLOADS ACCEPTED ({}):", accepted.len());
        for (upload, status) in &accepted {
            println!(
                "  {} (`{}`, {}) — status {status}",
                upload.label, upload.filename, upload.content_type
            );
            if let Some(risk) = upload.risk {
                println!("    {risk}");
            }
        }
        println!();
        println!("Each was accepted the same way the benign control was, so the endpoint did not");
        println!("reject it. That is a lead, not a confirmed shell: find where the file is served");
        println!("and whether it executes or runs script. `nullhawk send` can fetch it back.");
    }
    if !rejected.is_empty() {
        println!(
            "\nRejected (good): {}",
            rejected
                .iter()
                .map(|u| u.filename)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

/// Whether a dangerous upload was accepted like the control: the control succeeded, this
/// one shares its status, and this one's body did not newly turn into a rejection page.
fn is_accepted(control_status: u16, control_body: &str, status: u16, body: &str) -> bool {
    if !(200..400).contains(&control_status) || status != control_status {
        return false;
    }
    // A server that answers 200 to everything may still say "invalid file" in the body of
    // a rejection. If a rejection word appears in this response but not the control's, it
    // was rejected despite the status.
    const REJECTION_WORDS: &[&str] = &[
        "not allowed",
        "invalid file",
        "invalid type",
        "not permitted",
        "unsupported",
        "forbidden",
        "denied",
        "rejected",
        "disallowed",
        "bad extension",
        "file type",
    ];
    let lower = body.to_ascii_lowercase();
    let control_lower = control_body.to_ascii_lowercase();
    for word in REJECTION_WORDS {
        if lower.contains(word) && !control_lower.contains(word) {
            return false;
        }
    }
    true
}

/// A `multipart/form-data` body carrying one file.
fn multipart(boundary: &str, field: &str, upload: &Upload) -> Vec<u8> {
    format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n\
         Content-Type: {content_type}\r\n\r\n\
         {body}\r\n\
         --{boundary}--\r\n",
        filename = upload.filename,
        content_type = upload.content_type,
        body = upload.body,
    )
    .into_bytes()
}

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
    fn the_battery_has_one_control_and_several_dangerous_files() {
        let b = battery();
        assert_eq!(
            b.iter().filter(|u| u.risk.is_none()).count(),
            1,
            "exactly one control"
        );
        assert!(b.iter().filter(|u| u.risk.is_some()).count() >= 5);
        // The classics are present.
        assert!(b.iter().any(|u| u.filename == "nullhawk.php.jpg"));
        assert!(b.iter().any(|u| u.filename == "nullhawk.svg"));
    }

    #[test]
    fn multipart_body_is_well_formed() {
        let u = Upload {
            label: "t",
            filename: "x.php",
            content_type: "application/x-php",
            body: "DATA",
            risk: Some("r"),
        };
        let body = String::from_utf8(multipart("B", "upload", &u)).unwrap();
        assert!(body.starts_with("--B\r\n"));
        assert!(body.contains("name=\"upload\"; filename=\"x.php\""));
        assert!(body.contains("Content-Type: application/x-php"));
        assert!(body.contains("\r\n\r\nDATA\r\n"));
        assert!(body.ends_with("--B--\r\n"));
    }

    #[test]
    fn acceptance_needs_a_successful_control_and_a_matching_status() {
        // Control 200, dangerous 200, no rejection words -> accepted.
        assert!(is_accepted(200, "ok", 200, "stored at /u/1"));
        // Dangerous got a different status -> rejected.
        assert!(!is_accepted(200, "ok", 415, "no"));
        // Control itself failed -> cannot call anything accepted.
        assert!(!is_accepted(403, "no", 403, "no"));
    }

    #[test]
    fn a_rejection_message_in_the_body_overrides_a_200() {
        // Server answers 200 to everything but says "invalid file type" on rejection.
        assert!(!is_accepted(
            200,
            "uploaded ok",
            200,
            "Error: invalid file type"
        ));
        // The control also mentioning it would mean it is not a rejection signal.
        assert!(is_accepted(
            200,
            "file type: any",
            200,
            "file type: any, stored"
        ));
    }
}
