//! `nullhawk graphql` — test a GraphQL endpoint for the two ways it gives its schema away.
//!
//! A GraphQL API is one endpoint in front of a whole typed schema, and two server settings
//! decide how much of that schema a stranger can read:
//!
//!   - **Introspection.** The standard introspection query returns the entire schema —
//!     every type, field and argument. Meant for development; left on in production it
//!     hands an attacker the full API surface. This sends that query and, if a real schema
//!     comes back, says how many operations it exposes.
//!   - **Field suggestions.** Even with introspection off, many servers answer a mistyped
//!     field with "Did you mean …?", leaking real field names one guess at a time. This
//!     sends a near-miss of `__typename` (a field every type has) and watches for the hint.
//!
//! Both probes are ordinary GraphQL queries — reads, not mutations — but they are requests
//! to somebody's endpoint, so this is a tool a person runs against a target they are
//! authorized to test. It asks before sending. Neither finding is a breach on its own; each
//! is reconnaissance the application did not have to give away, and the lead for what to ask
//! the schema next.

use std::sync::Arc;

use nullhawk_engine::guard::ScopeGuard;
use nullhawk_engine::transport::{HttpTransport, Origin, SendOptions};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_types::http::{HttpRequest, HttpService};
use nullhawk_types::scope::{Scope, ScopeRule};
use nullhawk_types::{NullhawkError, Result};

/// A compact introspection query — enough of `__schema` for `parse_introspection` to read
/// the root operations, which is all this needs to say the schema is readable.
const INTROSPECTION_QUERY: &str =
    "query{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}";

/// A near-miss of `__typename`, the one field present on every GraphQL type. A server with
/// suggestions on answers "Did you mean \"__typename\"?", which needs no knowledge of the
/// real schema to provoke.
const SUGGESTION_QUERY: &str = "query{__typenam}";

pub struct Args<'a> {
    pub url: &'a str,
    pub method: Option<&'a str>,
    pub headers: &'a [String],
    /// How many aliases to batch in the amplification probe; 0 skips it.
    pub batch: usize,
    pub insecure: bool,
    pub yes: bool,
    pub json: bool,
}

pub fn run(args: Args<'_>) -> Result<()> {
    let (service, path) = HttpService::parse_url(args.url)?;
    let method = args.method.unwrap_or("POST").to_string();

    if !args.json {
        println!("GraphQL schema-exposure test");
        println!("  endpoint: {method} {}", args.url);
        println!();
        let probe_count = if args.batch > 0 { "three" } else { "two" };
        println!(
            "This sends {probe_count} GraphQL queries (introspection, a mistyped field{}) to \
             the endpoint. Only test an endpoint you are authorized to.",
            if args.batch > 0 {
                ", and one that aliases a harmless field many times"
            } else {
                ""
            }
        );
        if !args.yes && !crate::proxy::confirm("Send the probes?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(NullhawkError::invalid_input(
            "--yes",
            "a GraphQL test sends traffic, and --json cannot ask; pass --yes to confirm",
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

    let query_body = |query: &str| {
        let mut request = HttpRequest::get(service.clone(), path.clone());
        request.method = method.clone();
        request.headers.set("Content-Type", "application/json");
        for (name, value) in &extra {
            request.headers.set(name, value.clone());
        }
        let body = serde_json::json!({ "query": query }).to_string();
        request
            .headers
            .set("Content-Length", body.len().to_string());
        request.body = bytes::Bytes::from(body);
        request
    };

    let (introspection, suggestions, batching) = runtime()?.block_on(async {
        let introspection = match guard
            .send(query_body(INTROSPECTION_QUERY), options.clone())
            .await
        {
            Ok(exchange) => read_introspection(&exchange.response.body),
            Err(_) => Introspection::Unknown,
        };
        let suggestions = match guard
            .send(query_body(SUGGESTION_QUERY), options.clone())
            .await
        {
            Ok(exchange) => {
                String::from_utf8_lossy(&exchange.response.body).contains("Did you mean")
            }
            Err(_) => false,
        };
        let batching = if args.batch > 0 {
            match guard
                .send(query_body(&batching_query(args.batch)), options.clone())
                .await
            {
                Ok(exchange) => read_batching(&exchange.response.body, args.batch),
                Err(_) => Batching::Unknown,
            }
        } else {
            Batching::Skipped
        };
        (introspection, suggestions, batching)
    });

    report(&args, &introspection, suggestions, &batching);
    Ok(())
}

/// A query that aliases `__typename` `n` times: `{a0:__typename a1:__typename …}`. Harmless
/// — `__typename` returns a type name and nothing else — but if the server runs all `n` in
/// one request, it has no per-request field/cost limit.
fn batching_query(n: usize) -> String {
    let mut q = String::from("query{");
    for i in 0..n {
        q.push_str(&format!("a{i}:__typename "));
    }
    q.push('}');
    q
}

/// Reads the batching response: how many of the `n` aliases the server actually returned.
fn read_batching(body: &[u8], n: usize) -> Batching {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Batching::Unknown;
    };
    let Some(data) = value.get("data").and_then(|d| d.as_object()) else {
        // An error (e.g. a batch/complexity limit rejecting the query) is the hardened case.
        return Batching::Limited(0, n);
    };
    let executed = (0..n)
        .filter(|i| data.contains_key(&format!("a{i}")))
        .count();
    if executed >= n {
        Batching::Unrestricted(n)
    } else {
        Batching::Limited(executed, n)
    }
}

/// What the introspection probe found.
enum Introspection {
    /// Enabled, and the schema exposes this many root operations (when they parsed).
    Enabled(Option<usize>),
    /// The server did not return a schema.
    Disabled,
    /// The request could not be completed.
    Unknown,
}

/// What the batching probe found.
enum Batching {
    /// All `n` aliased fields ran in one request — no per-request cost limit.
    Unrestricted(usize),
    /// Only `executed` of `requested` ran — the request was limited or rejected.
    Limited(usize, usize),
    /// The request could not be completed.
    Unknown,
    /// Not sent (`--batch 0`).
    Skipped,
}

/// Reads the introspection response: a schema is present when `data.__schema` came back.
/// When it also parses cleanly, the operation count is a concrete measure of what leaked.
fn read_introspection(body: &[u8]) -> Introspection {
    let schema_present = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("data").and_then(|d| d.get("__schema")).cloned())
        .is_some_and(|s| !s.is_null());
    if !schema_present {
        return Introspection::Disabled;
    }
    let operations = nullhawk_import::parse_introspection(body)
        .ok()
        .map(|api| api.operations.len());
    Introspection::Enabled(operations)
}

fn report(args: &Args<'_>, introspection: &Introspection, suggestions: bool, batching: &Batching) {
    if args.json {
        let payload = serde_json::json!({
            "endpoint": args.url,
            "introspection_enabled": matches!(introspection, Introspection::Enabled(_)),
            "operations": match introspection { Introspection::Enabled(n) => *n, _ => None },
            "field_suggestions_enabled": suggestions,
            "batching_unrestricted": matches!(batching, Batching::Unrestricted(_)),
            "batch_executed": match batching {
                Batching::Unrestricted(n) => Some(*n),
                Batching::Limited(e, _) => Some(*e),
                _ => None,
            },
        });
        println!("{payload}");
        return;
    }

    println!();
    let mut found = false;
    match introspection {
        Introspection::Enabled(operations) => {
            found = true;
            match operations {
                Some(n) => println!("Introspection is ENABLED — the full schema is readable ({n} root operation(s))."),
                None => println!("Introspection is ENABLED — the endpoint returned a schema."),
            }
            println!("  Anyone can read every type, field and argument. Disable introspection in");
            println!("  production; `nullhawk import graphql` turns a saved schema into traffic to test.");
        }
        Introspection::Disabled => {
            println!("Introspection is disabled — the endpoint returned no schema.")
        }
        Introspection::Unknown => {
            println!("Introspection could not be determined — the request did not complete.")
        }
    }
    if suggestions {
        found = true;
        println!("\nField suggestions are ENABLED — a mistyped field was answered with \"Did you mean …?\".");
        println!("  The schema leaks one field at a time even with introspection off. Turn off");
        println!("  suggestions (`didYouMean`/validation hints) in the production GraphQL server.");
    } else {
        println!("Field suggestions: none seen — a mistyped field drew no \"Did you mean\" hint.");
    }

    match batching {
        Batching::Unrestricted(n) => {
            found = true;
            println!("\nBatching is UNRESTRICTED — the endpoint executed {n} aliased fields in one request.");
            println!(
                "  With no per-request field or cost limit, one request can be amplified into"
            );
            println!(
                "  many operations: a lever for rate-limit bypass (e.g. brute forcing a login"
            );
            println!("  mutation) and for denial of service. Add a query-cost/complexity or alias limit.");
        }
        Batching::Limited(executed, requested) => {
            println!("\nBatching: limited — {executed} of {requested} aliased fields ran, so the endpoint caps a request.");
        }
        Batching::Unknown => {
            println!("\nBatching could not be determined — the request did not complete.");
        }
        Batching::Skipped => {}
    }

    if !found {
        println!(
            "\nNo schema-exposure or amplification setting was observed. That is bounded by these"
        );
        println!("probes, not a full review of the endpoint's authorization or rate limiting.");
    }
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
    fn a_schema_response_is_read_as_enabled() {
        let body = br#"{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}"#;
        assert!(matches!(
            read_introspection(body),
            Introspection::Enabled(_)
        ));
    }

    #[test]
    fn an_error_or_null_schema_is_read_as_disabled() {
        // Introspection turned off: servers answer with an error and no data.__schema.
        let errored = br#"{"errors":[{"message":"GraphQL introspection is not allowed"}]}"#;
        assert!(matches!(
            read_introspection(errored),
            Introspection::Disabled
        ));
        let null_schema = br#"{"data":{"__schema":null}}"#;
        assert!(matches!(
            read_introspection(null_schema),
            Introspection::Disabled
        ));
        // Not even JSON.
        assert!(matches!(
            read_introspection(b"<html>no</html>"),
            Introspection::Disabled
        ));
    }

    #[test]
    fn the_probes_are_queries_not_mutations() {
        // A test that sends a mutation to a stranger's endpoint would be a different act;
        // both probes must be read-only queries.
        // Both are query operations. (The introspection query does *read* `mutationType`'s
        // name — that is introspecting the mutation type, not performing a mutation.)
        assert!(INTROSPECTION_QUERY.trim_start().starts_with("query"));
        assert!(SUGGESTION_QUERY.trim_start().starts_with("query"));
        assert!(!INTROSPECTION_QUERY.contains("mutation "));
        assert!(!INTROSPECTION_QUERY.contains("mutation{"));
        assert!(batching_query(3).trim_start().starts_with("query"));
    }

    #[test]
    fn the_batching_query_aliases_a_harmless_field_n_times() {
        let q = batching_query(3);
        assert!(q.contains("a0:__typename"));
        assert!(q.contains("a2:__typename"));
        assert!(!q.contains("a3:"));
        // Only __typename is aliased — nothing that reads data or mutates.
        assert!(!q.contains("mutation"));
    }

    #[test]
    fn batching_is_unrestricted_only_when_every_alias_ran() {
        // All three aliases came back -> no per-request limit.
        let all = br#"{"data":{"a0":"Query","a1":"Query","a2":"Query"}}"#;
        assert!(matches!(read_batching(all, 3), Batching::Unrestricted(3)));
        // Fewer returned -> the request was capped.
        let some = br#"{"data":{"a0":"Query"}}"#;
        assert!(matches!(read_batching(some, 3), Batching::Limited(1, 3)));
        // An error with no data (a complexity/batch limit rejecting it) is the hardened case.
        let errored = br#"{"errors":[{"message":"query is too complex"}]}"#;
        assert!(matches!(read_batching(errored, 3), Batching::Limited(0, 3)));
    }
}
