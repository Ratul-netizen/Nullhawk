//! `nullhawk fingerprint` — name the stack behind each host from the traffic already captured.
//!
//! Before you test an application it helps to know what it is: the web server, the language,
//! the framework, the CDN or WAF in front of it. Every one of those leaves marks in ordinary
//! responses — a `Server` header, an `X-Powered-By`, a framework's session cookie, a CMS's
//! `generator` meta tag. This reads the responses in the project and reports what it can name,
//! and — because a header is only a claim, and a trivially spoofed one — it cites the exact
//! header or cookie behind every line, so a reader can weigh it rather than trust it.
//!
//! It sends nothing. It is recon over what the proxy already saw.

use std::collections::BTreeMap;
use std::path::PathBuf;

use nullhawk_storage::repository::Limit;
use nullhawk_types::http::HttpService;
use nullhawk_types::Result;

const PAGE: u32 = 200;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
    pub json: bool,
}

/// One named technology, with the category it falls in and the evidence that named it.
#[derive(Clone)]
struct Tech {
    name: &'static str,
    category: &'static str,
    evidence: String,
}

/// Header rules: `(header, needle, tech, category)`. A rule fires when the response carries
/// `header` and — unless `needle` is empty — its value contains `needle` (case-insensitive).
/// Presence-only headers (an empty needle) are ones whose mere existence names the stack.
const HEADER_RULES: &[(&str, &str, &str, &str)] = &[
    // Web servers
    ("server", "nginx", "nginx", "web server"),
    ("server", "apache", "Apache", "web server"),
    ("server", "microsoft-iis", "IIS", "web server"),
    ("server", "caddy", "Caddy", "web server"),
    ("server", "litespeed", "LiteSpeed", "web server"),
    // Languages and frameworks
    ("x-powered-by", "php", "PHP", "language"),
    ("x-powered-by", "asp.net", "ASP.NET", "framework"),
    ("x-powered-by", "express", "Express", "framework"),
    ("x-powered-by", "next.js", "Next.js", "framework"),
    ("x-powered-by", "servlet", "Java Servlet", "framework"),
    ("x-aspnet-version", "", "ASP.NET", "framework"),
    ("x-aspnetmvc-version", "", "ASP.NET MVC", "framework"),
    ("x-drupal-cache", "", "Drupal", "CMS"),
    ("x-drupal-dynamic-cache", "", "Drupal", "CMS"),
    ("x-generator", "drupal", "Drupal", "CMS"),
    // CDN / edge / WAF
    ("cf-ray", "", "Cloudflare", "CDN/WAF"),
    ("server", "cloudflare", "Cloudflare", "CDN/WAF"),
    ("x-amz-cf-id", "", "AWS CloudFront", "CDN"),
    ("x-amz-request-id", "", "AWS S3", "storage"),
    ("x-vercel-id", "", "Vercel", "hosting"),
    ("x-nf-request-id", "", "Netlify", "hosting"),
    ("x-served-by", "cache", "Fastly", "CDN"),
    ("x-varnish", "", "Varnish", "cache"),
    ("via", "varnish", "Varnish", "cache"),
    // Platforms / gateways
    ("x-shopify-stage", "", "Shopify", "platform"),
    ("x-jenkins", "", "Jenkins", "CI"),
    ("x-kong-upstream-latency", "", "Kong", "API gateway"),
];

/// Cookie rules: a framework's session cookie names the framework. `(cookie name, tech, category)`.
const COOKIE_RULES: &[(&str, &str, &str)] = &[
    ("phpsessid", "PHP", "language"),
    ("jsessionid", "Java Servlet", "framework"),
    ("asp.net_sessionid", "ASP.NET", "framework"),
    ("aspsession", "ASP (classic)", "framework"),
    ("laravel_session", "Laravel", "framework"),
    ("ci_session", "CodeIgniter", "framework"),
    ("connect.sid", "Express", "framework"),
    ("_rails_session", "Ruby on Rails", "framework"),
    ("sessionid", "Django", "framework"),
    ("csrftoken", "Django", "framework"),
    ("wordpress_logged_in", "WordPress", "CMS"),
    ("wp-settings", "WordPress", "CMS"),
];

/// Match a header line against the rules, returning any technologies it names.
fn techs_from_header(name: &str, value: &str) -> Vec<Tech> {
    let name = name.trim().to_ascii_lowercase();
    let value_l = value.to_ascii_lowercase();
    HEADER_RULES
        .iter()
        .filter(|(h, needle, _, _)| *h == name && (needle.is_empty() || value_l.contains(needle)))
        .map(|(h, _, tech, category)| Tech {
            name: tech,
            category,
            evidence: format!("{}: {}", header_title(h), truncate(value.trim(), 48)),
        })
        .collect()
}

/// Match a `Set-Cookie` cookie name against the rules.
fn tech_from_cookie(cookie_name: &str) -> Option<Tech> {
    let lower = cookie_name.trim().to_ascii_lowercase();
    COOKIE_RULES
        .iter()
        .find(|(n, _, _)| lower == *n)
        .map(|(n, tech, category)| Tech {
            name: tech,
            category,
            evidence: format!("Set-Cookie: {n}"),
        })
}

/// A `<meta name="generator" content="...">` names a CMS or static generator.
fn tech_from_generator(content: &str) -> Option<Tech> {
    let first = content.split_whitespace().next().unwrap_or("");
    let tech = match first.to_ascii_lowercase().as_str() {
        "wordpress" => ("WordPress", "CMS"),
        "drupal" => ("Drupal", "CMS"),
        "joomla!" | "joomla" => ("Joomla", "CMS"),
        "hugo" => ("Hugo", "static generator"),
        "ghost" => ("Ghost", "CMS"),
        "gatsby" => ("Gatsby", "static generator"),
        _ => return None,
    };
    Some(Tech {
        name: tech.0,
        category: tech.1,
        evidence: format!("<meta generator> {}", truncate(content.trim(), 40)),
    })
}

pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let store = project.traffic();

    // host -> (tech name -> Tech). First evidence for a tech on a host wins.
    let mut by_host: BTreeMap<String, BTreeMap<&'static str, Tech>> = BTreeMap::new();
    let mut responses = 0usize;

    let mut cursor = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            let host = match HttpService::parse_url(&item.url) {
                Ok((service, _)) => service.host,
                Err(_) => continue,
            };
            if let Some(want) = &args.host {
                if &host != want {
                    continue;
                }
            }

            let Ok((_, _, _, headers_raw)) = store.response_head(item.id) else {
                continue;
            };
            responses += 1;
            let text = String::from_utf8_lossy(&headers_raw);
            let mut found: Vec<Tech> = Vec::new();
            let mut html = false;
            for line in text.lines() {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                let lname = name.trim().to_ascii_lowercase();
                if lname == "content-type" && value.to_ascii_lowercase().contains("html") {
                    html = true;
                }
                if lname == "set-cookie" {
                    let cookie_name = value.trim().split('=').next().unwrap_or("");
                    if let Some(tech) = tech_from_cookie(cookie_name) {
                        found.push(tech);
                    }
                }
                found.extend(techs_from_header(name, value));
            }

            // Only read a body to look for a generator tag when it is HTML — cheap, and it
            // is the one body-level signal worth the read.
            if html {
                if let Ok(body) = store.response_body(item.id, false) {
                    if let Some(content) = generator_content(&String::from_utf8_lossy(&body)) {
                        if let Some(tech) = tech_from_generator(&content) {
                            found.push(tech);
                        }
                    }
                }
            }

            if !found.is_empty() {
                let host_techs = by_host.entry(host).or_default();
                for tech in found {
                    host_techs.entry(tech.name).or_insert(tech);
                }
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    if args.json {
        print_json(responses, &by_host);
    } else {
        print_report(responses, &by_host);
    }
    Ok(())
}

/// Extract the `content` of a `<meta name="generator" ...>` tag, if present.
fn generator_content(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let meta = lower.match_indices("<meta").map(|(i, _)| i).find(|&i| {
        let end = body[i..].find('>').map(|e| i + e).unwrap_or(body.len());
        lower[i..end].contains("generator")
    })?;
    let end = body[meta..]
        .find('>')
        .map(|e| meta + e)
        .unwrap_or(body.len());
    let tag = &body[meta..end];
    // content="..." or content='...'
    let at = tag.to_ascii_lowercase().find("content")?;
    let rest = &tag[at..];
    let quote = rest.find(['"', '\''])?;
    let q = rest.as_bytes()[quote] as char;
    let after = &rest[quote + 1..];
    let close = after.find(q)?;
    Some(after[..close].to_string())
}

fn print_report(responses: usize, by_host: &BTreeMap<String, BTreeMap<&'static str, Tech>>) {
    println!("Fingerprinted {responses} response(s).\n");
    if by_host.is_empty() {
        println!(
            "No stack could be named from the captured headers and cookies. Bounded by what \
             the responses advertised, not proof the stack is unknowable."
        );
        return;
    }
    for (host, techs) in by_host {
        println!("{host}");
        for tech in techs.values() {
            println!(
                "  {:<16} {:<16} — {}",
                tech.name,
                format!("({})", tech.category),
                tech.evidence
            );
        }
        println!();
    }
    println!(
        "Each line is named by a header or cookie, which can be spoofed — treat it as a lead \
         to confirm, not a settled fact."
    );
}

fn print_json(responses: usize, by_host: &BTreeMap<String, BTreeMap<&'static str, Tech>>) {
    let hosts: BTreeMap<_, Vec<_>> = by_host
        .iter()
        .map(|(host, techs)| {
            let items: Vec<_> = techs
                .values()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "category": t.category,
                        "evidence": t.evidence,
                    })
                })
                .collect();
            (host.clone(), items)
        })
        .collect();
    let out = serde_json::json!({ "responses": responses, "hosts": hosts });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

fn header_title(lower: &str) -> String {
    lower
        .split('-')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        format!("{}…", value.chars().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_and_powered_by_name_the_stack() {
        let nginx = techs_from_header("Server", "nginx/1.25.3");
        assert_eq!(nginx.len(), 1);
        assert_eq!(nginx[0].name, "nginx");
        assert!(nginx[0].evidence.contains("nginx/1.25.3"));

        let php = techs_from_header("X-Powered-By", "PHP/8.1.2");
        assert_eq!(php[0].name, "PHP");
    }

    #[test]
    fn presence_only_headers_fire_on_existence() {
        assert_eq!(
            techs_from_header("CF-Ray", "7a1b-LHR")[0].name,
            "Cloudflare"
        );
        assert_eq!(
            techs_from_header("X-AspNet-Version", "4.0.30319")[0].name,
            "ASP.NET"
        );
    }

    #[test]
    fn an_ordinary_header_names_nothing() {
        assert!(techs_from_header("Date", "Mon, 01 Jan 2026 00:00:00 GMT").is_empty());
        assert!(techs_from_header("Content-Length", "1234").is_empty());
    }

    #[test]
    fn framework_cookies_are_recognised() {
        assert_eq!(tech_from_cookie("JSESSIONID").unwrap().name, "Java Servlet");
        assert_eq!(tech_from_cookie("laravel_session").unwrap().name, "Laravel");
        assert!(tech_from_cookie("sessiontoken").is_none());
    }

    #[test]
    fn generator_meta_names_a_cms() {
        assert_eq!(
            tech_from_generator("WordPress 6.4.2").unwrap().name,
            "WordPress"
        );
        assert!(tech_from_generator("Acme Custom Builder").is_none());
    }

    #[test]
    fn generator_content_is_extracted_from_a_tag() {
        let body =
            r#"<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>"#;
        assert_eq!(generator_content(body).as_deref(), Some("WordPress 6.4.2"));
        assert_eq!(generator_content("<html><head></head></html>"), None);
    }
}
