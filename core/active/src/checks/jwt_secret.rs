//! `jwt.secret` — a JWT signed with a secret anyone can guess.
//!
//! ```text
//! captured:  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.<sig>
//! offline:   HMAC-SHA256("your-256-bit-secret", "eyJ…9.eyJ…9")  ==  <sig>   ← it signs it
//! confirmed: a token minted with that secret, carrying a claim the server never issued,
//!            is accepted; the same token signed with a random key is refused.
//! ```
//!
//! # Why this is not [`auth::AuthEnforcement`]'s job
//!
//! `auth.enforcement` already asks whether the server *verifies* a signature — it sends a
//! token with a broken signature and a token with `alg: none` and watches for acceptance.
//! A server that passes both of those can still be fully forgeable: if it verifies HS256
//! correctly but with a secret like `secret` or the jwt.io sample key, an attacker who
//! knows the secret mints whatever token they like and every signature checks out. No
//! amount of *breaking* a signature finds that; you have to *make a valid one*.
//!
//! # Offline first, then one confirming send
//!
//! The secret is recovered without touching the target: the token carries its own
//! signature, so a candidate key either reproduces it or does not, and that is arithmetic
//! on bytes already captured — [`nullhawk_types::jwt::hs_secret_matches`]. Only once a
//! key is found does this send anything, and then only to confirm the server still
//! accepts a token minted with it: a token carrying a benign marker claim it never issued
//! (so acceptance cannot be the original token echoing back), against a control signed
//! with a random key (so acceptance is attributable to the signature, not the endpoint
//! being open). If that confirmation cannot be completed — the captured session has since
//! expired, or the token is HS384/512 rather than HS256 — the cryptographic match still
//! stands on its own as a firm finding, because a reproduced signature is proof the secret
//! is the signing key.
//!
//! # Scope
//!
//! The token must be an HS256/384/512 bearer in `Authorization` — those are the algorithms
//! with a shared secret to guess. An RS256/ES256 token has no guessable secret and is
//! refuted as such; a JWT carried in a cookie is a planned follow-up. The wordlist is
//! deliberately short: the secrets that show up in tutorials, samples and defaults, not a
//! brute force.

use async_trait::async_trait;
use nullhawk_repeater::Draft;
use nullhawk_types::finding::{
    Evidence, FindingSource, Hypothesis, Location, MessagePart, Severity,
};
use nullhawk_types::ids::RequestId;
use nullhawk_types::jwt::{self, Jwt};
use nullhawk_types::verify::{
    DetectorId, DetectorInfo, DetectorMode, Support, Verification, Writeup,
};
use nullhawk_types::Result;
use nullhawk_verify::Lab;
use serde_json::Value;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct JwtWeakSecret;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "jwt.guessable";

/// A benign claim added to the confirmation token. Unknown to the application, so it does
/// not change any authorization decision; present so the accepted token is demonstrably
/// one the server never issued rather than the original echoed back.
const MARKER_CLAIM: &str = "nh_probe";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("jwt.secret"),
    name: "Forgeable JWT (weak signing secret)",
    version: "1.0.0",
    about: "whether a JWT's HMAC signature was made with a guessable secret, letting anyone forge tokens",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Moderate,
};

#[async_trait]
impl ActiveCheck for JwtWeakSecret {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn handles(&self, hypothesis: &Hypothesis) -> bool {
        hypothesis.detector == SETTLES
    }

    async fn settle(
        &self,
        subject: &Subject,
        lab: &dyn Lab,
        budget: &Budget,
    ) -> Result<Verification> {
        let Some(token) = bearer_token(&subject.draft) else {
            return Ok(Verification::Inconclusive {
                why: "the replayed request carries no bearer token to test".into(),
            });
        };

        let jwt = match Jwt::parse(&token) {
            Ok(jwt) => jwt,
            Err(_) => {
                return Ok(Verification::Refuted {
                    note: "the Authorization bearer is not a JWT, so there is no signature to \
                           attribute to a secret"
                        .into(),
                })
            }
        };
        let alg = jwt.algorithm().unwrap_or("").to_string();
        if !alg.starts_with("HS") {
            return Ok(Verification::Refuted {
                note: format!(
                    "the token is signed with {}, which has no shared secret to guess; only an \
                     HMAC (HS256/384/512) token can be tested this way",
                    if alg.is_empty() {
                        "no stated algorithm"
                    } else {
                        &alg
                    },
                ),
            });
        }

        let candidates = common_secrets(&subject.exchange.host);
        let tried = candidates.len();
        let Some(secret) = candidates
            .into_iter()
            .find(|candidate| jwt::hs_secret_matches(&token, candidate.as_bytes()))
        else {
            return Ok(Verification::Refuted {
                note: format!(
                    "the token is {alg}, but none of the {tried} most common secrets produced its \
                     signature — the key is not one of the obvious ones (this is not a brute force)"
                ),
            });
        };

        // The secret is recovered, and that alone is a firm finding. Try to confirm the
        // server still accepts a token minted with it; fall back to the cryptographic
        // match if the confirmation cannot be completed.
        match confirm(subject, lab, &jwt, &alg, &secret, budget).await {
            Some(evidence) => Ok(Verification::Reproduced {
                note: format!(
                    "the token's HMAC signature is reproduced by the secret {secret:?}, and a \
                     token minted with it — carrying a claim the server never issued — was \
                     accepted while the same token signed with a random key was refused. The \
                     signing key is known, so any token can be forged"
                ),
                evidence,
            }),
            None => Ok(Verification::Supported {
                support: Support::Distinctive,
                note: format!(
                    "the token's {alg} signature is reproduced exactly by the secret {secret:?} — \
                     proof it is the signing key, so any token can be forged. (A live replay to \
                     confirm acceptance was not completed; the cryptographic match does not need \
                     one.)"
                ),
                evidence: vec![crypto_evidence(subject, &secret)],
            }),
        }
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        Writeup {
            target: subject.target,
            title: format!(
                "JWT on {} is signed with a guessable secret",
                path_of(&subject.exchange.url)
            ),
            description: format!(
                "{} {} was sent with a JSON Web Token in its Authorization header. {}\n\nThe \
                 secret was recovered offline — the token carries its own signature, so a \
                 candidate key either reproduces it or does not — and the wordlist tried was the \
                 short list of secrets found in tutorials, samples and framework defaults.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "The HMAC secret that signs the application's JWTs is known. An attacker who \
                     knows it can mint a token with any claims the application trusts — any user \
                     id, any role, any expiry — and every signature check will pass. This is a \
                     full authentication bypass and privilege escalation: the token is no longer \
                     evidence of anything, because anyone can produce a valid one."
                .into(),
            remediation: "Replace the secret with a long, random, high-entropy value (at least \
                          256 bits, from a CSPRNG), keep it out of source control and \
                          configuration that ships with the app, and rotate it — every token \
                          signed with the old secret is now forgeable. Prefer an asymmetric \
                          algorithm (RS256/ES256) so the verifier holds only a public key and \
                          pin the accepted algorithm server-side."
                .into(),
            reproduction: format!(
                "Recover the secret offline, then mint a token: `nullhawk jwt forge <token> \
                 --set <claim>=<value> --sign-hs256-env SECRET` and send it to {} {}. `nullhawk \
                 poc <project> <finding>` compiles the exact requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: Some("CWE-321".into()),
            owasp: Some("A02:2021 Cryptographic Failures".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: subject.hypothesis.location.clone(),
        }
    }
}

/// The bearer token in the replayed request's Authorization header, if present. Read from
/// the draft, not the exchange: the exchange's credentials are redacted, the draft's are
/// the real ones this check needs.
fn bearer_token(draft: &Draft) -> Option<String> {
    let header = draft.request.headers.get("authorization")?;
    let value = String::from_utf8_lossy(&header.value);
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Sends a token minted with the recovered secret against a random-key control, and
/// returns the evidence if the server accepted the first and refused the second. `None`
/// when the confirmation cannot be completed — too little budget, a non-HS256 token, a
/// baseline that no longer authenticates, or a server that does not distinguish the two.
async fn confirm(
    subject: &Subject,
    lab: &dyn Lab,
    jwt: &Jwt,
    alg: &str,
    secret: &str,
    budget: &Budget,
) -> Option<Vec<Evidence>> {
    // The live confirmation mints HS256; forging HS384/512 reliably would need to match
    // the server's pinned algorithm, which the offline proof already settles without a send.
    if alg != "HS256" || budget.per_hypothesis < 3 {
        return None;
    }

    let baseline = send(lab, &subject.draft).await.ok()?;
    if !(200..400).contains(&baseline.status) {
        // The captured session no longer authenticates; there is nothing live to confirm
        // against. The cryptographic match carries the finding instead.
        return None;
    }

    let mut payload = jwt.payload.clone();
    if let Some(map) = payload.as_object_mut() {
        map.insert(
            MARKER_CLAIM.to_string(),
            Value::String("nullhawk".to_string()),
        );
    }
    let forged = jwt::sign_hs256(&jwt.header, &payload, secret.as_bytes());
    let control = jwt::sign_hs256(&jwt.header, &payload, b"nullhawk-not-the-real-key");

    let forged_answer = send(lab, &with_bearer(&subject.draft, &forged))
        .await
        .ok()?;
    let control_answer = send(lab, &with_bearer(&subject.draft, &control))
        .await
        .ok()?;

    // The auth decision is the status: a minted-with-the-secret token that lands on the
    // baseline's status is accepted, and the random-key control must land somewhere else
    // (a rejection) for acceptance to be attributable to the signature rather than to an
    // endpoint that answers the same to everyone. Comparing status rather than body keeps
    // this robust against an endpoint that echoes the token's claims back.
    let accepted = forged_answer.status == baseline.status;
    let refused = control_answer.status != baseline.status;
    if accepted && refused {
        Some(vec![
            Evidence::Exchange {
                request: subject.exchange.id,
                response: None,
                note: "the captured request carrying the JWT".into(),
            },
            Evidence::Exchange {
                request: forged_answer.request,
                response: None,
                note: format!(
                    "a token minted with the recovered secret (carrying a `{MARKER_CLAIM}` claim \
                     the server never issued) was accepted: {}",
                    forged_answer.status
                ),
            },
            Evidence::Exchange {
                request: control_answer.request,
                response: None,
                note: format!(
                    "the same token signed with a random key was refused: {} — so acceptance \
                     tracks the signature, not an open endpoint",
                    control_answer.status
                ),
            },
        ])
    } else {
        None
    }
}

fn crypto_evidence(subject: &Subject, secret: &str) -> Evidence {
    Evidence::Exchange {
        request: subject.exchange.id,
        response: None,
        note: format!(
            "the JWT in this request's Authorization header is signed with the secret {secret:?} \
             — its HMAC signature is reproduced exactly by that key"
        ),
    }
}

/// One send and what came back. Only the status is read: this check's proof is the
/// cryptographic signature match, and the live step only needs the server's accept/reject
/// decision, which is the status line.
struct Answer {
    request: RequestId,
    status: u16,
}

async fn send(lab: &dyn Lab, draft: &Draft) -> std::result::Result<Answer, String> {
    let sent = lab
        .experiment(draft, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Answer {
        request: sent.id,
        status: sent.exchange.response.status,
    })
}

/// A draft with its Authorization bearer replaced by `token`.
fn with_bearer(draft: &Draft, token: &str) -> Draft {
    let mut draft = draft.clone();
    draft
        .request
        .headers
        .set("Authorization", format!("Bearer {token}"));
    draft
}

/// Severity from what was established. A recovered signing key is critical either way; a
/// live-confirmed one is reproduced, a cryptographically-matched one is firm.
fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } | Verification::Supported { .. } => Severity::Critical,
        _ => Severity::Low,
    }
}

/// The short wordlist of secrets a JWT should never be signed with: tutorial samples,
/// framework defaults, and the handful of words people reach for. Plus the target's own
/// host and its first label, which are a surprisingly common "secret". Not a brute force —
/// if the key is not an obvious one, this says so and sends nothing.
fn common_secrets(host: &str) -> Vec<String> {
    let mut out: Vec<String> = [
        "secret",
        "secretkey",
        "secret123",
        "your-256-bit-secret", // the jwt.io sample key
        "your_jwt_secret",
        "jwt",
        "jwtsecret",
        "jwt_secret",
        "password",
        "changeme",
        "change-me",
        "admin",
        "administrator",
        "token",
        "key",
        "private",
        "privatekey",
        "mysecret",
        "supersecret",
        "s3cr3t",
        "security",
        "test",
        "testing",
        "dev",
        "development",
        "qwerty",
        "123456",
        "0000",
        "",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let bare = host.split(':').next().unwrap_or(host);
    if !bare.is_empty() {
        out.push(bare.to_string());
        if let Some(label) = bare.split('.').next() {
            if label != bare && !label.is_empty() {
                out.push(label.to_string());
            }
        }
    }
    out
}

/// Raises one suspicion per authenticated, replayable request.
///
/// Credential values are redacted in the exchange, and even the header they arrived in is
/// not reliably reconstructed on the representative endpoint, so the gate here is just
/// "was sent with a credential" — the same gate `auth.enforcement` uses. Whether that
/// credential is actually an HMAC JWT with a guessable secret is read from the *draft* in
/// [`settle`](JwtWeakSecret::settle), which carries the real token; a request whose
/// credential is a cookie or an opaque bearer is refuted there, cheaply and without a
/// send. Non-`GET`/`HEAD`/`OPTIONS` requests are left alone — the confirmation replays the
/// request, and a scan must not replay a state-changing verb.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    if !exchange.authenticated {
        return Vec::new();
    }
    if crate::schedule::is_state_changing(&exchange.method) {
        return Vec::new();
    }
    if !(200..400).contains(&exchange.status) {
        return Vec::new();
    }

    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} was sent with a credential — whether it is a JWT signed with a guessable \
             secret needs the token read from the request and its signature tested",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: Some(Location {
            part: MessagePart::Header,
            name: "Authorization".to_string(),
        }),
        provisional_severity: Severity::Info,
    }]
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "x".into(),
            source_request: RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    fn exchange(
        method: &str,
        status: u16,
        authenticated: bool,
        authz: bool,
    ) -> nullhawk_scan::Exchange {
        let mut request_headers = nullhawk_types::http::Headers::new();
        if authz {
            request_headers.set("Authorization", "Bearer [redacted]");
        }
        nullhawk_scan::Exchange {
            id: RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: "https://api.example.com/account".into(),
            path: "/account".into(),
            status,
            request_headers,
            response_headers: nullhawk_types::http::Headers::new(),
            response_bytes: 0,
            authenticated,
            tls: None,
            sent_at: "2026-10-04T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        assert!(JwtWeakSecret.handles(&raised(SETTLES)));
        assert!(!JwtWeakSecret.handles(&raised("auth.unverified")));
    }

    #[test]
    fn it_is_an_active_settler() {
        let info = JwtWeakSecret.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn it_suspects_an_authenticated_replayable_request() {
        // Authenticated + replayable + succeeded: a target, whether or not the redacted
        // representative still shows the Authorization header (settle reads the draft).
        assert_eq!(exchange_suspects("GET", 200, true, true), 1);
        assert_eq!(exchange_suspects("GET", 200, true, false), 1);
        // Not authenticated, state-changing, or already-refused: not a target.
        assert_eq!(exchange_suspects("GET", 200, false, true), 0);
        assert_eq!(exchange_suspects("POST", 200, true, true), 0);
        assert_eq!(exchange_suspects("GET", 401, true, true), 0);
    }

    fn exchange_suspects(method: &str, status: u16, auth: bool, authz: bool) -> usize {
        suspect(&exchange(method, status, auth, authz)).len()
    }

    #[test]
    fn a_raised_suspicion_names_the_header_and_claims_nothing_yet() {
        let raised = suspect(&exchange("GET", 200, true, true));
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].provisional_severity, Severity::Info);
        let location = raised[0].location.as_ref().unwrap();
        assert_eq!(location.part, MessagePart::Header);
        assert_eq!(location.name, "Authorization");
    }

    #[test]
    fn the_wordlist_includes_the_classics_and_the_host() {
        let list = common_secrets("api.example.com:443");
        assert!(list.iter().any(|s| s == "your-256-bit-secret"));
        assert!(list.iter().any(|s| s == "secret"));
        assert!(
            list.iter().any(|s| s.is_empty()),
            "the empty secret is tried"
        );
        assert!(
            list.iter().any(|s| s == "api.example.com"),
            "the host is tried"
        );
        assert!(
            list.iter().any(|s| s == "api"),
            "the first host label is tried"
        );
    }

    #[test]
    fn bearer_token_is_read_from_the_draft() {
        let token = jwt::sign_hs256(&json!({"alg": "HS256"}), &json!({"sub": "a"}), b"secret");
        let mut request = nullhawk_types::http::HttpRequest::get(
            nullhawk_types::http::HttpService {
                host: "api.example.com".into(),
                port: 443,
                secure: true,
            },
            "/account",
        );
        request
            .headers
            .set("Authorization", format!("Bearer {token}"));
        let draft = Draft::new(request);
        assert_eq!(bearer_token(&draft).as_deref(), Some(token.as_str()));
    }
}
