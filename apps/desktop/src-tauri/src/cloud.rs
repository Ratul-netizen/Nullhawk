//! Leaked-credential validation — turn "a key was exposed" into "this key is live, and it
//! is <this> principal."
//!
//! The secret miner flags things that *look* like cloud keys. This confirms one: it asks
//! the cloud provider who the key is, read-only. For AWS that is STS `GetCallerIdentity` —
//! the one call every principal can make, which reveals the account, the ARN and the user
//! id without touching any resource. A 200 with an ARN is proof the key is live and names
//! whose it is; a 403 is proof it is not (or the secret is wrong).
//!
//! The request is a normal signed STS call sent through the engine's transport, so it is
//! an ordinary HTTPS request to `sts.amazonaws.com` and nothing else. Only validate keys
//! you are authorised to test.
//!
//! Signing is AWS Signature Version 4, built here on `ring` (HMAC-SHA256 + SHA-256) — no
//! AWS SDK, which would be an enormous dependency for one call.

use base64::Engine as _;
use bytes::Bytes;
use nullhawk_engine::transport::{HttpTransport, Origin, SendOptions};
use nullhawk_http::TcpTransport;
use nullhawk_types::http::{Headers, HttpRequest, HttpService, HttpVersion};
use nullhawk_types::jwt::{base64url_decode, base64url_encode};
use ring::{digest, hmac, rand, signature};
use serde::{Deserialize, Serialize};

type CommandResult<T> = std::result::Result<T, String>;

const HOST: &str = "sts.amazonaws.com";
const REGION: &str = "us-east-1";
const SERVICE: &str = "sts";
const BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";
const CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// The answer to "is this AWS key live, and whose is it?".
#[derive(Debug, Clone, Serialize)]
pub struct AwsIdentity {
    /// Whether the key authenticated.
    pub valid: bool,
    /// The principal's ARN (e.g. arn:aws:iam::123456789012:user/foo), when valid.
    pub arn: Option<String>,
    /// The 12-digit account id, when valid.
    pub account: Option<String>,
    /// The principal's unique id, when valid.
    pub user_id: Option<String>,
    /// AWS's error code when the key did not authenticate (e.g. InvalidClientTokenId).
    pub error_code: Option<String>,
    /// AWS's error message, when present.
    pub error_message: Option<String>,
    /// A one-line human summary.
    pub note: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// Produces the `Authorization` header for a signed STS `GetCallerIdentity` POST.
///
/// `amz_date` is ISO-8601 basic (YYYYMMDDTHHMMSSZ) and `datestamp` is YYYYMMDD; both are
/// passed in rather than read from the clock so the signing is a pure, testable function.
fn authorization(
    access_key: &str,
    secret: &str,
    session_token: Option<&str>,
    amz_date: &str,
    datestamp: &str,
) -> String {
    let signed_headers = if session_token.is_some() {
        "content-type;host;x-amz-date;x-amz-security-token"
    } else {
        "content-type;host;x-amz-date"
    };

    let mut canonical_headers =
        format!("content-type:{CONTENT_TYPE}\nhost:{HOST}\nx-amz-date:{amz_date}\n");
    if let Some(token) = session_token {
        canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
    }

    let payload_hash = sha256_hex(BODY.as_bytes());
    // Method, canonical URI, (empty) query, canonical headers, signed headers, payload hash.
    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let scope = format!("{datestamp}/{REGION}/{SERVICE}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

/// Extracts the text between `<tag>` and `</tag>` in a small XML document.
fn between(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

fn interpret(status: u16, body: &str) -> AwsIdentity {
    if status == 200 {
        let arn = between(body, "Arn");
        let account = between(body, "Account");
        let note = match &arn {
            Some(a) => format!("Live key — {a}"),
            None => "Live key (STS returned 200 but no ARN was parsed)".to_string(),
        };
        AwsIdentity {
            valid: true,
            arn,
            account,
            user_id: between(body, "UserId"),
            error_code: None,
            error_message: None,
            note,
        }
    } else {
        let code = between(body, "Code");
        let message = between(body, "Message");
        let note = match &code {
            Some(c) => format!("Not a valid key: {c}"),
            None => format!("Not a valid key (HTTP {status})"),
        };
        AwsIdentity {
            valid: false,
            arn: None,
            account: None,
            user_id: None,
            error_code: code,
            error_message: message,
            note,
        }
    }
}

/// Validates an AWS access key by asking STS who it is. Read-only; touches no resource.
#[tauri::command]
pub async fn cloud_validate_aws(
    access_key: String,
    secret: String,
    session_token: Option<String>,
) -> CommandResult<AwsIdentity> {
    let access_key = access_key.trim().to_string();
    let secret = secret.trim().to_string();
    let session_token = session_token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if access_key.is_empty() || secret.is_empty() {
        return Err("both an access key id and a secret access key are required".into());
    }

    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let datestamp = now.format("%Y%m%d").to_string();
    let auth = authorization(
        &access_key,
        &secret,
        session_token.as_deref(),
        &amz_date,
        &datestamp,
    );

    let (service, path) =
        HttpService::parse_url(&format!("https://{HOST}/")).map_err(|e| e.to_string())?;
    let mut headers = Headers::new();
    headers.set("Host", HOST);
    headers.set("Content-Type", CONTENT_TYPE);
    headers.set("X-Amz-Date", amz_date);
    if let Some(token) = &session_token {
        headers.set("X-Amz-Security-Token", token);
    }
    headers.set("Authorization", auth);
    headers.set("Content-Length", BODY.len().to_string());

    let request = HttpRequest {
        service,
        method: "POST".to_string(),
        path,
        version: HttpVersion::Http11,
        headers,
        body: Bytes::from_static(BODY.as_bytes()),
    };

    let exchange = TcpTransport::new()
        .send(request, SendOptions::interactive(Origin::Repeater))
        .await
        .map_err(|e| format!("could not reach AWS STS: {e}"))?;

    let status = exchange.response.status;
    let body = String::from_utf8_lossy(&exchange.response.body);
    Ok(interpret(status, &body))
}

// ---------------------------------------------------------------------------
// GCP — validate a leaked service-account key
// ---------------------------------------------------------------------------
//
// A GCP service-account key is a JSON file holding an RSA private key and the account's
// email. Unlike AWS there is no "who am I" call that returns an identity without a token,
// so validation mints one: sign a JWT assertion with the key and exchange it at Google's
// OAuth token endpoint (the standard jwt-bearer grant). A 200 with an access_token proves
// the key is live and names the service account; an `invalid_grant` proves it is not.
//
// The requested scope is cloud-platform **read-only** and the token is never used or
// stored — we only need the endpoint's yes/no. Only validate keys you are authorised to
// test. The request goes to the key's own `token_uri` (oauth2.googleapis.com) and nowhere
// else. Signing is RS256 on `ring`; no Google SDK.

const GCP_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform.read-only";
// grant_type with its colons percent-encoded for the form body.
const GCP_GRANT_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

/// The fields we read from a service-account key JSON (the rest are ignored).
#[derive(Debug, Clone, Deserialize)]
struct ServiceAccountKey {
    #[serde(default)]
    client_email: String,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    private_key_id: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
    #[serde(default)]
    project_id: String,
}

/// The answer to "is this GCP service-account key live, and whose is it?".
#[derive(Debug, Clone, Serialize)]
pub struct GcpIdentity {
    /// Whether the key minted a token.
    pub valid: bool,
    /// The service account's email (from the key file).
    pub client_email: Option<String>,
    /// The project the key belongs to (from the key file), when present.
    pub project_id: Option<String>,
    /// Google's OAuth error code when the key did not authenticate (e.g. invalid_grant).
    pub error: Option<String>,
    /// Google's error description, when present.
    pub error_description: Option<String>,
    /// A one-line human summary.
    pub note: String,
}

/// Decodes a PEM private key (any `-----BEGIN…-----` armour) to its DER bytes.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// The JWT claim set for a service-account assertion, as compact JSON.
fn sa_claims(sa: &ServiceAccountKey, iat: i64, exp: i64) -> String {
    format!(
        r#"{{"iss":"{iss}","scope":"{GCP_SCOPE}","aud":"{aud}","iat":{iat},"exp":{exp}}}"#,
        iss = sa.client_email,
        aud = sa.token_uri,
    )
}

/// Signs the `header.claims` input with the account's RSA key (RS256), returning the
/// complete JWT assertion.
fn sign_assertion(sa: &ServiceAccountKey, iat: i64, exp: i64) -> CommandResult<String> {
    let header = format!(
        r#"{{"alg":"RS256","typ":"JWT","kid":"{}"}}"#,
        sa.private_key_id
    );
    let signing_input = format!(
        "{}.{}",
        base64url_encode(header.as_bytes()),
        base64url_encode(sa_claims(sa, iat, exp).as_bytes())
    );

    let der = pem_to_der(&sa.private_key)
        .ok_or_else(|| "the private_key is not valid PEM".to_string())?;
    let key_pair = signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|e| format!("the private_key is not a PKCS#8 RSA key: {e}"))?;
    let rng = rand::SystemRandom::new();
    let mut sig = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &signature::RSA_PKCS1_SHA256,
            &rng,
            signing_input.as_bytes(),
            &mut sig,
        )
        .map_err(|_| "signing the assertion failed".to_string())?;
    Ok(format!("{signing_input}.{}", base64url_encode(&sig)))
}

/// The host portion of a URL, for the Host header.
fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

fn interpret_gcp(sa: &ServiceAccountKey, status: u16, body: &[u8]) -> GcpIdentity {
    let json: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let client_email = (!sa.client_email.is_empty()).then(|| sa.client_email.clone());
    let project_id = (!sa.project_id.is_empty()).then(|| sa.project_id.clone());

    let has_token = json
        .get("access_token")
        .and_then(|v| v.as_str())
        .is_some_and(|t| !t.is_empty());

    if status == 200 && has_token {
        let note = match &client_email {
            Some(e) => format!("Live key — {e}"),
            None => "Live key (a token was issued)".to_string(),
        };
        GcpIdentity {
            valid: true,
            client_email,
            project_id,
            error: None,
            error_description: None,
            note,
        }
    } else {
        let error = json
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let error_description = json
            .get("error_description")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let note = match &error {
            Some(e) => format!("Not a valid key: {e}"),
            None => format!("Not a valid key (HTTP {status})"),
        };
        GcpIdentity {
            valid: false,
            client_email,
            project_id,
            error,
            error_description,
            note,
        }
    }
}

/// Validates a GCP service-account key by minting a read-only token with it. The key never
/// leaves this machine except as a signed assertion to its own token endpoint.
#[tauri::command]
pub async fn cloud_validate_gcp(key_json: String) -> CommandResult<GcpIdentity> {
    let sa: ServiceAccountKey = serde_json::from_str(key_json.trim())
        .map_err(|e| format!("that is not a service-account key JSON: {e}"))?;
    if sa.client_email.is_empty() || sa.private_key.is_empty() {
        return Err("the key JSON needs both client_email and private_key".into());
    }

    let now = chrono::Utc::now().timestamp();
    let assertion = sign_assertion(&sa, now, now + 3600)?;
    let body = format!("grant_type={GCP_GRANT_TYPE}&assertion={assertion}");

    let (service, path) = HttpService::parse_url(&sa.token_uri).map_err(|e| e.to_string())?;
    let host = host_of(&sa.token_uri);
    let mut headers = Headers::new();
    headers.set("Host", &host);
    headers.set("Content-Type", "application/x-www-form-urlencoded");
    headers.set("Content-Length", body.len().to_string());
    let request = HttpRequest {
        service,
        method: "POST".to_string(),
        path,
        version: HttpVersion::Http11,
        headers,
        body: Bytes::from(body),
    };

    let exchange = TcpTransport::new()
        .send(request, SendOptions::interactive(Origin::Repeater))
        .await
        .map_err(|e| format!("could not reach the Google token endpoint: {e}"))?;

    Ok(interpret_gcp(
        &sa,
        exchange.response.status,
        &exchange.response.body,
    ))
}

// ---------------------------------------------------------------------------
// Azure — validate a leaked service-principal secret
// ---------------------------------------------------------------------------
//
// An Azure application credential is a trio: a tenant, an application (client) id, and a
// client secret. Validation is the OAuth2 client-credentials grant against Azure AD's
// token endpoint — present the secret and ask for a token. A 200 with an access_token
// proves the secret is live; the token is a JWT whose (unverified) claims name the
// application, tenant and object, which we read without using the token for anything. An
// `invalid_client` proves the secret is wrong or expired.
//
// The token is requested for the ARM scope's `.default` and is never used or stored. The
// request goes to `login.microsoftonline.com` and nowhere else. Only validate credentials
// you are authorised to test.

const AZURE_SCOPE: &str = "https://management.azure.com/.default";

/// The answer to "is this Azure app secret live, and which app is it?".
#[derive(Debug, Clone, Serialize)]
pub struct AzureIdentity {
    /// Whether the secret authenticated.
    pub valid: bool,
    /// The directory (tenant) id — from the token when valid, else echoed from the input.
    pub tenant: Option<String>,
    /// The application (client) id — from the token when valid, else echoed from the input.
    pub app_id: Option<String>,
    /// The service principal's object id, from the token's `oid` claim, when valid.
    pub object_id: Option<String>,
    /// Azure AD's error code when the secret did not authenticate (e.g. invalid_client).
    pub error: Option<String>,
    /// Azure AD's error description, when present.
    pub error_description: Option<String>,
    /// A one-line human summary.
    pub note: String,
}

/// Percent-encodes a string for an `application/x-www-form-urlencoded` body (RFC 3986
/// unreserved set passes through; everything else is `%XX`). Azure client secrets routinely
/// contain `+`, `/` and `=`, so the secret must be encoded or the grant silently fails.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decodes a JWT's payload claims without verifying its signature (we only read identity
/// fields from a token the endpoint just minted for us).
fn decode_claims(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&base64url_decode(payload)?).ok()
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn interpret_azure(tenant_in: &str, client_id_in: &str, status: u16, body: &[u8]) -> AzureIdentity {
    let json: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);

    if status == 200 {
        if let Some(token) = json.get("access_token").and_then(|v| v.as_str()) {
            let claims = decode_claims(token);
            let claim = |k: &str| {
                claims
                    .as_ref()
                    .and_then(|c| c.get(k))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            };
            let app_id = claim("appid").or_else(|| non_empty(client_id_in));
            let note = match &app_id {
                Some(a) => format!("Live credential — app {a}"),
                None => "Live credential (a token was issued)".to_string(),
            };
            return AzureIdentity {
                valid: true,
                tenant: claim("tid").or_else(|| non_empty(tenant_in)),
                app_id,
                object_id: claim("oid"),
                error: None,
                error_description: None,
                note,
            };
        }
    }

    let error = json
        .get("error")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let error_description = json
        .get("error_description")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let note = match &error {
        Some(e) => format!("Not a valid credential: {e}"),
        None => format!("Not a valid credential (HTTP {status})"),
    };
    AzureIdentity {
        valid: false,
        tenant: non_empty(tenant_in),
        app_id: non_empty(client_id_in),
        object_id: None,
        error,
        error_description,
        note,
    }
}

/// Validates an Azure service-principal secret via the client-credentials grant.
#[tauri::command]
pub async fn cloud_validate_azure(
    tenant: String,
    client_id: String,
    client_secret: String,
) -> CommandResult<AzureIdentity> {
    let tenant = tenant.trim().to_string();
    let client_id = client_id.trim().to_string();
    let client_secret = client_secret.trim().to_string();
    if tenant.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return Err("a tenant, a client id and a client secret are all required".into());
    }

    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
        form_encode(&client_id),
        form_encode(&client_secret),
        form_encode(AZURE_SCOPE),
    );

    let (service, path) = HttpService::parse_url(&url).map_err(|e| e.to_string())?;
    let mut headers = Headers::new();
    headers.set("Host", "login.microsoftonline.com");
    headers.set("Content-Type", "application/x-www-form-urlencoded");
    headers.set("Content-Length", body.len().to_string());
    let request = HttpRequest {
        service,
        method: "POST".to_string(),
        path,
        version: HttpVersion::Http11,
        headers,
        body: Bytes::from(body),
    };

    let exchange = TcpTransport::new()
        .send(request, SendOptions::interactive(Origin::Repeater))
        .await
        .map_err(|e| format!("could not reach the Azure AD token endpoint: {e}"))?;

    Ok(interpret_azure(
        &tenant,
        &client_id,
        exchange.response.status,
        &exchange.response.body,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_known_empty_hash() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn signing_is_deterministic_and_well_formed() {
        let a = authorization(
            "AKIAEXAMPLE",
            "secret",
            None,
            "20250101T000000Z",
            "20250101",
        );
        let b = authorization(
            "AKIAEXAMPLE",
            "secret",
            None,
            "20250101T000000Z",
            "20250101",
        );
        assert_eq!(a, b, "same inputs sign the same");
        assert!(a.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20250101/us-east-1/sts/aws4_request"
        ));
        assert!(a.contains("SignedHeaders=content-type;host;x-amz-date,"));
        assert!(a.contains("Signature="));
        // A session token adds the security-token header to the signed set.
        let withtok = authorization(
            "AKIAEXAMPLE",
            "secret",
            Some("TOK"),
            "20250101T000000Z",
            "20250101",
        );
        assert!(
            withtok.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,")
        );
        assert_ne!(
            a, withtok,
            "a different signed-header set changes the signature"
        );
    }

    #[test]
    fn interprets_a_live_identity() {
        let xml = "<GetCallerIdentityResponse><GetCallerIdentityResult>\
                   <Arn>arn:aws:iam::123456789012:user/alice</Arn>\
                   <UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>\
                   </GetCallerIdentityResult></GetCallerIdentityResponse>";
        let id = interpret(200, xml);
        assert!(id.valid);
        assert_eq!(id.account.as_deref(), Some("123456789012"));
        assert_eq!(
            id.arn.as_deref(),
            Some("arn:aws:iam::123456789012:user/alice")
        );
    }

    #[test]
    fn interprets_an_invalid_key() {
        let xml = "<ErrorResponse><Error><Type>Sender</Type>\
                   <Code>InvalidClientTokenId</Code>\
                   <Message>The security token included in the request is invalid.</Message>\
                   </Error></ErrorResponse>";
        let id = interpret(403, xml);
        assert!(!id.valid);
        assert_eq!(id.error_code.as_deref(), Some("InvalidClientTokenId"));
        assert!(id.note.contains("InvalidClientTokenId"));
    }

    // --- GCP -------------------------------------------------------------------------

    fn test_sa() -> ServiceAccountKey {
        ServiceAccountKey {
            client_email: "svc@proj.iam.gserviceaccount.com".to_string(),
            private_key: String::new(),
            private_key_id: "kid123".to_string(),
            token_uri: default_token_uri(),
            project_id: "proj".to_string(),
        }
    }

    #[test]
    fn pem_to_der_strips_armour_and_decodes() {
        let der = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        // Split across lines, as real PEM is wrapped.
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n{}\n-----END PRIVATE KEY-----\n",
            &b64[..4],
            &b64[4..]
        );
        assert_eq!(pem_to_der(&pem).as_deref(), Some(der.as_slice()));
    }

    #[test]
    fn the_assertion_claims_name_the_account_and_scope() {
        let claims = sa_claims(&test_sa(), 1_700_000_000, 1_700_003_600);
        assert!(claims.contains(r#""iss":"svc@proj.iam.gserviceaccount.com""#));
        assert!(claims.contains("cloud-platform.read-only"));
        assert!(claims.contains("oauth2.googleapis.com/token"));
        assert!(claims.contains(r#""exp":1700003600"#));
    }

    #[test]
    fn host_of_reads_the_authority() {
        assert_eq!(host_of("https://oauth2.googleapis.com/token"), "oauth2.googleapis.com");
    }

    #[test]
    fn interprets_a_live_gcp_token() {
        let body = br#"{"access_token":"ya29.redacted","expires_in":3599,"token_type":"Bearer"}"#;
        let id = interpret_gcp(&test_sa(), 200, body);
        assert!(id.valid);
        assert_eq!(
            id.client_email.as_deref(),
            Some("svc@proj.iam.gserviceaccount.com")
        );
        assert_eq!(id.project_id.as_deref(), Some("proj"));
    }

    #[test]
    fn interprets_an_invalid_gcp_key() {
        let body = br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#;
        let id = interpret_gcp(&test_sa(), 400, body);
        assert!(!id.valid);
        assert_eq!(id.error.as_deref(), Some("invalid_grant"));
        assert_eq!(
            id.error_description.as_deref(),
            Some("Invalid JWT Signature.")
        );
        assert!(id.note.contains("invalid_grant"));
    }

    // --- Azure -----------------------------------------------------------------------

    #[test]
    fn form_encode_escapes_reserved_but_not_unreserved() {
        // A realistic Azure-secret alphabet: +, / and = must be escaped.
        assert_eq!(form_encode("ab+cd/ef=gh"), "ab%2Bcd%2Fef%3Dgh");
        // The RFC 3986 unreserved set passes through untouched.
        assert_eq!(form_encode("Az09-._~"), "Az09-._~");
    }

    /// Builds a JWT whose payload carries the given claims (header and signature are inert —
    /// the validator reads the payload only).
    fn jwt_with_claims(claims: &str) -> String {
        format!(
            "{}.{}.{}",
            base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            base64url_encode(claims.as_bytes()),
            base64url_encode(b"signature"),
        )
    }

    #[test]
    fn interprets_a_live_azure_credential() {
        let token = jwt_with_claims(
            r#"{"appid":"11111111-1111-1111-1111-111111111111","tid":"22222222-2222-2222-2222-222222222222","oid":"33333333-3333-3333-3333-333333333333"}"#,
        );
        let body = format!(r#"{{"token_type":"Bearer","expires_in":3599,"access_token":"{token}"}}"#);
        let id = interpret_azure("tenant-in", "client-in", 200, body.as_bytes());
        assert!(id.valid);
        // Claims from the token win over the echoed inputs.
        assert_eq!(
            id.app_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            id.tenant.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
        assert_eq!(
            id.object_id.as_deref(),
            Some("33333333-3333-3333-3333-333333333333")
        );
    }

    #[test]
    fn interprets_an_invalid_azure_secret() {
        let body = br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#;
        let id = interpret_azure("tenant-in", "client-in", 401, body);
        assert!(!id.valid);
        assert_eq!(id.error.as_deref(), Some("invalid_client"));
        // Falls back to echoing the inputs when there is no token to read.
        assert_eq!(id.app_id.as_deref(), Some("client-in"));
        assert!(id.note.contains("invalid_client"));
    }
}
