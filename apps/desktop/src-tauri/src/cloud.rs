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

use bytes::Bytes;
use nullhawk_engine::transport::{HttpTransport, Origin, SendOptions};
use nullhawk_http::TcpTransport;
use nullhawk_types::http::{Headers, HttpRequest, HttpService, HttpVersion};
use ring::{digest, hmac};
use serde::Serialize;

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
}
