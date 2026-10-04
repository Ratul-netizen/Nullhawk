//! Reading, re-signing and forging JSON Web Tokens — the manual half of JWT testing.
//!
//! # Why this exists
//!
//! A JWT is the application's own signed statement about who the caller is. Three
//! questions decide whether that statement can be trusted, and none of them can be
//! answered by reading the token — only by making the server read a token it should
//! reject and watching whether it does:
//!
//!   - Does it accept `alg: none`? Then the signature is decorative and anyone can mint
//!     a token for anyone.
//!   - Does it verify the signature with a guessable secret? Then the signature is real
//!     but worthless.
//!   - Does it confuse an RS256 public key for an HMAC secret? Then a key the server
//!     publishes can be used to sign tokens it will accept.
//!
//! This module is the toolwork those tests are built on: decode a token to see what it
//! claims, change a claim, and re-emit it signed the way an attack would sign it (with
//! no signature, or with a key the tester supplies). It mints tokens; it does not decide
//! whether a server accepts one. That is a request, and it belongs to a detector or a
//! person driving `nullhawk send`.
//!
//! Nothing here is a secret-bearing operation on our own side: the only key involved is
//! one the tester chose to try. Reading a JWT's header and payload is reading base64url,
//! not breaking anything — the same reasoning as [`crate::expiry`], which reads `exp`
//! from the same place.

use crate::NullhawkError;
use serde_json::Value;

/// A parsed JWT, decoded as far as it decodes.
///
/// `header` and `payload` are the decoded JSON objects. `signature` is the raw bytes of
/// the third segment, which is empty for an unsigned (`alg: none`) token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwt {
    /// The decoded JOSE header, e.g. `{"alg":"HS256","typ":"JWT"}`.
    pub header: Value,
    /// The decoded claims set, e.g. `{"sub":"alice","exp":1789156566}`.
    pub payload: Value,
    /// The raw signature bytes; empty when the token carries no signature.
    pub signature: Vec<u8>,
}

impl Jwt {
    /// Parses a token of the form `header.payload.signature`, tolerating a `Bearer `
    /// prefix and surrounding whitespace. Both the header and the payload must decode
    /// to a JSON object; the signature may be empty but its segment must be present.
    pub fn parse(token: &str) -> Result<Jwt, NullhawkError> {
        let token = token.trim();
        let token = token.strip_prefix("Bearer ").unwrap_or(token).trim();
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(NullhawkError::invalid_input(
                "token",
                "a JWT has three dot-separated parts: header.payload.signature",
            ));
        };
        if parts.next().is_some() {
            return Err(NullhawkError::invalid_input(
                "token",
                "a JWT has exactly three parts; this has more",
            ));
        }
        let header = decode_segment(header, "header")?;
        let payload = decode_segment(payload, "payload")?;
        let signature = base64url_decode(signature).ok_or_else(|| {
            NullhawkError::invalid_input("token", "the signature is not valid base64url")
        })?;
        Ok(Jwt {
            header,
            payload,
            signature,
        })
    }

    /// The `alg` the token names, if it names one as a string.
    pub fn algorithm(&self) -> Option<&str> {
        self.header.get("alg").and_then(Value::as_str)
    }

    /// Re-emit with `alg` forced to the given value and an empty signature — the
    /// `alg: none` attack. The casing is a parameter because a verifier that rejects
    /// `none` often still accepts `None` or `nOnE` (a case-sensitive string compare
    /// against one spelling).
    pub fn with_alg_none(&self, casing: &str) -> String {
        let mut header = self.header.clone();
        header_set(&mut header, "alg", Value::String(casing.to_string()));
        unsigned(&header, &self.payload)
    }

    /// Re-sign as HS256 with a candidate secret. This is both the weak-secret test (try
    /// a guessed key) and the RS256→HS256 confusion test (pass the server's RSA public
    /// key bytes as the HMAC secret). The header's `alg` is set to `HS256`.
    pub fn resign_hs256(&self, secret: &[u8]) -> String {
        let mut header = self.header.clone();
        header_set(&mut header, "alg", Value::String("HS256".to_string()));
        sign_hs256(&header, &self.payload, secret)
    }

    /// Re-emit the token with its claims re-serialised and no signature. Used to deliver
    /// a tampered payload to a server that does not verify signatures at all.
    pub fn stripped(&self) -> String {
        unsigned(&self.header, &self.payload)
    }

    /// Set (or add) one top-level claim in the payload, returning a token re-signed
    /// HS256 with the given secret. For an unsigned result, mutate [`Jwt::payload`]
    /// directly and call [`Jwt::stripped`] or [`Jwt::with_alg_none`].
    pub fn with_claim_hs256(&self, key: &str, value: Value, secret: &[u8]) -> String {
        let mut payload = self.payload.clone();
        header_set(&mut payload, key, value);
        let mut header = self.header.clone();
        header_set(&mut header, "alg", Value::String("HS256".to_string()));
        sign_hs256(&header, &payload, secret)
    }
}

/// The signing input of a JWT: `base64url(header) "." base64url(payload)`, over the
/// compact JSON of each. A verifier recomputes the signature over exactly these bytes.
pub fn signing_input(header: &Value, payload: &Value) -> String {
    format!(
        "{}.{}",
        base64url_encode(&compact(header)),
        base64url_encode(&compact(payload))
    )
}

/// A token with no signature (`header.payload.`), as the `alg: none` family expects.
pub fn unsigned(header: &Value, payload: &Value) -> String {
    format!("{}.", signing_input(header, payload))
}

/// A token signed HS256 (HMAC-SHA256) with the given secret.
pub fn sign_hs256(header: &Value, payload: &Value, secret: &[u8]) -> String {
    let input = signing_input(header, payload);
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let tag = ring::hmac::sign(&key, input.as_bytes());
    format!("{input}.{}", base64url_encode(tag.as_ref()))
}

/// Compact JSON (no insignificant whitespace), the form a JWT segment carries.
fn compact(value: &Value) -> Vec<u8> {
    // serde_json never fails to serialise a Value it already holds.
    serde_json::to_vec(value).unwrap_or_default()
}

/// Sets a key on a JSON object, turning a non-object into one so the caller always gets
/// the key it asked for rather than a silent no-op.
fn header_set(target: &mut Value, key: &str, value: Value) {
    if !target.is_object() {
        *target = Value::Object(serde_json::Map::new());
    }
    if let Some(map) = target.as_object_mut() {
        map.insert(key.to_string(), value);
    }
}

fn decode_segment(segment: &str, which: &'static str) -> Result<Value, NullhawkError> {
    let bytes = base64url_decode(segment).ok_or_else(|| {
        NullhawkError::invalid_input("token", format!("the {which} is not base64url"))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| NullhawkError::invalid_input("token", format!("the {which} is not JSON")))
}

/// Encodes bytes as unpadded base64url, the form a JWT writes.
pub fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = u32::from_be_bytes([0, b0, b1, b2]);
        let indices = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        // Emit one character per 6 bits that is backed by an input byte: 2 chars for a
        // one-byte tail, 3 for a two-byte tail, 4 for a full triple.
        for idx in indices.iter().take(chunk.len() + 1) {
            out.push(ALPHABET[*idx as usize] as char);
        }
    }
    out
}

/// Decodes unpadded base64url. Padding is tolerated though a JWT never writes it.
pub fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hs256(header: &Value, payload: &Value, secret: &[u8]) -> String {
        sign_hs256(header, payload, secret)
    }

    #[test]
    fn base64url_round_trips_including_awkward_lengths() {
        for case in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"\x00\xff\x10\x81",
            br#"{"alg":"HS256","typ":"JWT"}"#,
        ] {
            let encoded = base64url_encode(case);
            assert!(!encoded.contains('='), "base64url is unpadded: {encoded}");
            assert_eq!(
                base64url_decode(&encoded).as_deref(),
                Some(case),
                "{case:?}"
            );
        }
    }

    #[test]
    fn a_signed_token_parses_into_its_parts() {
        let header = json!({"alg": "HS256", "typ": "JWT"});
        let payload = json!({"sub": "alice", "role": "user"});
        let token = hs256(&header, &payload, b"secret");

        let jwt = Jwt::parse(&token).unwrap();
        assert_eq!(jwt.algorithm(), Some("HS256"));
        assert_eq!(jwt.payload["sub"], json!("alice"));
        assert!(!jwt.signature.is_empty());
    }

    #[test]
    fn a_bearer_prefix_and_whitespace_are_tolerated() {
        let token = hs256(&json!({"alg": "HS256"}), &json!({"sub": "a"}), b"k");
        assert_eq!(
            Jwt::parse(&format!("  Bearer {token}  ")).unwrap(),
            Jwt::parse(&token).unwrap()
        );
    }

    #[test]
    fn non_tokens_are_rejected_not_guessed() {
        for value in ["", "one.two", "one.two.three.four", "not base64!.{}.sig"] {
            assert!(Jwt::parse(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn alg_none_drops_the_signature_and_keeps_the_claims() {
        let jwt = Jwt::parse(&hs256(
            &json!({"alg": "HS256"}),
            &json!({"sub": "alice", "admin": false}),
            b"secret",
        ))
        .unwrap();

        for casing in ["none", "None", "nOnE"] {
            let forged = jwt.with_alg_none(casing);
            assert!(forged.ends_with('.'), "no signature segment: {forged}");
            let reparsed = Jwt::parse(&forged).unwrap();
            assert_eq!(reparsed.algorithm(), Some(casing));
            assert!(reparsed.signature.is_empty());
            // The claims survive unchanged — only the signing was removed.
            assert_eq!(reparsed.payload["sub"], json!("alice"));
        }
    }

    #[test]
    fn resigning_hs256_with_a_guessed_secret_produces_a_token_that_verifies_under_it() {
        // The weak-secret / key-confusion attack: an attacker who guesses (or supplies)
        // the HMAC key can mint a token the server will verify. We prove the forged
        // token verifies under that key, which is exactly what the server would do.
        let jwt = Jwt::parse(&hs256(
            &json!({"alg": "RS256"}),
            &json!({"sub": "alice", "admin": false}),
            b"irrelevant",
        ))
        .unwrap();

        let forged = jwt.with_claim_hs256("admin", json!(true), b"guessed-key");
        let reparsed = Jwt::parse(&forged).unwrap();
        assert_eq!(reparsed.algorithm(), Some("HS256"));
        assert_eq!(reparsed.payload["admin"], json!(true));

        // Independently recompute the HMAC over the signing input and compare.
        let input = signing_input(&reparsed.header, &reparsed.payload);
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"guessed-key");
        assert!(ring::hmac::verify(&key, input.as_bytes(), &reparsed.signature).is_ok());
    }
}
