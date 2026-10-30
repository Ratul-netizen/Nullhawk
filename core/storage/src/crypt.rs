//! Credential encryption at rest.
//!
//! Identity credentials are the one thing in a project file that is "live access to a
//! client's systems" (`docs/threat-model.md`). Everything else in the file — captured
//! traffic, findings — is evidence; a credential is a working key. So the credential
//! column is sealed before it touches disk and opened only in memory.
//!
//! # Key model
//!
//! The data-encryption key (DEK) is a random 32 bytes held in the operating system's
//! secret store — Windows Credential Manager, macOS Keychain, the Linux Secret Service —
//! via the [`keyring`] crate, under service `nullhawk` / account `credential-key`. It is
//! generated on first use and never written to the project. Credentials are sealed with
//! ChaCha20-Poly1305 (`ring`) under that key, with a fresh random 96-bit nonce per value.
//!
//! The consequence that matters: copying a project directory to another machine or user
//! account carries the ciphertext but not the key, so the credentials are unreadable
//! there. That is the protection, not a bug — a stolen project file is no longer a stolen
//! set of sessions. Full-disk encryption and OS account hygiene remain prerequisites
//! (the OS keystore is only as safe as the logged-in account).
//!
//! # Headless and CI
//!
//! Where no OS keystore is reachable (CI, a headless Linux box), set
//! `NULLHAWK_CREDENTIAL_KEY` to a base64 32-byte key and it is used instead of the
//! keyring. This is the only way a key enters the process from outside the OS store.
//!
//! # Compatibility
//!
//! A sealed value is tagged `nh-enc:v1:`. [`open`] passes anything without that tag
//! through unchanged, so a project written before encryption existed still reads; its
//! credentials are sealed the next time that identity is written.

use std::sync::OnceLock;

use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{Result, StorageError};

/// Tag on a sealed value. Its absence means a pre-encryption (cleartext) value.
const TAG: &str = "nh-enc:v1:";
/// OS keystore coordinates for the DEK.
const SERVICE: &str = "nullhawk";
const ACCOUNT: &str = "credential-key";
/// Environment override for headless/CI use (base64 of 32 bytes).
const KEY_ENV: &str = "NULLHAWK_CREDENTIAL_KEY";

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn crypto<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::Crypto(e.to_string())
}

/// The process-wide DEK, loaded once. Only a successful load is cached; a failure (no
/// keystore, bad env value) is returned each call so a later fix is picked up.
fn dek() -> Result<&'static [u8; 32]> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(k) = KEY.get() {
        return Ok(k);
    }
    let key = load_or_create_dek()?;
    // If two threads raced, keep whichever landed first; the key is deterministic per
    // machine so it does not matter which.
    Ok(KEY.get_or_init(|| key))
}

fn load_or_create_dek() -> Result<[u8; 32]> {
    if let Ok(raw) = std::env::var(KEY_ENV) {
        let bytes = B64
            .decode(raw.trim())
            .map_err(|e| crypto(format!("{KEY_ENV} is not valid base64: {e}")))?;
        return to_key(&bytes)
            .map_err(|_| crypto(format!("{KEY_ENV} must decode to exactly 32 bytes")));
    }

    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(crypto)?;
    match entry.get_password() {
        Ok(stored) => {
            let bytes = B64
                .decode(stored.trim())
                .map_err(|e| crypto(format!("stored key is corrupt: {e}")))?;
            to_key(&bytes).map_err(|_| crypto("stored key is not 32 bytes"))
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| crypto("the system RNG failed"))?;
            entry.set_password(&B64.encode(key)).map_err(crypto)?;
            Ok(key)
        }
        Err(e) => Err(crypto(e)),
    }
}

fn to_key(bytes: &[u8]) -> std::result::Result<[u8; 32], ()> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    Ok(arr)
}

fn key_handle(dek: &[u8; 32]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, dek)
        .map_err(|_| crypto("could not build the cipher key"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Seals a credential string for storage. Fails closed: if the key is unavailable the
/// caller gets an error rather than a cleartext write.
pub fn seal(plaintext: &str) -> Result<String> {
    let dek = dek()?;
    let key = key_handle(dek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| crypto("the system RNG failed"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| crypto("sealing failed"))?;

    let mut combined = Vec::with_capacity(NONCE_LEN + buf.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&buf);
    Ok(format!("{TAG}{}", B64.encode(combined)))
}

/// Opens a stored credential string. A value without the [`TAG`] is a pre-encryption
/// cleartext value and is returned unchanged.
pub fn open(stored: &str) -> Result<String> {
    let Some(payload) = stored.strip_prefix(TAG) else {
        return Ok(stored.to_string());
    };

    let raw = B64
        .decode(payload.trim())
        .map_err(|e| crypto(format!("sealed value is not valid base64: {e}")))?;
    if raw.len() < NONCE_LEN + CHACHA20_POLY1305.tag_len() {
        return Err(crypto("sealed value is too short"));
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| crypto("sealed value has a malformed nonce"))?;

    let dek = dek()?;
    let key = key_handle(dek)?;
    let mut buf = ciphertext.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| crypto("could not decrypt the credential; the key for this project is not available on this machine"))?;
    String::from_utf8(plain.to_vec())
        .map_err(|e| crypto(format!("decrypted value is not UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Give the tests a deterministic key so they never touch the real OS keystore.
    fn with_test_key() {
        // 32 zero bytes, base64. Set once; harmless if another test set it already.
        std::env::set_var(KEY_ENV, B64.encode([7u8; 32]));
    }

    #[test]
    fn seals_and_opens_round_trip() {
        with_test_key();
        let secret = r#"{"kind":"bearer","token":"eyJhbGciOi.very.secret"}"#;
        let sealed = seal(secret).unwrap();
        assert!(sealed.starts_with(TAG));
        assert!(
            !sealed.contains("very.secret"),
            "ciphertext leaks plaintext"
        );
        assert_eq!(open(&sealed).unwrap(), secret);
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        with_test_key();
        let a = seal("same input").unwrap();
        let b = seal("same input").unwrap();
        assert_ne!(a, b, "identical plaintext produced identical ciphertext");
        assert_eq!(open(&a).unwrap(), "same input");
        assert_eq!(open(&b).unwrap(), "same input");
    }

    #[test]
    fn legacy_cleartext_passes_through() {
        with_test_key();
        let legacy = r#"{"kind":"none"}"#;
        assert_eq!(open(legacy).unwrap(), legacy);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        with_test_key();
        let sealed = seal("authentic").unwrap();
        // Flip a character in the base64 body.
        let mut bytes = sealed.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(open(&tampered).is_err());
    }
}
