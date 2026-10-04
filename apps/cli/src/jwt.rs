//! `nullhawk jwt` — read a JSON Web Token, and forge the variants that test whether a
//! server actually verifies one.
//!
//! This is toolwork, not a scan: it decodes a token and emits a tampered one. Whether
//! the server accepts the tampered token is the next request — send it with
//! `nullhawk send` or `nullhawk repeat` as the identity, and compare against the
//! original. The secret for re-signing is read from an environment variable or a file,
//! never an argument, for the same reason `identity add` does: `ps` and shell history
//! would both capture it.

use std::path::Path;

use nullhawk_types::expiry;
use nullhawk_types::jwt::Jwt;
use nullhawk_types::{NullhawkError, Result};
use serde_json::Value;

/// `nullhawk jwt decode <token>`.
pub struct DecodeArgs<'a> {
    pub token: &'a str,
    pub json: bool,
}

pub fn decode(args: DecodeArgs) -> Result<()> {
    let jwt = Jwt::parse(args.token)?;

    if args.json {
        let out = serde_json::json!({
            "header": jwt.header,
            "payload": jwt.payload,
            "signature_bytes": jwt.signature.len(),
            "algorithm": jwt.algorithm(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return Ok(());
    }

    println!("Header:");
    println!(
        "{}",
        serde_json::to_string_pretty(&jwt.header).unwrap_or_default()
    );
    println!("\nPayload:");
    println!(
        "{}",
        serde_json::to_string_pretty(&jwt.payload).unwrap_or_default()
    );
    println!(
        "\nSignature: {} byte(s){}",
        jwt.signature.len(),
        if jwt.signature.is_empty() {
            "  — UNSIGNED: if the server accepts this, it is not verifying signatures"
        } else {
            ""
        }
    );

    match jwt.algorithm() {
        Some(alg) => println!("Algorithm: {alg}"),
        None => println!("Algorithm: (none stated)"),
    }
    if let Some(sub) = expiry::subject_of(args.token) {
        println!("Subject:   {sub}");
    }
    if let Some(life) = expiry::of_jwt(args.token) {
        let now = chrono::Utc::now().timestamp();
        println!("Lifetime:  {}", life.describe(now));
    }
    Ok(())
}

/// `nullhawk jwt forge <token> ...`.
pub struct ForgeArgs<'a> {
    pub token: &'a str,
    pub set: &'a [String],
    pub alg_none: bool,
    pub none_casing: &'a str,
    pub sign_env: Option<&'a str>,
    pub sign_file: Option<&'a Path>,
    pub strip: bool,
    pub json: bool,
}

pub fn forge(args: ForgeArgs) -> Result<()> {
    let mut jwt = Jwt::parse(args.token)?;

    // Apply each `--set key=value`. The value is read as JSON when it parses as JSON
    // (so `--set admin=true` sets a boolean, `--set uid=5` a number), and as a plain
    // string otherwise (so `--set sub=alice` sets a string without needing quotes).
    for pair in args.set {
        let (key, raw) = pair.split_once('=').ok_or_else(|| {
            NullhawkError::invalid_input("set", format!("expected key=value, got {pair:?}"))
        })?;
        let value = serde_json::from_str::<Value>(raw).unwrap_or(Value::String(raw.to_string()));
        match jwt.payload.as_object_mut() {
            Some(map) => {
                map.insert(key.to_string(), value);
            }
            None => {
                let mut map = serde_json::Map::new();
                map.insert(key.to_string(), value);
                jwt.payload = Value::Object(map);
            }
        }
    }

    // Exactly one signing mode. Each corresponds to a distinct server weakness, and
    // combining them would produce a token that tests nothing in particular.
    let secret = read_secret(args.sign_env, args.sign_file)?;
    let modes = [args.alg_none, secret.is_some(), args.strip];
    let chosen = modes.iter().filter(|m| **m).count();
    if chosen != 1 {
        return Err(NullhawkError::invalid_input(
            "mode",
            "choose exactly one of --alg-none, --sign-hs256-env/--sign-hs256-file, or --strip-signature",
        ));
    }

    let forged = if args.alg_none {
        jwt.with_alg_none(args.none_casing)
    } else if let Some(secret) = secret {
        jwt.resign_hs256(&secret)
    } else {
        jwt.stripped()
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({ "token": forged })).unwrap_or_default()
        );
    } else {
        println!("{forged}");
    }
    Ok(())
}

fn read_secret(env: Option<&str>, file: Option<&Path>) -> Result<Option<Vec<u8>>> {
    if let Some(var) = env {
        let value = std::env::var(var).map_err(|_| {
            NullhawkError::invalid_input(
                "sign-hs256-env",
                format!("environment variable {var} is not set"),
            )
        })?;
        return Ok(Some(value.into_bytes()));
    }
    if let Some(path) = file {
        let bytes = std::fs::read(path).map_err(|e| {
            NullhawkError::invalid_input(
                "sign-hs256-file",
                format!("cannot read {}: {e}", path.display()),
            )
        })?;
        return Ok(Some(bytes));
    }
    Ok(None)
}
