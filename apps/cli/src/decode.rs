//! `nullhawk decode` — the workbench's decoder: run a value through a chain of codecs, in
//! either direction, or let it peel the layers itself.
//!
//! A captured value is rarely in the clear: a token is base64url, a redirect target is
//! percent-encoded inside a base64 blob, a parameter is hex inside that. Reading it by hand
//! is a chain of small transforms, and getting one step wrong wastes a lead. This does the
//! chain: `--from base64 --from url` decodes base64 then percent-decodes the result, and
//! `--encode` runs the same chain the other way. `--smart` is for when you do not yet know
//! the chain — it tries the codecs that plainly apply and peels them one layer at a time,
//! showing its work, so you can see what it did rather than trust a single answer.
//!
//! It is offline and deterministic: no network, no project, just bytes in and bytes out.

use std::io::{Read, Write};

use nullhawk_types::{NullhawkError, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Codec {
    Base64,
    Base64Url,
    Url,
    Hex,
    Html,
    Gzip,
    Deflate,
}

impl Codec {
    fn parse(name: &str) -> Result<Codec> {
        Ok(match name.to_ascii_lowercase().as_str() {
            "base64" | "b64" => Codec::Base64,
            "base64url" | "b64url" => Codec::Base64Url,
            "url" | "percent" => Codec::Url,
            "hex" => Codec::Hex,
            "html" | "entities" => Codec::Html,
            "gzip" | "gz" => Codec::Gzip,
            "deflate" => Codec::Deflate,
            other => {
                return Err(NullhawkError::invalid_input(
                    "--from",
                    format!(
                        "unknown codec '{other}'; known: base64, base64url, url, hex, html, \
                         gzip, deflate"
                    ),
                ))
            }
        })
    }

    fn label(self) -> &'static str {
        match self {
            Codec::Base64 => "base64",
            Codec::Base64Url => "base64url",
            Codec::Url => "url",
            Codec::Hex => "hex",
            Codec::Html => "html",
            Codec::Gzip => "gzip",
            Codec::Deflate => "deflate",
        }
    }

    fn decode(self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Codec::Base64 => base64_decode(input, false),
            Codec::Base64Url => base64_decode(input, true),
            Codec::Url => Ok(url_decode(input)),
            Codec::Hex => hex_decode(input),
            Codec::Html => Ok(html_decode(input)),
            Codec::Gzip => inflate(input, true),
            Codec::Deflate => inflate(input, false),
        }
    }

    fn encode(self, input: &[u8]) -> Vec<u8> {
        match self {
            Codec::Base64 => base64_encode(input, false),
            Codec::Base64Url => base64_encode(input, true),
            Codec::Url => url_encode(input),
            Codec::Hex => hex_encode(input),
            Codec::Html => html_encode(input),
            Codec::Gzip => deflate(input, true),
            Codec::Deflate => deflate(input, false),
        }
    }
}

pub struct Args<'a> {
    /// The value to transform; `None` or `-` reads standard input.
    pub input: Option<&'a str>,
    pub from: &'a [String],
    pub encode: bool,
    pub smart: bool,
    pub json: bool,
}

pub fn run(args: Args<'_>) -> Result<()> {
    let input = match args.input {
        Some(value) if value != "-" => value.as_bytes().to_vec(),
        _ => read_stdin()?,
    };

    if args.smart {
        let layers = smart_peel(&input);
        return report_smart(&args, &input, &layers);
    }

    let codecs: Vec<Codec> = args
        .from
        .iter()
        .map(|n| Codec::parse(n))
        .collect::<Result<_>>()?;
    if codecs.is_empty() {
        return Err(NullhawkError::invalid_input(
            "--from",
            "say what to decode, e.g. `--from base64`, or pass `--smart` to let it guess",
        ));
    }

    let mut bytes = input;
    for codec in &codecs {
        bytes = if args.encode {
            codec.encode(&bytes)
        } else {
            codec.decode(&bytes)?
        };
    }

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "direction": if args.encode { "encode" } else { "decode" },
                "chain": codecs.iter().map(|c| c.label()).collect::<Vec<_>>(),
                "output": String::from_utf8_lossy(&bytes),
            })
        );
    } else {
        print!("{}", String::from_utf8_lossy(&bytes));
        if !bytes.ends_with(b"\n") {
            println!();
        }
    }
    Ok(())
}

/// One peeled layer: the codec that applied and what it produced.
struct Layer {
    codec: Codec,
    output: Vec<u8>,
}

/// Peel encoding layers one at a time, choosing at each step the codec that plainly applies
/// and yields readable text. Conservative on purpose: it would rather stop early than claim
/// a layer that was not really there, so a value that merely happens to be valid base64 is
/// only peeled when the result reads as text.
fn smart_peel(input: &[u8]) -> Vec<Layer> {
    let mut layers = Vec::new();
    let mut current = input.to_vec();
    for _ in 0..12 {
        let Some(layer) = peel_one(&current) else {
            break;
        };
        current = layer.output.clone();
        layers.push(layer);
    }
    layers
}

fn peel_one(bytes: &[u8]) -> Option<Layer> {
    // Unambiguous magic first.
    if bytes.starts_with(&[0x1f, 0x8b]) {
        if let Ok(out) = inflate(bytes, true) {
            return Some(Layer {
                codec: Codec::Gzip,
                output: out,
            });
        }
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Percent-encoding announces itself with `%XX`.
    if has_percent_escape(trimmed) {
        let out = url_decode(trimmed.as_bytes());
        if out != bytes && mostly_printable(&out) {
            return Some(Layer {
                codec: Codec::Url,
                output: out,
            });
        }
    }
    // HTML entities announce themselves with `&...;`.
    if trimmed.contains('&') && trimmed.contains(';') {
        let out = html_decode(trimmed.as_bytes());
        if out != bytes && mostly_printable(&out) {
            return Some(Layer {
                codec: Codec::Html,
                output: out,
            });
        }
    }
    // Hex: all hex digits, even length, worth a few bytes.
    if trimmed.len() >= 4
        && trimmed.len().is_multiple_of(2)
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if let Ok(out) = hex_decode(trimmed.as_bytes()) {
            if mostly_printable(&out) {
                return Some(Layer {
                    codec: Codec::Hex,
                    output: out,
                });
            }
        }
    }
    // Base64 last, and only when the decode reads as text — so ordinary words that are
    // coincidentally valid base64 are left alone.
    if looks_base64(trimmed) {
        for url_safe in [false, true] {
            if let Ok(out) = base64_decode(trimmed.as_bytes(), url_safe) {
                if out.len() > 2 && mostly_printable(&out) && out != bytes {
                    let codec = if url_safe {
                        Codec::Base64Url
                    } else {
                        Codec::Base64
                    };
                    return Some(Layer { codec, output: out });
                }
            }
        }
    }
    None
}

fn report_smart(args: &Args<'_>, input: &[u8], layers: &[Layer]) -> Result<()> {
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "input": String::from_utf8_lossy(input),
                "layers": layers.iter().map(|l| serde_json::json!({
                    "codec": l.codec.label(),
                    "output": String::from_utf8_lossy(&l.output),
                })).collect::<Vec<_>>(),
                "output": layers.last().map(|l| String::from_utf8_lossy(&l.output).into_owned())
                    .unwrap_or_else(|| String::from_utf8_lossy(input).into_owned()),
            })
        );
        return Ok(());
    }

    if layers.is_empty() {
        println!("No encoding layer was recognised — the value already looks decoded, or uses a codec this does not try.");
        return Ok(());
    }
    println!("Peeled {} layer(s):", layers.len());
    for (i, layer) in layers.iter().enumerate() {
        let preview = String::from_utf8_lossy(&layer.output);
        let preview = preview.trim();
        let shown = if preview.chars().count() > 72 {
            format!("{}…", preview.chars().take(72).collect::<String>())
        } else {
            preview.to_string()
        };
        println!("  {}. {:<10} → {shown}", i + 1, layer.codec.label());
    }
    Ok(())
}

// --- codecs --------------------------------------------------------------------------

fn base64_decode(input: &[u8], url_safe: bool) -> Result<Vec<u8>> {
    use base64::Engine;
    let text: String = std::str::from_utf8(input)
        .map_err(|_| NullhawkError::invalid_input("input", "base64 input is not text"))?
        .split_whitespace()
        .collect();
    let stripped = text.trim_end_matches('=');
    let engine = if url_safe {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD
    };
    engine
        .decode(stripped)
        .map_err(|e| NullhawkError::invalid_input("input", format!("not valid base64: {e}")))
}

fn base64_encode(input: &[u8], url_safe: bool) -> Vec<u8> {
    use base64::Engine;
    let engine = if url_safe {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::STANDARD
    };
    engine.encode(input).into_bytes()
}

fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hi = (input[i + 1] as char).to_digit(16);
            let lo = (input[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn url_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

fn hex_decode(input: &[u8]) -> Result<Vec<u8>> {
    let digits: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err(NullhawkError::invalid_input(
            "input",
            "hex input has an odd number of digits",
        ));
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| NullhawkError::invalid_input("input", "not valid hex"))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| NullhawkError::invalid_input("input", "not valid hex"))?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

fn hex_encode(input: &[u8]) -> Vec<u8> {
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input {
        out.push_str(&format!("{b:02x}"));
    }
    out.into_bytes()
}

fn html_decode(input: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(input);
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_ref();
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let Some(semi) = rest.find(';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..semi];
        let decoded = match entity {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => decode_numeric_entity(entity),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out.into_bytes()
}

fn decode_numeric_entity(entity: &str) -> Option<char> {
    let code = entity.strip_prefix('#')?;
    let value = if let Some(hex) = code.strip_prefix(['x', 'X']) {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        code.parse::<u32>().ok()?
    };
    char::from_u32(value)
}

fn html_encode(input: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(input);
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out.into_bytes()
}

fn inflate(input: &[u8], gzip: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let result = if gzip {
        flate2::read::GzDecoder::new(input).read_to_end(&mut out)
    } else {
        flate2::read::DeflateDecoder::new(input).read_to_end(&mut out)
    };
    result.map_err(|e| {
        NullhawkError::invalid_input(
            "input",
            format!("not valid {}: {e}", if gzip { "gzip" } else { "deflate" }),
        )
    })?;
    Ok(out)
}

fn deflate(input: &[u8], gzip: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if gzip {
        let mut enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        let _ = enc.write_all(input);
        let _ = enc.finish();
    } else {
        let mut enc = flate2::write::DeflateEncoder::new(&mut out, flate2::Compression::default());
        let _ = enc.write_all(input);
        let _ = enc.finish();
    }
    out
}

// --- heuristics ----------------------------------------------------------------------

fn has_percent_escape(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len().saturating_sub(2)).any(|i| {
        b[i] == b'%'
            && (b[i + 1] as char).is_ascii_hexdigit()
            && (b[i + 2] as char).is_ascii_hexdigit()
    })
}

fn looks_base64(s: &str) -> bool {
    let core = s.trim_end_matches('=');
    core.len() >= 8
        && core
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
}

fn mostly_printable(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if text.is_empty() {
        return false;
    }
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    printable as f64 / text.chars().count() as f64 >= 0.85
}

fn read_stdin() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| NullhawkError::Internal(format!("could not read stdin: {e}")))?;
    // A trailing newline from a shell pipe is virtually never part of the value.
    while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(codec: Codec, input: &str) -> String {
        String::from_utf8(codec.decode(input.as_bytes()).unwrap()).unwrap()
    }
    fn enc(codec: Codec, input: &str) -> String {
        String::from_utf8(codec.encode(input.as_bytes())).unwrap()
    }

    #[test]
    fn base64_round_trips_both_alphabets() {
        assert_eq!(dec(Codec::Base64, "aGVsbG8="), "hello");
        assert_eq!(dec(Codec::Base64, "aGVsbG8"), "hello"); // padding optional
        assert_eq!(enc(Codec::Base64, "hello"), "aGVsbG8=");
        // url-safe uses - and _ instead of + and /
        let raw = [0xfb, 0xff, 0xbf];
        let b = base64_encode(&raw, true);
        assert_eq!(base64_decode(&b, true).unwrap(), raw);
    }

    #[test]
    fn url_hex_html_round_trip() {
        assert_eq!(dec(Codec::Url, "a%20b%2Fc"), "a b/c");
        assert_eq!(enc(Codec::Url, "a b/c"), "a%20b%2Fc");
        assert_eq!(dec(Codec::Hex, "68656c6c6f"), "hello");
        assert_eq!(enc(Codec::Hex, "hi"), "6869");
        assert_eq!(dec(Codec::Html, "&lt;b&gt;&amp;&#39;&#x41;"), "<b>&'A");
        assert_eq!(enc(Codec::Html, "<b>&\"'"), "&lt;b&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn gzip_and_deflate_round_trip() {
        for gzip in [true, false] {
            let codec = if gzip { Codec::Gzip } else { Codec::Deflate };
            let packed = codec.encode(b"the quick brown fox");
            assert_eq!(codec.decode(&packed).unwrap(), b"the quick brown fox");
        }
    }

    #[test]
    fn smart_peels_a_nested_chain() {
        // base64( url_encode("a b/c") ): a base64 blob whose decode is itself percent-
        // encoded, so smart peeling should take base64 then url.
        let inner = String::from_utf8(url_encode(b"a b/c")).unwrap(); // "a%20b%2Fc"
        let wrapped = String::from_utf8(base64_encode(inner.as_bytes(), false)).unwrap();
        let layers = smart_peel(wrapped.as_bytes());
        assert!(
            layers.len() >= 2,
            "expected to peel base64 then url, got {}",
            layers.len()
        );
        assert_eq!(layers[0].codec, Codec::Base64);
        assert_eq!(
            String::from_utf8_lossy(&layers.last().unwrap().output),
            "a b/c"
        );
    }

    #[test]
    fn smart_leaves_a_plain_word_alone() {
        // "password" is valid base64, but decoding it yields bytes that do not read as text,
        // so smart peeling must not claim a layer.
        let layers = smart_peel(b"hello world");
        assert!(
            layers.is_empty(),
            "plain text should not be peeled: {:?}",
            layers.iter().map(|l| l.codec).collect::<Vec<_>>()
        );
    }
}
