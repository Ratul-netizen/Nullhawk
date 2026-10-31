//! Mobile onboarding — get a phone from "nothing" to "its HTTPS is in History".
//!
//! A phone's traffic is just traffic, so the proxy and CA that read a browser's HTTPS
//! read an app's too. The only friction is device setup: find this machine's LAN IP,
//! trust the CA on the phone, and point the phone's proxy here. This module removes the
//! two slow parts:
//!
//! - [`primary_lan_ip`] reports the address a phone should actually use, so nobody has
//!   to go digging in network settings for it.
//! - A small HTTP server (the same raw-TCP shape the OOB collaborator uses) serves the
//!   CA certificate and a phone-friendly setup page on the LAN, so the phone just opens
//!   a URL (or scans a QR for it) and taps "install" — no email, no `adb push`.
//!
//! The server only ever serves the public CA certificate and a static page. It holds no
//! secrets and takes no input, so binding it to the LAN is safe.

use std::collections::BTreeSet;
use std::io::Read;
use std::net::{IpAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::state::{AppState, RunningOnboarding};

type CommandResult<T> = std::result::Result<T, String>;

const CA_FILE: &str = "nullhawk-ca.crt";

fn ca_dir() -> CommandResult<PathBuf> {
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| "cannot determine a home directory".to_string())?;
    Ok(PathBuf::from(base).join(".nullhawk").join("ca"))
}

/// The machine's primary LAN IPv4, found by asking the OS which local address it would
/// use to reach a public host. **No packet is sent** — a UDP `connect` only records a
/// destination so the kernel picks the matching source address, which `local_addr` then
/// reads back. Needs no capability and no extra crate. Returns `None` when there is no
/// usable route (offline, or only loopback), and the UI then falls back to asking the
/// tester to read their own IP.
fn primary_lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // A routable destination so the default route's interface is chosen; nothing is
    // transmitted by connect(), so this reaches no host.
    socket.connect("8.8.8.8:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}

/// What the Mobile view needs to show the "point your phone here" panel.
#[derive(Debug, Clone, Serialize)]
pub struct MobileSetup {
    /// This machine's LAN IP, or null if none could be determined.
    pub lan_ip: Option<String>,
    /// Whether the intercepting proxy is listening.
    pub proxy_running: bool,
    /// The port it is listening on, if it is.
    pub proxy_port: Option<u16>,
    /// Whether the proxy is bound to loopback only — a phone cannot reach it there.
    pub proxy_loopback: bool,
    /// Whether the onboarding (CA + setup page) server is running.
    pub onboarding_running: bool,
    /// Its port, if running.
    pub onboarding_port: Option<u16>,
    /// The URL a phone opens to get the CA and the setup page (needs a LAN IP).
    pub onboarding_url: Option<String>,
    /// An SVG QR code of `onboarding_url` so the phone can scan it instead of typing.
    pub onboarding_qr_svg: Option<String>,
    /// Whether the CA certificate exists on disk.
    pub ca_present: bool,
    /// Its SHA-256 fingerprint, for the tester to verify on the device.
    pub ca_fingerprint: Option<String>,
    /// Where the certificate lives on disk, for a manual transfer if preferred.
    pub ca_path: String,
}

/// Renders `data` as a minimal SVG QR code (its viewBox is in module units, so the page
/// scales it to any size). White field with a quiet-zone border so it scans against a dark
/// UI. Uses only the core matrix API, so the SVG is ours and there is no render feature to
/// depend on.
fn qr_svg(data: &str) -> Option<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    let w = code.width();
    let colors = code.to_colors();
    const QUIET: usize = 4;
    let dim = w + QUIET * 2;
    let mut rects = String::new();
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                let (px, py) = (x + QUIET, y + QUIET);
                rects.push_str(&format!(
                    r#"<rect x="{px}" y="{py}" width="1" height="1"/>"#
                ));
            }
        }
    }
    Some(format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges"><rect width="{dim}" height="{dim}" fill="#fff"/><g fill="#000">{rects}</g></svg>"##
    ))
}

fn build_setup(state: &AppState) -> CommandResult<MobileSetup> {
    let lan_ip = primary_lan_ip().map(|ip| ip.to_string());

    let proxy_addr = state.proxy_address().map_err(|e| e.to_string())?;
    let proxy_loopback = proxy_addr.map(|a| a.ip().is_loopback()).unwrap_or(false);

    let onboarding_addr = state.onboarding_address().map_err(|e| e.to_string())?;
    let onboarding_port = onboarding_addr.map(|a| a.port());
    let onboarding_url = match (&lan_ip, onboarding_port) {
        (Some(ip), Some(port)) => Some(format!("http://{ip}:{port}/")),
        _ => None,
    };
    let onboarding_qr_svg = onboarding_url.as_deref().and_then(qr_svg);

    let dir = ca_dir()?;
    let path = dir.join(CA_FILE);
    // load_or_create mints the CA the first time, so the fingerprint and file are ready
    // to show and serve even on a fresh install.
    let ca_fingerprint = nullhawk_proxy::CertificateAuthority::load_or_create(&dir)
        .ok()
        .map(|ca| ca.fingerprint_display());

    Ok(MobileSetup {
        lan_ip,
        proxy_running: proxy_addr.is_some(),
        proxy_port: proxy_addr.map(|a| a.port()),
        proxy_loopback,
        onboarding_running: onboarding_addr.is_some(),
        onboarding_port,
        onboarding_url,
        onboarding_qr_svg,
        ca_present: path.exists(),
        ca_fingerprint,
        ca_path: path.display().to_string(),
    })
}

/// Reports the mobile-onboarding state for the Mobile view.
#[tauri::command]
pub fn mobile_setup(state: State<'_, AppState>) -> CommandResult<MobileSetup> {
    build_setup(&state)
}

/// Starts the LAN onboarding server (CA + setup page) and returns the refreshed state.
#[tauri::command]
pub async fn mobile_onboarding_start(state: State<'_, AppState>) -> CommandResult<MobileSetup> {
    let dir = ca_dir()?;
    let ca =
        nullhawk_proxy::CertificateAuthority::load_or_create(&dir).map_err(|e| e.to_string())?;
    let fingerprint = ca.fingerprint_display();
    let ca_pem = std::fs::read(dir.join(CA_FILE))
        .map_err(|e| format!("could not read the CA certificate to serve it: {e}"))?;

    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("could not start the onboarding server: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let handle = tokio::spawn(run_onboarding(listener, ca_pem, fingerprint));
    state
        .set_onboarding(RunningOnboarding::new(addr, handle))
        .map_err(|e| e.to_string())?;
    build_setup(&state)
}

/// Stops the onboarding server and returns the refreshed state.
#[tauri::command]
pub fn mobile_onboarding_stop(state: State<'_, AppState>) -> CommandResult<MobileSetup> {
    state.stop_onboarding().map_err(|e| e.to_string())?;
    build_setup(&state)
}

// ---------------------------------------------------------------------------
// The onboarding HTTP server (raw TCP, like the OOB collaborator)
// ---------------------------------------------------------------------------

async fn run_onboarding(listener: TcpListener, ca_pem: Vec<u8>, fingerprint: String) {
    let ca_pem = Arc::new(ca_pem);
    let fingerprint = Arc::new(fingerprint);
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let ca = ca_pem.clone();
                let fp = fingerprint.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(stream, ca, fp).await;
                });
            }
            Err(error) => tracing::warn!(%error, "onboarding accept failed"),
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    ca_pem: Arc<Vec<u8>>,
    fingerprint: Arc<String>,
) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let target = request_target(&head);
    match target.as_str() {
        "/nullhawk-ca.crt" | "/ca" | "/ca.crt" | "/cert" => {
            write_bytes(
                &mut stream,
                "application/x-x509-ca-cert",
                Some("nullhawk-ca.crt"),
                &ca_pem,
            )
            .await
        }
        "/ca.pem" => {
            write_bytes(
                &mut stream,
                "application/x-pem-file",
                Some("nullhawk-ca.pem"),
                &ca_pem,
            )
            .await
        }
        "/" | "/index.html" => {
            let page = landing_page(&fingerprint);
            write_bytes(
                &mut stream,
                "text/html; charset=utf-8",
                None,
                page.as_bytes(),
            )
            .await
        }
        _ => write_status(&mut stream, "404 Not Found", "text/plain", b"not found\n").await,
    }
}

/// Reads the request head (up to the blank line), capped so a slow or hostile client
/// cannot make the task read forever.
async fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The request path, without the query string. Defaults to `/`.
fn request_target(head: &str) -> String {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string()
}

async fn write_bytes(
    stream: &mut TcpStream,
    content_type: &str,
    filename: Option<&str>,
    body: &[u8],
) -> std::io::Result<()> {
    let disposition = filename
        .map(|f| format!("Content-Disposition: attachment; filename=\"{f}\"\r\n"))
        .unwrap_or_default();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{disposition}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

async fn write_status(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// The phone-friendly setup page served at `/`.
fn landing_page(fingerprint: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nullhawk — mobile capture setup</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, system-ui, Segoe UI, Roboto, sans-serif; margin: 0;
          padding: 24px 18px 48px; line-height: 1.5; max-width: 640px; }}
  h1 {{ font-size: 1.35rem; margin: 0 0 4px; }}
  p.sub {{ color: #666; margin: 0 0 24px; }}
  .btn {{ display: block; text-align: center; background: #2d7d46; color: #fff;
          text-decoration: none; font-weight: 600; padding: 16px; border-radius: 12px;
          font-size: 1.1rem; margin: 0 0 8px; }}
  .fp {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.8rem;
         word-break: break-all; background: rgba(127,127,127,.12); padding: 10px 12px;
         border-radius: 8px; margin: 0 0 28px; }}
  h2 {{ font-size: 1.05rem; margin: 28px 0 8px; }}
  ol {{ padding-left: 1.2em; margin: 0; }}
  li {{ margin: 6px 0; }}
  .note {{ color: #666; font-size: 0.9rem; }}
</style>
</head>
<body>
  <h1>Nullhawk — mobile capture setup</h1>
  <p class="sub">Install this CA, then point your Wi-Fi proxy at this machine.</p>

  <a class="btn" href="/nullhawk-ca.crt">Download CA certificate</a>
  <div class="fp">SHA-256: {fingerprint}</div>

  <h2>Android</h2>
  <ol>
    <li>Tap the button above to download the certificate.</li>
    <li>Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate.</li>
    <li class="note">Since Android 7, apps trust user CAs only if their network-security
        config opts in. If an app still shows nothing, it must be patched or run on a
        rooted device with the CA in the system store.</li>
  </ol>

  <h2>iOS</h2>
  <ol>
    <li>Tap the button above in Safari and allow the profile to download.</li>
    <li>Settings → General → VPN &amp; Device Management → install the Nullhawk profile.</li>
    <li>Settings → General → About → Certificate Trust Settings → enable full trust for Nullhawk.</li>
  </ol>

  <h2>Then</h2>
  <ol>
    <li>Set this network's HTTP proxy to this machine's IP and the proxy port shown in Nullhawk.</li>
    <li>Use the app. Its requests appear in Nullhawk's History.</li>
  </ol>
</body>
</html>
"#
    )
}

// ---------------------------------------------------------------------------
// Static package analysis (APK / IPA)
// ---------------------------------------------------------------------------
//
// An APK or IPA is a ZIP. To mine it for secrets and endpoints we have to inflate the
// entries (the juicy strings live in deflated DEX / resources), so this is a minimal
// read-only ZIP reader on top of flate2 — no new dependency, and no `zip` crate feature
// lottery or C-toolchain transitive (bzip2-sys). It handles the two methods APK/IPA
// actually use, store (0) and deflate (8); anything else is skipped rather than guessed.
// ZIP64 entries (rare below 4 GiB) are skipped too. The extracted strings then go through
// the same secret/endpoint miner the rest of the UI uses, in the frontend.

/// What a dropped app package is, and the text pulled out of it for the miner.
#[derive(Debug, Clone, Serialize)]
pub struct MobilePackage {
    /// "apk", "ipa", or "zip" (an archive that is neither).
    pub kind: String,
    /// The app (IPA bundle) or file name.
    pub label: String,
    /// Number of entries in the archive.
    pub entry_count: usize,
    /// Total uncompressed size of the entries.
    pub total_size: u64,
    /// Printable strings pulled from the entries, newline-joined and de-duplicated, for
    /// the secret/endpoint miner to scan.
    pub strings: String,
    /// Set when extraction hit a cap, so the UI can say the view is partial.
    pub note: Option<String>,
}

struct ZipEntry {
    name: String,
    method: u16,
    comp_size: u32,
    uncomp_size: u32,
    local_offset: u32,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parses the central directory into entry records.
fn zip_entries(data: &[u8]) -> Vec<ZipEntry> {
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const CDH: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    if data.len() < 22 {
        return Vec::new();
    }
    // The End Of Central Directory record is within the last 64 KiB + 22 bytes.
    let scan_from = data.len().saturating_sub(65_557);
    let mut eocd = None;
    for i in (scan_from..=data.len() - 22).rev() {
        if data[i..i + 4] == EOCD {
            eocd = Some(i);
            break;
        }
    }
    let Some(e) = eocd else {
        return Vec::new();
    };
    let cd_offset = le32(data, e + 16) as usize;
    let mut entries = Vec::new();
    let mut p = cd_offset;
    while p + 46 <= data.len() && data[p..p + 4] == CDH {
        let method = le16(data, p + 10);
        let comp_size = le32(data, p + 20);
        let uncomp_size = le32(data, p + 24);
        let name_len = le16(data, p + 28) as usize;
        let extra_len = le16(data, p + 30) as usize;
        let comment_len = le16(data, p + 32) as usize;
        let local_offset = le32(data, p + 42);
        let name_start = p + 46;
        if name_start + name_len > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_start + name_len]).into_owned();
        entries.push(ZipEntry {
            name,
            method,
            comp_size,
            uncomp_size,
            local_offset,
        });
        p = name_start + name_len + extra_len + comment_len;
    }
    entries
}

/// Returns an entry's bytes (store or deflate), inflated up to `cap`.
fn zip_read_entry(data: &[u8], e: &ZipEntry, cap: usize) -> Option<Vec<u8>> {
    const LFH: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    let lo = e.local_offset as usize;
    if lo + 30 > data.len() || data[lo..lo + 4] != LFH {
        return None;
    }
    let name_len = le16(data, lo + 26) as usize;
    let extra_len = le16(data, lo + 28) as usize;
    let dstart = lo + 30 + name_len + extra_len;
    if dstart > data.len() {
        return None;
    }
    let dend = (dstart + e.comp_size as usize).min(data.len());
    let comp = &data[dstart..dend];
    match e.method {
        0 => Some(comp[..comp.len().min(cap)].to_vec()),
        8 => {
            let mut out = Vec::new();
            flate2::read::DeflateDecoder::new(comp)
                .take(cap as u64)
                .read_to_end(&mut out)
                .ok()?;
            Some(out)
        }
        _ => None,
    }
}

/// Collects printable-ASCII runs of at least six characters, into a set so duplicates
/// collapse, until `budget` bytes have been taken.
fn extract_strings(bytes: &[u8], out: &mut BTreeSet<String>, budget: &mut usize) {
    const MIN: usize = 6;
    let mut run: Vec<u8> = Vec::new();
    let flush = |run: &mut Vec<u8>, out: &mut BTreeSet<String>, budget: &mut usize| {
        if run.len() >= MIN && *budget > 0 {
            if let Ok(s) = std::str::from_utf8(run) {
                *budget = budget.saturating_sub(s.len());
                out.insert(s.to_string());
            }
        }
        run.clear();
    };
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            run.push(b);
        } else {
            flush(&mut run, out, budget);
            if *budget == 0 {
                return;
            }
        }
    }
    flush(&mut run, out, budget);
}

fn file_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// Reads an APK/IPA (or any ZIP) and pulls its strings out for the miner.
#[tauri::command]
pub fn mobile_analyze(path: String) -> CommandResult<MobilePackage> {
    let data = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    let entries = zip_entries(&data);
    if entries.is_empty() {
        return Err("that file is not a readable archive (APK, IPA and ZIP are supported)".into());
    }

    let kind = if entries.iter().any(|e| e.name == "AndroidManifest.xml") {
        "apk"
    } else if entries
        .iter()
        .any(|e| e.name.starts_with("Payload/") && e.name.contains(".app/"))
    {
        "ipa"
    } else {
        "zip"
    };

    let label = if kind == "ipa" {
        entries
            .iter()
            .find_map(|e| {
                e.name
                    .strip_prefix("Payload/")
                    .and_then(|r| r.split('/').next())
                    .filter(|s| s.ends_with(".app"))
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| file_name(&path))
    } else {
        file_name(&path)
    };

    let total_size: u64 = entries.iter().map(|e| e.uncomp_size as u64).sum();

    const TOTAL_CAP: usize = 2 * 1024 * 1024;
    const PER_ENTRY_CAP: usize = 8 * 1024 * 1024;
    let mut set = BTreeSet::new();
    let mut budget = TOTAL_CAP;
    let mut truncated = false;
    for e in &entries {
        if budget == 0 {
            truncated = true;
            break;
        }
        if let Some(bytes) = zip_read_entry(&data, e, PER_ENTRY_CAP) {
            extract_strings(&bytes, &mut set, &mut budget);
        }
    }

    let strings = set.into_iter().collect::<Vec<_>>().join("\n");
    let note = truncated.then(|| "String extraction was capped; the view is partial.".to_string());

    Ok(MobilePackage {
        kind: kind.to_string(),
        label,
        entry_count: entries.len(),
        total_size,
        strings,
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Deflates `data` to a raw deflate stream (ZIP method 8).
    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Builds a minimal but valid ZIP (one deflated entry) the way the reader expects.
    /// CRCs are left zero because the reader does not verify them.
    fn build_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let comp = deflate(data);
        let mut z = Vec::new();
        // Local file header.
        z.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u16.to_le_bytes()); // flags
        z.extend_from_slice(&8u16.to_le_bytes()); // method: deflate
        z.extend_from_slice(&0u16.to_le_bytes()); // mod time
        z.extend_from_slice(&0u16.to_le_bytes()); // mod date
        z.extend_from_slice(&0u32.to_le_bytes()); // crc32 (ignored by reader)
        z.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra len
        z.extend_from_slice(name.as_bytes());
        z.extend_from_slice(&comp);
        // Central directory header.
        let cd_offset = z.len() as u32;
        z.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        z.extend_from_slice(&20u16.to_le_bytes()); // version made by
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u16.to_le_bytes()); // flags
        z.extend_from_slice(&8u16.to_le_bytes()); // method
        z.extend_from_slice(&0u16.to_le_bytes()); // mod time
        z.extend_from_slice(&0u16.to_le_bytes()); // mod date
        z.extend_from_slice(&0u32.to_le_bytes()); // crc32
        z.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra
        z.extend_from_slice(&0u16.to_le_bytes()); // comment
        z.extend_from_slice(&0u16.to_le_bytes()); // disk start
        z.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        z.extend_from_slice(name.as_bytes());
        let cd_size = z.len() as u32 - cd_offset;
        // End of central directory.
        z.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        z.extend_from_slice(&0u16.to_le_bytes()); // disk num
        z.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
        z.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        z.extend_from_slice(&1u16.to_le_bytes()); // total entries
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&cd_offset.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // comment len
        z
    }

    #[test]
    fn reads_a_deflated_entry_and_extracts_its_strings() {
        // Secret assembled from parts so no secret-shaped literal lives in the source.
        let key = format!("AKIA{}{}", "IOSFODNN7", "EXAMPLE");
        let payload = format!("noise noise {key} more https://api.example.test/v1 noise");
        let zip = build_zip("classes.dex", payload.as_bytes());

        let entries = zip_entries(&zip);
        assert_eq!(entries.len(), 1, "one central-directory entry");
        assert_eq!(entries[0].name, "classes.dex");

        let bytes = zip_read_entry(&zip, &entries[0], 1 << 20).expect("inflates");
        assert_eq!(bytes, payload.as_bytes(), "inflated bytes round-trip");

        let mut set = BTreeSet::new();
        let mut budget = 1 << 20;
        extract_strings(&bytes, &mut set, &mut budget);
        let all = set.into_iter().collect::<Vec<_>>().join("\n");
        assert!(all.contains(&key), "the key survives extraction");
        assert!(
            all.contains("api.example.test"),
            "the endpoint survives extraction"
        );
    }

    #[test]
    fn a_non_archive_has_no_entries() {
        assert!(zip_entries(b"this is not a zip file at all").is_empty());
    }
}
