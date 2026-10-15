//! Connection speed test (latency / download / upload) in the spirit of
//! OpenSpeedTest. It talks to Cloudflare's public speed endpoints
//! (`speed.cloudflare.com/__down` and `/__up`) using a tiny HTTP/1.1 client
//! built directly on the rustls stack we already depend on — no extra crates.
//!
//! The test is *sustained*: after a short probe sizes the transfers, it keeps
//! moving data for `per_phase_secs` in each direction (default 25 s each, so a
//! run lasts about 50 s). It discards a warm-up chunk so TCP slow-start
//! and per-connection setup don't skew the result, and it can be cancelled.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use webpki_roots::TLS_SERVER_ROOTS;

const HOST: &str = "speed.cloudflare.com";
const PORT: u16 = 443;
pub const SERVER_LABEL: &str = "Cloudflare (speed.cloudflare.com)";
const MIB: f64 = 1_048_576.0;

/// Small transfers used to estimate the link rate before the real test.
const DL_PROBE: u64 = 3_000_000;
const UL_PROBE: u64 = 1_500_000;
/// Aim for each sustained chunk to take about this long.
const CHUNK_TARGET_SECS: f64 = 4.0;

/// Cloudflare caps how many bytes a single `__down` request may pull (observed
/// ceiling ~9–10 MB; it tightens under abuse mitigation). Stay comfortably
/// under it, and shrink further if a request still comes back 429.
const MAX_DL_CHUNK: u64 = 8_000_000;
const MIN_DL_CHUNK: u64 = 1_000_000;
const MAX_UL_CHUNK: u64 = 4_000_000;
const MIN_UL_CHUNK: u64 = 500_000;

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

#[derive(Debug, Clone)]
pub struct SpeedOptions {
    /// Seconds spent measuring each direction (download, then upload).
    pub per_phase_secs: u64,
}

impl Default for SpeedOptions {
    fn default() -> Self {
        SpeedOptions { per_phase_secs: 25 }
    }
}

#[derive(Debug, Clone)]
pub struct SpeedResult {
    pub ping_ms: f64,
    pub jitter_ms: f64,
    pub download_mbps: f64,
    pub download_mibps: f64,
    pub upload_mbps: f64,
    pub upload_mibps: f64,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub download_secs: f64,
    pub upload_secs: f64,
    /// Human-readable description of what was measured (which backend/server).
    pub source: String,
}

impl SpeedResult {
    pub fn summary(&self) -> String {
        format!(
            "Ping {:.1} ms (jitter {:.1} ms) · Download {:.2} Mbps ({:.2} MiB/s) · Upload {:.2} Mbps ({:.2} MiB/s)",
            self.ping_ms,
            self.jitter_ms,
            self.download_mbps,
            self.download_mibps,
            self.upload_mbps,
            self.upload_mibps
        )
    }
}

/// Bits per second, in megabits (10^6).
fn mbps(bytes: u64, secs: f64) -> f64 {
    (bytes as f64 * 8.0) / secs.max(0.001) / 1_000_000.0
}

/// Bytes per second, in mebibytes (2^20).
fn mibps(bytes: u64, secs: f64) -> f64 {
    bytes as f64 / secs.max(0.001) / MIB
}

/// Choose a sustained chunk size from an observed rate, so each chunk runs for
/// roughly `CHUNK_TARGET_SECS` and short links still make progress.
fn pick_chunk(probe_bytes: u64, probe_secs: f64, min: u64, max: u64) -> u64 {
    let rate = probe_bytes as f64 / probe_secs.max(0.001);
    ((rate * CHUNK_TARGET_SECS) as u64).clamp(min, max)
}

fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {host}"))
}

fn connect() -> Result<TlsStream, String> {
    let addr = resolve(HOST, PORT)?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("connect: {e}"))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(30)));
    let _ = tcp.set_nodelay(true);

    let server_name = ServerName::try_from(HOST.to_string()).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(tls_config(), server_name).map_err(|e| e.to_string())?;
    Ok(StreamOwned::new(conn, tcp))
}

/// Position just past the `\r\n\r\n` that ends the response headers.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse the `HTTP/1.1 200 OK` status line at the start of a header block.
fn parse_status(headers: &[u8]) -> Option<u16> {
    let line_end = headers
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(headers.len());
    let line = String::from_utf8_lossy(&headers[..line_end]);
    line.split_whitespace().nth(1)?.parse::<u16>().ok()
}

/// Case-insensitive `Content-Length` lookup from a raw header block.
fn parse_content_length(headers: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

/// True for the success status codes we expect from the speed endpoints.
fn is_ok_status(code: u16) -> bool {
    (200..300).contains(&code)
}

/// Does an error look like the server refused the request for rate/size reasons
/// (HTTP 429 or similar)? Used to shrink chunk sizes and retry.
fn is_rate_limit(err: &str) -> bool {
    err.contains("429") || err.to_ascii_lowercase().contains("too many")
}

/// TCP round-trip latency (SYN → SYN-ACK). Closest cheap analogue to ICMP ping,
/// and unlike TLS+HTTP timing it is not inflated by the handshake.
fn measure_ping(samples: usize, progress: &mut impl FnMut(String)) -> Result<(f64, f64), String> {
    let addr = resolve(HOST, PORT)?;
    let mut vals: Vec<f64> = Vec::new();
    for i in 0..samples {
        let t0 = Instant::now();
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("ping connect: {e}"))?;
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        drop(s);
        vals.push(ms);
        progress(format!("  ping {}/{}: {:.1} ms", i + 1, samples, ms));
    }
    let avg = vals.iter().sum::<f64>() / vals.len() as f64;
    let jitter = if vals.len() > 1 {
        let mut d = 0.0;
        for w in vals.windows(2) {
            d += (w[1] - w[0]).abs();
        }
        d / (vals.len() - 1) as f64
    } else {
        0.0
    };
    Ok((avg, jitter))
}

/// One `GET /__down` transfer. Returns (body_bytes, seconds streaming the body),
/// excluding connection setup and time-to-first-byte.
fn download_once(bytes: u64, stop: &AtomicBool) -> Result<(u64, f64), String> {
    let mut s = connect()?;
    let req = format!(
        "GET /__down?bytes={bytes} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: waynes-dns-gtk/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let _ = s.flush();

    let mut buf = vec![0u8; 256 * 1024];
    let mut header_buf: Vec<u8> = Vec::new();
    let mut body_bytes: u64 = 0;
    let mut body_start: Option<Instant> = None;
    let mut content_len: Option<u64> = None;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        // Stop the moment the declared body length is in hand. Cloudflare keeps
        // the socket alive (`Connection: keep-alive`), so waiting for EOF would
        // stall until the read timeout.
        if body_start.is_some() {
            if let Some(cl) = content_len {
                if body_bytes >= cl {
                    break;
                }
            }
        }
        let n = match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(format!("read: {e}")),
        };
        if body_start.is_none() {
            header_buf.extend_from_slice(&buf[..n]);
            if let Some(pos) = find_header_end(&header_buf) {
                let status = parse_status(&header_buf[..pos]);
                if status.map(is_ok_status) != Some(true) {
                    return Err(format!(
                        "download got HTTP {}",
                        status.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
                    ));
                }
                content_len = parse_content_length(&header_buf[..pos]);
                body_start = Some(Instant::now());
                body_bytes += (header_buf.len() - pos) as u64;
                header_buf.clear();
            } else if header_buf.len() > 1 << 20 {
                return Err("response headers too large".into());
            }
        } else {
            body_bytes += n as u64;
        }
    }
    let start = body_start.ok_or_else(|| "no response body".to_string())?;
    Ok((body_bytes, start.elapsed().as_secs_f64().max(0.001)))
}

/// Read a complete HTTP response (headers + the `Content-Length` body) from a
/// stream the server may keep alive. Returns `(status, body_bytes)`; `status`
/// is 0 when no response line was seen before the connection ended.
fn read_response(s: &mut TlsStream) -> (u16, u64) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut header_buf: Vec<u8> = Vec::new();
    let mut body: u64 = 0;
    let mut content_len: Option<u64> = None;
    let mut headers_done = false;
    let mut status: u16 = 0;
    loop {
        if headers_done {
            if let Some(cl) = content_len {
                if body >= cl {
                    break;
                }
            }
        }
        let n = match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if !headers_done {
            header_buf.extend_from_slice(&buf[..n]);
            if let Some(pos) = find_header_end(&header_buf) {
                status = parse_status(&header_buf[..pos]).unwrap_or(0);
                content_len = parse_content_length(&header_buf[..pos]);
                body += (header_buf.len() - pos) as u64;
                headers_done = true;
                header_buf.clear();
            } else if header_buf.len() > 1 << 20 {
                break;
            }
        } else {
            body += n as u64;
        }
    }
    (status, body)
}

/// One `POST /__up` transfer. Returns (bytes_sent, seconds spent sending).
fn upload_once(bytes: u64, stop: &AtomicBool) -> Result<(u64, f64), String> {
    let mut s = connect()?;
    let header = format!(
        "POST /__up HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: waynes-dns-gtk/0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(header.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let chunk = vec![0u8; 64 * 1024];
    let mut sent: u64 = 0;
    let t0 = Instant::now();
    while sent < bytes {
        if stop.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        let n = std::cmp::min(chunk.len() as u64, bytes - sent) as usize;
        s.write_all(&chunk[..n])
            .map_err(|e| format!("upload: {e}"))?;
        sent += n as u64;
    }
    s.flush().map_err(|e| format!("flush: {e}"))?;
    let secs = t0.elapsed().as_secs_f64().max(0.001);

    // Read the (tiny) response so the server definitely saw the whole body,
    // and so a non-2xx reply (e.g. throttling / rate limiting) surfaces as a
    // real error instead of a bogus rate.
    let (status, _body) = read_response(&mut s);
    if status != 0 && !is_ok_status(status) {
        return Err(format!("upload got HTTP {status}"));
    }
    Ok((sent, secs))
}

/// Keep downloading chunks until `duration` of *measured* transfer time has
/// elapsed. The first chunk is discarded as a warm-up.
fn sustained_download(
    mut chunk: u64,
    duration: Duration,
    progress: &mut impl FnMut(String),
    stop: &AtomicBool,
) -> Result<(u64, f64), String> {
    let wall_start = Instant::now();
    // Hard cap so a misbehaving endpoint can never spin forever.
    let wall_cap = duration + Duration::from_secs(30);
    let mut total_bytes: u64 = 0;
    let mut total_secs: f64 = 0.0;
    let mut first = true;
    let mut last_report = Instant::now();
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        if total_secs >= duration.as_secs_f64() {
            break;
        }
        if wall_start.elapsed() > wall_cap {
            return Err("download test timed out".into());
        }

        let (b, s) = match download_once(chunk, stop) {
            Ok(v) => v,
            // The endpoint caps how many bytes one request may pull. Shrink and
            // retry rather than giving up; only fail once we're at the floor.
            Err(e) if is_rate_limit(&e) && chunk > MIN_DL_CHUNK => {
                chunk = (chunk / 2).max(MIN_DL_CHUNK);
                progress(format!(
                    "  (server rate-limited; retrying in {:.1} MiB chunks)",
                    chunk as f64 / MIB
                ));
                continue;
            }
            Err(e) => return Err(e),
        };
        if b == 0 {
            return Err("no data returned by the server — try again shortly".into());
        }
        if first {
            first = false; // discard warm-up
        } else {
            total_bytes += b;
            total_secs += s;
        }
        if last_report.elapsed() >= Duration::from_millis(500) {
            progress(format!(
                "  download: {:.2} Mbps ({:.2} MiB/s) — total {:.1} MiB in {:.0}s",
                mbps(total_bytes, total_secs),
                mibps(total_bytes, total_secs),
                total_bytes as f64 / MIB,
                total_secs
            ));
            last_report = Instant::now();
        }
    }
    if total_bytes == 0 {
        return Err("download produced no data".into());
    }
    Ok((total_bytes, total_secs))
}

/// Keep uploading chunks until `duration` of *measured* transfer time has
/// elapsed. The first chunk is discarded as a warm-up.
fn sustained_upload(
    mut chunk: u64,
    duration: Duration,
    progress: &mut impl FnMut(String),
    stop: &AtomicBool,
) -> Result<(u64, f64), String> {
    let wall_start = Instant::now();
    let wall_cap = duration + Duration::from_secs(30);
    let mut total_bytes: u64 = 0;
    let mut total_secs: f64 = 0.0;
    let mut first = true;
    let mut last_report = Instant::now();
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        if total_secs >= duration.as_secs_f64() {
            break;
        }
        if wall_start.elapsed() > wall_cap {
            return Err("upload test timed out".into());
        }

        let (b, s) = match upload_once(chunk, stop) {
            Ok(v) => v,
            Err(e) if is_rate_limit(&e) && chunk > MIN_UL_CHUNK => {
                chunk = (chunk / 2).max(MIN_UL_CHUNK);
                progress(format!(
                    "  (server rate-limited; retrying in {:.1} MiB chunks)",
                    chunk as f64 / MIB
                ));
                continue;
            }
            Err(e) => return Err(e),
        };
        if b == 0 || s <= 0.0 {
            return Err("upload made no progress".into());
        }
        if first {
            first = false; // discard warm-up
        } else {
            total_bytes += b;
            total_secs += s;
        }
        if last_report.elapsed() >= Duration::from_millis(500) {
            progress(format!(
                "  upload: {:.2} Mbps ({:.2} MiB/s) — total {:.1} MiB in {:.0}s",
                mbps(total_bytes, total_secs),
                mibps(total_bytes, total_secs),
                total_bytes as f64 / MIB,
                total_secs
            ));
            last_report = Instant::now();
        }
    }
    if total_bytes == 0 {
        return Err("upload produced no data".into());
    }
    Ok((total_bytes, total_secs))
}

// ---------------------------------------------------------------------------
// Preferred backend: the official Ookla `speedtest` CLI, when installed. It
// talks to Ookla's own nearby servers, so its numbers match speedtest.net —
// unlike any single public HTTP endpoint we could pick ourselves.
// ---------------------------------------------------------------------------

/// Locate an Ookla `speedtest` binary, if one is installed.
pub fn ookla_bin() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".local/bin/speedtest"));
    }
    for fixed in [
        "/usr/bin/speedtest",
        "/usr/local/bin/speedtest",
        "/opt/homebrew/bin/speedtest",
    ] {
        candidates.push(PathBuf::from(fixed));
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            candidates.push(dir.join("speedtest"));
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// The slice of JSON just after `"obj"`.
fn obj_region<'a>(json: &'a str, obj: &str) -> Option<&'a str> {
    let key = format!("\"{obj}\"");
    Some(&json[json.find(&key)? + key.len()..])
}

/// The value slice just after `"field":` within `region`.
fn field_after<'a>(region: &'a str, field: &str) -> Option<&'a str> {
    let key = format!("\"{field}\"");
    let after = &region[region.find(&key)? + key.len()..];
    Some(after[after.find(':')? + 1..].trim_start())
}

/// First numeric `field` inside top-level `obj` (e.g. download.bandwidth).
fn num_field(json: &str, obj: &str, field: &str) -> Option<f64> {
    let v = field_after(obj_region(json, obj)?, field)?;
    let end = v
        .find(|c: char| {
            !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e' || c == 'E' || c == '+')
        })
        .unwrap_or(v.len());
    v[..end].parse().ok()
}

/// First quoted string `field` inside top-level `obj` (e.g. server.name).
fn str_field(json: &str, obj: &str, field: &str) -> Option<String> {
    let v = field_after(obj_region(json, obj)?, field)?.strip_prefix('"')?;
    Some(v[..v.find('"')?].to_string())
}

/// Quoted string for a top-level key (e.g. isp).
fn top_str(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\"");
    let after = &json[json.find(&key)? + key.len()..];
    let v = after[after.find(':')? + 1..]
        .trim_start()
        .strip_prefix('"')?;
    Some(v[..v.find('"')?].to_string())
}

/// Run the Ookla CLI and turn its JSON into a [`SpeedResult`]. Cancellation
/// kills the child process.
pub fn run_ookla_speed_test(
    bin: &PathBuf,
    progress: &mut impl FnMut(String),
    stop: &AtomicBool,
) -> Result<SpeedResult, String> {
    progress("Running Ookla Speedtest CLI (this matches speedtest.net)…".to_string());
    let mut child = Command::new(bin)
        .args(["--accept-license", "--accept-gdpr", "--format=json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", bin.display()))?;

    let stdout = child.stdout.take().ok_or("no stdout from speedtest")?;
    let reader = thread::spawn(move || {
        let mut s = String::new();
        let mut f = stdout;
        let _ = f.read_to_string(&mut s);
        s
    });

    let t0 = Instant::now();
    let mut next_report = 5u64;
    let status = loop {
        if stop.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cancelled".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let secs = t0.elapsed().as_secs();
                if secs >= next_report {
                    progress(format!("  working… {secs}s"));
                    next_report = secs + 5;
                }
                thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(format!("speedtest wait failed: {e}")),
        }
    };

    let out = reader.join().unwrap_or_default();
    let json = &out[out.find('{').unwrap_or(0)..];
    if num_field(json, "download", "bandwidth").is_none() {
        return Err(format!(
            "speedtest produced no usable result (exit {:?}) — network error?",
            status.code()
        ));
    }

    let ping_ms = num_field(json, "ping", "latency").unwrap_or(0.0);
    let jitter_ms = num_field(json, "ping", "jitter").unwrap_or(0.0);
    let dl_bps = num_field(json, "download", "bandwidth").unwrap_or(0.0);
    let ul_bps = num_field(json, "upload", "bandwidth").unwrap_or(0.0);
    let dl_bytes = num_field(json, "download", "bytes").unwrap_or(0.0) as u64;
    let ul_bytes = num_field(json, "upload", "bytes").unwrap_or(0.0) as u64;
    let dl_ms = num_field(json, "download", "elapsed").unwrap_or(0.0);
    let ul_ms = num_field(json, "upload", "elapsed").unwrap_or(0.0);

    let server = str_field(json, "server", "name").unwrap_or_else(|| "Ookla".into());
    let location = str_field(json, "server", "location").unwrap_or_default();
    let isp = top_str(json, "isp").unwrap_or_default();
    if !isp.is_empty() {
        progress(format!("  ISP: {isp}"));
    }
    let source = if location.is_empty() {
        format!("Ookla Speedtest · {server}")
    } else {
        format!("Ookla Speedtest · {server} ({location})")
    };

    Ok(SpeedResult {
        ping_ms,
        jitter_ms,
        download_mbps: dl_bps * 8.0 / 1_000_000.0,
        download_mibps: dl_bps / MIB,
        upload_mbps: ul_bps * 8.0 / 1_000_000.0,
        upload_mibps: ul_bps / MIB,
        downloaded_bytes: dl_bytes,
        uploaded_bytes: ul_bytes,
        download_secs: dl_ms / 1000.0,
        upload_secs: ul_ms / 1000.0,
        source,
    })
}

/// Run the full speed test. Prefers the official Ookla CLI when it is
/// installed (so results match speedtest.net); otherwise falls back to the
/// bundled sustained Cloudflare HTTP test. Set `WAYNES_DNS_SPEEDTEST=builtin`
/// to always use the bundled client. `stop` cancels promptly.
pub fn run_speed_test(
    opts: &SpeedOptions,
    progress: &mut impl FnMut(String),
    stop: &AtomicBool,
) -> Result<SpeedResult, String> {
    let force_builtin = std::env::var("WAYNES_DNS_SPEEDTEST")
        .map(|v| v.eq_ignore_ascii_case("builtin"))
        .unwrap_or(false);
    if !force_builtin {
        if let Some(bin) = ookla_bin() {
            return run_ookla_speed_test(&bin, progress, stop);
        }
        progress("Ookla speedtest CLI not found — using the built-in test.".to_string());
    }

    progress(format!("Server: {SERVER_LABEL}"));
    progress(format!(
        "Sustained test: ~{}s download + ~{}s upload",
        opts.per_phase_secs, opts.per_phase_secs
    ));

    progress("Measuring latency...".into());
    let (ping_ms, jitter_ms) = measure_ping(5, progress)?;
    if stop.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }

    // Size the sustained transfers from a quick probe.
    progress("Sizing download...".into());
    let (pb, ps) = download_once(DL_PROBE, stop)?;
    let dl_chunk = pick_chunk(pb, ps, MIN_DL_CHUNK, MAX_DL_CHUNK);

    progress("Measuring download...".into());
    let (dl_bytes, dl_secs) = sustained_download(
        dl_chunk,
        Duration::from_secs(opts.per_phase_secs),
        progress,
        stop,
    )?;
    if stop.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }

    progress("Sizing upload...".into());
    let (ub, us) = upload_once(UL_PROBE, stop)?;
    let ul_chunk = pick_chunk(ub, us, MIN_UL_CHUNK, MAX_UL_CHUNK);

    progress("Measuring upload...".into());
    let (ul_bytes, ul_secs) = sustained_upload(
        ul_chunk,
        Duration::from_secs(opts.per_phase_secs),
        progress,
        stop,
    )?;

    Ok(SpeedResult {
        ping_ms,
        jitter_ms,
        download_mbps: mbps(dl_bytes, dl_secs),
        download_mibps: mibps(dl_bytes, dl_secs),
        upload_mbps: mbps(ul_bytes, ul_secs),
        upload_mibps: mibps(ul_bytes, ul_secs),
        downloaded_bytes: dl_bytes,
        uploaded_bytes: ul_bytes,
        download_secs: dl_secs,
        upload_secs: ul_secs,
        source: format!("Cloudflare ({HOST})"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_end_found() {
        assert_eq!(
            find_header_end(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody"),
            Some(25)
        );
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn status_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\n"), Some(200));
        assert_eq!(
            parse_status(b"HTTP/1.1 429 Too Many Requests\r\n"),
            Some(429)
        );
        assert_eq!(parse_status(b"HTTP/1.1 403 \r\n"), Some(403));
        assert!(is_ok_status(200));
        assert!(is_ok_status(204));
        assert!(!is_ok_status(429));
        assert!(!is_ok_status(0));
    }

    #[test]
    fn content_length_parsing() {
        assert_eq!(
            parse_content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"),
            Some(1234)
        );
        // Case-insensitive header name.
        assert_eq!(
            parse_content_length(b"HTTP/1.1 200 OK\r\ncontent-length: 42\r\n\r\n"),
            Some(42)
        );
        assert_eq!(
            parse_content_length(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n"),
            None
        );
    }

    #[test]
    fn summary_is_readable() {
        let r = SpeedResult {
            ping_ms: 12.34,
            jitter_ms: 1.2,
            download_mbps: 87.65,
            download_mibps: 10.45,
            upload_mbps: 22.1,
            upload_mibps: 2.63,
            downloaded_bytes: 0,
            uploaded_bytes: 0,
            download_secs: 0.0,
            upload_secs: 0.0,
            source: "Cloudflare (speed.cloudflare.com)".into(),
        };
        let s = r.summary();
        assert!(s.contains("Ping 12.3 ms"));
        assert!(s.contains("Download 87.65 Mbps (10.45 MiB/s)"));
        assert!(s.contains("Upload 22.10 Mbps (2.63 MiB/s)"));
    }

    #[test]
    fn unit_conversions() {
        // 1 MiB/s == 8.388608 Mbps
        assert!((mbps(1_048_576, 1.0) - 8.388608).abs() < 1e-6);
        assert!((mibps(1_048_576, 1.0) - 1.0).abs() < 1e-9);
        // 1 MB/s == 8 Mbps, which is 0.9537 MiB/s
        assert!((mbps(1_000_000, 1.0) - 8.0).abs() < 1e-9);
        assert!((mibps(1_000_000, 1.0) - 0.95367431640625).abs() < 1e-9);
    }

    #[test]
    fn chunk_sizing_respects_bounds() {
        // Very fast link → capped at max.
        assert_eq!(
            pick_chunk(100_000_000, 1.0, 1_000_000, 50_000_000),
            50_000_000
        );
        // Very slow link → floored at min.
        assert_eq!(pick_chunk(10_000, 1.0, 1_000_000, 50_000_000), 1_000_000);
        // ~10 MB/s → ~40 MB chunk.
        assert_eq!(
            pick_chunk(10_000_000, 1.0, 1_000_000, 50_000_000),
            40_000_000
        );
    }

    #[test]
    fn default_runs_about_fifty_seconds() {
        let total = SpeedOptions::default().per_phase_secs * 2;
        assert!((45..=55).contains(&total), "default total was {total}s");
    }

    #[test]
    fn parses_ookla_json() {
        let json = r#"{"type":"result","ping":{"jitter":5.496,"latency":47.283,"low":43.277,"high":50.194},"download":{"bandwidth":25220172,"bytes":348348608,"elapsed":15012,"latency":{"iqm":696.4}},"upload":{"bandwidth":3512227,"bytes":44754204,"elapsed":14994},"isp":"T-Mobile USA","server":{"id":57444,"name":"Fastwyre Broadband","location":"Kansas City, MO","country":"United States"}}"#;
        assert_eq!(num_field(json, "ping", "latency"), Some(47.283));
        assert_eq!(num_field(json, "ping", "jitter"), Some(5.496));
        assert_eq!(num_field(json, "download", "bandwidth"), Some(25_220_172.0));
        assert_eq!(num_field(json, "upload", "bandwidth"), Some(3_512_227.0));
        assert_eq!(num_field(json, "download", "bytes"), Some(348_348_608.0));
        assert_eq!(num_field(json, "upload", "elapsed"), Some(14_994.0));
        assert_eq!(
            str_field(json, "server", "name").as_deref(),
            Some("Fastwyre Broadband")
        );
        assert_eq!(
            str_field(json, "server", "location").as_deref(),
            Some("Kansas City, MO")
        );
        assert_eq!(top_str(json, "isp").as_deref(), Some("T-Mobile USA"));
        // 25_220_172 B/s * 8 / 1e6 == 201.76 Mbps
        assert!(
            (num_field(json, "download", "bandwidth").unwrap() * 8.0 / 1e6 - 201.761_376).abs()
                < 1e-6
        );
    }
}
