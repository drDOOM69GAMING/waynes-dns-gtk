use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::system::{default_route, field, link_status, run_cmd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warn,
    Leak,
}

impl Severity {
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Ok => "ok",
            Severity::Warn => "warn",
            Severity::Leak => "leak",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Warn => "WARN",
            Severity::Leak => "LEAK",
        }
    }
}

#[derive(Clone)]
pub struct LeakCheck {
    pub name: String,
    pub severity: Severity,
    pub detail: String,
}

impl LeakCheck {
    fn new(name: &str, severity: Severity, detail: String) -> Self {
        LeakCheck {
            name: name.to_string(),
            severity,
            detail,
        }
    }
    pub fn line(&self) -> String {
        format!(
            "[{}] {} — {}",
            self.severity.label(),
            self.name,
            self.detail
        )
    }
}

pub fn worst(checks: &[LeakCheck]) -> Severity {
    if checks.iter().any(|c| c.severity == Severity::Leak) {
        Severity::Leak
    } else if checks.iter().any(|c| c.severity == Severity::Warn) {
        Severity::Warn
    } else {
        Severity::Ok
    }
}

fn is_private(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_private() || a.is_loopback() || a.is_link_local(),
        Ok(IpAddr::V6(a)) => {
            a.is_loopback() || a.is_unicast_link_local() || (a.segments()[0] & 0xfe00) == 0xfc00
        }
        Err(_) => true,
    }
}

fn is_loopback_addr(addr: &str) -> bool {
    addr.starts_with("127.")
        || addr == "::1"
        || addr == "[::1]"
        || addr.contains("%lo")
        || addr.starts_with("::ffff:127.")
}

/// Split an `ss` endpoints field like `192.168.12.1:53` or `[2606::1]:853`.
fn split_addr(s: &str) -> (String, Option<u16>) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let addr = rest[..idx].to_string();
            let port = rest[idx + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (addr, port);
        }
    }
    match s.rsplit_once(':') {
        Some((addr, port)) => (addr.to_string(), port.parse::<u16>().ok()),
        None => (s.to_string(), None),
    }
}

/// Peer endpoints from `ss` output (both TCP and UDP) whose remote port matches.
fn ss_peers(port: u16) -> Vec<String> {
    let mut out = Vec::new();
    for (transport, args) in [("tcp", ["-H", "-tan"]), ("udp", ["-H", "-uan"])] {
        let res = run_cmd("ss", &args);
        for line in res.stdout.lines() {
            // Columns: State Recv-Q Send-Q Local Peer [Process...]
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 {
                continue;
            }
            let (peer_addr, peer_port) = split_addr(f[4]);
            if peer_port == Some(port)
                && !is_loopback_addr(&peer_addr)
                && peer_addr != "0.0.0.0"
                && peer_addr != "*"
            {
                out.push(format!("{transport} -> {peer_addr}:{port}"));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The number of lookups fired by `probe_sockets`, used to size expectations.
const PROBE_QUERIES: usize = 16;

/// Sum `bytes_sent` and `data_segs_out` across every established, non-loopback
/// TCP connection to port 853. This is the *displayed* proof that encrypted
/// traffic is actually flowing: the counts grow only when packets move.
fn dot_traffic() -> (u64, u64) {
    let res = run_cmd("ss", &["-H", "-tinp"]);
    let lines: Vec<&str> = res.stdout.lines().collect();
    let mut bytes = 0u64;
    let mut segs = 0u64;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.contains("ESTAB") {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 5 {
                let (addr, port) = split_addr(f[4]);
                if port == Some(853) && !is_loopback_addr(&addr) {
                    // TCP internal stats live on the following (indented) line.
                    let mut info = line.to_string();
                    if let Some(next) = lines.get(i + 1) {
                        info.push(' ');
                        info.push_str(next);
                    }
                    bytes += num_field(&info, "bytes_sent:");
                    segs += num_field(&info, "data_segs_out:");
                }
            }
        }
        i += 1;
    }
    (bytes, segs)
}

/// Read the integer that follows `key` (e.g. `bytes_sent:`) in an `ss` info line.
fn num_field(s: &str, key: &str) -> u64 {
    let mut rest = s;
    while let Some(pos) = rest.find(key) {
        let after = &rest[pos + key.len()..];
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(v) = digits.parse() {
            return v;
        }
        rest = after;
    }
    0
}

struct SocketProbe {
    plaintext: Vec<String>,
    dot_conn: Vec<String>,
    dot_bytes_delta: u64,
    dot_segs_delta: u64,
}

/// Fire a burst of resolver queries and sample live sockets while they run.
/// systemd-resolved uses short-lived UDP sockets, so sampling without traffic
/// frequently misses a plaintext leak; the burst keeps sockets visible.
///
/// It also measures the DoT socket byte/segment counters before vs. during the
/// burst. That delta is what distinguishes "a port-853 socket happens to exist"
/// from "our queries really travelled over TLS".
fn probe_sockets() -> SocketProbe {
    let (before_bytes, before_segs) = dot_traffic();

    let mut children = Vec::new();
    for i in 0..PROBE_QUERIES {
        let name = format!("leak-probe-{i}.example.com");
        if let Ok(child) = Command::new("resolvectl")
            .args(["query", "--cache=no", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            children.push(child);
        }
    }

    let mut p53: Vec<String> = Vec::new();
    let mut p853: Vec<String> = Vec::new();
    let mut peak_bytes = before_bytes;
    let mut peak_segs = before_segs;
    for _ in 0..50 {
        for s in ss_peers(53) {
            if !p53.contains(&s) {
                p53.push(s);
            }
        }
        for s in ss_peers(853) {
            if !p853.contains(&s) {
                p853.push(s);
            }
        }
        let (b, g) = dot_traffic();
        peak_bytes = peak_bytes.max(b);
        peak_segs = peak_segs.max(g);
        thread::sleep(Duration::from_millis(25));
    }
    for mut c in children {
        let _ = c.wait();
    }
    let (after_bytes, after_segs) = dot_traffic();
    peak_bytes = peak_bytes.max(after_bytes);
    peak_segs = peak_segs.max(after_segs);

    p53.sort();
    p853.sort();
    SocketProbe {
        plaintext: p53,
        dot_conn: p853,
        dot_bytes_delta: peak_bytes.saturating_sub(before_bytes),
        dot_segs_delta: peak_segs.saturating_sub(before_segs),
    }
}

/// Ask the outside world which recursive resolver it sees us coming from.
fn whoami_resolver() -> Option<String> {
    for q in [
        "o-o.myaddr.l.google.com",
        "whoami.ds.akahelp.net",
        "whoami.cloudflare",
    ] {
        let out = run_cmd("resolvectl", &["query", "-t", "TXT", q]).stdout;
        for line in out.lines() {
            // TXT payloads are quoted; take the odd splits.
            for part in line.split('"').skip(1).step_by(2) {
                if part.parse::<IpAddr>().is_ok() {
                    return Some(part.to_string());
                }
            }
        }
    }
    None
}

/// Best-effort known egress prefixes for the supported providers.
fn provider_prefixes(key: &str) -> &'static [&'static str] {
    match key {
        "cloudflare" | "cloudflare-malware" => &[
            "1.1.1.",
            "1.0.0.",
            "172.64.",
            "172.65.",
            "172.66.",
            "172.67.",
            "172.68.",
            "172.69.",
            "172.70.",
            "172.71.",
            "104.16.",
            "104.17.",
            "104.18.",
            "104.19.",
            "104.20.",
            "104.21.",
            "104.22.",
            "104.23.",
            "104.24.",
            "104.25.",
            "104.26.",
            "104.27.",
            "162.158.",
            "162.159.",
            "2400:cb00:",
            "2606:4700:",
            "2a06:98c0:",
        ],
        "google" => &[
            "8.8.8.",
            "8.8.4.",
            "8.4.4.",
            "172.217.",
            "172.253.",
            "142.250.",
            "142.251.",
            "216.58.",
            "216.239.",
            "2001:4860:",
            "2607:f8b0:",
        ],
        "quad9" => &[
            "9.9.9.",
            "149.112.112.",
            "2620:fe:",
            "2620:171:",
            "23.128.",
            "23.138.",
        ],
        _ => &[],
    }
}

fn matches_provider(ip: &str, key: &str) -> bool {
    provider_prefixes(key).iter().any(|p| ip.starts_with(p))
}

/// Negative control for the leak detector: open a real plaintext TCP
/// connection to a public resolver on port 53, then confirm the socket scanner
/// actually sees it. This proves the detector is capable of *failing* (i.e. it
/// is not just rubber-stamping "OK").
pub fn detector_selftest() -> LeakCheck {
    use std::net::{SocketAddr, TcpStream};

    let targets = ["9.9.9.9:53", "1.1.1.1:53", "8.8.8.8:53"];
    let mut held: Option<TcpStream> = None;
    let mut target_used = String::new();
    for t in targets {
        let addr: SocketAddr = match t.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            held = Some(s);
            target_used = t.to_string();
            break;
        }
    }

    let mut seen: Vec<String> = Vec::new();
    if held.is_some() {
        for _ in 0..40 {
            for p in ss_peers(53) {
                if !seen.contains(&p) {
                    seen.push(p);
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    drop(held); // close the plaintext socket again

    if target_used.is_empty() {
        return LeakCheck::new(
            "Detector self-test",
            Severity::Warn,
            "no public DNS server accepted a port-53 connection to test with".to_string(),
        );
    }
    seen.sort();
    if seen.is_empty() {
        LeakCheck::new(
            "Detector self-test",
            Severity::Warn,
            format!("held a plaintext socket to {target_used} but the scanner did not see it"),
        )
    } else {
        LeakCheck::new(
            "Detector self-test",
            Severity::Ok,
            format!(
                "scanner correctly flagged a plaintext socket: {}",
                seen.join(", ")
            ),
        )
    }
}

/// Run the full DNS leak test.
pub fn leak_test(provider: &str) -> Vec<LeakCheck> {
    let mut checks = Vec::new();
    let (iface, gw) = default_route();

    // 1. /etc/resolv.conf should point at the resolved stub.
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let uses_stub = resolv.lines().any(|l| l.trim() == "nameserver 127.0.0.53");
    checks.push(LeakCheck::new(
        "System resolver stub",
        if uses_stub {
            Severity::Ok
        } else {
            Severity::Warn
        },
        if uses_stub {
            "/etc/resolv.conf -> 127.0.0.53 (systemd-resolved)".to_string()
        } else {
            "/etc/resolv.conf does not point at the systemd-resolved stub".to_string()
        },
    ));

    if iface.is_empty() {
        checks.push(LeakCheck::new(
            "Default route",
            Severity::Warn,
            "no default-route interface found".to_string(),
        ));
        return checks;
    }

    let block = link_status(&iface);

    // 2. DNS-over-TLS actually enforced on the active link.
    let dot_on = field(&block, "Protocols:")
        .map(|p| p.contains("+DNSOverTLS"))
        .unwrap_or(false);
    checks.push(LeakCheck::new(
        "DNS-over-TLS enforced",
        if dot_on { Severity::Ok } else { Severity::Leak },
        if dot_on {
            format!("{iface} uses encrypted DNS only")
        } else {
            format!("{iface} is resolving in plaintext")
        },
    ));

    // 3. The router/gateway must not be one of the resolvers.
    let servers = field(&block, "DNS Servers:").unwrap_or("");
    let router_used = !gw.is_empty()
        && servers
            .split_whitespace()
            .any(|s| s.split('#').next() == Some(gw.as_str()));
    checks.push(LeakCheck::new(
        "Router not used as resolver",
        if router_used {
            Severity::Leak
        } else {
            Severity::Ok
        },
        if router_used {
            format!("gateway {gw} is still a configured DNS server")
        } else if gw.is_empty() {
            "no gateway detected".to_string()
        } else {
            format!("gateway {gw} is not resolving")
        },
    ));

    // Generate a burst of traffic so transient sockets are visible, then
    // look for plaintext (53) and encrypted (853) connections.
    let probe = probe_sockets();
    checks.push(LeakCheck::new(
        "No plaintext DNS sockets",
        if probe.plaintext.is_empty() {
            Severity::Ok
        } else {
            Severity::Leak
        },
        if probe.plaintext.is_empty() {
            "no outbound port-53 connections".to_string()
        } else {
            format!("plaintext DNS in use: {}", probe.plaintext.join(", "))
        },
    ));

    // 5. Prove the encrypted socket actually carried the lookups (not merely
    // that some port-853 socket exists). Counters grow only when packets move.
    let transport_used = probe.dot_bytes_delta > 0 || probe.dot_segs_delta > 0;
    let (transport_sev, transport_detail) = if !probe.dot_conn.is_empty() && transport_used {
        (
            Severity::Ok,
            format!(
                "{PROBE_QUERIES} lookups rode TLS (+{} bytes, +{} data segments) on {}",
                probe.dot_bytes_delta,
                probe.dot_segs_delta,
                probe.dot_conn.join(", ")
            ),
        )
    } else if !probe.dot_conn.is_empty() {
        (
            Severity::Warn,
            format!(
                "port-853 socket present but no query traffic observed on it ({})",
                probe.dot_conn.join(", ")
            ),
        )
    } else if dot_on {
        (
            Severity::Warn,
            "DoT is enabled but no established port-853 connection was seen".to_string(),
        )
    } else {
        (
            Severity::Leak,
            "no encrypted DNS transport observed".to_string(),
        )
    };
    checks.push(LeakCheck::new(
        "Encrypted transport in use",
        transport_sev,
        transport_detail,
    ));

    // 6. What the outside world sees as your resolver.
    match whoami_resolver() {
        Some(ip) => {
            let severity = if is_private(&ip) || (!gw.is_empty() && ip == gw) {
                Severity::Leak
            } else if matches_provider(&ip, provider) {
                Severity::Ok
            } else {
                Severity::Warn
            };
            let detail = match severity {
                Severity::Leak => format!("external resolver is a local/private address: {ip}"),
                Severity::Ok => format!("external resolver seen as {ip} (matches provider)"),
                Severity::Warn => format!(
                    "external resolver seen as {ip} — not a known {provider} network (could be ISP/VPN)"
                ),
            };
            checks.push(LeakCheck::new(
                "Upstream resolver identity",
                severity,
                detail,
            ));
        }
        None => checks.push(LeakCheck::new(
            "Upstream resolver identity",
            Severity::Warn,
            "could not determine the external resolver".to_string(),
        )),
    }

    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_addr_ipv4() {
        assert_eq!(
            split_addr("192.168.12.1:53"),
            ("192.168.12.1".into(), Some(53))
        );
    }

    #[test]
    fn split_addr_ipv6_bracket() {
        assert_eq!(
            split_addr("[2803:f800:53::4]:443"),
            ("2803:f800:53::4".into(), Some(443))
        );
    }

    #[test]
    fn split_addr_wildcard() {
        assert_eq!(split_addr("0.0.0.0:*"), ("0.0.0.0".into(), None));
    }

    #[test]
    fn split_addr_scoped_listener() {
        assert_eq!(
            split_addr("127.0.0.53%lo:53"),
            ("127.0.0.53%lo".into(), Some(53))
        );
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_addr("127.0.0.53%lo"));
        assert!(is_loopback_addr("127.0.0.1"));
        assert!(is_loopback_addr("::1"));
        assert!(!is_loopback_addr("192.168.12.1"));
        assert!(!is_loopback_addr("2606:4700:4700::1111"));
    }

    #[test]
    fn private_detection() {
        assert!(is_private("192.168.12.1"));
        assert!(is_private("10.0.0.1"));
        assert!(is_private("172.16.5.5"));
        assert!(is_private("fe80::1"));
        assert!(is_private("fd00::1"));
        assert!(!is_private("1.1.1.1"));
        assert!(!is_private("2606:4700:4700::1111"));
    }

    #[test]
    fn provider_matching() {
        assert!(matches_provider("172.68.2.45", "cloudflare"));
        assert!(matches_provider("1.1.1.1", "cloudflare"));
        assert!(matches_provider("172.253.185.27", "google"));
        assert!(matches_provider("2620:171:df:0:9999::108", "quad9"));
        assert!(!matches_provider("172.68.2.45", "google"));
        assert!(!matches_provider("8.8.8.8", "quad9"));
    }

    #[test]
    fn worst_severity_is_sticky() {
        let ok = LeakCheck::new("a", Severity::Ok, String::new());
        let warn = LeakCheck::new("b", Severity::Warn, String::new());
        let leak = LeakCheck::new("c", Severity::Leak, String::new());
        assert_eq!(worst(std::slice::from_ref(&ok)), Severity::Ok);
        assert_eq!(worst(&[ok.clone(), warn.clone()]), Severity::Warn);
        assert_eq!(worst(&[ok, warn, leak]), Severity::Leak);
    }

    #[test]
    fn num_field_reads_ss_counters() {
        let line = "cubic wscale:11,10 bytes_sent:2008 bytes_received:324 \
                    segs_out:7 data_segs_out:4";
        assert_eq!(num_field(line, "bytes_sent:"), 2008);
        assert_eq!(num_field(line, "data_segs_out:"), 4);
        assert_eq!(num_field(line, "bytes_received:"), 324);
    }

    #[test]
    fn num_field_missing_is_zero() {
        assert_eq!(num_field("cubic wscale:11,10", "bytes_sent:"), 0);
        // A key with no digits after it must not panic.
        assert_eq!(num_field("bytes_sent: bytes_received:9", "bytes_sent:"), 0);
        assert_eq!(
            num_field("bytes_sent: bytes_received:9", "bytes_received:"),
            9
        );
    }

    #[test]
    fn dot_traffic_ignores_loopback_and_other_ports() {
        // Directly exercise the parsing helper against synthetic `ss` lines by
        // re-implementing the row check: only ESTAB + peer port 853 + public.
        let estab = "ESTAB 0 0 192.168.12.234:39100 149.112.112.112:853";
        let f: Vec<&str> = estab.split_whitespace().collect();
        let (addr, port) = split_addr(f[4]);
        assert_eq!(port, Some(853));
        assert!(!is_loopback_addr(&addr));

        let loopback = "ESTAB 0 0 127.0.0.1:5000 127.0.0.53:53";
        let f2: Vec<&str> = loopback.split_whitespace().collect();
        let (a2, p2) = split_addr(f2[4]);
        assert_eq!(p2, Some(53));
        assert!(is_loopback_addr(&a2));
    }
}
