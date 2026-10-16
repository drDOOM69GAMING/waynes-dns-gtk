use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::system::{default_route, link_status, run_cmd};

#[derive(Debug, Clone)]
pub struct DnsServer {
    pub ip: String, // ip or [ipv6]
    pub sni: String,
}

#[derive(Debug, Clone)]
pub struct Provider {
    pub key: &'static str,
    pub label: &'static str,
    pub v4: Vec<DnsServer>,
    pub v6: Vec<DnsServer>,
}

pub fn all_providers() -> Vec<Provider> {
    vec![
        Provider {
            key: "cloudflare",
            label: "Cloudflare (no filtering)",
            v4: vec![
                DnsServer {
                    ip: "1.1.1.1".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
                DnsServer {
                    ip: "1.0.0.1".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
            ],
            v6: vec![
                DnsServer {
                    ip: "2606:4700:4700::1111".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
                DnsServer {
                    ip: "2606:4700:4700::1001".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
            ],
        },
        Provider {
            key: "cloudflare-malware",
            label: "Cloudflare Security (blocks malware)",
            v4: vec![
                DnsServer {
                    ip: "1.1.1.2".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
                DnsServer {
                    ip: "1.0.0.2".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
            ],
            v6: vec![
                DnsServer {
                    ip: "2606:4700:4700::1112".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
                DnsServer {
                    ip: "2606:4700:4700::1002".to_string(),
                    sni: "cloudflare-dns.com".to_string(),
                },
            ],
        },
        Provider {
            key: "quad9",
            label: "Quad9 (blocks malware)",
            v4: vec![
                DnsServer {
                    ip: "9.9.9.9".to_string(),
                    sni: "dns.quad9.net".to_string(),
                },
                DnsServer {
                    ip: "149.112.112.112".to_string(),
                    sni: "dns.quad9.net".to_string(),
                },
            ],
            v6: vec![
                DnsServer {
                    ip: "2620:fe::fe".to_string(),
                    sni: "dns.quad9.net".to_string(),
                },
                DnsServer {
                    ip: "2620:fe::9".to_string(),
                    sni: "dns.quad9.net".to_string(),
                },
            ],
        },
        Provider {
            key: "google",
            label: "Google (no filtering)",
            v4: vec![
                DnsServer {
                    ip: "8.8.8.8".to_string(),
                    sni: "dns.google".to_string(),
                },
                DnsServer {
                    ip: "8.8.4.4".to_string(),
                    sni: "dns.google".to_string(),
                },
            ],
            v6: vec![
                DnsServer {
                    ip: "2001:4860:4860::8888".to_string(),
                    sni: "dns.google".to_string(),
                },
                DnsServer {
                    ip: "2001:4860:4860::8844".to_string(),
                    sni: "dns.google".to_string(),
                },
            ],
        },
    ]
}

pub fn find_provider(key: &str) -> Option<Provider> {
    all_providers().into_iter().find(|p| p.key == key)
}

/// Pull `ip` and `ip#sni` server tokens out of `resolvectl` output, including
/// values that wrap onto following (continued) lines.
fn extract_servers(text: &str) -> (Vec<String>, Vec<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut ips = Vec::new();
    let mut snis = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.contains("DNS Servers:") || line.contains("Current DNS Server:") {
            if let Some((_, v)) = line.split_once(':') {
                add_server_tokens(v, &mut ips, &mut snis);
            }
            // Consume wrapped continuation lines: a real field line always
            // contains a token ending in ':' (e.g. "DNS Domain:"), server
            // tokens never do.
            let mut j = i + 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() || t.split_whitespace().any(|tok| tok.ends_with(':')) {
                    break;
                }
                add_server_tokens(t, &mut ips, &mut snis);
                j += 1;
            }
            i = j;
            continue;
        }
        i += 1;
    }

    ips.sort();
    ips.dedup();
    snis.sort();
    snis.dedup();
    (ips, snis)
}

fn add_server_tokens(s: &str, ips: &mut Vec<String>, snis: &mut Vec<String>) {
    for tok in s.split_whitespace() {
        match tok.split_once('#') {
            Some((ip, sni)) => {
                ips.push(ip.to_string());
                snis.push(sni.to_string());
            }
            None => ips.push(tok.to_string()),
        }
    }
}

/// Match a set of observed server IPs/SNIs to a known provider key. IPs are
/// tried first because Cloudflare and Cloudflare-Security share an SNI.
fn provider_from_servers(ips: &[String], snis: &[String]) -> Option<String> {
    let providers = all_providers();
    for p in &providers {
        let known: Vec<&str> =
            p.v4.iter()
                .chain(p.v6.iter())
                .map(|s| s.ip.as_str())
                .collect();
        if ips.iter().any(|ip| known.contains(&ip.as_str())) {
            return Some(p.key.to_string());
        }
    }
    for p in &providers {
        let known: Vec<&str> =
            p.v4.iter()
                .chain(p.v6.iter())
                .map(|s| s.sni.as_str())
                .collect();
        if snis.iter().any(|s| known.contains(&s.as_str())) {
            return Some(p.key.to_string());
        }
    }
    None
}

/// Detect which of the known providers the machine is *currently* configured to
/// use, from the live systemd-resolved state (active link plus global config).
pub fn detect_active_provider() -> Option<String> {
    let mut text = String::new();
    let (iface, _gw) = default_route();
    if !iface.is_empty() {
        text.push_str(&link_status(&iface));
        text.push('\n');
    }
    text.push_str(&run_cmd("resolvectl", &["status"]).stdout);
    let (ips, snis) = extract_servers(&text);
    provider_from_servers(&ips, &snis)
}

/// How long to wait before the single retry of an unreachable server, so a
/// momentary IPv6/route blip does not read as `DEAD`.
const RETRY_DELAY: Duration = Duration::from_millis(750);

/// Why a DoT probe failed. Kept structured so transient failures (connect or
/// TLS) can be retried once while a permanent one (bad address) is not.
#[derive(Debug, Clone)]
pub enum ProbeError {
    /// The configured `ip` was not a literal IP address.
    Addr(String),
    /// The TCP connection failed or timed out.
    Connect(String),
    /// The TLS handshake failed or never completed.
    Tls(String),
}

impl ProbeError {
    /// Human-readable reason, suitable for the log.
    pub fn reason(&self) -> &str {
        match self {
            ProbeError::Addr(s) | ProbeError::Connect(s) | ProbeError::Tls(s) => s,
        }
    }

    /// Whether a retry is worth attempting (a wrong address never is).
    fn transient(&self) -> bool {
        matches!(self, ProbeError::Connect(_) | ProbeError::Tls(_))
    }
}

/// The result of probing one server: the server itself plus either success or
/// the reason it was unreachable (after the single retry).
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub server: DnsServer,
    pub result: Result<(), String>,
}

/// Build the `ip:853` socket address from the server table. The `ip` field is
/// always a literal address, so it is parsed directly rather than resolved.
fn parse_server_addr(server: &DnsServer) -> Result<SocketAddr, ProbeError> {
    let raw = server.ip.trim();
    let raw = raw.strip_prefix('[').unwrap_or(raw);
    let raw = raw.strip_suffix(']').unwrap_or(raw);
    match raw.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, 853)),
        Err(_) => Err(ProbeError::Addr(format!(
            "not an IP address: {}",
            server.ip
        ))),
    }
}

/// Turn a failed connect into a plain-English reason, keeping the raw OS error
/// for detail. Common Linux errnos are named explicitly so the log explains
/// *why* instead of just quoting a number. `is_ipv6` tailors the wording to the
/// address family that actually failed.
fn connect_reason(e: &std::io::Error, timeout: Duration, is_ipv6: bool) -> String {
    let os = e.raw_os_error().unwrap_or(-1);
    let no_route = || {
        if is_ipv6 {
            "no IPv6 route; this link may be IPv6-less".to_string()
        } else {
            "no IPv4 route".to_string()
        }
    };
    let no_source = || {
        if is_ipv6 {
            "no usable IPv6 source address on this link".to_string()
        } else {
            "no usable IPv4 source address on this link".to_string()
        }
    };
    let (hint, timed_out) = match e.kind() {
        ErrorKind::TimedOut => ("no response; firewall or server down?".to_string(), true),
        ErrorKind::ConnectionRefused => (
            "connection refused; nothing listening on port 853".to_string(),
            false,
        ),
        ErrorKind::NetworkUnreachable => (no_route(), false),
        ErrorKind::HostUnreachable => ("host unreachable".to_string(), false),
        ErrorKind::AddrNotAvailable => (no_source(), false),
        ErrorKind::PermissionDenied => ("permission denied".to_string(), false),
        _ => match os {
            101 => (no_route(), false),
            99 => (no_source(), false),
            111 => (
                "connection refused; nothing listening on port 853".to_string(),
                false,
            ),
            113 => ("host unreachable".to_string(), false),
            _ => (String::new(), false),
        },
    };
    if hint.is_empty() {
        format!("connect failed: {e}")
    } else if timed_out {
        format!("connect timed out after {}s: {hint}", timeout.as_secs())
    } else {
        format!("connect failed: {hint} (os error {os})")
    }
}

/// Probe one DNS-over-TLS server on port 853 and report *why* it failed.
///
/// A full, trusted TLS handshake must complete. The reason distinguishes a bad
/// address, a connect failure, and a TLS failure so callers can retry the
/// transient cases and log the rest.
pub fn dot_probe_tls_reason(server: &DnsServer, timeout: Duration) -> Result<(), ProbeError> {
    let addr = parse_server_addr(server)?;

    let mut tcp = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| ProbeError::Connect(connect_reason(&e, timeout, addr.is_ipv6())))?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| ProbeError::Tls(format!("tls setup: {e}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);

    let server_name: ServerName<'static> = ServerName::try_from(server.sni.clone())
        .map_err(|e| ProbeError::Tls(format!("invalid server name {}: {e}", server.sni)))?;
    let mut client = ClientConnection::new(config, server_name)
        .map_err(|e| ProbeError::Tls(format!("tls init: {e}")))?;

    // Drive the handshake to completion. If it finishes without error the
    // endpoint is a valid, trusted DNS-over-TLS server.
    for _ in 0..8 {
        if !client.is_handshaking() {
            break;
        }
        client
            .complete_io(&mut tcp)
            .map_err(|e| ProbeError::Tls(format!("tls handshake failed: {e}")))?;
    }
    if client.is_handshaking() {
        return Err(ProbeError::Tls(
            "tls handshake did not complete".to_string(),
        ));
    }
    Ok(())
}

/// Probe a group of servers, retrying each failure once after a short pause.
/// Every outcome carries the reason it failed, if it did.
pub fn probe_servers(servers: &[DnsServer], timeout: Duration) -> Vec<ProbeOutcome> {
    servers
        .iter()
        .map(|s| {
            let result = match dot_probe_tls_reason(s, timeout) {
                Ok(()) => Ok(()),
                Err(first) if first.transient() => {
                    thread::sleep(RETRY_DELAY);
                    match dot_probe_tls_reason(s, timeout) {
                        Ok(()) => Ok(()),
                        Err(second) => {
                            Err(format!("{} (retry: {})", first.reason(), second.reason()))
                        }
                    }
                }
                Err(e) => Err(e.reason().to_string()),
            };
            ProbeOutcome {
                server: s.clone(),
                result,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_servers_handles_ipv4_sni_and_ipv6() {
        let text = "\
Link 3 (wlan0)
       DNS Servers: 9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
                    2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net
    Current DNS Server: 149.112.112.112#dns.quad9.net
";
        let (ips, snis) = extract_servers(text);
        assert!(ips.contains(&"9.9.9.9".to_string()));
        assert!(ips.contains(&"2620:fe::9".to_string()));
        assert!(snis.contains(&"dns.quad9.net".to_string()));
    }

    #[test]
    fn provider_detected_by_ip() {
        let ips = vec!["9.9.9.9".to_string()];
        assert_eq!(provider_from_servers(&ips, &[]), Some("quad9".to_string()));
    }

    #[test]
    fn provider_disambiguates_cloudflare_variants_by_ip() {
        let normal = vec!["1.1.1.1".to_string()];
        assert_eq!(
            provider_from_servers(&normal, &[]),
            Some("cloudflare".to_string())
        );
        let secure = vec!["1.1.1.2".to_string()];
        assert_eq!(
            provider_from_servers(&secure, &[]),
            Some("cloudflare-malware".to_string())
        );
    }

    #[test]
    fn provider_falls_back_to_sni() {
        let snis = vec!["dns.google".to_string()];
        assert_eq!(
            provider_from_servers(&[], &snis),
            Some("google".to_string())
        );
    }

    #[test]
    fn unknown_servers_detect_nothing() {
        let ips = vec!["192.168.12.1".to_string()];
        assert_eq!(provider_from_servers(&ips, &[]), None);
    }

    #[test]
    fn probe_rejects_non_ip_address_without_connecting() {
        let s = DnsServer {
            ip: "not-an-ip".to_string(),
            sni: "dns.quad9.net".to_string(),
        };
        let err = dot_probe_tls_reason(&s, Duration::from_millis(50)).unwrap_err();
        assert!(matches!(err, ProbeError::Addr(_)));
        assert!(err.reason().contains("not an IP address"));
    }

    #[test]
    fn probe_servers_reports_reason_for_bad_address() {
        // A bad address is permanent, so no retry delay is incurred here.
        let servers = vec![DnsServer {
            ip: "[nonsense]".to_string(),
            sni: "dns.quad9.net".to_string(),
        }];
        let out = probe_servers(&servers, Duration::from_millis(50));
        assert_eq!(out.len(), 1);
        assert!(out[0].result.is_err());
        assert!(out[0]
            .result
            .as_ref()
            .unwrap_err()
            .contains("not an IP address"));
    }

    #[test]
    fn parse_server_addr_accepts_bracketed_ipv6() {
        let s = DnsServer {
            ip: "[2620:fe::fe]".to_string(),
            sni: "dns.quad9.net".to_string(),
        };
        let addr = parse_server_addr(&s).unwrap();
        assert_eq!(addr.port(), 853);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn connect_reason_explains_common_errnos() {
        let unreachable = std::io::Error::from_raw_os_error(101);
        let msg = connect_reason(&unreachable, Duration::from_secs(5), true);
        assert!(msg.contains("no IPv6 route"), "got: {msg}");
        assert!(msg.contains("os error 101"), "got: {msg}");
        let msg4 = connect_reason(&unreachable, Duration::from_secs(5), false);
        assert!(msg4.contains("no IPv4 route"), "got: {msg4}");

        let refused = std::io::Error::from_raw_os_error(111);
        let msg = connect_reason(&refused, Duration::from_secs(5), true);
        assert!(msg.contains("connection refused"), "got: {msg}");

        let noaddr = std::io::Error::from_raw_os_error(99);
        let msg = connect_reason(&noaddr, Duration::from_secs(5), true);
        assert!(msg.contains("no usable IPv6 source address"), "got: {msg}");
    }
}
