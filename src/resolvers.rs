use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
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

pub fn dot_probe_tls(server: &DnsServer, timeout: Duration) -> bool {
    let ip = &server.ip;
    let host = &server.sni;

    // Build socket address (port 853)
    let mut addr_str = format!("{}:853", ip);
    if ip.contains(':') && !ip.starts_with('[') {
        addr_str = format!("[{}]:853", ip);
    }
    let addrs = match addr_str.to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mut tcp = match addrs.into_iter().next() {
        Some(a) => match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => s,
            Err(_) => return false,
        },
        None => return false,
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);

    let server_name: ServerName<'static> = match ServerName::try_from(host.clone()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut client = match ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // Drive the TLS handshake to completion. If it finishes without error the
    // endpoint is a valid, trusted DNS-over-TLS server.
    for _ in 0..8 {
        if !client.is_handshaking() {
            break;
        }
        if client.complete_io(&mut tcp).is_err() {
            return false;
        }
    }
    !client.is_handshaking()
}

pub fn filter_reachable(servers: &[DnsServer], timeout: Duration) -> Vec<DnsServer> {
    let mut out = Vec::new();
    for s in servers {
        if dot_probe_tls(s, timeout) {
            out.push(s.clone());
        }
    }
    out
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
}
