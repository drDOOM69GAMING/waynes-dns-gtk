use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

pub const RESOLVED_DROPIN: &str = "/etc/systemd/resolved.conf.d/10-dns-over-tls.conf";
pub const STATE_FILE: &str = "/etc/waynes-dns-gtk.state";
pub const NFT_FILE: &str = "/etc/waynes-dns-leak-guard.nft";
pub const NFT_UNIT: &str = "/etc/systemd/system/waynes-dns-leak-guard.service";

#[derive(Debug, Clone, Default)]
pub struct ApplyPlan {
    pub resolver: String,
    pub dns4: Vec<String>, // "ip#sni"
    pub dns6: Vec<String>,
    pub conns: Vec<String>, // connection UUIDs
    pub firewall: bool,
    pub apply_all: bool,
}

impl ApplyPlan {
    /// Space-joined DNS server list for resolved.conf / nmcli.
    pub fn dns_line(&self) -> String {
        let mut s = self.dns4.join(" ");
        if !self.dns6.is_empty() {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(&self.dns6.join(" "));
        }
        s
    }
}

/// systemd-resolved drop-in. `DNSOverTLS=yes` means no plaintext fallback.
pub fn resolved_dropin(dns_line: &str) -> String {
    format!(
        "[Resolve]\n\
         # Managed by waynes-dns-gtk — DNS-over-TLS, no plaintext fallback.\n\
         DNS={dns_line}\n\
         FallbackDNS={dns_line}\n\
         DNSOverTLS=yes\n\
         DNSSEC=allow-downgrade\n\
         Domains=~.\n\
         CacheFromLocalhost=no\n"
    )
}

/// NetworkManager arguments that replace DHCP DNS and force DNS-over-TLS.
pub fn nmcli_modify_args(uuid: &str, dns4: &str, dns6: &str) -> Vec<String> {
    [
        "connection",
        "modify",
        uuid,
        "connection.dns-over-tls",
        "yes",
        "ipv4.ignore-auto-dns",
        "yes",
        "ipv6.ignore-auto-dns",
        "yes",
        "ipv4.dns",
        dns4,
        "ipv4.dns-search",
        "~.",
        "ipv6.dns",
        dns6,
        "ipv6.dns-search",
        "~.",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// nftables ruleset that drops outbound plaintext DNS (everything except the
/// loopback stub and the loopback interface).
pub fn nft_ruleset() -> &'static str {
    "table inet dns_leak_guard {\n\
     \x20   chain output {\n\
     \x20       type filter hook output priority filter; policy accept;\n\
     \x20       oifname \"lo\" accept\n\
     \x20       ip daddr 127.0.0.0/8 accept\n\
     \x20       ip6 daddr ::1 accept\n\
     \x20       udp dport 53 drop\n\
     \x20       tcp dport 53 drop\n\
     \x20   }\n\
     }\n"
}

pub fn leak_guard_unit() -> String {
    format!(
        "[Unit]\n\
         Description=Wayne's DNS plaintext leak guard (block outbound port 53)\n\
         After=network-pre.target\n\
         Wants=network-pre.target\n\
         Before=network.target\n\n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         ExecStart=/usr/bin/nft -f {NFT_FILE}\n\
         ExecStop=/usr/bin/nft delete table inet dns_leak_guard\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

// ---------------------------------------------------------------------------
// Privileged execution (runs as root, launched via pkexec)
// ---------------------------------------------------------------------------

pub fn apply_plan(plan: &ApplyPlan) -> i32 {
    let dns_line = plan.dns_line();

    if fs::create_dir_all("/etc/systemd/resolved.conf.d").is_err() {
        eprintln!("failed to create /etc/systemd/resolved.conf.d");
        return 1;
    }
    if write_file(RESOLVED_DROPIN, resolved_dropin(&dns_line).as_bytes()).is_err() {
        eprintln!("failed to write {RESOLVED_DROPIN}");
        return 1;
    }

    // Save originals exactly once. If a state file already exists we keep the
    // first-seen originals so pressing Apply again can't record the
    // already-encrypted settings as the thing to revert to.
    let existing = fs::read_to_string(STATE_FILE).unwrap_or_default();
    let mut known: Vec<String> = existing
        .lines()
        .filter_map(|l| l.split('|').next().map(str::to_string))
        .collect();
    for uuid in &plan.conns {
        if known.iter().any(|k| k == uuid) {
            continue;
        }
        let name = cmd_stdout(
            "nmcli",
            &["-g", "connection.id", "connection", "show", uuid],
        );
        let g = |k: &str| cmd_stdout("nmcli", &["-g", k, "connection", "show", uuid]);
        let line = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            uuid,
            name.trim(),
            g("connection.dns-over-tls").trim(),
            g("ipv4.ignore-auto-dns").trim(),
            g("ipv4.dns").trim(),
            g("ipv4.dns-search").trim(),
            g("ipv6.ignore-auto-dns").trim(),
            g("ipv6.dns").trim(),
            g("ipv6.dns-search").trim(),
        );
        append_file(STATE_FILE, format!("{line}\n").as_bytes());
        known.push(uuid.clone());
    }

    let dns4 = plan.dns4.join(" ");
    let dns6 = plan.dns6.join(" ");
    let mut failures = 0;
    for uuid in &plan.conns {
        let args = nmcli_modify_args(uuid, &dns4, &dns6);
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match Command::new("nmcli").args(&refs).status() {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!(
                    "nmcli modify failed for {uuid} (exit {})",
                    s.code().unwrap_or(-1)
                );
                failures += 1;
            }
            Err(e) => {
                eprintln!("nmcli modify failed for {uuid}: {e}");
                failures += 1;
            }
        }
    }

    // Reload resolved so it picks up the new drop-in.
    let _ = Command::new("systemctl")
        .args(["restart", "systemd-resolved"])
        .status();

    // Push the new per-connection DNS onto the live links.
    reapply_active_links();

    // Drop answers cached from the old (possibly plaintext) resolvers.
    let _ = Command::new("resolvectl").args(["flush-caches"]).status();

    if plan.firewall {
        apply_firewall();
    }

    if failures > 0 {
        eprintln!("{failures} connection profile(s) could not be updated");
        return 1;
    }
    0
}

pub fn revert() -> i32 {
    if Path::new(STATE_FILE).exists() {
        if let Ok(mut f) = File::open(STATE_FILE) {
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            for line in buf.lines() {
                let p: Vec<&str> = line.split('|').collect();
                if p.len() < 9 {
                    continue;
                }
                let dot = normalize_dns_over_tls(p[2]);
                let args = [
                    "connection",
                    "modify",
                    p[0],
                    "connection.dns-over-tls",
                    dot,
                    "ipv4.ignore-auto-dns",
                    p[3],
                    "ipv4.dns",
                    p[4],
                    "ipv4.dns-search",
                    p[5],
                    "ipv6.ignore-auto-dns",
                    p[6],
                    "ipv6.dns",
                    p[7],
                    "ipv6.dns-search",
                    p[8],
                ];
                let _ = Command::new("nmcli").args(args).status();
            }
        }
        let _ = fs::remove_file(STATE_FILE);
    } else {
        for uuid in list_conns() {
            let args = [
                "connection",
                "modify",
                uuid.as_str(),
                "connection.dns-over-tls",
                "default",
                "ipv4.ignore-auto-dns",
                "no",
                "ipv4.dns",
                "",
                "ipv4.dns-search",
                "",
                "ipv6.ignore-auto-dns",
                "no",
                "ipv6.dns",
                "",
                "ipv6.dns-search",
                "",
            ];
            let _ = Command::new("nmcli").args(args).status();
        }
    }

    let _ = fs::remove_file(RESOLVED_DROPIN);
    let _ = Command::new("systemctl")
        .args(["restart", "systemd-resolved"])
        .status();
    remove_firewall();
    reapply_active_links();
    let _ = Command::new("resolvectl").args(["flush-caches"]).status();
    0
}

/// Map an `nmcli -g connection.dns-over-tls` value back to something
/// `nmcli connection modify` accepts. Unset shows up as `-1`; empty lists too.
fn normalize_dns_over_tls(v: &str) -> &str {
    if v.is_empty() || v == "-1" || v.contains("default") {
        "default"
    } else {
        v
    }
}

fn write_file(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)
}
fn append_file(path: &str, bytes: &[u8]) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(bytes);
    }
}
fn cmd_stdout(cmd: &str, args: &[&str]) -> String {
    match Command::new(cmd).args(args).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    }
}
/// Parse `nmcli -t -f UUID,TYPE,DEVICE connection show --active` output into
/// (uuid, device) pairs for wired/wifi links.
/// Field order is UUID, TYPE, DEVICE — so the type is index 1 and the device index 2.
fn parse_active_conns(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split(':').collect();
            if p.len() >= 3 && (p[1] == "802-11-wireless" || p[1] == "802-3-ethernet") {
                Some((p[0].to_string(), p[2].to_string()))
            } else {
                None
            }
        })
        .collect()
}

fn active_conns() -> Vec<(String, String)> {
    parse_active_conns(&cmd_stdout(
        "nmcli",
        &[
            "-t",
            "-f",
            "UUID,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ],
    ))
}

/// Apply the (already-saved) connection profiles to the running devices without
/// a full reconnect. Falls back to `nmcli connection up` on older NM.
fn reapply_active_links() {
    for (uuid, dev) in active_conns() {
        let ok = Command::new("nmcli")
            .args(["device", "reapply", &dev])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = Command::new("nmcli")
                .args(["connection", "up", &uuid])
                .status();
        }
    }
}
fn list_conns() -> Vec<String> {
    let out = cmd_stdout("nmcli", &["-t", "-f", "UUID,TYPE", "connection", "show"]);
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split(':').collect();
            (p.len() >= 2 && (p[1] == "802-11-wireless" || p[1] == "802-3-ethernet"))
                .then(|| p[0].to_string())
        })
        .collect()
}

fn apply_firewall() {
    let _ = write_file(NFT_FILE, nft_ruleset().as_bytes());
    let _ = write_file(NFT_UNIT, leak_guard_unit().as_bytes());
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "waynes-dns-leak-guard.service"])
        .status();
}
fn remove_firewall() {
    let _ = Command::new("systemctl")
        .args(["disable", "--now", "waynes-dns-leak-guard.service"])
        .status();
    let _ = fs::remove_file(NFT_UNIT);
    let _ = fs::remove_file(NFT_FILE);
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_line_joins_v4_and_v6() {
        let p = ApplyPlan {
            dns4: vec!["1.1.1.1#cloudflare-dns.com".into()],
            dns6: vec!["2606:4700:4700::1111#cloudflare-dns.com".into()],
            ..Default::default()
        };
        assert_eq!(
            p.dns_line(),
            "1.1.1.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com"
        );
    }

    #[test]
    fn dns_line_handles_v4_only() {
        let p = ApplyPlan {
            dns4: vec!["9.9.9.9#dns.quad9.net".into()],
            dns6: vec![],
            ..Default::default()
        };
        assert_eq!(p.dns_line(), "9.9.9.9#dns.quad9.net");
    }

    #[test]
    fn dropin_enforces_tls_without_fallback() {
        let s = resolved_dropin("1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com");
        assert!(s.contains("DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com"));
        assert!(s.contains("FallbackDNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com"));
        assert!(
            s.contains("DNSOverTLS=yes"),
            "must enforce, not opportunistic"
        );
        assert!(!s.contains("opportunistic"));
        assert!(s.contains("Domains=~."));
    }

    #[test]
    fn nmcli_args_ignore_dhcp_and_force_tls() {
        let a = nmcli_modify_args("uuid-1", "1.1.1.1#cloudflare-dns.com", "");
        let joined = a.join(" ");
        assert!(joined.contains("connection modify uuid-1"));
        assert!(joined.contains("connection.dns-over-tls yes"));
        assert!(joined.contains("ipv4.ignore-auto-dns yes"));
        assert!(joined.contains("ipv6.ignore-auto-dns yes"));
        assert!(joined.contains("ipv4.dns 1.1.1.1#cloudflare-dns.com"));
        assert!(joined.contains("ipv4.dns-search ~."));
    }

    #[test]
    fn nft_blocks_plaintext_dns_but_allows_loopback() {
        let s = nft_ruleset();
        assert!(s.contains("udp dport 53 drop"));
        assert!(s.contains("tcp dport 53 drop"));
        assert!(s.contains("oifname \"lo\" accept"));
    }

    #[test]
    fn unit_loads_nft_ruleset() {
        assert!(
            leak_guard_unit().contains("ExecStart=/usr/bin/nft -f /etc/waynes-dns-leak-guard.nft")
        );
    }

    #[test]
    fn dns_over_tls_unset_normalizes_to_default() {
        assert_eq!(normalize_dns_over_tls("-1"), "default");
        assert_eq!(normalize_dns_over_tls(""), "default");
        assert_eq!(normalize_dns_over_tls("-1 (default)"), "default");
        assert_eq!(normalize_dns_over_tls("yes"), "yes");
        assert_eq!(normalize_dns_over_tls("opportunistic"), "opportunistic");
    }

    #[test]
    fn parse_active_conns_uses_type_at_index_one() {
        // Exact shape of `nmcli -t -f UUID,TYPE,DEVICE connection show --active`.
        let sample = "958d4d2f-932a-4346-9d5a-a61ef5b60291:802-11-wireless:wlan0\n\
                      9f3bfb73-81c7-4ed9-b2db-4b2ed0be4975:loopback:lo\n\
                      f012d281-5c89-3e3f-a655-8df8e5c90c1d:802-3-ethernet:enp4s0";
        let parsed = parse_active_conns(sample);
        assert_eq!(
            parsed,
            vec![
                (
                    "958d4d2f-932a-4346-9d5a-a61ef5b60291".to_string(),
                    "wlan0".to_string()
                ),
                (
                    "f012d281-5c89-3e3f-a655-8df8e5c90c1d".to_string(),
                    "enp4s0".to_string()
                ),
            ]
        );
    }
}
