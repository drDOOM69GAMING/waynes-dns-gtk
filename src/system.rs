use std::process::Command;

#[derive(Debug)]
pub struct CmdResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_cmd(cmd: &str, args: &[&str]) -> CmdResult {
    match Command::new(cmd).args(args).output() {
        Ok(o) => CmdResult {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).to_string(),
            stderr: String::from_utf8_lossy(&o.stderr).to_string(),
        },
        Err(e) => CmdResult {
            code: -2,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

/// Re-run this same binary through pkexec (polkit) so privileged steps get a
/// proper graphical authentication prompt.
pub fn run_privileged_self(args: &[String]) -> CmdResult {
    let exe = std::env::current_exe()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let mut full: Vec<String> = vec!["pkexec".to_string(), exe];
    full.extend(args.iter().cloned());
    let refs: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
    run_cmd(refs[0], &refs[1..])
}

/// Default-route interface and gateway (parsed from `ip route`).
///
/// Scans every line, not just the first, and tries IPv4 before IPv6, so a
/// leading non-default line (or an `ip` formatting quirk) cannot hide a valid
/// default route. Falls back to `ip route get`, which always names the egress
/// device, before giving up.
pub fn default_route() -> (String, String) {
    for family in ["-4", "-6"] {
        let out = run_cmd("ip", &[family, "route", "show", "default"]).stdout;
        if let Some(found) = parse_default_route(&out) {
            return found;
        }
    }
    // Last resort: ask the kernel which device/next-hop it would use.
    for probe in ["9.9.9.9", "1.1.1.1"] {
        let out = run_cmd("ip", &["route", "get", probe]).stdout;
        if let Some(found) = parse_default_route(&out) {
            return found;
        }
    }
    (String::new(), String::new())
}

/// Pull `dev <iface>` (and optional `via <gw>`) out of `ip` output.
///
/// Prefers a line that actually says `default` (as `ip route show default`
/// does); if none does, `ip route get` output is accepted as-is.
fn parse_default_route(out: &str) -> Option<(String, String)> {
    for require_default in [true, false] {
        for line in out.lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            if require_default && !toks.contains(&"default") {
                continue;
            }
            let mut iface = String::new();
            let mut gw = String::new();
            let mut i = 0;
            while i < toks.len() {
                match toks[i] {
                    "dev" if i + 1 < toks.len() => iface = toks[i + 1].to_string(),
                    "via" if i + 1 < toks.len() => gw = toks[i + 1].to_string(),
                    _ => {}
                }
                i += 1;
            }
            if !iface.is_empty() {
                return Some((iface, gw));
            }
        }
    }
    None
}

/// `resolvectl status <iface>` block for one link.
pub fn link_status(iface: &str) -> String {
    run_cmd("resolvectl", &["status", iface]).stdout
}

/// Extract the value after a label from a resolvectl block.
pub fn field<'a>(block: &'a str, label: &str) -> Option<&'a str> {
    block
        .lines()
        .find(|l| l.contains(label))
        .and_then(|l| l.split(label).nth(1))
        .map(|s| s.trim())
}

/// Like [`field`], but also joins any wrapped continuation lines.
///
/// `resolvectl` right-aligns the colon of each key and indents long values
/// under the first one, so a single logical field can span several lines:
///
/// ```text
///        DNS Servers: 9.9.9.9 149.112.112.112
///                     2620:fe::fe 2620:fe::9
///         DNS Domain: ~.
/// ```
///
/// Continuations are indented at least as far as the value; the next key is
/// not, which is where collection stops.
pub fn field_wrapped(block: &str, label: &str) -> Option<String> {
    let lines: Vec<&str> = block.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(pos) = line.find(label) else {
            continue;
        };
        let after = &line[pos + label.len()..];
        let value_col = pos + label.len() + (after.len() - after.trim_start().len());
        let mut value = after.trim().to_string();
        for cont in &lines[i + 1..] {
            if cont.trim().is_empty() {
                break;
            }
            let indent = cont.len() - cont.trim_start().len();
            if indent < value_col {
                break;
            }
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(cont.trim());
        }
        return Some(value);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{field_wrapped, parse_default_route};

    #[test]
    fn parses_ipv4_default() {
        let out = "default via 192.168.12.1 dev wlan0 proto dhcp src 192.168.12.234 metric 600\n";
        assert_eq!(
            parse_default_route(out),
            Some(("wlan0".to_string(), "192.168.12.1".to_string()))
        );
    }

    #[test]
    fn parses_ipv6_default() {
        let out = "default via fe80::1 dev wlan0 proto ra metric 600 pref medium\n";
        assert_eq!(
            parse_default_route(out),
            Some(("wlan0".to_string(), "fe80::1".to_string()))
        );
    }

    #[test]
    fn skips_leading_non_default_line() {
        // The real default is on the second line; the old code only read the first.
        let out = "192.168.12.0/24 dev wlan0 proto kernel scope link\ndefault via 192.168.12.1 dev wlan0\n";
        assert_eq!(
            parse_default_route(out),
            Some(("wlan0".to_string(), "192.168.12.1".to_string()))
        );
    }

    #[test]
    fn parses_route_get_output() {
        let out = "9.9.9.9 via 192.168.12.1 dev wlan0 src 192.168.12.234 uid 1000\n    cache\n";
        assert_eq!(
            parse_default_route(out),
            Some(("wlan0".to_string(), "192.168.12.1".to_string()))
        );
    }

    #[test]
    fn empty_output_returns_none() {
        assert_eq!(parse_default_route(""), None);
        assert_eq!(parse_default_route("\n\n"), None);
    }

    #[test]
    fn field_wrapped_joins_continuation_lines() {
        let block = concat!(
            "       DNS Servers: 9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net\n",
            "                    2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net\n",
            "        DNS Domain: ~.\n",
        );
        assert_eq!(
            field_wrapped(block, "DNS Servers:").as_deref(),
            Some(
                "9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net"
            )
        );
    }

    #[test]
    fn field_wrapped_handles_single_line() {
        let block = "  DNS Servers: 9.9.9.9 149.112.112.112\n  DNS Domain: ~.\n";
        assert_eq!(
            field_wrapped(block, "DNS Servers:").as_deref(),
            Some("9.9.9.9 149.112.112.112")
        );
    }
}
