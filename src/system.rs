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
pub fn default_route() -> (String, String) {
    let out = run_cmd("ip", &["route", "show", "default"]).stdout;
    let first = out.lines().next().unwrap_or("");
    let toks: Vec<&str> = first.split_whitespace().collect();
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
    (iface, gw)
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
