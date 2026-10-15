use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    ApplicationWindow, Box, Button, DropDown, Label, Orientation, PolicyType, ScrolledWindow,
    Switch, TextView,
};

use crate::leak::{self, Severity};
use crate::resolvers::{all_providers, filter_reachable, DnsServer};
use crate::system::{default_route, field, link_status, run_cmd, run_privileged_self};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

enum Msg {
    Log(String),
    /// (tag, text) — tag is one of `ok`/`warn`/`leak`/`info`.
    Tagged(String, String),
    RefreshStatus,
    /// Speed test running state changed (drives the button label).
    SpeedUi(bool),
    Done,
}

pub struct App {
    pub window: ApplicationWindow,
}

fn append_log(buffer: &gtk4::TextBuffer, msg: &str) {
    append_tagged(buffer, "info", msg);
}

/// Append a line and colour it by severity tag (`info`, `ok`, `warn`, `leak`).
fn append_tagged(buffer: &gtk4::TextBuffer, tag: &str, msg: &str) {
    let start = buffer.end_iter();
    let mut end = buffer.end_iter();
    buffer.insert(&mut end, &format!("{}\n", msg));
    if buffer.tag_table().lookup(tag).is_some() {
        buffer.apply_tag_by_name(tag, &start, &end);
    }
}

/// Read the live DNS status from systemd-resolved for the default-route link.
pub fn status_text() -> String {
    if run_cmd("resolvectl", &["--version"]).code != 0 {
        return "systemd-resolved not available (resolvectl missing)".to_string();
    }
    let (iface, gw) = default_route();
    if iface.is_empty() {
        return "No default-route interface found".to_string();
    }
    let block = link_status(&iface);

    let mut parts: Vec<String> = Vec::new();
    match field(&block, "Protocols:") {
        Some(p) if p.contains("+DNSOverTLS") => parts.push("DoT: ENFORCED".to_string()),
        Some(_) => parts.push("DoT: off (plaintext)".to_string()),
        None => parts.push("DoT: unknown".to_string()),
    }
    if let Some(cur) = field(&block, "Current DNS Server:") {
        if !cur.is_empty() {
            parts.push(format!("DNS: {cur}"));
        }
    }
    if !gw.is_empty() {
        let servers = field(&block, "DNS Servers:").unwrap_or("");
        if servers
            .split_whitespace()
            .any(|s| s.split('#').next() == Some(gw.as_str()))
        {
            parts.push(format!("LEAK → router {gw}"));
        } else {
            parts.push("no router leak".to_string());
        }
    }
    parts.push(format!("link {iface}"));
    parts.join("   ·   ")
}

fn wired_wifi_uuids() -> Vec<String> {
    let out = run_cmd("nmcli", &["-t", "-f", "UUID,TYPE", "connection", "show"]);
    out.stdout
        .lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split(':').collect();
            if p.len() >= 2 && (p[1] == "802-11-wireless" || p[1] == "802-3-ethernet") {
                Some(p[0].to_string())
            } else {
                None
            }
        })
        .collect()
}

fn active_uuids() -> Vec<String> {
    let out = run_cmd(
        "nmcli",
        &[
            "-t",
            "-f",
            "UUID,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ],
    );
    out.stdout
        .lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split(':').collect();
            // Fields are UUID, TYPE, DEVICE — the type is at index 1.
            if p.len() >= 3 && (p[1] == "802-11-wireless" || p[1] == "802-3-ethernet") {
                Some(p[0].to_string())
            } else {
                None
            }
        })
        .collect()
}

pub fn build_ui(app: &gtk4::Application) -> App {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Wayne's DNS Encryptor")
        .default_width(780)
        .default_height(560)
        .build();

    let root = Box::new(Orientation::Vertical, 12);
    root.set_margin_top(14);
    root.set_margin_bottom(14);
    root.set_margin_start(14);
    root.set_margin_end(14);

    let title = Label::new(Some("Encrypted DNS (DNS-over-TLS)"));
    title.set_xalign(0.0);
    title.add_css_class("title-2");

    let status_label = Label::new(Some(&status_text()));
    status_label.set_xalign(0.0);
    status_label.set_wrap(true);

    // --- provider row ---
    let providers = all_providers();
    let keys: Vec<String> = providers.iter().map(|p| p.key.to_string()).collect();
    let labels: Vec<&str> = providers.iter().map(|p| p.label).collect();

    let prow = Box::new(Orientation::Horizontal, 10);
    prow.append(&Label::new(Some("Provider:")));
    let dropdown = DropDown::from_strings(&labels);
    dropdown.set_selected(0);
    prow.append(&dropdown);

    // --- options row ---
    let orow = Box::new(Orientation::Horizontal, 10);
    let sw_fire = Switch::new();
    let sw_all = Switch::new();
    orow.append(&Label::new(Some("Block plaintext DNS (port 53 firewall)")));
    orow.append(&sw_fire);
    let spacer = Box::new(Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    orow.append(&spacer);
    orow.append(&Label::new(Some("Apply to all wired/wifi")));
    orow.append(&sw_all);

    // --- buttons ---
    let brow = Box::new(Orientation::Horizontal, 10);
    let btn_probe = Button::with_label("Test reachability");
    let btn_leak = Button::with_label("Test DNS leaks");
    let btn_speed = Button::with_label("Speed test");
    let btn_apply = Button::with_label("Apply & Encrypt");
    btn_apply.add_css_class("suggested-action");
    let btn_revert = Button::with_label("Revert");
    let spinner = gtk4::Spinner::new();
    brow.append(&btn_probe);
    brow.append(&btn_leak);
    brow.append(&btn_speed);
    brow.append(&btn_apply);
    brow.append(&btn_revert);
    brow.append(&spinner);

    // --- log view ---
    let log_view = TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::WordChar)
        .build();
    let log_buf = log_view.buffer();
    {
        let ok = String::from("#26a269");
        let warn = String::from("#c64600");
        let leak = String::from("#c01c28");
        log_buf.create_tag(Some("ok"), &[("foreground", &ok)]);
        log_buf.create_tag(Some("warn"), &[("foreground", &warn)]);
        log_buf.create_tag(Some("leak"), &[("foreground", &leak), ("weight", &700i32)]);
    }
    let scroll = ScrolledWindow::builder()
        .child(&log_view)
        .vexpand(true)
        .hscrollbar_policy(PolicyType::Never)
        .build();

    root.append(&title);
    root.append(&status_label);
    root.append(&prow);
    root.append(&orow);
    root.append(&brow);
    root.append(&scroll);
    window.set_child(Some(&root));

    // --- current selections (shared) ---
    let provider = Rc::new(RefCell::new("cloudflare".to_string()));
    let firewall = Rc::new(RefCell::new(false));
    let all_conns = Rc::new(RefCell::new(false));

    dropdown.connect_selected_notify({
        let provider = provider.clone();
        let keys = keys.clone();
        move |d| {
            let idx = d.selected() as usize;
            if let Some(k) = keys.get(idx) {
                *provider.borrow_mut() = k.clone();
            }
        }
    });
    sw_fire.connect_active_notify({
        let firewall = firewall.clone();
        move |s| *firewall.borrow_mut() = s.is_active()
    });
    sw_all.connect_active_notify({
        let all_conns = all_conns.clone();
        move |s| *all_conns.borrow_mut() = s.is_active()
    });

    // --- worker -> UI message pump ---
    let (tx, rx): (mpsc::Sender<Msg>, Receiver<Msg>) = mpsc::channel();
    let rx = Rc::new(RefCell::new(rx));

    {
        let log_buf = log_buf.clone();
        let status_label = status_label.clone();
        let spinner = spinner.clone();
        let btn_probe = btn_probe.clone();
        let btn_leak = btn_leak.clone();
        let btn_speed = btn_speed.clone();
        let btn_apply = btn_apply.clone();
        let btn_revert = btn_revert.clone();
        glib::timeout_add_local(Duration::from_millis(80), move || {
            loop {
                let msg = rx.borrow().try_recv();
                match msg {
                    Ok(Msg::Log(m)) => append_log(&log_buf, &m),
                    Ok(Msg::Tagged(t, m)) => append_tagged(&log_buf, &t, &m),
                    Ok(Msg::RefreshStatus) => status_label.set_text(&status_text()),
                    Ok(Msg::SpeedUi(running)) => {
                        btn_speed.set_label(if running {
                            "Stop speed test"
                        } else {
                            "Speed test"
                        });
                        btn_speed.set_sensitive(true);
                    }
                    Ok(Msg::Done) => {
                        spinner.stop();
                        btn_probe.set_sensitive(true);
                        btn_leak.set_sensitive(true);
                        btn_speed.set_sensitive(true);
                        btn_apply.set_sensitive(true);
                        btn_revert.set_sensitive(true);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }
            glib::ControlFlow::Continue
        });
    }

    let started = |spinner: &gtk4::Spinner,
                   btn_probe: &Button,
                   btn_leak: &Button,
                   btn_speed: &Button,
                   btn_apply: &Button,
                   btn_revert: &Button| {
        spinner.start();
        btn_probe.set_sensitive(false);
        btn_leak.set_sensitive(false);
        btn_speed.set_sensitive(false);
        btn_apply.set_sensitive(false);
        btn_revert.set_sensitive(false);
    };

    // --- Test DNS leaks ---
    btn_leak.connect_clicked({
        let tx = tx.clone();
        let provider = provider.clone();
        let dropdown = dropdown.clone();
        let keys = keys.clone();
        let spinner = spinner.clone();
        let btn_probe = btn_probe.clone();
        let btn_leak = btn_leak.clone();
        let btn_speed = btn_speed.clone();
        let btn_apply = btn_apply.clone();
        let btn_revert = btn_revert.clone();
        move |_| {
            // Auto-switch the Provider selector to the DNS that is actually in
            // use, so the leak test compares against the right provider.
            if let Some(detected) = crate::resolvers::detect_active_provider() {
                if let Some(idx) = keys.iter().position(|k| *k == detected) {
                    let already = dropdown.selected() as usize == idx;
                    dropdown.set_selected(idx as u32);
                    *provider.borrow_mut() = detected.clone();
                    if !already {
                        let label = all_providers()
                            .into_iter()
                            .find(|p| p.key == detected)
                            .map(|p| p.label.to_string())
                            .unwrap_or_else(|| detected.clone());
                        let _ = tx.send(Msg::Log(format!(
                            "Detected active DNS provider: {label} — switching."
                        )));
                    }
                }
            }
            let key = provider.borrow().clone();
            started(
                &spinner,
                &btn_probe,
                &btn_leak,
                &btn_speed,
                &btn_apply,
                &btn_revert,
            );
            let tx = tx.clone();
            thread::spawn(move || {
                let label = all_providers()
                    .into_iter()
                    .find(|p| p.key == key)
                    .map(|p| p.label.to_string())
                    .unwrap_or_else(|| key.clone());
                let _ = tx.send(Msg::Log(format!("DNS leak test (expecting {label}) ...")));
                let checks = leak::leak_test(&key);
                for c in &checks {
                    let _ = tx.send(Msg::Tagged(c.severity.tag().to_string(), c.line()));
                }
                let worst = leak::worst(&checks);
                let summary = match worst {
                    Severity::Ok => "No leaks detected.".to_string(),
                    Severity::Warn => "No hard leak, but something needs attention.".to_string(),
                    Severity::Leak => "DNS LEAK DETECTED.".to_string(),
                };
                let _ = tx.send(Msg::Tagged(
                    worst.tag().to_string(),
                    format!("Result: {summary}"),
                ));
                let _ = tx.send(Msg::Done);
            });
        }
    });

    // --- Test reachability ---
    btn_probe.connect_clicked({
        let tx = tx.clone();
        let provider = provider.clone();
        let spinner = spinner.clone();
        let btn_probe = btn_probe.clone();
        let btn_leak = btn_leak.clone();
        let btn_speed = btn_speed.clone();
        let btn_apply = btn_apply.clone();
        let btn_revert = btn_revert.clone();
        move |_| {
            let key = provider.borrow().clone();
            started(
                &spinner,
                &btn_probe,
                &btn_leak,
                &btn_speed,
                &btn_apply,
                &btn_revert,
            );
            let tx = tx.clone();
            thread::spawn(move || {
                let prov = all_providers()
                    .into_iter()
                    .find(|p| p.key == key)
                    .unwrap_or_else(|| all_providers()[0].clone());
                let _ = tx.send(Msg::Log(format!("Testing DoT/853 for {} ...", prov.label)));
                let v4 = filter_reachable(&prov.v4, PROBE_TIMEOUT);
                let v6 = filter_reachable(&prov.v6, PROBE_TIMEOUT);
                report_group(&tx, "IPv4", &prov.v4, &v4);
                report_group(&tx, "IPv6", &prov.v6, &v6);
                let _ = tx.send(Msg::Done);
            });
        }
    });

    // --- Speed test (sustained, cancellable) ---
    let speed_running: Arc<Mutex<Option<Arc<AtomicBool>>>> = Arc::new(Mutex::new(None));
    btn_speed.connect_clicked({
        let tx = tx.clone();
        let spinner = spinner.clone();
        let btn_probe = btn_probe.clone();
        let btn_leak = btn_leak.clone();
        let btn_speed = btn_speed.clone();
        let btn_apply = btn_apply.clone();
        let btn_revert = btn_revert.clone();
        let speed_running = speed_running.clone();
        move |_| {
            // A click while a test is running means "stop".
            if let Some(flag) = speed_running.lock().unwrap().as_ref() {
                flag.store(true, Ordering::SeqCst);
                let _ = tx.send(Msg::Log("Stopping speed test...".into()));
                return;
            }

            let stop = Arc::new(AtomicBool::new(false));
            *speed_running.lock().unwrap() = Some(stop.clone());

            started(
                &spinner,
                &btn_probe,
                &btn_leak,
                &btn_speed,
                &btn_apply,
                &btn_revert,
            );
            // Keep this button live so it can cancel, and relabel it.
            btn_speed.set_label("Stop speed test");
            btn_speed.set_sensitive(true);

            let tx = tx.clone();
            let running = speed_running.clone();
            thread::spawn(move || {
                let opts = crate::speedtest::SpeedOptions::default();
                let _ = tx.send(Msg::Log("Running speed test…".to_string()));
                let mut progress = |line: String| {
                    let _ = tx.send(Msg::Log(line));
                };
                match crate::speedtest::run_speed_test(&opts, &mut progress, &stop) {
                    Ok(r) => {
                        let _ = tx.send(Msg::Log(format!("Source: {}", r.source)));
                        let _ = tx.send(Msg::Tagged("ok".to_string(), r.summary()));
                    }
                    Err(e) if e == "cancelled" => {
                        let _ = tx.send(Msg::Log("Speed test stopped.".to_string()));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Tagged(
                            "leak".to_string(),
                            format!("Speed test failed: {e}"),
                        ));
                    }
                }
                *running.lock().unwrap() = None;
                let _ = tx.send(Msg::SpeedUi(false));
                let _ = tx.send(Msg::Done);
            });
        }
    });

    // --- Apply ---
    btn_apply.connect_clicked({
        let tx = tx.clone();
        let provider = provider.clone();
        let firewall = firewall.clone();
        let all_conns = all_conns.clone();
        let spinner = spinner.clone();
        let btn_probe = btn_probe.clone();
        let btn_leak = btn_leak.clone();
        let btn_speed = btn_speed.clone();
        let btn_apply = btn_apply.clone();
        let btn_revert = btn_revert.clone();
        move |_| {
            let key = provider.borrow().clone();
            let fw = *firewall.borrow();
            let all = *all_conns.borrow();
            started(
                &spinner,
                &btn_probe,
                &btn_leak,
                &btn_speed,
                &btn_apply,
                &btn_revert,
            );
            let tx = tx.clone();
            thread::spawn(move || {
                let prov = all_providers()
                    .into_iter()
                    .find(|p| p.key == key)
                    .unwrap_or_else(|| all_providers()[0].clone());
                let _ = tx.send(Msg::Log(format!("Provider: {}", prov.label)));
                let _ = tx.send(Msg::Log("Checking which servers are reachable...".into()));
                let v4 = filter_reachable(&prov.v4, PROBE_TIMEOUT);
                let v6 = filter_reachable(&prov.v6, PROBE_TIMEOUT);

                if v4.is_empty() && v6.is_empty() {
                    let _ = tx.send(Msg::Log(
                        "ERROR: no reachable DNS-over-TLS server — nothing changed.".into(),
                    ));
                    let _ = tx.send(Msg::Done);
                    return;
                }
                report_group(&tx, "IPv4", &prov.v4, &v4);
                report_group(&tx, "IPv6", &prov.v6, &v6);

                let conns: Vec<String> = if all {
                    wired_wifi_uuids()
                } else {
                    let a = active_uuids();
                    if a.is_empty() {
                        wired_wifi_uuids()
                    } else {
                        a
                    }
                };
                if conns.is_empty() {
                    let _ = tx.send(Msg::Log(
                        "ERROR: no NetworkManager connection to configure.".into(),
                    ));
                    let _ = tx.send(Msg::Done);
                    return;
                }

                let dns4: Vec<String> = v4.iter().map(|s| format!("{}#{}", s.ip, s.sni)).collect();
                let dns6: Vec<String> = v6.iter().map(|s| format!("{}#{}", s.ip, s.sni)).collect();

                let mut args: Vec<String> = vec![
                    "--apply-privileged".into(),
                    "--resolver".into(),
                    prov.key.to_string(),
                    "--dns4".into(),
                    dns4.join(" "),
                    "--dns6".into(),
                    dns6.join(" "),
                    "--conns".into(),
                    conns.join(" "),
                ];
                if fw {
                    args.push("--firewall".into());
                    args.push("yes".into());
                }

                let _ = tx.send(Msg::Log(
                    "Requesting administrator rights (polkit prompt)...".into(),
                ));
                let res = run_privileged_self(&args);
                if res.code == 0 {
                    let _ = tx.send(Msg::Log("Applied DNS-over-TLS configuration.".into()));
                    let _ = tx.send(Msg::Log("Verifying...".into()));
                    for line in verify_lines() {
                        let _ = tx.send(Msg::Log(line));
                    }
                    let _ = tx.send(Msg::Log("Running DNS leak test...".into()));
                    let checks = leak::leak_test(prov.key);
                    for c in &checks {
                        let _ = tx.send(Msg::Tagged(c.severity.tag().to_string(), c.line()));
                    }
                    let _ = tx.send(Msg::Tagged(
                        leak::worst(&checks).tag().to_string(),
                        format!("Leak test result: {}", leak::worst(&checks).label()),
                    ));
                } else {
                    let _ = tx.send(Msg::Log(format!(
                        "Failed (exit {}). {}",
                        res.code,
                        res.stderr.trim()
                    )));
                }
                let _ = tx.send(Msg::RefreshStatus);
                let _ = tx.send(Msg::Done);
            });
        }
    });

    // --- Revert ---
    btn_revert.connect_clicked({
        let tx = tx.clone();
        let spinner = spinner.clone();
        let btn_probe = btn_probe.clone();
        let btn_leak = btn_leak.clone();
        let btn_speed = btn_speed.clone();
        let btn_apply = btn_apply.clone();
        let btn_revert = btn_revert.clone();
        move |_| {
            started(
                &spinner,
                &btn_probe,
                &btn_leak,
                &btn_speed,
                &btn_apply,
                &btn_revert,
            );
            let tx = tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Msg::Log(
                    "Reverting to previous DNS configuration...".into(),
                ));
                let args = vec!["--revert-privileged".to_string()];
                let res = run_privileged_self(&args);
                if res.code == 0 {
                    let _ = tx.send(Msg::Log("Reverted.".into()));
                } else {
                    let _ = tx.send(Msg::Log(format!("Revert failed (exit {}).", res.code)));
                }
                let _ = tx.send(Msg::RefreshStatus);
                let _ = tx.send(Msg::Done);
            });
        }
    });

    App { window }
}

fn report_group(tx: &mpsc::Sender<Msg>, label: &str, all: &[DnsServer], ok: &[DnsServer]) {
    let _ = tx.send(Msg::Log(format!(
        "{label}: {}/{} reachable",
        ok.len(),
        all.len()
    )));
    for s in all {
        let reachable = ok.iter().any(|o| o.ip == s.ip);
        let mark = if reachable { "OK  " } else { "DEAD" };
        let _ = tx.send(Msg::Log(format!("   [{mark}] {}  ({})", s.ip, s.sni)));
    }
}

/// Post-apply checks, mirroring the shell script's "no leak" verification.
pub fn verify_lines() -> Vec<String> {
    let mut out = Vec::new();
    let (iface, gw) = default_route();
    if iface.is_empty() {
        out.push("  [!!] no default-route interface".to_string());
        return out;
    }
    let block = link_status(&iface);

    match field(&block, "Protocols:") {
        Some(p) if p.contains("+DNSOverTLS") => {
            out.push("  [OK] DNS-over-TLS is enforced".to_string())
        }
        _ => out.push("  [!!] DNS-over-TLS not shown as enforced".to_string()),
    }

    let servers = field(&block, "DNS Servers:").unwrap_or("").to_string();
    if !gw.is_empty()
        && servers
            .split_whitespace()
            .any(|s| s.split('#').next() == Some(gw.as_str()))
    {
        out.push(format!("  [!!] LEAK: router DNS {gw} is still in use"));
    } else if !gw.is_empty() {
        out.push(format!("  [OK] router DNS {gw} is not used"));
    }
    out.push(format!(
        "  DNS servers: {}",
        if servers.is_empty() {
            "(none)"
        } else {
            &servers
        }
    ));

    if run_cmd("resolvectl", &["query", "--cache=no", "example.com"]).code == 0 {
        out.push("  [OK] name resolution works".to_string());
    } else {
        out.push("  [!!] name resolution FAILED".to_string());
    }
    out
}
