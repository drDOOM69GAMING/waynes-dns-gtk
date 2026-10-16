mod app;
mod leak;
mod privileged;
mod resolvers;
mod speedtest;
mod system;

use gtk4::prelude::*;
use std::env;
use std::process::exit;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--help" | "-h" => {
                print_help();
                exit(0);
            }
            "--revert-privileged" => {
                exit(privileged::revert());
            }
            "--apply-privileged" => {
                // args: --apply-privileged --resolver X --dns4 "a b" --dns6 "c d" --conns "u1 u2" --firewall yes/no
                let mut plan = privileged::ApplyPlan {
                    resolver: "cloudflare".to_string(),
                    dns4: vec![],
                    dns6: vec![],
                    conns: vec![],
                    firewall: false,
                    apply_all: false,
                };
                let mut i = 2;
                while i < args.len() {
                    match args[i].as_str() {
                        "--resolver" => {
                            i += 1;
                            if i < args.len() {
                                plan.resolver = args[i].clone();
                            }
                        }
                        "--dns4" => {
                            i += 1;
                            if i < args.len() {
                                for s in args[i].split_whitespace() {
                                    plan.dns4.push(s.to_string());
                                }
                            }
                        }
                        "--dns6" => {
                            i += 1;
                            if i < args.len() {
                                for s in args[i].split_whitespace() {
                                    plan.dns6.push(s.to_string());
                                }
                            }
                        }
                        "--conns" => {
                            i += 1;
                            if i < args.len() {
                                for s in args[i].split_whitespace() {
                                    plan.conns.push(s.to_string());
                                }
                            }
                        }
                        "--firewall" => {
                            i += 1;
                            if i < args.len() && args[i] == "yes" {
                                plan.firewall = true;
                            }
                        }
                        "--all" => {
                            plan.apply_all = true;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                exit(privileged::apply_plan(&plan));
            }
            "--status" => {
                println!("{}", app::status_text());
                exit(0);
            }
            "--verify" => {
                for l in app::verify_lines() {
                    println!("{l}");
                }
                exit(0);
            }
            "--leak" => {
                let (key, auto) = match args.get(2) {
                    Some(k) => (k.clone(), false),
                    None => match resolvers::detect_active_provider() {
                        Some(k) => (k, true),
                        None => ("cloudflare".to_string(), false),
                    },
                };
                let label = resolvers::find_provider(&key)
                    .map(|p| p.label.to_string())
                    .unwrap_or_else(|| key.clone());
                if auto {
                    println!("(provider auto-detected from the live DNS config)\n");
                }
                println!("DNS leak test (expecting provider: {label})\n");
                let checks = leak::leak_test(&key);
                for c in &checks {
                    println!("{}", c.line());
                }
                let worst = leak::worst(&checks);
                println!("\nResult: {}", worst.label());
                exit(if worst == leak::Severity::Leak { 1 } else { 0 });
            }
            "--leak-selftest" => {
                println!("DNS leak detector self-test (negative control)\n");
                let c = leak::detector_selftest();
                println!("{}", c.line());
                println!(
                    "\n{}\n",
                    if c.severity == leak::Severity::Ok {
                        "PASS — the detector can see plaintext DNS, so a clean result is meaningful."
                    } else {
                        "INCONCLUSIVE — could not exercise the detector."
                    }
                );
                exit(if c.severity == leak::Severity::Ok {
                    0
                } else {
                    1
                });
            }
            "--speedtest" => {
                let secs = args
                    .get(2)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(25);
                let opts = speedtest::SpeedOptions {
                    per_phase_secs: secs,
                };
                println!("Connection speed test\n");
                let stop = std::sync::atomic::AtomicBool::new(false);
                let mut progress = |line: String| println!("{line}");
                match speedtest::run_speed_test(&opts, &mut progress, &stop) {
                    Ok(r) => {
                        println!("\nSource: {}", r.source);
                        println!("Result: {}", r.summary());
                        println!(
                            "(downloaded {:.1} MB / {:.1} MiB in {:.0}s, uploaded {:.1} MB / {:.1} MiB in {:.0}s)",
                            r.downloaded_bytes as f64 / 1_000_000.0,
                            r.downloaded_bytes as f64 / 1_048_576.0,
                            r.download_secs,
                            r.uploaded_bytes as f64 / 1_000_000.0,
                            r.uploaded_bytes as f64 / 1_048_576.0,
                            r.upload_secs
                        );
                        exit(0);
                    }
                    Err(e) => {
                        eprintln!("\nSpeed test failed: {e}");
                        exit(1);
                    }
                }
            }
            "--print-config" => {
                let key = args
                    .get(2)
                    .cloned()
                    .unwrap_or_else(|| "cloudflare".to_string());
                let prov = resolvers::find_provider(&key).unwrap_or_else(|| {
                    eprintln!("unknown provider: {key}");
                    exit(2);
                });
                let dns4 = prov
                    .v4
                    .iter()
                    .map(|s| format!("{}#{}", s.ip, s.sni))
                    .collect::<Vec<_>>()
                    .join(" ");
                let dns6 = prov
                    .v6
                    .iter()
                    .map(|s| format!("{}#{}", s.ip, s.sni))
                    .collect::<Vec<_>>()
                    .join(" ");
                let line = if dns6.is_empty() {
                    dns4.clone()
                } else {
                    format!("{dns4} {dns6}")
                };
                println!("# Provider: {}\n", prov.label);
                println!(
                    "# Families: IPv4 {} server(s), IPv6 {} server(s)",
                    prov.v4.len(),
                    prov.v6.len()
                );
                println!("# {}", privileged::RESOLVED_DROPIN);
                print!("{}", privileged::resolved_dropin(&line));
                println!("\n# NetworkManager args per connection (example UUID):");
                println!(
                    "nmcli {}",
                    privileged::nmcli_modify_args("<uuid>", &dns4, &dns6).join(" ")
                );
                println!("\n# Plaintext leak guard ({})", privileged::NFT_FILE);
                print!("{}", privileged::nft_ruleset());
                exit(0);
            }
            "--probe" => {
                let key = args
                    .get(2)
                    .cloned()
                    .unwrap_or_else(|| "cloudflare".to_string());
                let prov = resolvers::find_provider(&key).unwrap_or_else(|| {
                    eprintln!("unknown provider: {key}");
                    exit(2);
                });
                println!("Provider: {}", prov.label);
                let v4 = resolvers::probe_servers(&prov.v4, std::time::Duration::from_secs(5));
                let v6 = resolvers::probe_servers(&prov.v6, std::time::Duration::from_secs(5));
                for (label, probes) in [("IPv4", &v4), ("IPv6", &v6)] {
                    let reachable = probes.iter().filter(|p| p.result.is_ok()).count();
                    println!("{label}: {reachable}/{} reachable", probes.len());
                    for p in probes.iter() {
                        match &p.result {
                            Ok(()) => println!("   [OK  ] {} ({})", p.server.ip, p.server.sni),
                            Err(reason) => {
                                println!("   [DEAD] {} ({}): {reason}", p.server.ip, p.server.sni);
                            }
                        }
                    }
                }
                exit(0);
            }
            _ => {}
        }
    }
    let app = gtk4::Application::builder()
        .application_id("net.wayneamd.dns-gtk")
        .build();
    app.connect_activate(|app| {
        if let Some(existing) = app.active_window() {
            existing.present();
            return;
        }
        let ui = app::build_ui(app);
        ui.window.present();
    });
    app.run();
}

fn print_help() {
    println!(
        r#"Wayne's DNS Encryptor — enforce DNS-over-TLS and verify there are no leaks.

USAGE:
    waynes-dns-gtk [OPTION] [PROVIDER]

With no options, launches the GTK4 desktop interface.

OPTIONS:
    -h, --help              Show this help.
        --status            Print current DNS/DoT status for the active link.
        --verify            Run post-apply verification checks.
        --leak [PROVIDER]   Run the DNS leak test (config + live sockets + egress
                            identity). Exits non-zero if a leak is found.
        --leak-selftest     Negative control: confirm the leak detector can
                            actually see a plaintext DNS socket.
        --speedtest [SECS]  Latency/download/upload test. Uses the official Ookla
                            `speedtest` CLI when installed (so results match
                            speedtest.net); otherwise a built-in sustained
                            Cloudflare test runs for SECS per direction
                            (default 25, ~50s). Set WAYNES_DNS_SPEEDTEST=builtin
                            to force the built-in test.
        --probe [PROVIDER]  Test which DNS-over-TLS servers are reachable on 853.
        --print-config [P]  Print the resolved.conf drop-in, nmcli args and the
                            nftables leak-guard ruleset without applying anything.
        --apply-privileged  (internal) apply configuration; run as root via pkexec.
        --revert-privileged (internal) restore the saved configuration.

PROVIDER defaults to "cloudflare". Other options include google, quad9.

The leak test reports OK / WARN / LEAK for:
    * /etc/resolv.conf using the systemd-resolved stub
    * DNS-over-TLS enforced on the active link
    * the router/gateway not being used as a resolver
    * no live plaintext (port 53) sockets
    * the encrypted (port 853) socket actually carrying the lookups
    * what resolver the outside world actually sees (egress identity)
"#
    );
}
