# Wayne's DNS Encryptor (GTK4)

[![CI](https://github.com/drDOOM69GAMING/waynes-dns-gtk/actions/workflows/ci.yml/badge.svg)](https://github.com/drDOOM69GAMING/waynes-dns-gtk/actions/workflows/ci.yml)
[![OS: Linux](https://img.shields.io/badge/OS-Linux-1793D1?logo=linux&logoColor=white)](https://github.com/drDOOM69GAMING/waynes-dns-gtk)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![GTK: 4.24+](https://img.shields.io/badge/GTK-4.24%2B-7A5AF8?logo=gtk&logoColor=white)](https://gtk.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small native GTK4 app that turns on **DNS-over-TLS** for the active
NetworkManager connection(s), makes sure the router's DHCP-provided DNS is
*ignored*, and then lets you **prove there is no leak**, including a live
DNS leak test that samples actual sockets while generating traffic.

It talks to the system directly (`resolvectl`, `nmcli`, `nft`, `systemctl`)
rather than wrapping a shell script. The only privileged part is re-invoking
this same binary through `pkexec`, so you get a single graphical polkit prompt.

## Why

The usual "turn on DoT" tip sets `DNSOverTLS=opportunistic` and only writes a
global `resolved.conf`. In practice that:

- falls back to plaintext when a server doesn't speak TLS, and
- keeps using the router as a resolver on each link,

so lookups still leave the machine in the clear to `192.168.x.1`. This app
forces `DNSOverTLS=yes` per link, drops the router as a resolver, and gives you
a leak test to confirm it.

## Build

```sh
cargo build --release
```

Requires GTK **4.24+** development headers (`gtk4`) and a current Rust
toolchain. At runtime it drives `NetworkManager` (`nmcli`), `systemd-resolved`
(`resolvectl`) and `polkit`, plus `nftables` if you enable the optional
firewall.

## Run

```sh
./target/release/waynes-dns-gtk          # GUI
```

The GUI has these actions:

- **Test reachability**: does a real TLS handshake on port 853 for every
  server and reports which answered. Failures are explained in plain English
  with the address family (`no IPv6 route`, `no usable IPv6 source address`,
  `connection refused`, ...) and retried once. The result is advisory: a
  server that did not answer is still written to the config, so a temporary
  outage in one family does not drop that family's DNS. systemd-resolved fails
  over to the family that is up.
- **Speed test**: measures latency, download and upload speed. Prefers the
  official Ookla CLI when installed, so the numbers match speedtest.net (see
  below).
- **Apply & Encrypt**: asks polkit for rights once, then:
  1. writes a `systemd-resolved` drop-in with `DNSOverTLS=yes` (no fallback),
  2. sets every chosen DoT server, IPv4 and IPv6, on the connection(s) with
     `ipv4.ignore-auto-dns yes` / `ipv6.ignore-auto-dns yes`,
  3. optionally installs an `nftables` rule that blocks outbound port 53,
  4. verifies the result and automatically runs the **leak test**.
- **Test DNS leaks**: runs the leak test (see below) at any time. Before it
  runs, the **Provider** selector auto-switches to whatever DNS is actually in
  use (detected from the live `resolvectl` state), so the test compares against
  the right provider without you having to pick it.

## DNS leak test

The leak test reports **OK / WARN / LEAK** for six things, and exits non-zero
from the CLI if any check is a hard leak:

| Check | What it means |
| --- | --- |
| System resolver stub | `/etc/resolv.conf` points at `127.0.0.53` (systemd-resolved) |
| DNS-over-TLS enforced | the active link shows `+DNSOverTLS` |
| Router not used as resolver | the gateway is **not** among the link's DNS servers |
| No plaintext DNS sockets | no live outbound port-53 sockets |
| Encrypted transport in use | the port-853 socket actually carried the lookups |
| Upstream resolver identity | what resolver the outside world actually sees |

Three checks are worth calling out:

- **No plaintext DNS sockets** is not a passive `ss` sample. `systemd-resolved`
  opens short-lived UDP sockets per query, so a one-shot sample often misses a
  leak. The test fires a burst of concurrent queries and samples sockets
  throughout, so a plaintext connection to the router is reliably observed.
- **Encrypted transport in use** does not merely check that *a* port-853 socket
  exists (an unrelated app could own one). It records the socket's byte and
  segment counters, fires the query burst, and requires the counters to grow,
  proving that *our* lookups travelled over TLS. Run `--leak-selftest` to confirm
  the detector itself can see a plaintext socket (so a clean result is
  meaningful, not rubber-stamped).
- **Upstream resolver identity** queries `o-o.myaddr.l.google.com` /
  `whoami.ds.akahelp.net` through the system resolver. The answer is the
  resolver the internet sees. A private/loopback answer is a hard leak; a
  public answer that isn't in the expected provider's ranges is a warning
  (it could be your ISP or a VPN).

> The provider-range match is a heuristic (Cloudflare/Google/Quad9 egress
> prefixes); treat a WARN there as "look closer", not proof.

## Speed test

**Speed test** (GUI button) or `--speedtest [SECS]`.

**It prefers the official Ookla `speedtest` CLI when one is installed.** That
CLI talks to Ookla's own nearby servers, so the numbers match speedtest.net
exactly. Either install the AUR package or drop Ookla's official tarball in
`~/.local/bin` (no root needed):

```sh
paru -S ookla-speedtest-bin        # AUR: official Ookla CLI
# …or, without root:
curl -sSL https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz \
  | tar xzO speedtest > ~/.local/bin/speedtest && chmod +x ~/.local/bin/speedtest
```

If no such CLI is found, the app falls back to a **built-in** test: a tiny
HTTP/1.1 client on the existing `rustls` stack (no extra crates) that runs a
*sustained* download and upload against Cloudflare for `SECS` per direction
(default **25 s each, ~50 s total**). Chunk sizes stay under Cloudflare's
per-request ceiling and shrink automatically if the server answers `429`.

Speeds are shown in **Mbps** (10^6 bits/s) and **MiB/s** (2^20 bytes/s);
transferred amounts in both MB and MiB. Clicking the button again while it runs
stops the test.

```sh
waynes-dns-gtk --speedtest                                    # Ookla if installed, else built-in
WAYNES_DNS_SPEEDTEST=builtin waynes-dns-gtk --speedtest 10    # force built-in, 10 s each way
```

```
Source: Ookla Speedtest · T-Mobile (Kansas City, MO)
Result: Ping 23.9 ms (jitter 11.0 ms) · Download 201.22 Mbps (23.99 MiB/s) · Upload 31.25 Mbps (3.73 MiB/s)
```

## CLI

```
waynes-dns-gtk [OPTION] [PROVIDER]
```

`PROVIDER` is one of `cloudflare` (default), `cloudflare-malware`, `quad9`,
`google`.

- `--help`
- `--status`: current DNS/DoT status for the active link
- `--verify`: post-apply verification checks
- `--leak [PROVIDER]`: run the DNS leak test (exit 1 on a hard leak). With no
  PROVIDER, one is auto-detected from the live DNS config.
- `--leak-selftest`: negative control for the leak detector
- `--speedtest [SECS]`: sustained latency / download / upload speed test
- `--probe [PROVIDER]`: which DoT/853 servers are reachable
- `--print-config [PROVIDER]`: show the config that *would* be written
- `--apply-privileged` / `--revert-privileged`: internal, run as root via `pkexec`

Example:

```sh
waynes-dns-gtk --leak cloudflare
```

## Revert

Press **Revert** (or `waynes-dns-gtk --revert-privileged` as root). The original
NetworkManager settings are saved to a state file before the first apply and
restored on revert; the `resolved.conf` drop-in and any firewall unit are
removed.

## Install (optional)

```sh
cargo build --release
sudo install -Dm755 target/release/waynes-dns-gtk /usr/local/bin/waynes-dns-gtk
sudo install -Dm644 waynes-dns-gtk.desktop /usr/share/applications/waynes-dns-gtk.desktop
```

The `.desktop` entry assumes `waynes-dns-gtk` is on `PATH`.

## Layout

- `src/main.rs`: CLI dispatch and the GTK application entry
- `src/app.rs`: the GTK4 UI and its worker thread
- `src/privileged.rs`: the root-side apply/revert plan (drop-in, nmcli, nft)
- `src/resolvers.rs`: provider definitions and the DoT/853 reachability probe
- `src/leak.rs`: the DNS leak test
- `src/speedtest.rs`: the latency/download/upload speed test
- `src/system.rs`: small process helpers

## Changelog

### v0.1.1
- Fixed `default_route()` reading only the first line of `ip route show
  default`, which produced a false `[WARN] Default route` in the leak test and
  truncated the remaining checks.
- The leak test no longer returns early when no default route is found.
- The DoT probe now reports a plain-English, address-family aware reason for
  each failure (`no IPv6 route`, `no usable IPv6 source address`, `connection
  refused`, ...), retries a failed server once, and logs which families apply.
- Apply now configures every IPv4 and IPv6 server, so a temporary IPv6 outage
  no longer drops IPv6 DNS.
- `--verify` now reads the full wrapped `DNS Servers:` field from `resolvectl`,
  so IPv6 resolvers are shown.

### v0.1.0
- First public release.

## License

MIT. See [LICENSE](LICENSE).
