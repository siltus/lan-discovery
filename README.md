# lan-discovery

Cross-platform tool that scans your local network for devices, identifies them
using **non-intrusive** techniques (no exploits, no CVE probing, no auth
attempts), and lets you rename and annotate every device. Available as both a
**CLI** and a small **web UI**.

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![license](https://img.shields.io/badge/license-MIT-green)

## Features

- **Auto-detects** the local LAN interface (prefers `192.168.x.x`), excluding
  VPNs and virtual adapters (Hyper-V, VMware, WSL, ZeroTier, Tailscale, Docker, …).
- **Multi-pronged discovery**:
  - ARP scan (Scapy, requires admin/root) with OS arp-table fallback
  - Async TCP/ICMP-style ping sweep
  - mDNS / Bonjour (zeroconf)
  - SSDP / UPnP (M-SEARCH + descriptor XML)
  - NetBIOS name query (UDP 137)
  - DHCP lease parsing (Linux/macOS)
  - TCP connect probes on a curated list of common ports
- **Non-intrusive fingerprinting**:
  - MAC OUI vendor lookup, with **auto-refresh** from the IEEE registry (with
    User-Agent and a Wireshark `manuf` fallback mirror)
  - Detection of **randomized / privacy MACs** (locally-administered bit)
  - mDNS service types, SSDP descriptors
  - HTTP(S) `Server` header + `<title>`
  - SSH / FTP / SMTP first-line banner
  - Reverse DNS / NetBIOS hostname
  - TTL-based OS family hint
- **Smart device-type classifier** (router / access-point / printer / NAS /
  smart-TV / camera / IoT / phone / game-console / computer / server / web-host
  / unknown). Avoids common false positives (e.g. an Apple Mac advertising
  AirPlay won't be tagged as a TV).
- **Persistence in SQLite**, with MAC-based identity merge and protection of
  user-supplied annotations.
- **Quality-of-life on Windows**:
  - Auto-elevates via UAC when run from a normal shell (suppress with
    `--no-elevate`).
  - `landiscovery install-npcap` downloads and launches the official Npcap
    installer.
  - Detects when Npcap is missing and degrades gracefully.

## Install

Python 3.10 or newer.

**Install directly from GitHub (no clone required):**

```bash
pip install git+https://github.com/siltus/lan-discovery.git
```

Pin to a tag, branch, or commit:

```bash
pip install git+https://github.com/siltus/lan-discovery.git@v0.1.0
pip install git+https://github.com/siltus/lan-discovery.git@main
pip install git+https://github.com/siltus/lan-discovery.git@<commit-sha>
```

Upgrade later:

```bash
pip install --upgrade --force-reinstall git+https://github.com/siltus/lan-discovery.git
```

**Or install from a local clone (for development):**

```bash
git clone https://github.com/siltus/lan-discovery.git
cd lan-discovery
pip install -e .
```

### Privileges & Npcap (Windows)

- Raw ARP scanning needs **admin/root**.
- On **Windows**, ARP additionally requires [Npcap](https://npcap.com/).
  Install with one command:
  ```cmd
  landiscovery install-npcap
  ```
- Without admin/Npcap, the tool falls back to ping + the OS arp table + mDNS /
  SSDP / NetBIOS — you still get most devices, just with fewer MACs.

## CLI

Running `landiscovery` with no arguments prints every command **and** its flags.

```bash
landiscovery interfaces                           # list candidate interfaces
landiscovery scan                                 # scan the auto-detected LAN
landiscovery scan --interface eth0                # explicit interface
landiscovery scan --subnet 192.168.1.0/24         # explicit subnet
landiscovery scan --no-arp                        # skip raw ARP entirely
landiscovery scan --no-elevate                    # don't auto-prompt UAC (Windows)
landiscovery scan --no-oui-update                 # offline mode
landiscovery scan --no-warnings --json            # machine-readable output
landiscovery list                                 # list known devices
landiscovery list --online --type printer
landiscovery show 192.168.1.10                    # by id, ip, or mac
landiscovery rename 192.168.1.10 "Office printer"
landiscovery note   192.168.1.10 "HP M404, ink low"
landiscovery reclassify                           # re-run vendor + type on stored rows
landiscovery oui-update                           # force-refresh IEEE OUI DB
landiscovery install-npcap                        # Windows only
landiscovery serve                                # web UI on http://127.0.0.1:8765
landiscovery db-path                              # show SQLite location
```

## Web UI

```bash
landiscovery serve --host 127.0.0.1 --port 8765
```

Then visit <http://127.0.0.1:8765>. The UI:

- lists every known device with type / vendor / hostname / online dot
- per-device page with full service list and editable name + notes
- "Scan now" button with live status updates (HTMX polling)
- `GET /api/devices` returns the same data as JSON for scripting

By default the server binds to localhost (no auth). Passing a non-loopback
`--host` prints a warning.

## What this tool does NOT do

- No exploit attempts, CVE probing, brute-forcing, or authentication.
- No payloads beyond a TCP `connect()` and a single `GET /` on common HTTP ports.
- No IPv6 (out of scope per the requirements).

## Storage

The SQLite database lives at `landiscovery db-path`:

- Windows: `%APPDATA%\landiscovery\landiscovery.sqlite`
- Linux / macOS: `~/.local/share/landiscovery/landiscovery.sqlite`

The OUI database is cached next to it.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE) © Sagi Iltus and contributors.
