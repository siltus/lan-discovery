"""Global configuration / constants."""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "landiscovery"


def data_dir() -> Path:
    """Return per-user data dir for the database and caches."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    p = base / APP_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_path() -> Path:
    return data_dir() / "landiscovery.sqlite"


COMMON_TCP_PORTS: tuple[int, ...] = (
    22, 23, 53, 80, 139, 443, 445, 515, 554, 631,
    1900, 5000, 5353, 8000, 8080, 8443, 9100, 32400,
)

# Interface name patterns to exclude (case-insensitive substring match).
EXCLUDED_IFACE_PATTERNS: tuple[str, ...] = (
    "loopback", "lo0", "lo:",
    "vethernet", "vmware", "virtualbox", "vmnet", "vbox",
    "tun", "tap", "wg", "zerotier", "tailscale", "utun",
    "docker", "br-", "veth", "hyper-v", "wsl", "npcap loopback",
    "bluetooth", "ppp", "isatap", "teredo",
)

# Scanning concurrency limits.
PING_CONCURRENCY = 64
PORT_CONCURRENCY = 128
BANNER_CONCURRENCY = 32
HTTP_TIMEOUT = 2.5
TCP_CONNECT_TIMEOUT = 1.0
BANNER_READ_TIMEOUT = 1.5
