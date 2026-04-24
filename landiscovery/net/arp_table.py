"""Read the OS ARP table (no privileges needed)."""
from __future__ import annotations

import re
import subprocess
from typing import Optional


_MAC_RE = re.compile(r"([0-9a-f]{2}([:-])[0-9a-f]{2}(\2[0-9a-f]{2}){4})", re.I)
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _normalize_mac(mac: str) -> str:
    mac = mac.lower().replace("-", ":")
    return mac


def read_arp_table() -> dict[str, str]:
    """Return {ip: mac} from the OS ARP cache. Best-effort, cross-platform."""
    out: dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        )
        text = proc.stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return out
    for line in text.splitlines():
        ip_m = _IP_RE.search(line)
        mac_m = _MAC_RE.search(line)
        if ip_m and mac_m:
            ip = ip_m.group(1)
            mac = _normalize_mac(mac_m.group(1))
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue
            out[ip] = mac
    return out


def lookup(ip: str) -> Optional[str]:
    return read_arp_table().get(ip)
