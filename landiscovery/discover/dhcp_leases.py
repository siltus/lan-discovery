"""Best-effort DHCP lease parsing for Linux/macOS."""
from __future__ import annotations

import glob
import re
from pathlib import Path


_LEASE_BLOCK = re.compile(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{([^}]*)\}", re.S)
_HW = re.compile(r"hardware\s+ethernet\s+([0-9a-fA-F:]{17});")
_HOST = re.compile(r"client-hostname\s+\"([^\"]+)\";")


def parse_isc(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for m in _LEASE_BLOCK.finditer(text):
        ip = m.group(1)
        body = m.group(2)
        hw = _HW.search(body)
        host = _HOST.search(body)
        out[ip] = {
            "mac": hw.group(1).lower() if hw else None,
            "hostname": host.group(1) if host else None,
        }
    return out


def parse_macos(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for block in re.split(r"\}\s*", text):
        ip_m = re.search(r"ip_address=(\d+\.\d+\.\d+\.\d+)", block)
        hw_m = re.search(r"hw_address=\d+,([0-9a-fA-F:]+)", block)
        nm_m = re.search(r"name=([^\s\}]+)", block)
        if ip_m:
            out[ip_m.group(1)] = {
                "mac": hw_m.group(1).lower() if hw_m else None,
                "hostname": nm_m.group(1) if nm_m else None,
            }
    return out


def discover() -> dict[str, dict]:
    """Return {ip: {"mac": .., "hostname": ..}} from any readable lease files."""
    out: dict[str, dict] = {}
    candidates = glob.glob("/var/lib/dhcp/*.leases") + glob.glob("/var/lib/dhcpd/*.leases")
    for path in candidates:
        try:
            text = Path(path).read_text(errors="ignore")
        except OSError:
            continue
        out.update(parse_isc(text))
    macos = Path("/var/db/dhcpd_leases")
    if macos.exists():
        try:
            out.update(parse_macos(macos.read_text(errors="ignore")))
        except OSError:
            pass
    return out
