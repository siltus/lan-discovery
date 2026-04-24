"""ARP scan via Scapy. Requires admin/root (and Npcap on Windows)."""
from __future__ import annotations

import ipaddress
import logging
import os
from typing import Optional

# Quiet Scapy's import-time "No libpcap provider available" warning on Windows;
# we detect Npcap ourselves and surface a single, actionable message.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

log = logging.getLogger(__name__)


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:  # pragma: no cover - import-time
        return False


def arp_scan(network: ipaddress.IPv4Network, timeout: float = 2.0,
             iface: Optional[str] = None) -> dict[str, str]:
    """Return {ip: mac} discovered via ARP. Empty dict on failure (caller falls back)."""
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except Exception as e:  # pragma: no cover
        log.warning("Scapy unavailable: %s", e)
        return {}
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        ans, _ = srp(pkt, timeout=timeout, verbose=False, iface=iface)
    except PermissionError:
        log.warning("ARP scan requires elevated privileges (admin/root).")
        return {}
    except OSError as e:
        log.warning("ARP scan OS error (Npcap missing on Windows?): %s", e)
        return {}
    except Exception as e:
        # Scapy raises its own Scapy_Exception when winpcap/libpcap is missing.
        log.warning("ARP scan failed: %s", e)
        return {}
    out: dict[str, str] = {}
    for _, rcv in ans:
        out[rcv.psrc] = rcv.hwsrc.lower()
    return out
