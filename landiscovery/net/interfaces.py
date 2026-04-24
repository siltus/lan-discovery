"""Pick the best LAN interface and subnet."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional

import psutil

from ..config import EXCLUDED_IFACE_PATTERNS


@dataclass
class Interface:
    name: str
    ip: str
    netmask: str
    mac: Optional[str]

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Interface(f"{self.ip}/{self.netmask}").network


def _is_excluded(name: str) -> bool:
    n = name.lower()
    return any(p in n for p in EXCLUDED_IFACE_PATTERNS)


def _score(net: ipaddress.IPv4Network) -> int:
    if not net.is_private:
        return -1
    s = 0
    if str(net.network_address).startswith("192.168."):
        s += 100
    elif str(net.network_address).startswith("10."):
        s += 50
    elif net.network_address in ipaddress.IPv4Network("172.16.0.0/12"):
        s += 30
    if net.prefixlen >= 23:
        s += 10
    return s


def list_candidate_interfaces() -> list[Interface]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out: list[Interface] = []
    for name, alist in addrs.items():
        if _is_excluded(name):
            continue
        st = stats.get(name)
        if st is None or not st.isup:
            continue
        ip = mask = None
        mac = None
        for a in alist:
            fam = getattr(a, "family", None)
            if fam == socket.AF_INET:
                if not ip:
                    ip, mask = a.address, a.netmask
            elif fam == getattr(psutil, "AF_LINK", -1) or str(fam).endswith("AF_PACKET"):
                mac = (a.address or "").lower() or None
        if not ip or not mask or ip.startswith("127."):
            continue
        try:
            net = ipaddress.IPv4Interface(f"{ip}/{mask}").network
        except ValueError:
            continue
        if not net.is_private:
            continue
        out.append(Interface(name=name, ip=ip, netmask=mask, mac=mac))
    return out


def select_interface(name: Optional[str] = None) -> Optional[Interface]:
    cands = list_candidate_interfaces()
    if name:
        for c in cands:
            if c.name == name:
                return c
        return None
    if not cands:
        return None
    return max(cands, key=lambda c: _score(c.network))


def parse_subnet(value: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(value, strict=False)
