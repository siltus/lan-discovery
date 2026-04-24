"""SSDP / UPnP discovery: M-SEARCH then fetch device descriptor XML."""
from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

import httpx

from ..config import HTTP_TIMEOUT

log = logging.getLogger(__name__)

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


@dataclass
class SSDPDevice:
    ip: str
    location: str = ""
    server: str = ""
    friendly_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    device_type: str = ""
    services: list[str] = field(default_factory=list)


def _parse_headers(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in data.decode(errors="ignore").splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().upper()] = v.strip()
    return out


def _fetch_descriptor(location: str) -> Optional[dict]:
    try:
        r = httpx.get(location, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        text = r.text
    except Exception:
        return None
    try:
        # strip namespace for simpler queries
        text = re.sub(r'\sxmlns="[^"]+"', "", text, count=1)
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    dev = root.find("device")
    if dev is None:
        return None

    def _t(tag: str) -> str:
        el = dev.find(tag)
        return (el.text or "").strip() if el is not None and el.text else ""

    return {
        "friendly_name": _t("friendlyName"),
        "manufacturer": _t("manufacturer"),
        "model_name": _t("modelName"),
        "device_type": _t("deviceType"),
    }


def discover(timeout: float = 3.0) -> dict[str, SSDPDevice]:
    """Send M-SEARCH and collect responses keyed by source IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.8)
    try:
        sock.sendto(M_SEARCH, (SSDP_ADDR, SSDP_PORT))
    except OSError as e:
        log.warning("SSDP send failed: %s", e)
        sock.close()
        return {}

    devices: dict[str, SSDPDevice] = {}
    end = __import__("time").monotonic() + timeout
    while __import__("time").monotonic() < end:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        ip = addr[0]
        headers = _parse_headers(data)
        loc = headers.get("LOCATION", "")
        d = devices.setdefault(ip, SSDPDevice(ip=ip))
        if loc and not d.location:
            d.location = loc
        if "SERVER" in headers and not d.server:
            d.server = headers["SERVER"]
        st = headers.get("ST")
        if st and st not in d.services:
            d.services.append(st)
    sock.close()

    for d in devices.values():
        if d.location:
            try:
                host = urlparse(d.location).hostname
                if host:
                    d.ip = host
            except Exception:
                pass
            info = _fetch_descriptor(d.location)
            if info:
                d.friendly_name = info["friendly_name"]
                d.manufacturer = info["manufacturer"]
                d.model_name = info["model_name"]
                d.device_type = info["device_type"]
    return devices
