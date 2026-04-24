"""Combine signals from all sources into a device classification."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Signals:
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    os_hint: Optional[str] = None
    open_ports: list[int] = field(default_factory=list)
    mdns_services: list[str] = field(default_factory=list)
    ssdp_device_type: str = ""
    ssdp_friendly_name: str = ""
    ssdp_manufacturer: str = ""
    ssdp_model: str = ""
    http_servers: list[str] = field(default_factory=list)
    http_titles: list[str] = field(default_factory=list)
    is_gateway: bool = False


def _hay(s: Signals) -> str:
    parts = [
        s.vendor or "", s.hostname or "",
        s.ssdp_device_type, s.ssdp_friendly_name, s.ssdp_manufacturer, s.ssdp_model,
        " ".join(s.mdns_services), " ".join(s.http_servers), " ".join(s.http_titles),
    ]
    return " ".join(parts).lower()


def _has(text: str, *needles: str) -> bool:
    return any(n in text for n in needles)


def _has_word(text: str, *words: str) -> bool:
    """Word-boundary match — avoids matching 'tv' inside 'studio', 'iot' inside 'patriot'."""
    return any(re.search(rf"(?:^|[^a-z0-9]){re.escape(w)}(?:$|[^a-z0-9])", text) for w in words)


COMPUTER_HOST_HINTS = ("mac-mini", "macmini", "macbook", "imac", "mac-studio",
                       "mac-pro", "macpro", "hackintosh",
                       "desktop-", "laptop-", "pc-", "-pc", "workstation",
                       "ubuntu", "debian", "fedora", "arch-", "ws-")


def classify(s: Signals) -> str:
    h = _hay(s)
    ports = set(s.open_ports)
    mdns = " ".join(s.mdns_services).lower()

    # ---- 0. Strong "this is a regular computer" signals win first ----
    if _has(h, *COMPUTER_HOST_HINTS):
        return "computer"
    if s.vendor and "apple" in s.vendor.lower() and not _has(h, "appletv", "apple tv", "homepod"):
        # Apple devices that aren't explicitly TV/HomePod are almost always Macs/iDevices.
        if _has(h, "iphone", "ipad"):
            return "phone"
        return "computer"

    # ---- 1. Network gear ----
    if s.is_gateway or _has(h, "router", "gateway", "openwrt", "mikrotik", "edgerouter"):
        return "router"
    if _has(h, "ubiquiti", "unifi", "access point", "aruba ap", "airport"):
        return "access-point"

    # ---- 2. Printers / NAS ----
    if (_has(h, "printer", "_ipp", "_pdl-datastream", "_printer", "epson", "brother", "laserjet", "kyocera")
            or 9100 in ports or 631 in ports or 515 in ports):
        return "printer"
    if _has(h, "synology", "qnap", "freenas", "truenas", "readynas") or (445 in ports and 5000 in ports):
        return "nas"

    # ---- 3. Smart-TV / cast: needs a TV-specific signal, NOT just AirPlay ----
    tv_mdns = any(svc in mdns for svc in (
        "_googlecast", "_androidtvremote", "_amzn-wplay", "_viziocast",
        "_bravia", "_lge-tv", "_appletv-v2", "_mediaremotetv",
    ))
    if tv_mdns or _has(h, "chromecast", "roku", "bravia", "smart tv", "smarttv",
                       "hisense", "webos", "appletv", "apple tv", "fire tv", "firetv",
                       "shield tv") or _has_word(h, "tv"):
        return "smart-tv"

    # ---- 4. Phones / tablets ----
    if _has(h, "iphone", "ipad", "android-", "samsung-galaxy") or _has_word(h, "phone", "tablet"):
        return "phone"

    # ---- 5. Game consoles ----
    if _has(h, "xbox", "playstation", "nintendo", "switch-"):
        return "game-console"

    # ---- 6. Cameras ----
    if _has(h, "ipcam", "hikvision", "dahua", "axis comm", "amcrest") or 554 in ports:
        return "camera"

    # ---- 7. IoT / smart-home ----
    if _has(h, "philips hue", "tplink-smart", "tasmota", "shelly", "espressif",
            "tuya", "sonoff", "_hap._tcp"):
        return "iot"

    # ---- 8. OS hints ----
    if _has(h, "raspbian", "raspberry pi"):
        return "computer"
    if _has(h, "windows ", "microsoft windows"):
        return "computer"

    # ---- 9. Generic port-based fallbacks ----
    if 22 in ports and (80 in ports or 443 in ports):
        return "server"
    if 80 in ports or 443 in ports:
        return "web-host"
    if 22 in ports or 445 in ports or 139 in ports:
        return "computer"
    return "unknown"
