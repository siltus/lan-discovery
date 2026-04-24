"""Dataclass models used across the package."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Service:
    proto: str           # tcp / udp / mdns / ssdp / http
    port: Optional[int]  # None for non-port services (mdns/ssdp)
    name: str = ""       # service name (e.g. "_airplay._tcp", "ssh")
    banner: str = ""     # short captured banner / title
    extra: dict = field(default_factory=dict)


@dataclass
class Device:
    id: Optional[int] = None
    mac: Optional[str] = None         # canonical lower-case "aa:bb:cc:dd:ee:ff"
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os_hint: Optional[str] = None
    device_type: Optional[str] = None
    custom_name: Optional[str] = None
    notes: Optional[str] = None
    first_seen: Optional[str] = None  # ISO8601
    last_seen: Optional[str] = None
    online: bool = False
    services: list[Service] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return (
            self.custom_name
            or self.hostname
            or (f"{self.vendor} device" if self.vendor else None)
            or self.ip
            or self.mac
            or "unknown"
        )


@dataclass
class ScanRun:
    id: Optional[int] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    subnet: Optional[str] = None
    host_count: int = 0
