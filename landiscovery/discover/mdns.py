"""mDNS / Bonjour browser using zeroconf."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class MDNSRecord:
    ip: str
    hostname: str = ""
    services: list[str] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)


def discover(timeout: float = 4.0) -> dict[str, MDNSRecord]:
    """Browse common mDNS service types and return {ip: MDNSRecord}."""
    try:
        from zeroconf import ServiceBrowser, Zeroconf, ServiceListener
    except Exception as e:  # pragma: no cover
        log.warning("zeroconf unavailable: %s", e)
        return {}

    types = [
        "_http._tcp.local.", "_https._tcp.local.",
        "_ipp._tcp.local.", "_ipps._tcp.local.", "_pdl-datastream._tcp.local.",
        "_printer._tcp.local.", "_scanner._tcp.local.",
        "_airplay._tcp.local.", "_raop._tcp.local.",
        "_googlecast._tcp.local.", "_spotify-connect._tcp.local.",
        "_smb._tcp.local.", "_afpovertcp._tcp.local.",
        "_ssh._tcp.local.", "_sftp-ssh._tcp.local.",
        "_workstation._tcp.local.", "_device-info._tcp.local.",
        "_hap._tcp.local.", "_homekit._tcp.local.",
    ]

    results: dict[str, MDNSRecord] = {}

    class L:  # ServiceListener-compatible
        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:
                return
            if not info:
                return
            for raw in info.parsed_addresses() if hasattr(info, "parsed_addresses") else []:
                if ":" in raw:  # skip IPv6
                    continue
                rec = results.setdefault(raw, MDNSRecord(ip=raw))
                if info.server:
                    rec.hostname = info.server.rstrip(".")
                if type_ not in rec.services:
                    rec.services.append(type_)
                try:
                    for k, v in (info.properties or {}).items():
                        if isinstance(k, bytes):
                            k = k.decode(errors="ignore")
                        if isinstance(v, bytes):
                            v = v.decode(errors="ignore")
                        if k and v and k not in rec.properties:
                            rec.properties[k] = v
                except Exception:
                    pass

        def update_service(self, *a, **kw):
            pass

        def remove_service(self, *a, **kw):
            pass

    zc = Zeroconf()
    listener = L()
    browsers = [ServiceBrowser(zc, t, listener) for t in types]
    try:
        time.sleep(timeout)
    finally:
        for b in browsers:
            try:
                b.cancel()
            except Exception:
                pass
        try:
            zc.close()
        except Exception:
            pass
    return results
