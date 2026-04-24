"""Reverse DNS hostname lookup."""
from __future__ import annotations

import socket
from typing import Optional


def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)
