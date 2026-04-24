"""TTL-based OS family hint. Works only when we have an observed TTL (best-effort)."""
from __future__ import annotations

from typing import Optional


def os_from_ttl(ttl: Optional[int]) -> Optional[str]:
    if ttl is None:
        return None
    # Common boot TTLs: Linux/macOS=64, Windows=128, network gear=255.
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    return "Network device"
