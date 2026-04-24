"""MAC OUI vendor lookup. Uses a small bundled prefix list; can be refreshed online."""
from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import Optional

import httpx

from ..config import data_dir as user_data_dir

log = logging.getLogger(__name__)

_BUNDLED = Path(__file__).resolve().parent.parent / "data" / "oui.csv"
_USER = lambda: user_data_dir() / "oui.csv"

# Authoritative IEEE MA-L registry (and mirrors)
IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"
FALLBACK_URLS = (
    IEEE_URL,
    "https://standards-oui.ieee.org/oui.txt",  # text format also blocked by 418 sometimes
    "https://www.wireshark.org/download/automated/data/manuf",  # well-formed, hex-prefix list
)
_UA = "Mozilla/5.0 (compatible; landiscovery/0.1; +https://example.invalid)"

_cache: Optional[dict[str, str]] = None


def is_locally_administered(mac: Optional[str]) -> bool:
    """True if the MAC has the locally-administered bit set (randomized / privacy MAC)."""
    if not mac:
        return False
    s = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(s) < 2:
        return False
    try:
        return bool(int(s[:2], 16) & 0b00000010)
    except ValueError:
        return False


def is_multicast(mac: Optional[str]) -> bool:
    if not mac:
        return False
    s = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(s) < 2:
        return False
    try:
        return bool(int(s[:2], 16) & 0b00000001)
    except ValueError:
        return False


def _norm_prefix(mac: str) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    return s[:6]


def _load_csv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with path.open(newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            # Two known formats:
            # 1) Bundled minimal: prefix,vendor
            # 2) IEEE: Registry,Assignment,Organization Name,Organization Address
            if header and len(header) >= 3 and header[0].lower().startswith("registry"):
                for row in reader:
                    if len(row) >= 3:
                        out[_norm_prefix(row[1])] = row[2].strip()
            else:
                # Treat first row as data if it didn't look like IEEE header.
                if header and len(header) >= 2 and not header[0].lower().startswith("prefix"):
                    out[_norm_prefix(header[0])] = header[1].strip()
                for row in reader:
                    if len(row) >= 2:
                        out[_norm_prefix(row[0])] = row[1].strip()
    except (OSError, StopIteration):
        pass
    return out


def _load() -> dict[str, str]:
    global _cache
    if _cache is not None:
        return _cache
    data: dict[str, str] = {}
    if _BUNDLED.exists():
        data.update(_load_csv(_BUNDLED))
    user = _USER()
    if user.exists():
        data.update(_load_csv(user))
    _cache = data
    return data


def lookup(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    if is_locally_administered(mac):
        return "Randomized MAC (privacy)"
    db = _load()
    return db.get(_norm_prefix(mac))


def _parse_wireshark_manuf(text: str) -> dict[str, str]:
    """Parse wireshark 'manuf' file: lines like 'AA:BB:CC\tShort\tLong description'."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        prefix = parts[0]
        # Skip mask-suffixed prefixes (e.g. "AA:BB:CC:00:00:00/28") - not OUI-aligned.
        if "/" in prefix:
            continue
        name = parts[2] if len(parts) >= 3 else parts[1]
        out[_norm_prefix(prefix)] = name.strip()
    return out


def refresh(url: Optional[str] = None, timeout: float = 30.0) -> int:
    """Download the OUI database. Tries IEEE first, then mirrors. Returns entry count."""
    global _cache
    target = _USER()
    target.parent.mkdir(parents=True, exist_ok=True)
    urls = (url,) if url else FALLBACK_URLS
    last_err: Optional[Exception] = None
    for u in urls:
        try:
            log.info("Downloading OUI database from %s", u)
            r = httpx.get(u, timeout=timeout, follow_redirects=True,
                          headers={"User-Agent": _UA, "Accept": "text/csv,text/plain,*/*"})
            r.raise_for_status()
            text = r.text
        except Exception as e:
            last_err = e
            log.warning("OUI fetch failed for %s: %s", u, e)
            continue
        if "wireshark" in u or "manuf" in u:
            data = _parse_wireshark_manuf(text)
            # Re-serialize as our minimal CSV so _load_csv can read it back.
            lines = ["prefix,vendor"] + [f"{k},{v.replace(',', ' ')}" for k, v in data.items()]
            target.write_text("\n".join(lines), encoding="utf-8")
        else:
            target.write_text(text, encoding="utf-8")
        _cache = None
        return len(_load())
    raise RuntimeError(f"All OUI sources failed: {last_err}")


def _age_days(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    import time
    return (time.time() - path.stat().st_mtime) / 86400.0


def ensure_fresh(max_age_days: int = 30, timeout: float = 15.0) -> Optional[int]:
    """Download OUI DB if missing or older than `max_age_days`. Best-effort; returns
    the new entry count or None if no download happened (or it failed silently)."""
    user = _USER()
    age = _age_days(user)
    if age is not None and age <= max_age_days:
        return None
    try:
        return refresh(timeout=timeout)
    except Exception as e:
        log.warning("OUI auto-update failed: %s", e)
        return None
