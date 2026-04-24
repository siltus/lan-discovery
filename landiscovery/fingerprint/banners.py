"""HTTP(S) banner + service banner grabbing (no auth, no exploits)."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Optional

import httpx

from ..config import BANNER_CONCURRENCY, BANNER_READ_TIMEOUT, HTTP_TIMEOUT, TCP_CONNECT_TIMEOUT


HTTP_PORTS = {80, 8000, 8080, 5000, 32400}
HTTPS_PORTS = {443, 8443}
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class HttpBanner:
    server: str = ""
    title: str = ""


@dataclass
class TextBanner:
    proto: str
    port: int
    text: str


async def grab_http(ip: str, port: int) -> Optional[HttpBanner]:
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        async with httpx.AsyncClient(verify=False, timeout=HTTP_TIMEOUT,
                                     follow_redirects=False) as c:
            r = await c.get(url)
        server = r.headers.get("server", "").strip()
        m = TITLE_RE.search(r.text or "")
        title = (m.group(1).strip()[:120] if m else "")
        if not server and not title:
            return None
        return HttpBanner(server=server, title=title)
    except Exception:
        return None


async def grab_text(ip: str, port: int, *, send: Optional[bytes] = None) -> Optional[TextBanner]:
    """Read a single line of plaintext banner. For SSH/FTP/SMTP."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=TCP_CONNECT_TIMEOUT)
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        if send:
            writer.write(send)
            try:
                await writer.drain()
            except Exception:
                pass
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=BANNER_READ_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    text = data.decode(errors="ignore").strip()
    if not text:
        return None
    proto = {22: "ssh", 21: "ftp", 25: "smtp", 23: "telnet"}.get(port, "tcp")
    return TextBanner(proto=proto, port=port, text=text[:200])


async def grab_all(ip: str, open_ports: list[int]) -> dict[int, object]:
    """Run banner grabs for all relevant open ports. Returns {port: HttpBanner|TextBanner}."""
    sem = asyncio.Semaphore(BANNER_CONCURRENCY)
    results: dict[int, object] = {}

    async def go(port: int):
        async with sem:
            if port in HTTP_PORTS or port in HTTPS_PORTS:
                b = await grab_http(ip, port)
            elif port in (22, 21, 25, 23):
                b = await grab_text(ip, port)
            else:
                b = None
            if b is not None:
                results[port] = b

    await asyncio.gather(*[go(p) for p in open_ports])
    return results
