"""Async TCP connect-only port prober."""
from __future__ import annotations

import asyncio
from typing import Iterable

from ..config import COMMON_TCP_PORTS, PORT_CONCURRENCY, TCP_CONNECT_TIMEOUT


async def _try_port(ip: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def scan_host(ip: str, ports: Iterable[int] = COMMON_TCP_PORTS) -> list[int]:
    sem = asyncio.Semaphore(min(PORT_CONCURRENCY, 32))

    async def one(p):
        async with sem:
            return p if await _try_port(ip, p, TCP_CONNECT_TIMEOUT) else None

    res = await asyncio.gather(*[one(p) for p in ports])
    return sorted([p for p in res if p is not None])


async def scan_many(ips: Iterable[str], ports: Iterable[int] = COMMON_TCP_PORTS) -> dict[str, list[int]]:
    sem = asyncio.Semaphore(PORT_CONCURRENCY)

    async def one(ip):
        async with sem:
            return ip, await scan_host(ip, ports)

    results = await asyncio.gather(*[one(ip) for ip in ips])
    return dict(results)
