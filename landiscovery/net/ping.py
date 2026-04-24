"""Async ping sweep. Uses TCP connect probes to common ports as a portable fallback to ICMP."""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Iterable

from ..config import PING_CONCURRENCY, TCP_CONNECT_TIMEOUT


# Small set of high-signal ports; if any is open or RST, host is up.
PROBE_PORTS = (80, 443, 445, 22, 53, 8080)


async def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
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


async def _is_alive(ip: str, sem: asyncio.Semaphore) -> bool:
    async with sem:
        # Probe ports concurrently; first success short-circuits.
        tasks = [asyncio.create_task(_tcp_probe(ip, p, TCP_CONNECT_TIMEOUT)) for p in PROBE_PORTS]
        try:
            for coro in asyncio.as_completed(tasks):
                if await coro:
                    for t in tasks:
                        t.cancel()
                    return True
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
        return False


async def sweep(network: ipaddress.IPv4Network) -> set[str]:
    sem = asyncio.Semaphore(PING_CONCURRENCY)
    hosts = [str(h) for h in network.hosts()]
    results = await asyncio.gather(*[_is_alive(h, sem) for h in hosts])
    return {ip for ip, alive in zip(hosts, results) if alive}


def sweep_sync(network: ipaddress.IPv4Network) -> set[str]:
    return asyncio.run(sweep(network))
