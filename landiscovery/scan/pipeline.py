"""Scan pipeline: orchestrates discovery + fingerprinting + persistence."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..config import COMMON_TCP_PORTS
from ..discover import dhcp_leases, mdns, netbios, ports as port_scan, ssdp
from ..fingerprint import banners as banner_fp, classify, hostname as hn, oui
from ..fingerprint.banners import HttpBanner, TextBanner
from ..net import arp, arp_table, interfaces, ping
from ..net.privileges import is_admin, npcap_available
from ..store import db
from ..store.models import Device, Service
from ..store.repo import Repo

log = logging.getLogger(__name__)

ProgressCb = Callable[[str, dict], None]


@dataclass
class ScanOptions:
    interface: Optional[str] = None
    subnet: Optional[str] = None
    use_arp: bool = True            # try Scapy ARP if available
    full: bool = False              # allow > /22 networks
    fingerprint: bool = True
    auto_oui: bool = True           # fetch IEEE OUI db when missing/old
    oui_max_age_days: int = 30
    progress: Optional[ProgressCb] = None


@dataclass
class ScanResult:
    network: ipaddress.IPv4Network
    devices: list[Device] = field(default_factory=list)


def _emit(opts: ScanOptions, event: str, **payload):
    if opts.progress:
        try:
            opts.progress(event, payload)
        except Exception:
            log.exception("progress callback failed")


async def _enrich(ip: str, mac: Optional[str]) -> Device:
    dev = Device(ip=ip, mac=mac, online=True)
    open_ports = await port_scan.scan_host(ip, COMMON_TCP_PORTS)
    grabs = await banner_fp.grab_all(ip, open_ports) if open_ports else {}

    services: list[Service] = []
    sig_servers: list[str] = []
    sig_titles: list[str] = []
    for p in open_ports:
        b = grabs.get(p)
        if isinstance(b, HttpBanner):
            services.append(Service(proto="tcp", port=p, name="http",
                                    banner=(b.server or "")[:200],
                                    extra={"title": b.title} if b.title else {}))
            if b.server:
                sig_servers.append(b.server)
            if b.title:
                sig_titles.append(b.title)
        elif isinstance(b, TextBanner):
            services.append(Service(proto="tcp", port=p, name=b.proto, banner=b.text))
            sig_servers.append(b.text)
        else:
            services.append(Service(proto="tcp", port=p))

    nb = await asyncio.to_thread(netbios.query, ip)
    if nb and nb.hostname:
        dev.hostname = nb.hostname.lower()
    rev = await asyncio.to_thread(hn.reverse_dns, ip)
    if rev and not dev.hostname:
        dev.hostname = rev.split(".")[0].lower()

    dev.vendor = oui.lookup(mac) if mac else None
    dev.services = services

    sigs = classify.Signals(
        vendor=dev.vendor, hostname=dev.hostname,
        open_ports=open_ports,
        http_servers=sig_servers, http_titles=sig_titles,
    )
    dev._signals = sigs  # type: ignore[attr-defined]
    return dev


async def scan(opts: ScanOptions) -> ScanResult:
    iface = interfaces.select_interface(opts.interface)
    if opts.subnet:
        net = interfaces.parse_subnet(opts.subnet)
    elif iface is None:
        raise RuntimeError("Could not detect a LAN interface. Use --interface or --subnet.")
    else:
        net = iface.network
    if net.num_addresses > 1024 and not opts.full:
        raise RuntimeError(f"Subnet {net} has {net.num_addresses} hosts; pass --full to allow.")

    _emit(opts, "start", subnet=str(net), interface=iface.name if iface else None)

    if opts.auto_oui:
        _emit(opts, "phase", name="oui-refresh")
        added = await asyncio.to_thread(oui.ensure_fresh, opts.oui_max_age_days)
        if added:
            _emit(opts, "oui-updated", entries=added)

    # 1. Find live hosts (ARP + ping + arp table merge).
    ip_to_mac: dict[str, Optional[str]] = {}
    arp_runnable = opts.use_arp and arp.scapy_available() and is_admin() and npcap_available()
    if opts.use_arp and not arp_runnable:
        _emit(opts, "phase", name="arp-skipped")
        log.info("Skipping ARP scan (need admin%s).",
                 " + Npcap" if not npcap_available() else "")
    if arp_runnable:
        _emit(opts, "phase", name="arp")
        arp_results = await asyncio.to_thread(arp.arp_scan, net, 2.0, iface.name if iface else None)
        for ip, mac in arp_results.items():
            ip_to_mac[ip] = mac
    _emit(opts, "phase", name="ping")
    alive = await ping.sweep(net)
    for ip in alive:
        ip_to_mac.setdefault(ip, None)
    _emit(opts, "phase", name="arp-table")
    cache = await asyncio.to_thread(arp_table.read_arp_table)
    for ip, mac in cache.items():
        if ipaddress.IPv4Address(ip) in net:
            existing = ip_to_mac.get(ip)
            if existing is None:
                ip_to_mac[ip] = mac
    # DHCP leases (Linux/macOS)
    leases = await asyncio.to_thread(dhcp_leases.discover)
    for ip, info in leases.items():
        if ipaddress.IPv4Address(ip) in net and info.get("mac"):
            ip_to_mac.setdefault(ip, info["mac"])

    _emit(opts, "alive", count=len(ip_to_mac))

    # 2. mDNS + SSDP (subnet-wide listeners; not per host).
    _emit(opts, "phase", name="mdns")
    mdns_recs = await asyncio.to_thread(mdns.discover, 4.0)
    _emit(opts, "phase", name="ssdp")
    ssdp_devs = await asyncio.to_thread(ssdp.discover, 3.0)
    # Hosts seen only via mdns/ssdp should also be enriched.
    for ip in list(mdns_recs.keys()) + list(ssdp_devs.keys()):
        if ipaddress.IPv4Address(ip) in net:
            ip_to_mac.setdefault(ip, None)

    # 3. Per-host enrichment in parallel.
    _emit(opts, "phase", name="enrich", hosts=len(ip_to_mac))
    enrich_sem = asyncio.Semaphore(32)

    async def go(ip: str, mac: Optional[str]):
        async with enrich_sem:
            d = await _enrich(ip, mac)
            _emit(opts, "host", ip=ip)
            return d

    devices = await asyncio.gather(*[go(ip, mac) for ip, mac in ip_to_mac.items()])

    # 4. Apply mDNS/SSDP info + classify + persist.
    conn = db.init_db()
    repo = Repo(conn)
    run = repo.start_scan(str(net))
    final: list[Device] = []
    for d in devices:
        sigs = getattr(d, "_signals", classify.Signals())
        m = mdns_recs.get(d.ip)
        if m:
            if m.hostname and not d.hostname:
                d.hostname = m.hostname.split(".")[0].lower()
            for svc in m.services:
                d.services.append(Service(proto="mdns", port=None, name=svc))
            sigs.mdns_services.extend(m.services)
        s = ssdp_devs.get(d.ip)
        if s:
            sigs.ssdp_device_type = s.device_type
            sigs.ssdp_friendly_name = s.friendly_name
            sigs.ssdp_manufacturer = s.manufacturer
            sigs.ssdp_model = s.model_name
            d.services.append(Service(
                proto="ssdp", port=None,
                name=s.friendly_name or s.device_type or "upnp",
                banner=s.server,
                extra={"manufacturer": s.manufacturer, "model": s.model_name,
                       "device_type": s.device_type, "location": s.location},
            ))
        if iface and d.ip == str(_first_hop(net, iface)):
            sigs.is_gateway = True
        d.device_type = classify.classify(sigs)
        repo.upsert_device(d, scan_run_id=run.id)
        final.append(d)
    repo.finish_scan(run, host_count=len(final))

    _emit(opts, "done", count=len(final))
    return ScanResult(network=net, devices=final)


def _first_hop(net: ipaddress.IPv4Network, iface) -> Optional[ipaddress.IPv4Address]:
    """Heuristic: assume gateway is .1 or our address-1 within the subnet."""
    candidates = [
        ipaddress.IPv4Address(int(net.network_address) + 1),
    ]
    return candidates[0] if candidates else None


def run_scan(opts: ScanOptions) -> ScanResult:
    return asyncio.run(scan(opts))
