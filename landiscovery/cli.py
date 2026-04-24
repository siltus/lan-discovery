"""Typer-based CLI."""
from __future__ import annotations

import json
import logging
import sys
from typing import Optional

# Make the CLI safe on Windows consoles that default to cp1252 - Rich emits Unicode.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table

from .config import db_path
from .net.interfaces import list_candidate_interfaces, select_interface
from .net.privileges import is_admin, npcap_available, relaunch_as_admin
from .scan.pipeline import ScanOptions, run_scan
from .store import db
from .store.repo import Repo

app = typer.Typer(add_completion=False, no_args_is_help=False,
                  help="LAN discovery: find and identify devices on your local network.")
console = Console()


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context):
    """Default action: with no subcommand, show full help (commands + flags)."""
    if ctx.invoked_subcommand is not None:
        return
    # Top-level help
    console.print(ctx.get_help())
    console.print()
    # Per-subcommand help
    for name, cmd in sorted(ctx.command.commands.items()):
        if cmd.hidden:
            continue
        sub_ctx = typer.Context(cmd, info_name=name, parent=ctx)
        console.rule(f"[bold]landiscovery {name}[/]")
        console.print(cmd.get_help(sub_ctx))
        console.print()
    raise typer.Exit(0)


def _setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _device_table(devices) -> Table:
    t = Table(show_lines=False, header_style="bold")
    t.add_column("ID", justify="right")
    t.add_column("Name")
    t.add_column("IP")
    t.add_column("MAC")
    t.add_column("Vendor")
    t.add_column("Type")
    t.add_column("Hostname")
    t.add_column("Online")
    for d in devices:
        t.add_row(
            str(d.id) if d.id is not None else "",
            d.display_name or "",
            d.ip or "",
            d.mac or "",
            (d.vendor or "")[:24],
            d.device_type or "",
            d.hostname or "",
            "●" if d.online else "·",
        )
    return t


@app.command()
def interfaces(verbose: bool = typer.Option(False, "-v")):
    """List candidate LAN interfaces."""
    _setup_logging(verbose)
    cands = list_candidate_interfaces()
    if not cands:
        console.print("[yellow]No candidate LAN interface found.[/]")
        raise typer.Exit(1)
    t = Table(header_style="bold")
    for col in ("Name", "IP", "Network", "MAC"):
        t.add_column(col)
    for c in cands:
        t.add_row(c.name, c.ip, str(c.network), c.mac or "")
    console.print(t)


@app.command()
def scan(
    interface: Optional[str] = typer.Option(None, "--interface", "-i"),
    subnet: Optional[str] = typer.Option(None, "--subnet", "-s"),
    no_arp: bool = typer.Option(False, "--no-arp", help="Skip raw ARP scan."),
    full: bool = typer.Option(False, "--full", help="Allow large subnets."),
    json_out: bool = typer.Option(False, "--json"),
    no_warnings: bool = typer.Option(False, "--no-warnings",
                                     help="Suppress privilege/Npcap warnings."),
    no_oui_update: bool = typer.Option(False, "--no-oui-update",
                                       help="Do not auto-download the IEEE OUI database."),
    no_elevate: bool = typer.Option(False, "--no-elevate",
                                    help="Don't auto-elevate via UAC on Windows when not admin."),
    verbose: bool = typer.Option(False, "-v"),
):
    """Scan the local network and print discovered devices."""
    _setup_logging(verbose)

    import os as _os
    if not no_elevate and _os.name == "nt" and not is_admin():
        argv = ["scan"]
        if interface:    argv += ["--interface", interface]
        if subnet:       argv += ["--subnet", subnet]
        if no_arp:       argv += ["--no-arp"]
        if full:         argv += ["--full"]
        if json_out:     argv += ["--json"]
        if no_warnings:  argv += ["--no-warnings"]
        if no_oui_update:argv += ["--no-oui-update"]
        argv += ["--no-elevate"]   # prevent infinite loop in the elevated child
        if verbose:      argv += ["-v"]
        console.print("[cyan]Requesting admin privileges (UAC prompt)...[/]")
        console.print("[dim]Output will appear in a new console window. "
                      "Use --no-elevate to disable.[/]")
        rc = relaunch_as_admin(argv)
        if rc <= 32:
            console.print(f"[yellow]Elevation cancelled or failed (code {rc}). "
                          "Continuing without admin privileges.[/]")
        else:
            raise typer.Exit(0)

    if not no_arp and not json_out and not no_warnings:
        admin = is_admin()
        npcap = npcap_available()
        if not admin or not npcap:
            import os as _os
            elevate = ("Right-click your terminal and choose 'Run as administrator'."
                       if _os.name == "nt"
                       else "Re-run with sudo, e.g. `sudo landiscovery scan`.")
            console.print("[yellow]Warning:[/] running without full privileges.")
            if not admin:
                console.print(f"  - Not running as {'administrator' if _os.name == 'nt' else 'root'}.")
            if _os.name == "nt" and not npcap:
                console.print("  - Npcap does not appear to be installed "
                              "(https://npcap.com).")
            console.print("  [dim]ARP scanning will be skipped; falling back to "
                          "ping sweep + OS arp table + mDNS/SSDP/NetBIOS.[/]")
            console.print("  [dim]You may miss:[/]")
            console.print("    [dim]* hosts that don't respond to TCP/ICMP probes "
                          "(e.g. firewalled IoT devices)[/]")
            console.print("    [dim]* MAC addresses for hosts you have not yet "
                          "communicated with (no vendor lookup, weaker identity)[/]")
            console.print(f"  [dim]To fix: {elevate}  "
                          "Use --no-arp to silence this warning, or --no-warnings.[/]")
            if _os.name == "nt" and not npcap:
                console.print("  [dim]To install Npcap automatically: "
                              "[bold]landiscovery install-npcap[/][/]\n")
            else:
                console.print("")

    def progress(event: str, payload: dict):
        if event == "start":
            console.print(f"[cyan]Scanning {payload.get('subnet')} on {payload.get('interface')}...[/]")
        elif event == "phase":
            console.print(f"  [dim]phase:[/] {payload.get('name')}")
        elif event == "oui-updated":
            console.print(f"  [dim]OUI database refreshed ({payload.get('entries')} entries)[/]")
        elif event == "alive":
            console.print(f"  [dim]alive:[/] {payload.get('count')} hosts")
        elif event == "done":
            console.print(f"[green]Done.[/] {payload.get('count')} devices.")

    try:
        result = run_scan(ScanOptions(
            interface=interface, subnet=subnet,
            use_arp=not no_arp, full=full,
            auto_oui=not no_oui_update,
            progress=None if json_out else progress,
        ))
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2)

    if json_out:
        out = [{
            "id": d.id, "ip": d.ip, "mac": d.mac, "hostname": d.hostname,
            "vendor": d.vendor, "device_type": d.device_type,
            "custom_name": d.custom_name, "notes": d.notes,
            "ports": [s.port for s in d.services if s.proto == "tcp" and s.port],
        } for d in result.devices]
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
    else:
        console.print(_device_table(result.devices))


@app.command(name="list")
def list_cmd(
    online: bool = typer.Option(False, "--online"),
    type_: Optional[str] = typer.Option(None, "--type"),
):
    """List previously seen devices from the database."""
    repo = Repo(db.init_db())
    devices = repo.list_devices(online_only=online, device_type=type_)
    console.print(_device_table(devices))


@app.command()
def show(key: str):
    """Show details for a device (id, ip, or mac)."""
    repo = Repo(db.init_db())
    d = repo.get_device(key)
    if not d:
        console.print(f"[red]Device not found:[/] {key}")
        raise typer.Exit(1)
    console.print(f"[bold]{d.display_name}[/] (#{d.id})")
    console.print(f"  IP:        {d.ip}")
    console.print(f"  MAC:       {d.mac}")
    console.print(f"  Hostname:  {d.hostname}")
    console.print(f"  Vendor:    {d.vendor}")
    console.print(f"  Type:      {d.device_type}")
    console.print(f"  OS hint:   {d.os_hint}")
    console.print(f"  Notes:     {d.notes or ''}")
    console.print(f"  First/Last:{d.first_seen}  ->  {d.last_seen}")
    if d.services:
        t = Table(title="Services", header_style="bold")
        for c in ("proto", "port", "name", "banner"):
            t.add_column(c)
        for s in d.services:
            t.add_row(s.proto, str(s.port or ""), s.name, (s.banner or "")[:80])
        console.print(t)


@app.command()
def rename(key: str, name: str):
    """Set a custom name for a device."""
    repo = Repo(db.init_db())
    d = repo.get_device(key)
    if not d:
        console.print(f"[red]Device not found:[/] {key}")
        raise typer.Exit(1)
    repo.set_custom_name(d.id, name)
    console.print(f"[green]Renamed[/] #{d.id} -> {name}")


@app.command()
def note(key: str, text: str):
    """Set a free-form note on a device."""
    repo = Repo(db.init_db())
    d = repo.get_device(key)
    if not d:
        console.print(f"[red]Device not found:[/] {key}")
        raise typer.Exit(1)
    repo.set_notes(d.id, text)
    console.print(f"[green]Note saved[/] for #{d.id}")


@app.command()
def reclassify():
    """Re-run vendor lookup + device-type classification on all stored devices,
    without doing a network scan. Useful after the OUI database is updated or
    after the classifier is improved."""
    from .fingerprint import oui as oui_mod
    from .fingerprint.classify import Signals, classify
    repo = Repo(db.init_db())
    devices = repo.list_devices()
    changed = 0
    for d in devices:
        new_vendor = oui_mod.lookup(d.mac) if d.mac else None
        sig = Signals(
            vendor=new_vendor or d.vendor,
            hostname=d.hostname,
            open_ports=[s.port for s in d.services if s.proto == "tcp" and s.port],
            mdns_services=[s.name for s in d.services if s.proto == "mdns"],
            http_servers=[s.banner for s in d.services if s.proto == "tcp" and s.name == "http"],
        )
        new_type = classify(sig)
        if new_vendor != d.vendor or new_type != d.device_type:
            repo.conn.execute(
                "UPDATE devices SET vendor=?, device_type=? WHERE id=?",
                (new_vendor or d.vendor, new_type, d.id),
            )
            changed += 1
    repo.conn.commit()
    console.print(f"[green]Reclassified {changed}/{len(devices)} devices.[/]")


@app.command(name="install-npcap")
def install_npcap_cmd():
    """Download and run the official Npcap installer (Windows only)."""
    from .net.npcap_install import install_interactive
    raise typer.Exit(install_interactive())


@app.command(name="oui-update")
def oui_update():
    """Refresh the IEEE OUI vendor database."""
    from .fingerprint import oui
    n = oui.refresh()
    console.print(f"[green]OUI updated:[/] {n} entries")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8765):
    """Run the web UI."""
    import uvicorn
    if host != "127.0.0.1":
        console.print(f"[yellow]Warning:[/] binding to {host}; UI has no auth.")
    console.print(f"[cyan]Web UI:[/] http://{host}:{port}")
    console.print(f"[dim]DB:[/] {db_path()}")
    uvicorn.run("landiscovery.web.app:app", host=host, port=port, log_level="warning")


@app.command(name="db-path")
def db_path_cmd():
    """Print the path to the SQLite database."""
    console.print(str(db_path()))


if __name__ == "__main__":
    app()
