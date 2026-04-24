"""FastAPI web UI."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..scan.pipeline import ScanOptions, scan
from ..store import db
from ..store.repo import Repo

BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="LAN Discovery")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

# Single in-flight scan tracker.
_scan_state: dict = {"running": False, "phase": "idle", "log": []}
_scan_lock = asyncio.Lock()


def _repo() -> Repo:
    return Repo(db.init_db())


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    devices = _repo().list_devices()
    return templates.TemplateResponse(request, "index.html", {
        "devices": devices, "scan_state": _scan_state,
    })


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: int):
    d = _repo().get_device(device_id)
    if not d:
        raise HTTPException(404, "Not found")
    return templates.TemplateResponse(request, "device.html", {"d": d})


@app.post("/devices/{device_id}/rename")
def rename(device_id: int, name: str = Form("")):
    repo = _repo()
    if not repo.get_device(device_id):
        raise HTTPException(404)
    repo.set_custom_name(device_id, name.strip() or None)
    return RedirectResponse(f"/devices/{device_id}", status_code=303)


@app.post("/devices/{device_id}/note")
def note(device_id: int, notes: str = Form("")):
    repo = _repo()
    if not repo.get_device(device_id):
        raise HTTPException(404)
    repo.set_notes(device_id, notes.strip() or None)
    return RedirectResponse(f"/devices/{device_id}", status_code=303)


@app.post("/scan")
async def trigger_scan(interface: Optional[str] = Form(None),
                       subnet: Optional[str] = Form(None),
                       full: bool = Form(False)):
    if _scan_state["running"]:
        return JSONResponse({"ok": False, "error": "scan already running"}, status_code=409)

    async def runner():
        async with _scan_lock:
            _scan_state.update(running=True, phase="starting", log=[])
            try:
                def cb(event, payload):
                    _scan_state["phase"] = event
                    _scan_state["log"].append({"event": event, **payload})
                await scan(ScanOptions(
                    interface=interface or None,
                    subnet=subnet or None,
                    full=full,
                    progress=cb,
                ))
            except Exception as e:
                _scan_state["log"].append({"event": "error", "message": str(e)})
            finally:
                _scan_state["running"] = False
                _scan_state["phase"] = "done"

    asyncio.create_task(runner())
    return RedirectResponse("/", status_code=303)


@app.get("/scan/status", response_class=HTMLResponse)
def scan_status(request: Request):
    return templates.TemplateResponse(request, "_scan_status.html",
                                      {"scan_state": _scan_state})


@app.get("/api/devices")
def api_devices():
    devs = _repo().list_devices()
    return [{
        "id": d.id, "ip": d.ip, "mac": d.mac,
        "hostname": d.hostname, "vendor": d.vendor,
        "device_type": d.device_type,
        "custom_name": d.custom_name, "notes": d.notes,
        "online": d.online, "first_seen": d.first_seen, "last_seen": d.last_seen,
        "services": [{"proto": s.proto, "port": s.port, "name": s.name,
                      "banner": s.banner, "extra": s.extra} for s in d.services],
    } for d in devs]
