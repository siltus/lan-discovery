"""Repository: CRUD + upsert/merge logic for devices and services."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Iterable, Optional

from .models import Device, ScanRun, Service


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row_to_device(row: sqlite3.Row) -> Device:
    return Device(
        id=row["id"], mac=row["mac"], ip=row["ip"],
        hostname=row["hostname"], vendor=row["vendor"],
        os_hint=row["os_hint"], device_type=row["device_type"],
        custom_name=row["custom_name"], notes=row["notes"],
        first_seen=row["first_seen"], last_seen=row["last_seen"],
        online=bool(row["online"]),
    )


class Repo:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # -------- scan runs --------
    def start_scan(self, subnet: str) -> ScanRun:
        cur = self.conn.execute(
            "INSERT INTO scan_runs(started_at, subnet) VALUES(?, ?)",
            (_now(), subnet),
        )
        self.conn.commit()
        return ScanRun(id=cur.lastrowid, started_at=_now(), subnet=subnet)

    def finish_scan(self, run: ScanRun, host_count: int) -> None:
        self.conn.execute(
            "UPDATE scan_runs SET finished_at=?, host_count=? WHERE id=?",
            (_now(), host_count, run.id),
        )
        self.conn.commit()

    # -------- devices --------
    def upsert_device(self, dev: Device, scan_run_id: Optional[int] = None) -> Device:
        """Insert-or-merge using MAC as primary identity, falling back to IP."""
        now = _now()
        existing: Optional[sqlite3.Row] = None
        if dev.mac:
            existing = self.conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (dev.mac,)
            ).fetchone()
        if existing is None and dev.ip:
            # Match a MAC-less prior record on same IP, to be promoted on first MAC sighting.
            existing = self.conn.execute(
                "SELECT * FROM devices WHERE mac IS NULL AND ip = ?", (dev.ip,)
            ).fetchone()

        if existing is None:
            cur = self.conn.execute(
                """INSERT INTO devices(mac, ip, hostname, vendor, os_hint, device_type,
                                       custom_name, notes, first_seen, last_seen, online)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (dev.mac, dev.ip, dev.hostname, dev.vendor, dev.os_hint, dev.device_type,
                 dev.custom_name, dev.notes, now, now, int(dev.online)),
            )
            dev.id = cur.lastrowid
            dev.first_seen = now
            dev.last_seen = now
        else:
            dev.id = existing["id"]
            merged = {
                "mac": dev.mac or existing["mac"],
                "ip": dev.ip or existing["ip"],
                "hostname": dev.hostname or existing["hostname"],
                "vendor": dev.vendor or existing["vendor"],
                "os_hint": dev.os_hint or existing["os_hint"],
                "device_type": dev.device_type or existing["device_type"],
                # Never overwrite user annotations.
                "custom_name": existing["custom_name"] or dev.custom_name,
                "notes": existing["notes"] or dev.notes,
                "last_seen": now,
                "online": int(dev.online),
            }
            self.conn.execute(
                """UPDATE devices SET mac=?, ip=?, hostname=?, vendor=?, os_hint=?,
                       device_type=?, custom_name=?, notes=?, last_seen=?, online=?
                   WHERE id=?""",
                (merged["mac"], merged["ip"], merged["hostname"], merged["vendor"],
                 merged["os_hint"], merged["device_type"], merged["custom_name"],
                 merged["notes"], merged["last_seen"], merged["online"], dev.id),
            )
            dev.first_seen = existing["first_seen"]
            dev.last_seen = now
            dev.custom_name = merged["custom_name"]
            dev.notes = merged["notes"]

        for svc in dev.services:
            self.upsert_service(dev.id, svc)

        if scan_run_id is not None:
            self.conn.execute(
                "INSERT INTO device_history(device_id, scan_run_id, ip, online, seen_at) VALUES(?,?,?,?,?)",
                (dev.id, scan_run_id, dev.ip, int(dev.online), now),
            )
        self.conn.commit()
        return dev

    def upsert_service(self, device_id: int, svc: Service) -> None:
        self.conn.execute(
            """INSERT INTO services(device_id, proto, port, name, banner, extra_json)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(device_id, proto, port, name) DO UPDATE SET
                 banner=excluded.banner, extra_json=excluded.extra_json""",
            (device_id, svc.proto, svc.port, svc.name, svc.banner,
             json.dumps(svc.extra) if svc.extra else None),
        )

    def list_devices(self, online_only: bool = False, device_type: Optional[str] = None) -> list[Device]:
        q = "SELECT * FROM devices"
        clauses, params = [], []
        if online_only:
            clauses.append("online = 1")
        if device_type:
            clauses.append("device_type = ?")
            params.append(device_type)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY ip"
        rows = self.conn.execute(q, params).fetchall()
        devs = [_row_to_device(r) for r in rows]
        for d in devs:
            d.services = self.list_services(d.id)
        return devs

    def list_services(self, device_id: int) -> list[Service]:
        rows = self.conn.execute(
            "SELECT proto, port, name, banner, extra_json FROM services WHERE device_id=?",
            (device_id,),
        ).fetchall()
        out: list[Service] = []
        for r in rows:
            extra = json.loads(r["extra_json"]) if r["extra_json"] else {}
            out.append(Service(proto=r["proto"], port=r["port"],
                               name=r["name"] or "", banner=r["banner"] or "",
                               extra=extra))
        return out

    def get_device(self, key: str | int) -> Optional[Device]:
        if isinstance(key, int) or (isinstance(key, str) and key.isdigit()):
            row = self.conn.execute("SELECT * FROM devices WHERE id=?", (int(key),)).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM devices WHERE mac=? OR ip=?", (key.lower(), key)
            ).fetchone()
        if not row:
            return None
        d = _row_to_device(row)
        d.services = self.list_services(d.id)
        return d

    def set_custom_name(self, device_id: int, name: Optional[str]) -> None:
        self.conn.execute("UPDATE devices SET custom_name=? WHERE id=?", (name, device_id))
        self.conn.commit()

    def set_notes(self, device_id: int, notes: Optional[str]) -> None:
        self.conn.execute("UPDATE devices SET notes=? WHERE id=?", (notes, device_id))
        self.conn.commit()

    def mark_all_offline(self) -> None:
        self.conn.execute("UPDATE devices SET online=0")
        self.conn.commit()
