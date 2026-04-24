"""SQLite schema, connection, and migrations."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from ..config import db_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mac          TEXT UNIQUE,
    ip           TEXT,
    hostname     TEXT,
    vendor       TEXT,
    os_hint      TEXT,
    device_type  TEXT,
    custom_name  TEXT,
    notes        TEXT,
    first_seen   TEXT,
    last_seen    TEXT,
    online       INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    proto       TEXT NOT NULL,
    port        INTEGER,
    name        TEXT,
    banner      TEXT,
    extra_json  TEXT,
    UNIQUE(device_id, proto, port, name)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    subnet       TEXT,
    host_count   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_run_id  INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
    ip           TEXT,
    online       INTEGER,
    seen_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_device ON device_history(device_id);
"""


def connect(path: Optional[Path] = None) -> sqlite3.Connection:
    p = Path(path) if path else db_path()
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(path: Optional[Path] = None) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
