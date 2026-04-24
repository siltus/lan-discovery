import sqlite3
from pathlib import Path

from landiscovery.store import db
from landiscovery.store.models import Device, Service
from landiscovery.store.repo import Repo


def _repo(tmp_path: Path) -> Repo:
    conn = db.init_db(tmp_path / "test.sqlite")
    return Repo(conn)


def test_insert_then_merge_by_mac(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_device(Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01",
                              hostname="firstname"))
    repo.upsert_device(Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01",
                              vendor="Acme"))
    devs = repo.list_devices()
    assert len(devs) == 1
    assert devs[0].vendor == "Acme"
    assert devs[0].hostname == "firstname"


def test_promote_macless_record(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_device(Device(ip="192.168.1.20"))
    repo.upsert_device(Device(ip="192.168.1.20", mac="11:22:33:44:55:66"))
    devs = repo.list_devices()
    assert len(devs) == 1
    assert devs[0].mac == "11:22:33:44:55:66"


def test_user_annotation_not_overwritten(tmp_path):
    repo = _repo(tmp_path)
    d = repo.upsert_device(Device(ip="192.168.1.30", mac="aa:bb:cc:dd:ee:30"))
    repo.set_custom_name(d.id, "Living room TV")
    repo.set_notes(d.id, "Alice's TV")
    repo.upsert_device(Device(ip="192.168.1.30", mac="aa:bb:cc:dd:ee:30",
                              custom_name="should not overwrite", notes="ignored"))
    got = repo.get_device(d.id)
    assert got.custom_name == "Living room TV"
    assert got.notes == "Alice's TV"


def test_services_persist_unique(tmp_path):
    repo = _repo(tmp_path)
    d = Device(ip="192.168.1.40", mac="aa:bb:cc:dd:ee:40", services=[
        Service(proto="tcp", port=80, name="http", banner="nginx"),
        Service(proto="tcp", port=80, name="http", banner="nginx-updated"),
        Service(proto="mdns", port=None, name="_airplay._tcp.local."),
    ])
    repo.upsert_device(d)
    got = repo.get_device(d.id)
    names = sorted((s.proto, s.port, s.name) for s in got.services)
    assert names == [("mdns", None, "_airplay._tcp.local."), ("tcp", 80, "http")]
    http = next(s for s in got.services if s.proto == "tcp")
    assert http.banner == "nginx-updated"
