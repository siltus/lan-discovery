"""NetBIOS Name Service query (UDP 137) - hostname + workgroup."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class NBName:
    hostname: str = ""
    workgroup: str = ""


def _build_query() -> bytes:
    # NBSTAT query for "*"
    tid = 0x4C44
    flags = 0x0010  # broadcast
    qd = 1
    header = struct.pack(">HHHHHH", tid, flags, qd, 0, 0, 0)
    # encoded "*" + NULs (32 chars) -> 'CKAAAA...'
    name = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    qtype = 0x0021  # NBSTAT
    qclass = 0x0001
    return header + name + struct.pack(">HH", qtype, qclass)


def _parse_response(data: bytes) -> NBName:
    out = NBName()
    try:
        # Skip header(12) + name(34) + type(2) + class(2) + ttl(4) + rdlength(2) = 56
        idx = 56
        if len(data) < idx + 1:
            return out
        num = data[idx]
        idx += 1
        for _ in range(num):
            if idx + 18 > len(data):
                break
            name = data[idx:idx + 15].rstrip(b" \x00").decode(errors="ignore")
            suffix = data[idx + 15]
            flags = struct.unpack(">H", data[idx + 16:idx + 18])[0]
            idx += 18
            group = bool(flags & 0x8000)
            if suffix == 0x00 and not group and not out.hostname:
                out.hostname = name
            elif suffix == 0x00 and group and not out.workgroup:
                out.workgroup = name
    except Exception:
        pass
    return out


def query(ip: str, timeout: float = 1.0) -> Optional[NBName]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(_build_query(), (ip, 137))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
    nb = _parse_response(data)
    if not nb.hostname and not nb.workgroup:
        return None
    return nb
