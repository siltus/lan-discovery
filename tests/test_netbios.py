import struct

from landiscovery.discover.netbios import _build_query, _parse_response


def test_build_query_shape():
    q = _build_query()
    assert len(q) == 12 + 34 + 4
    assert q.endswith(b"\x00\x21\x00\x01")


def _mk_response(host: str, group: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x4C44, 0x8400, 0, 1, 0, 0)
    name_field = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    type_class_ttl_rdlen = struct.pack(">HHIH", 0x0021, 0x0001, 0, 0)
    body = bytes([2])  # number of names
    # name 1: hostname, suffix 0x00, flags 0x0400 (unique, active)
    body += host.ljust(15).encode()[:15] + b"\x00" + struct.pack(">H", 0x0400)
    # name 2: workgroup, suffix 0x00, flags 0x8400 (group, active)
    body += group.ljust(15).encode()[:15] + b"\x00" + struct.pack(">H", 0x8400)
    return header + name_field + type_class_ttl_rdlen + body


def test_parse_response_extracts_names():
    data = _mk_response("MYPC", "WORKGROUP")
    nb = _parse_response(data)
    assert nb.hostname == "MYPC"
    assert nb.workgroup == "WORKGROUP"
