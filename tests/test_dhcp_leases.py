import pytest

from landiscovery.discover.dhcp_leases import parse_isc, parse_macos


def test_parse_isc():
    text = """
    lease 192.168.1.50 {
      starts 1 2024/01/02 03:04:05;
      hardware ethernet aa:bb:cc:dd:ee:ff;
      client-hostname "myhost";
    }
    lease 192.168.1.51 {
      hardware ethernet 11:22:33:44:55:66;
    }
    """
    out = parse_isc(text)
    assert out["192.168.1.50"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert out["192.168.1.50"]["hostname"] == "myhost"
    assert out["192.168.1.51"]["mac"] == "11:22:33:44:55:66"
    assert out["192.168.1.51"]["hostname"] is None


def test_parse_macos():
    text = """{
        name=tv
        ip_address=192.168.1.20
        hw_address=1,aa:bb:cc:dd:ee:ff
        identifier=1,aa:bb:cc:dd:ee:ff
        lease=0x65a
    }"""
    out = parse_macos(text)
    assert "192.168.1.20" in out
    assert out["192.168.1.20"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert out["192.168.1.20"]["hostname"] == "tv"
