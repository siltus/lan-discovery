from landiscovery.fingerprint.ttl import os_from_ttl


def test_ttl_linux():
    assert os_from_ttl(64) == "Linux/Unix"
    assert os_from_ttl(60) == "Linux/Unix"


def test_ttl_windows():
    assert os_from_ttl(128) == "Windows"
    assert os_from_ttl(120) == "Windows"


def test_ttl_network():
    assert os_from_ttl(255) == "Network device"


def test_ttl_none():
    assert os_from_ttl(None) is None
