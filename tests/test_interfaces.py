from landiscovery.config import EXCLUDED_IFACE_PATTERNS
from landiscovery.net import interfaces


def test_excluded_pattern_match():
    bad = ["vEthernet (Default Switch)", "vmnet8", "tun0", "ZeroTier One",
           "tailscale0", "docker0", "br-abc123"]
    for n in bad:
        assert interfaces._is_excluded(n), n


def test_score_prefers_192168():
    import ipaddress
    a = ipaddress.IPv4Network("192.168.1.0/24")
    b = ipaddress.IPv4Network("10.0.0.0/24")
    c = ipaddress.IPv4Network("172.16.0.0/24")
    assert interfaces._score(a) > interfaces._score(b) > interfaces._score(c)
