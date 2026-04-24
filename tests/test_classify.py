from landiscovery.fingerprint.classify import Signals, classify


def test_classify_router_by_keyword():
    assert classify(Signals(hostname="router-home")) == "router"
    assert classify(Signals(ssdp_friendly_name="Mikrotik Gateway")) == "router"


def test_classify_printer_by_port():
    assert classify(Signals(open_ports=[9100])) == "printer"
    assert classify(Signals(open_ports=[631])) == "printer"


def test_classify_camera_rtsp():
    assert classify(Signals(open_ports=[554])) == "camera"


def test_classify_iot_by_vendor():
    assert classify(Signals(vendor="Espressif Inc.")) == "iot"


def test_classify_smart_tv_by_mdns():
    assert classify(Signals(mdns_services=["_googlecast._tcp.local."])) == "smart-tv"


def test_classify_unknown():
    assert classify(Signals()) == "unknown"


def test_classify_gateway_flag_wins():
    assert classify(Signals(is_gateway=True, vendor="Cisco")) == "router"


def test_apple_with_airplay_is_computer_not_tv():
    # Mac Studio advertises AirPlay receiver; should not be classified as smart-tv.
    assert classify(Signals(
        vendor="Apple, Inc.",
        hostname="ss-mac-studio",
        mdns_services=["_airplay._tcp.local.", "_raop._tcp.local.", "_ssh._tcp.local."],
        open_ports=[22, 445, 5000],
    )) == "computer"


def test_iphone_classified_as_phone():
    assert classify(Signals(vendor="Apple, Inc.", hostname="alice-iphone")) == "phone"


def test_appletv_still_tv():
    assert classify(Signals(vendor="Apple, Inc.", hostname="living-appletv")) == "smart-tv"


def test_tv_substring_does_not_match_studio():
    # 'tv' inside 'studio' must not trigger smart-tv via word-boundary check.
    assert classify(Signals(hostname="studio-host")) != "smart-tv"
