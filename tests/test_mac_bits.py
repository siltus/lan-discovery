from landiscovery.fingerprint import oui


def test_lua_bit_detected():
    # 02:xx:xx:xx:xx:xx -> bit 1 set -> locally administered.
    assert oui.is_locally_administered("02:11:22:33:44:55")
    assert oui.is_locally_administered("56:75:52:02:e4:c7")  # user's example
    assert oui.is_locally_administered("DE:AD:BE:EF:00:01")
    # 10:a2:d3 -> universally administered.
    assert not oui.is_locally_administered("10:a2:d3:02:14:84")
    assert not oui.is_locally_administered("3C:22:FB:11:22:33")  # Apple


def test_lookup_labels_random_mac():
    assert oui.lookup("56:75:52:02:e4:c7") == "Randomized MAC (privacy)"


def test_multicast_detection():
    assert oui.is_multicast("01:00:5e:00:00:01")
    assert not oui.is_multicast("3c:22:fb:11:22:33")
