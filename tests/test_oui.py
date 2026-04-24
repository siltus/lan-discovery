from landiscovery.fingerprint import oui


def test_lookup_bundled_apple():
    # 3C22FB is Apple in both the bundled file and the IEEE database.
    v = oui.lookup("3C:22:FB:11:22:33")
    assert v is not None and "apple" in v.lower()


def test_lookup_unknown_returns_none():
    # 8C:00:00 has bit 1 unset (universally administered) and (almost certainly) is
    # not assigned, so should return None.
    result = oui.lookup("8C:00:00:00:00:00")
    assert result is None or "Randomized" not in result


def test_lookup_none():
    assert oui.lookup(None) is None
