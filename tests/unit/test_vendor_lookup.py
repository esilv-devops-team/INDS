"""Unit tests for backend/services/vendor_lookup.py (INDS-40)."""

import pytest

from backend.services.vendor_lookup import is_randomized, lookup_vendor, normalize_mac


def test_known_vendor():
    assert lookup_vendor("B8:27:EB:12:34:56") == "Raspberry Pi Foundation"


def test_dash_and_lowercase_format_is_accepted():
    assert lookup_vendor("b8-27-eb-12-34-56") == "Raspberry Pi Foundation"


def test_unknown_vendor():
    assert lookup_vendor("00:11:22:33:44:55") == "Unknown"


def test_randomized_mac():
    # 0xDA = 1101 1010 -> "locally administered" bit is set
    assert is_randomized("DA:A1:19:00:00:01") is True
    assert lookup_vendor("DA:A1:19:00:00:01") == "Randomized"


def test_real_mac_is_not_randomized():
    assert is_randomized("B8:27:EB:12:34:56") is False


def test_normalize_mac():
    assert normalize_mac(" aa-bb-cc-dd-ee-ff ") == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize("bad", ["", "B8:27:EB", "B8:27:EB:12:34:5G", "hello", "B8:27:EB:12:34:56:78"])
def test_invalid_mac_is_rejected(bad):
    with pytest.raises(ValueError):
        lookup_vendor(bad)