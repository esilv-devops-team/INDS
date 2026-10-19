"""Device manufacturer lookup from MAC addresses (INDS-40).

The first 3 bytes of a MAC address (the OUI) identify the manufacturer.
This small table covers common devices on the test network; it can be
replaced later by the full IEEE OUI list.
"""

import re

OUI_VENDORS = {
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "00:03:93": "Apple",
    "00:1C:B3": "Apple",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "44:65:0D": "Amazon",
    "00:16:6C": "Samsung",
    "28:57:BE": "Hikvision",
    "08:00:27": "VirtualBox",
    "00:50:56": "VMware",
}

MAC_PATTERN = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def normalize_mac(mac):
    """Return the MAC in the form AA:BB:CC:DD:EE:FF, or raise ValueError."""
    cleaned = mac.strip().upper().replace("-", ":")
    if not MAC_PATTERN.match(cleaned):
        raise ValueError(f"invalid MAC address: {mac}")
    return cleaned


def is_randomized(mac):
    """True if the MAC is locally administered (random private address).

    Phones and laptops use these to hide their real MAC. The flag is the
    second lowest bit of the first byte.
    """
    first_byte = int(normalize_mac(mac)[:2], 16)
    return bool(first_byte & 0x02)


def lookup_vendor(mac):
    """Return the manufacturer name, "Randomized" or "Unknown"."""
    normalized = normalize_mac(mac)
    if is_randomized(normalized):
        return "Randomized"
    return OUI_VENDORS.get(normalized[:8], "Unknown")