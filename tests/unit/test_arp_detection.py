from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from scapy.all import ARP, Ether

from backend.services.arp_detection import evaluate_arp, parse_bindings
from detection.registry import arp_rules
from gateway.traffic import read_metadata

ROUTER = "02:00:00:00:00:01"
GUEST = "02:00:00:00:00:02"
ADDRESS = "192.0.2.1"
START = datetime(2026, 11, 20)


def claim(mac, ip=ADDRESS, operation=2):
    packet = Ether(bytes(Ether(src=mac, dst=ROUTER) / ARP(
        op=operation, hwsrc=mac, hwdst=ROUTER, psrc=ip, pdst="192.0.2.20",
    )))
    packet.sniffed_on = "ap0"
    packet.time = START.replace(tzinfo=UTC).timestamp() + 1
    return read_metadata(packet)


def test_conflicting_protected_claim_reports_evidence_and_deduplicates():
    engine = arp_rules({ADDRESS: ROUTER})
    metadata = claim(GUEST)
    finding, = evaluate_arp(engine, metadata, {}, START)
    assert finding.rule_id == "ARP_SPOOFING"
    assert finding.source_mac == GUEST
    assert finding.source_device_id is None
    assert finding.evidence == {"sender_ip": ADDRESS, "expected_mac": ROUTER, "claimed_mac": GUEST}
    assert finding.measured == {"arp_operation": 2}
    assert evaluate_arp(engine, metadata, {GUEST: 1}, START) == []
    another, = evaluate_arp(engine, claim("02:00:00:00:00:03"), {}, START)
    assert another.source_mac != finding.source_mac


def test_matching_claims_unprotected_changes_and_probes_are_ignored():
    engine = arp_rules({ADDRESS: ROUTER})
    for metadata in (claim(ROUTER), claim(GUEST, "192.0.2.9"), claim(GUEST, "0.0.0.0", 1),
                     claim(GUEST, operation=3), SimpleNamespace(protocol="TCP")):
        assert evaluate_arp(engine, metadata, {GUEST: 1}, START) == []
    finding, = evaluate_arp(engine, claim(GUEST, operation=1), {GUEST: 1}, START)
    assert finding.source_device_id == 1


def test_bindings_are_opt_in_and_normalize_mac():
    assert arp_rules(parse_bindings({})).rules == ()
    assert parse_bindings({ADDRESS: "02-00-00-00-00-01"}) == {ADDRESS: ROUTER}
    assert arp_rules({ADDRESS: ROUTER}, enabled=False).rules == ()
    rule, = arp_rules({ADDRESS: ROUTER}, severity="Critical", cooldown_seconds=60).rules
    assert (rule.info.severity, rule.info.cooldown_seconds) == ("Critical", 60)


@pytest.mark.parametrize("bindings", [{"::1": "02:00:00:00:00:01"}, {"192.0.2.1": "ff:ff:ff:ff:ff:ff"},
                                      {"192.0.2.1": "02:00:00:00:00:01", " 192.0.2.1": "02:00:00:00:00:02"},
                                      {"192.0.2.1": 5}, ["192.0.2.1"]])
def test_invalid_bindings_are_rejected(bindings):
    with pytest.raises(ValueError):
        parse_bindings(bindings)