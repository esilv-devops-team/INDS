from types import SimpleNamespace

import pytest

from backend.services.response_policy import assess_response


@pytest.mark.parametrize(("severity", "expected"), [
    ("Low", "observe"), ("Medium", "alert"), ("High", "block"), ("Critical", "temporary_block"),
])
def test_policy_reuses_incident_risk(severity, expected, monkeypatch):
    monkeypatch.setenv("INDS_ALLOW_BLOCK_PROPOSALS", "1")
    incident = SimpleNamespace(
        source_device=SimpleNamespace(mac_address="02:00:00:00:00:42", reported_ip="192.168.50.121",
                                      ip_source="dhcp_lease", is_trusted=False),
        severity=severity, status="open", evidence_json={"rule_severity": "Medium", "occurrences": 3},
    )
    result = assess_response(incident)
    assert result["rule_severity"] == "Medium"
    assert result["risk"] == severity.upper()
    assert result["recommendation"] == expected
    assert result["approval_required"] == (severity in ("High", "Critical"))
    incident.source_device.is_trusted = True
    assert not assess_response(incident)["approval_required"]
    incident.source_device.is_trusted = False
    incident.source_device.ip_source = "arp"
    assert not assess_response(incident)["approval_required"]
