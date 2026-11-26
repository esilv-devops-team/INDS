from datetime import timedelta
from ipaddress import IPv4Interface

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Device
from backend.services.device_inventory import expire_addresses, save_observation
from backend.services.monitoring import routed_observations
from gateway.discovery import read_leases

FIRST = "02:00:00:00:00:01"
SECOND = "02:00:00:00:00:02"
ADDRESS = "192.168.50.101"


def test_lease_presence_and_reassignment(database):
    now = utc_now()
    with Session(database[0]) as session:
        save_observation(session, FIRST, ADDRESS, source="dhcp_lease", expires_at=now + timedelta(minutes=1))
        first = session.scalar(select(Device).where(Device.mac_address == FIRST))
        assert first.last_active_at is None
        save_observation(session, SECOND, ADDRESS, source="arp")
        second = session.scalar(select(Device).where(Device.mac_address == SECOND))
        assert second.current_ip is None
        assert second.last_active_at is not None
        save_observation(session, SECOND, ADDRESS, source="dhcp_lease", expires_at=now + timedelta(minutes=2))
        assert first.current_ip is None
        assert second.current_ip == ADDRESS
        expire_addresses(session, now + timedelta(minutes=3))
        assert second.current_ip is None
        assert second.last_active_at is not None


def test_lease_parser_and_routed_packet_filter(tmp_path):
    path = tmp_path / "dnsmasq.leases"
    path.write_text(f"0 {FIRST} {ADDRESS} phone *\n1 {SECOND} {ADDRESS} * *\ninvalid\n")
    now = utc_now()
    assert [lease["mac"] for lease in read_leases(path, now)] == [FIRST]
    packets = {
        FIRST: dict(mac=FIRST, ip=ADDRESS, hostname="phone", source="dhcp_request"),
        SECOND: dict(mac=SECOND, ip="192.168.50.1", hostname=None, source="arp"),
    }
    observations = list(routed_observations(
        "eth1", IPv4Interface("192.168.50.1/24"), packets, now, snapshot=False,
    ))
    assert [item["mac"] for item in observations] == [FIRST]
    assert observations[0]["ip"] is None
