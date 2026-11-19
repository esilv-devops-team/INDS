from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from backend.database.models import Device, Incident
from backend.database.session import create_database_engine
from backend.services.device_inventory import get_all_devices, save_observation, save_observations


def test_new_device_is_created(database):
    engine, _, _ = database
    with Session(engine) as session:
        is_new = save_observation(session, "b8-27-eb-12-34-56", "192.168.1.20", "pi")
        session.commit()

        device = session.scalar(select(Device))
        assert is_new
        assert device.mac_address == "B8:27:EB:12:34:56"
        assert device.current_ip == "192.168.1.20"
        assert device.hostname == "pi"
        assert device.vendor == "Raspberry Pi Foundation"


def test_same_mac_updates_device(database):
    engine, _, _ = database
    with Session(engine) as session:
        save_observation(session, "B8:27:EB:12:34:56", "192.168.1.20", "pi")
        session.commit()
        first_seen = session.scalar(select(Device)).first_seen_at

        is_new = save_observation(session, "B8:27:EB:12:34:56", "192.168.1.21")
        session.commit()

        devices = session.scalars(select(Device)).all()
        assert not is_new
        assert len(devices) == 1
        assert devices[0].current_ip == "192.168.1.21"
        assert devices[0].hostname == "pi"
        assert devices[0].first_seen_at == first_seen
        assert devices[0].last_seen_at >= first_seen


def test_save_many(database):
    engine, _, _ = database
    with Session(engine) as session:
        new_count = save_observations(session, [
            {"mac": "00:11:22:33:44:01"},
            {"mac": "00:11:22:33:44:02", "ip": "192.168.1.30"},
            {"mac": "00:11:22:33:44:01"},
        ])
        assert new_count == 2
        assert len(get_all_devices(session)) == 2


def test_inventory_survives_restart(database):
    engine, _, _ = database
    with Session(engine) as session:
        save_observations(session, [{"mac": "B8:27:EB:12:34:56", "ip": "192.168.1.20"}])
    engine.dispose()

    new_engine = create_database_engine()
    with Session(new_engine) as session:
        device = session.scalar(select(Device))
        assert device.mac_address == "B8:27:EB:12:34:56"
        assert device.current_ip == "192.168.1.20"
    new_engine.dispose()


def test_inventory_counts_incidents_without_loading_history(database):
    engine, _, _ = database
    with Session(engine) as session, session.begin():
        device = Device(mac_address="00:11:22:33:44:01")
        session.add(Incident(
            source_device=device, source_ip="192.0.2.1", target_ip="192.0.2.2",
            rule_code="port_scan", status="investigating",
        ))
        session.add(Device(mac_address="00:11:22:33:44:02"))

    with Session(engine) as session:
        devices = get_all_devices(session)
        assert {device.mac_address: device.open_incidents for device in devices} == {
            "00:11:22:33:44:01": 1,
            "00:11:22:33:44:02": 0,
        }
        assert all("incidents" in inspect(device).unloaded for device in devices)
