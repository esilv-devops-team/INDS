from sqlalchemy import select

from backend.database.base import utc_now
from backend.database.models import Device
from backend.services.vendor_lookup import lookup_vendor, normalize_mac


def save_observation(session, mac, ip=None, hostname=None):
    mac = normalize_mac(mac)
    now = utc_now()

    device = session.scalar(select(Device).where(Device.mac_address == mac))
    is_new = device is None
    if is_new:
        device = Device(mac_address=mac, vendor=lookup_vendor(mac), first_seen_at=now)
        session.add(device)

    device.last_seen_at = now
    if ip:
        device.current_ip = ip
    if hostname:
        device.hostname = hostname

    return is_new


def save_observations(session, observations):
    new_count = 0
    for obs in observations:
        if save_observation(session, obs["mac"], obs.get("ip"), obs.get("hostname")):
            new_count += 1
    session.commit()
    return new_count


def get_all_devices(session):
    return session.scalars(select(Device).order_by(Device.last_seen_at.desc())).all()