from sqlalchemy import func, select
from sqlalchemy.orm import with_expression

from backend.database.base import utc_now
from backend.database.models import Device, Incident
from backend.services.vendor_lookup import lookup_vendor, normalize_mac


ADDRESS_CONFIDENCE = {None: 0, "arp": 1, "neighbor": 2, "dhcp_lease": 3}


def clear_address(device):
    device.current_ip = device.ip_source = device.ip_expires_at = None


def save_observation(session, mac, ip=None, hostname=None, source=None, expires_at=None):
    mac = normalize_mac(mac)
    now = utc_now()

    device = session.scalar(select(Device).where(Device.mac_address == mac))
    is_new = device is None
    if is_new:
        device = Device(mac_address=mac, vendor=lookup_vendor(mac), first_seen_at=now)
        session.add(device)

    if source != "dhcp_lease":
        device.last_seen_at = now
        device.last_active_at = now
    if ip:
        if device.ip_expires_at and device.ip_expires_at <= now:
            clear_address(device)
        confidence = ADDRESS_CONFIDENCE[source]
        if confidence >= ADDRESS_CONFIDENCE[device.ip_source]:
            owners = [] if source is None else session.scalars(
                select(Device).where(Device.current_ip == ip, Device.mac_address != mac)
            ).all()
            for owner in owners:
                if owner.ip_expires_at and owner.ip_expires_at <= now:
                    clear_address(owner)
            if all(confidence > ADDRESS_CONFIDENCE[owner.ip_source]
                   or (source == owner.ip_source == "dhcp_lease") for owner in owners):
                for owner in owners:
                    clear_address(owner)
                device.current_ip = ip
                device.ip_source = source
                device.ip_expires_at = expires_at
    if hostname:
        device.hostname = hostname

    return is_new


def expire_addresses(session, now):
    for device in session.scalars(select(Device).where(Device.ip_expires_at <= now)):
        clear_address(device)


def save_observations(session, observations):
    new_count = 0
    for obs in observations:
        if save_observation(session, obs["mac"], obs.get("ip"), obs.get("hostname")):
            new_count += 1
    session.commit()
    return new_count


def get_all_devices(session):
    return session.scalars(
        select(Device).options(active_incident_counts()).order_by(Device.last_seen_at.desc(), Device.id)
    ).all()


def get_device_with_incident_count(session, device_id):
    return session.get(Device, device_id, options=(active_incident_counts(),))


def active_incident_counts():
    count = (
        select(func.count(Incident.id))
        .where(Incident.source_device_id == Device.id, Incident.status != "resolved")
        .correlate(Device)
        .scalar_subquery()
    )
    return with_expression(Device._open_incident_count, count)
