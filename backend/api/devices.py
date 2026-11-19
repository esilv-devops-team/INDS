"""Device endpoints (INDS-40, INDS-41)."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, IPvAnyAddress, field_validator
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.models import Administrator, Device
from backend.database.session import get_session
from backend.services.audit import record_event
from backend.services.device_inventory import get_all_devices, save_observations
from backend.services.monitoring import configured_interface
from backend.services.statistics import StatisticsWindow
from backend.services.traffic_activity import device_rates, device_traffic_history
from backend.services.vendor_lookup import lookup_vendor, normalize_mac

router = APIRouter(prefix="/api/devices", tags=["devices"])


class Observation(BaseModel):
    mac: str
    ip: IPvAnyAddress | None = None
    hostname: str | None = None

    @field_validator("mac")
    @classmethod
    def check_mac(cls, value):
        return normalize_mac(value)


class ObservationList(BaseModel):
    observations: list[Observation]


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mac_address: str
    current_ip: str | None
    hostname: str | None
    vendor: str | None
    is_trusted: bool
    first_seen_at: datetime
    last_seen_at: datetime
    open_incidents: int

class DeviceUpdate(BaseModel):
    is_trusted: bool


class DeviceRates(BaseModel):
    window_start: datetime
    window_end: datetime
    upload_bps: float
    download_bps: float


@router.get("/vendor/{mac}")
def get_vendor(mac: str):
    try:
        normalized = normalize_mac(mac)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid MAC address")
    return {"mac": normalized, "vendor": lookup_vendor(normalized)}


@router.post("/observations")
def post_observations(data: ObservationList, session: Session = Depends(get_session)):
    if configured_interface():
        raise HTTPException(status_code=409, detail="device discovery is managed by monitoring")
    observations = []
    for obs in data.observations:
        ip = str(obs.ip) if obs.ip else None
        observations.append({"mac": obs.mac, "ip": ip, "hostname": obs.hostname})

    new_count = save_observations(session, observations)
    return {"received": len(observations), "new": new_count}


@router.get("", response_model=list[DeviceOut])
def list_devices(session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    return get_all_devices(session)


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    device = session.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device

@router.get("/{device_id}/traffic", response_model=DeviceRates)
def get_device_traffic(
    device_id: int,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    if session.get(Device, device_id) is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device_rates(session, device_id)


@router.get("/{device_id}/traffic/history")
def get_device_traffic_history(
    device_id: int,
    window: StatisticsWindow = "24h",
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    if session.get(Device, device_id) is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device_traffic_history(session, device_id, window)


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: int,
    data: DeviceUpdate,
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    device = session.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")

    if device.is_trusted != data.is_trusted:
        record_event(
            session, "device.trust_changed", admin=admin, device_id=device.id,
            details={"from": device.is_trusted, "to": data.is_trusted},
        )
        device.is_trusted = data.is_trusted
        session.commit()
    return device
