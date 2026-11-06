"""Device endpoints (INDS-40, INDS-41)."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, IPvAnyAddress, field_validator
from sqlalchemy.orm import Session

from backend.database.models import Device
from backend.database.session import get_session
from backend.services.device_inventory import get_all_devices, save_observations
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


@router.get("/vendor/{mac}")
def get_vendor(mac: str):
    try:
        normalized = normalize_mac(mac)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid MAC address")
    return {"mac": normalized, "vendor": lookup_vendor(normalized)}


@router.post("/observations")
def post_observations(data: ObservationList, session: Session = Depends(get_session)):
    observations = []
    for obs in data.observations:
        ip = str(obs.ip) if obs.ip else None
        observations.append({"mac": obs.mac, "ip": ip, "hostname": obs.hostname})

    new_count = save_observations(session, observations)
    return {"received": len(observations), "new": new_count}


@router.get("", response_model=list[DeviceOut])
def list_devices(session: Session = Depends(get_session)):
    return get_all_devices(session)


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, session: Session = Depends(get_session)):
    device = session.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device