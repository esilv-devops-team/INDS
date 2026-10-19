"""Device endpoints (INDS-40)."""

from fastapi import APIRouter, HTTPException

from backend.services.vendor_lookup import lookup_vendor, normalize_mac

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/vendor/{mac}")
def get_vendor(mac: str):
    try:
        normalized = normalize_mac(mac)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid MAC address")
    return {"mac": normalized, "vendor": lookup_vendor(normalized)}