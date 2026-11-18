from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.models import Administrator
from backend.database.session import get_session
from backend.services.gateway_health import collect_health

router = APIRouter(prefix="/api/gateway", tags=["gateway"])


@router.get("/health")
def gateway_health(session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    return collect_health(session)