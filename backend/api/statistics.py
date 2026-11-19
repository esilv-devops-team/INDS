from typing import Literal

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.models import Administrator
from backend.database.session import get_session
from backend.services.statistics import build_statistics

router = APIRouter(prefix="/api/statistics", tags=["statistics"])


@router.get("")
def get_statistics(
    window: Literal["1h", "24h", "7d"] = "24h",
    session: Session = Depends(get_session),
    admin: Administrator = Depends(get_current_admin),
):
    return build_statistics(session, window)