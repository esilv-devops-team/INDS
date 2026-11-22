from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from backend.api.auth import get_current_admin
from backend.database.models import Administrator
from backend.database.session import get_session
from backend.services.detection_rules import list_rules

router = APIRouter(prefix="/api/detection/rules", tags=["detection rules"])


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_code: str
    description: str
    enabled: bool
    severity: str
    cooldown_seconds: int
    settings: dict = Field(validation_alias="settings_json")
    updated_at: datetime


@router.get("", response_model=list[RuleOut])
def get_rules(session: Session = Depends(get_session), admin: Administrator = Depends(get_current_admin)):
    return list_rules(session)