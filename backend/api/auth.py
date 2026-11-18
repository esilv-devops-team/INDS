import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.base import utc_now
from backend.database.models import Administrator
from backend.database.session import get_session
from backend.services import auth
from backend.services.audit import record_event

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE_NAME = "inds_session"
COOKIE_SECURE = os.environ.get("INDS_COOKIE_SECURE") == "1"


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=72)


class AdminOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    created_at: datetime
    last_login_at: datetime | None


def set_session_cookie(response, admin_id):
    response.set_cookie(
        COOKIE_NAME,
        auth.create_token(admin_id),
        max_age=auth.SESSION_MINUTES * 60,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
    )


def get_current_admin(request: Request, response: Response, session: Session = Depends(get_session)):
    token = request.cookies.get(COOKIE_NAME)
    admin_id = auth.read_token(token) if token else None
    admin = session.get(Administrator, admin_id) if admin_id else None
    if admin is None or not admin.is_active:
        raise HTTPException(status_code=401, detail="not logged in")
    set_session_cookie(response, admin.id)
    return admin


@router.post("/setup", status_code=201, response_model=AdminOut)
def setup(data: Credentials, response: Response, session: Session = Depends(get_session)):
    if session.scalar(select(func.count(Administrator.id))) > 0:
        raise HTTPException(status_code=409, detail="an administrator already exists")

    admin = Administrator(username=data.username, password_hash=auth.hash_password(data.password))
    session.add(admin)
    session.flush()
    record_event(session, "admin.setup", admin=admin)
    session.commit()
    set_session_cookie(response, admin.id)
    return admin


@router.post("/login", response_model=AdminOut)
def login(data: Credentials, response: Response, session: Session = Depends(get_session)):
    username = data.username.lower()
    if auth.is_locked(username):
        raise HTTPException(status_code=429, detail="too many failed attempts, try again later")

    admin = session.scalar(select(Administrator).where(Administrator.username == username))
    if admin is None or not admin.is_active or not auth.check_password(data.password, admin.password_hash):
        auth.register_failure(username)
        record_event(session, "admin.login", outcome="failure", details={"username": username})
        session.commit()
        raise HTTPException(status_code=401, detail="wrong username or password")

    auth.clear_failures(username)
    admin.last_login_at = utc_now()
    record_event(session, "admin.login", admin=admin)
    session.commit()
    set_session_cookie(response, admin.id)
    return admin


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"message": "logged out"}


@router.get("/me", response_model=AdminOut)
def me(admin: Administrator = Depends(get_current_admin)):
    return admin