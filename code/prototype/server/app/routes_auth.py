"""Вход, пользователи, роли."""
import time
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from .db import get_db
from . import models as m
from .security import (PERMISSIONS, audit, create_token, current_user, hash_password, require,
                       user_perms, verify_password)

router = APIRouter(prefix="/api")
_fails: dict[str, list[float]] = defaultdict(list)  # защита от подбора пароля


class LoginIn(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=100)
    role_id: int


class UserPatch(BaseModel):
    role_id: int | None = None
    active: bool | None = None
    password: str | None = Field(None, min_length=6, max_length=100)


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    permissions: list[str]


def user_out(u: m.User):
    return {"id": u.id, "username": u.username, "active": u.active, "role_id": u.role_id,
            "role": u.role.name, "permissions": sorted(user_perms(u))}


@router.post("/auth/login")
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    key = data.username.lower()
    now = time.time()
    _fails[key] = [t for t in _fails[key] if now - t < 60]
    if len(_fails[key]) >= 5:
        raise HTTPException(429, "Әрекет тым көп, бір минут күтіңіз")
    user = db.query(m.User).filter_by(username=data.username).first()
    if not user or not user.active or not verify_password(data.password, user.password_hash):
        _fails[key].append(now)
        audit(db, request, None, "login_failed", data.username[:50], username=data.username[:50])
        raise HTTPException(401, "Логин немесе құпия сөз қате")
    audit(db, request, user, "login")
    return {"token": create_token(user.id), "user": user_out(user)}


@router.get("/auth/me")
def me(user: m.User = Depends(current_user)):
    return user_out(user)


@router.get("/permissions")
def permissions(user: m.User = Depends(require("manage_users"))):
    return PERMISSIONS


@router.get("/roles")
def roles(user: m.User = Depends(require("manage_users")), db: Session = Depends(get_db)):
    return [{"id": r.id, "name": r.name, "is_system": r.is_system,
             "permissions": sorted(p.code for p in r.permissions)} for r in db.query(m.Role).order_by(m.Role.id)]


def _perm_objects(db: Session, codes: list[str]):
    unknown = set(codes) - set(PERMISSIONS)
    if unknown:
        raise HTTPException(400, f"Белгісіз құқықтар: {sorted(unknown)}")
    return db.query(m.Permission).filter(m.Permission.code.in_(codes)).all()


@router.post("/roles", status_code=201)
def create_role(data: RoleIn, request: Request, user: m.User = Depends(require("manage_users")), db: Session = Depends(get_db)):
    if db.query(m.Role).filter_by(name=data.name).first():
        raise HTTPException(409, "Мұндай атаумен рөл бар")
    role = m.Role(name=data.name, permissions=_perm_objects(db, data.permissions))
    db.add(role); db.commit()
    audit(db, request, user, "role_create", data.name, ",".join(data.permissions))
    return {"id": role.id}


@router.put("/roles/{role_id}")
def update_role(role_id: int, data: RoleIn, request: Request, user: m.User = Depends(require("manage_users")), db: Session = Depends(get_db)):
    role = db.get(m.Role, role_id)
    if not role:
        raise HTTPException(404, "Рөл табылмады")
    if role.is_system:
        raise HTTPException(400, "Жүйелік рөлді өзгертуге болмайды")
    role.name = data.name
    role.permissions = _perm_objects(db, data.permissions)
    db.commit()
    audit(db, request, user, "role_update", role.name, ",".join(data.permissions))
    return {"ok": True}


@router.get("/users")
def users(user: m.User = Depends(require("manage_users")), db: Session = Depends(get_db)):
    return [user_out(u) for u in db.query(m.User).order_by(m.User.id)]


@router.post("/users", status_code=201)
def create_user(data: UserIn, request: Request, user: m.User = Depends(require("manage_users")), db: Session = Depends(get_db)):
    if db.query(m.User).filter_by(username=data.username).first():
        raise HTTPException(409, "Бұл логин бос емес")
    if not db.get(m.Role, data.role_id):
        raise HTTPException(400, "Рөл табылмады")
    u = m.User(username=data.username, password_hash=hash_password(data.password), role_id=data.role_id)
    db.add(u); db.commit()
    audit(db, request, user, "user_create", data.username)
    return {"id": u.id}


@router.patch("/users/{user_id}")
def patch_user(user_id: int, data: UserPatch, request: Request, user: m.User = Depends(require("manage_users")), db: Session = Depends(get_db)):
    u = db.get(m.User, user_id)
    if not u:
        raise HTTPException(404, "Пайдаланушы табылмады")
    if u.id == user.id and (data.active is False or (data.role_id and data.role_id != u.role_id)):
        raise HTTPException(400, "Өзіңізді өшіруге немесе өз рөліңізді өзгертуге болмайды")
    changes = []
    if data.role_id is not None:
        if not db.get(m.Role, data.role_id):
            raise HTTPException(400, "Рөл табылмады")
        u.role_id = data.role_id; changes.append(f"role={data.role_id}")
    if data.active is not None:
        u.active = data.active; changes.append(f"active={data.active}")
    if data.password:
        u.password_hash = hash_password(data.password); changes.append("password")
    db.commit()
    audit(db, request, user, "user_update", u.username, ",".join(changes))
    return {"ok": True}
