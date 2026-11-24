"""Пароли, JWT, токены агентов, проверка прав, журнал аудита."""
import os, time, hmac, hashlib, secrets
import jwt
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session
from .db import get_db
from . import models as m

SECRET = os.environ.get("ITMON_SECRET", "dev-secret-change-me-please-0123456789")
TOKEN_TTL = 8 * 3600

# Все права системы (код -> описание)
PERMISSIONS = {
    "view_devices": "Құрылғыларды, метрикаларды және командаларды көру",
    "run_diagnostics": "Қауіпсіз диагностикалық командаларды жіберу",
    "manage_devices": "Агенттерді және шекті мәндерді басқару",
    "manage_users": "Пайдаланушылар мен рөлдерді басқару",
    "view_audit": "Әрекеттер журналын көру",
    "export_reports": "Есептерді жүктеп алу",
    "power_control": "Қайта жүктеу және өшіру (4-кезең)",
    "terminal": "Қашықтан терминал (4-кезең)",
    "files_view": "Файлдарды көру (5-кезең)",
    "files_delete": "Файлдарды жою (5-кезең)",
}


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2 ** 14, r=8, p=1)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def create_token(user_id: int) -> str:
    return jwt.encode({"sub": str(user_id), "exp": int(time.time()) + TOKEN_TTL}, SECRET, algorithm="HS256")


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_agent_token() -> str:
    return secrets.token_urlsafe(32)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def audit(db: Session, request: Request | None, user: "m.User | None", action: str, target: str = "", details: str = "", username: str = ""):
    db.add(m.AuditLog(user_id=user.id if user else None, username=user.username if user else username,
                      action=action, target=target, details=details, ip=client_ip(request) if request else ""))
    db.commit()


def current_user(authorization: str | None = Header(None), db: Session = Depends(get_db)) -> m.User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Жүйеге кіру қажет")
    try:
        data = jwt.decode(authorization[7:], SECRET, algorithms=["HS256"])
        user = db.get(m.User, int(data["sub"]))
    except Exception:
        raise HTTPException(401, "Сессия жарамсыз")
    if not user or not user.active:
        raise HTTPException(401, "Пайдаланушы өшірілген")
    return user


def user_perms(user: m.User) -> set[str]:
    return {p.code for p in user.role.permissions}


def require(perm: str):
    """Зависимость FastAPI: пропускает только пользователей с нужным правом."""
    def dep(user: m.User = Depends(current_user)) -> m.User:
        if perm not in user_perms(user):
            raise HTTPException(403, f"Құқық жоқ: {perm}")
        return user
    return dep


def current_agent(x_agent_token: str | None = Header(None), db: Session = Depends(get_db)) -> m.Agent:
    if not x_agent_token:
        raise HTTPException(401, "Агент токені жоқ")
    agent = db.query(m.Agent).filter_by(token_hash=hash_agent_token(x_agent_token)).first()
    if not agent or agent.revoked:
        raise HTTPException(401, "Агент токені жарамсыз")
    return agent
