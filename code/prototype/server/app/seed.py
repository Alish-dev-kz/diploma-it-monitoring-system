"""Начальные данные: права, роли, администратор."""
import os
from sqlalchemy.orm import Session
from . import models as m
from .security import PERMISSIONS, hash_password

EMPLOYEE_PERMS = ["view_devices", "run_diagnostics"]
DEFAULT_THRESHOLDS = {"cpu": (80, 95, 3), "ram": (85, 95, 3), "disk": (85, 95, 3), "temp": (75, 90, 2)}


def seed(db: Session):
    perms = {p.code: p for p in db.query(m.Permission)}
    for code, desc in PERMISSIONS.items():
        if code not in perms:
            perms[code] = m.Permission(code=code, description=desc)
            db.add(perms[code])
        else:
            perms[code].description = desc
    db.flush()
    admin_role = db.query(m.Role).filter_by(name="Администратор").first()
    if not admin_role:
        admin_role = m.Role(name="Администратор", is_system=True)
        db.add(admin_role)
    admin_role.permissions = list(perms.values())  # админ всегда имеет все права
    if not db.query(m.Role).filter_by(name="Сотрудник").first():
        db.add(m.Role(name="Сотрудник", permissions=[perms[c] for c in EMPLOYEE_PERMS]))
    db.flush()
    for metric, (warn, crit, n) in DEFAULT_THRESHOLDS.items():
        if not db.get(m.Threshold, metric):
            db.add(m.Threshold(metric=metric, warn=warn, crit=crit, consecutive=n))
    if not db.query(m.User).first():
        pwd = os.environ.get("ITMON_ADMIN_PASSWORD", "admin123")
        db.add(m.User(username="admin", password_hash=hash_password(pwd), role_id=admin_role.id))
        print("[ITMon] admin пайдаланушысы құрылды (құпия сөз ITMON_ADMIN_PASSWORD-тан, әдепкі admin123). Оны міндетті түрде ауыстырыңыз!")
    db.commit()
