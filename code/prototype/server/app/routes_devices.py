"""Құрылғылар: агенттерден метрика қабылдау, диагностика, команда кезегі, шекті мәндер, журнал."""
import os, time, hmac, uuid
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from .db import get_db
from . import models as m
from .security import audit, current_agent, hash_agent_token, new_agent_token, require

router = APIRouter(prefix="/api")
ENROLL_KEY = os.environ.get("ITMON_ENROLL_KEY", "enroll-dev")
ALLOWED_COMMANDS = {"top_processes", "disk_usage", "uptime", "ping_test"}  # whitelist
METRICS_KEEP_DAYS = 30
ONLINE_SEC = 30
# "difficult part": command lifetime for offline agents and retries for agents that dropped mid-execution
COMMAND_TTL = int(os.environ.get("ITMON_COMMAND_TTL", "300"))
COMMAND_TIMEOUT = int(os.environ.get("ITMON_COMMAND_TIMEOUT", "60"))
MAX_ATTEMPTS = int(os.environ.get("ITMON_MAX_ATTEMPTS", "3"))
METRIC_NAMES = {"cpu": "CPU", "ram": "RAM", "disk": "Диск", "temp": "Температура"}
_inserts = 0


# ---------- diagnostics: N samples in a row ----------
def thresholds(db: Session) -> dict[str, m.Threshold]:
    return {t.metric: t for t in db.query(m.Threshold)}


def _level(value, t: m.Threshold) -> int:
    if value is None:
        return 0
    return 2 if value >= t.crit else 1 if value >= t.warn else 0


def diagnose_window(rows: list, rules: dict[str, m.Threshold]) -> dict:
    """rows: newest first. A metric is a problem only if it exceeds the threshold in the last
    `consecutive` samples in a row; the level is the minimum over that window (a spike is ignored)."""
    issues, level = [], 0
    for key, t in rules.items():
        window = rows[: t.consecutive]
        if len(window) < t.consecutive:
            continue
        lv = min(_level(getattr(r, key, None), t) for r in window)
        if lv:
            v = getattr(window[0], key)
            unit = "°C" if key == "temp" else "%"
            word = "қауіпті" if lv == 2 else "жоғары"
            issues.append(f"{METRIC_NAMES[key]} {word}: {v:.0f}{unit} ({t.consecutive} рет қатарынан)")
            level = max(level, lv)
    return {"status": ["ok", "warn", "crit"][level], "issues": issues}


# ---------- command queue: TTL, timeout, retries ----------
def maintain_queue(db: Session, now: float):
    q = db.query(m.Command)
    # rows created before the migration have no TTL / start time
    for c in q.filter(m.Command.status.in_(("pending", "running")), m.Command.expires_at.is_(None)):
        c.expires_at = c.created + COMMAND_TTL
        if c.status == "running" and c.started_at is None:
            c.started_at = c.created
    db.flush()
    for c in q.filter(m.Command.status == "pending", m.Command.expires_at < now):
        c.status, c.finished_at = "expired", now
    for c in q.filter(m.Command.status == "running", m.Command.started_at < now - COMMAND_TIMEOUT):
        if c.attempts < MAX_ATTEMPTS and c.expires_at >= now:
            c.status, c.started_at = "pending", None          # retry: agent dropped mid-execution
        else:
            c.status, c.finished_at = "failed", now
            c.result = c.result or "timeout"
    db.commit()


def command_out(c: m.Command, hostname: str = "", username: str = "") -> dict:
    return {"id": c.id, "agent_id": c.agent_id, "hostname": hostname, "name": c.name, "status": c.status,
            "created": c.created, "expires_at": c.expires_at, "attempts": c.attempts, "max_attempts": MAX_ATTEMPTS,
            "finished_at": c.finished_at, "created_by": username, "result": c.result}


class EnrollIn(BaseModel):
    hostname: str
    os: str = ""


class MetricIn(BaseModel):
    cpu: float = Field(ge=0, le=100)
    ram: float = Field(ge=0, le=100)
    disk: float = Field(ge=0, le=100)
    temp: float | None = None
    net_sent: float = 0
    net_recv: float = 0
    hostname: str | None = None
    os: str | None = None


class ResultIn(BaseModel):
    result: str


class ThresholdIn(BaseModel):
    metric: str
    warn: float = Field(ge=0, le=150)
    crit: float = Field(ge=0, le=150)
    consecutive: int = Field(ge=1, le=20)


# ---------- agent endpoints ----------
@router.post("/agent/enroll")
def enroll(data: EnrollIn, request: Request, x_enroll_key: str | None = Header(None), db: Session = Depends(get_db)):
    if not x_enroll_key or not hmac.compare_digest(x_enroll_key, ENROLL_KEY):
        audit(db, request, None, "enroll_failed", data.hostname[:100])
        raise HTTPException(401, "Тіркеу кілті қате")
    token = new_agent_token()
    agent = m.Agent(id=uuid.uuid4().hex[:12], hostname=data.hostname[:100], os=data.os[:100],
                    token_hash=hash_agent_token(token))
    db.add(agent); db.commit()
    audit(db, request, None, "agent_enrolled", agent.id, data.hostname[:100], username="agent")
    return {"agent_id": agent.id, "token": token}


@router.post("/agent/metrics")
def post_metrics(data: MetricIn, agent: m.Agent = Depends(current_agent), db: Session = Depends(get_db)):
    global _inserts
    now = time.time()
    agent.last_seen = now
    if data.hostname:
        agent.hostname = data.hostname[:100]
    if data.os:
        agent.os = data.os[:100]
    db.add(m.Metric(agent_id=agent.id, ts=now, cpu=data.cpu, ram=data.ram, disk=data.disk, temp=data.temp,
                    net_sent=data.net_sent, net_recv=data.net_recv))
    _inserts += 1
    if _inserts % 500 == 0:  # periodic cleanup of old metrics
        db.query(m.Metric).filter(m.Metric.ts < now - METRICS_KEEP_DAYS * 86400).delete()
    db.commit()
    return {"ok": True}


@router.get("/agent/pending")
def pending(agent: m.Agent = Depends(current_agent), db: Session = Depends(get_db)):
    now = time.time()
    maintain_queue(db, now)
    cmds = db.query(m.Command).filter_by(agent_id=agent.id, status="pending").order_by(m.Command.id).all()
    out = [{"id": c.id, "name": c.name} for c in cmds]
    for c in cmds:
        c.status, c.started_at, c.attempts = "running", now, (c.attempts or 0) + 1
    db.commit()
    return out


@router.post("/agent/commands/{cmd_id}/result")
def command_result(cmd_id: int, data: ResultIn, agent: m.Agent = Depends(current_agent), db: Session = Depends(get_db)):
    cmd = db.get(m.Command, cmd_id)
    if not cmd or cmd.agent_id != agent.id:  # an agent sees only its own commands
        raise HTTPException(404, "Команда табылмады")
    if cmd.status != "running":              # late result for expired/failed command
        raise HTTPException(409, "Команда орындалу күйінде емес")
    cmd.status, cmd.result, cmd.finished_at = "done", data.result[:20000], time.time()
    db.commit()
    return {"ok": True}


# ---------- panel endpoints ----------
def _last_rows(db: Session, agent_id: str, n: int):
    return db.query(m.Metric).filter_by(agent_id=agent_id).order_by(m.Metric.ts.desc()).limit(n).all()


@router.get("/agents")
def agents(user: m.User = Depends(require("view_devices")), db: Session = Depends(get_db)):
    out, now = [], time.time()
    rules = thresholds(db)
    depth = max([t.consecutive for t in rules.values()] + [1])
    for a in db.query(m.Agent).filter_by(revoked=False).order_by(m.Agent.hostname):
        rows = _last_rows(db, a.id, depth)
        last = rows[0] if rows else None
        online = now - a.last_seen < ONLINE_SEC
        d = diagnose_window(rows, rules)
        if not online:
            d = {"status": "offline", "issues": ["Агентпен байланыс жоқ"]}
        out.append({"id": a.id, "hostname": a.hostname, "os": a.os, "online": online, "last_seen": a.last_seen,
                    "last": {k: getattr(last, k) for k in ("ts", "cpu", "ram", "disk", "temp")} if last else None, **d})
    return out


def _agent_or_404(db: Session, agent_id: str) -> m.Agent:
    a = db.get(m.Agent, agent_id)
    if not a or a.revoked:
        raise HTTPException(404, "Құрылғы табылмады")
    return a


@router.get("/agents/{agent_id}/metrics")
def metrics(agent_id: str, minutes: int = 15, user: m.User = Depends(require("view_devices")), db: Session = Depends(get_db)):
    _agent_or_404(db, agent_id)
    minutes = max(1, min(minutes, 24 * 60))
    rows = db.query(m.Metric).filter(m.Metric.agent_id == agent_id, m.Metric.ts > time.time() - minutes * 60).order_by(m.Metric.ts).all()
    step = max(1, len(rows) // 400)  # keep the chart light for 24 h
    return [{"ts": r.ts, "cpu": r.cpu, "ram": r.ram, "disk": r.disk, "temp": r.temp} for r in rows[::step]]


@router.post("/agents/{agent_id}/revoke")
def revoke(agent_id: str, request: Request, user: m.User = Depends(require("manage_devices")), db: Session = Depends(get_db)):
    a = _agent_or_404(db, agent_id)
    a.revoked = True
    db.commit()
    audit(db, request, user, "agent_revoked", a.id, a.hostname)
    return {"ok": True}


@router.post("/agents/{agent_id}/commands/{name}")
def queue_command(agent_id: str, name: str, request: Request, user: m.User = Depends(require("run_diagnostics")), db: Session = Depends(get_db)):
    _agent_or_404(db, agent_id)
    if name not in ALLOWED_COMMANDS:
        raise HTTPException(400, f"Команда рұқсат етілмеген. Қолжетімді: {sorted(ALLOWED_COMMANDS)}")
    now = time.time()
    cmd = m.Command(agent_id=agent_id, name=name, created_by=user.id, created=now, expires_at=now + COMMAND_TTL, attempts=0)
    db.add(cmd); db.commit()
    audit(db, request, user, "command", agent_id, name)
    return {"id": cmd.id, "status": "pending", "expires_at": cmd.expires_at}


@router.get("/agents/{agent_id}/commands")
def list_commands(agent_id: str, user: m.User = Depends(require("view_devices")), db: Session = Depends(get_db)):
    a = _agent_or_404(db, agent_id)
    maintain_queue(db, time.time())
    rows = (db.query(m.Command, m.User.username).outerjoin(m.User, m.User.id == m.Command.created_by)
            .filter(m.Command.agent_id == agent_id).order_by(m.Command.id.desc()).limit(20))
    return [command_out(c, a.hostname, u or "") for c, u in rows]


@router.get("/commands")
def all_commands(limit: int = 50, user: m.User = Depends(require("view_devices")), db: Session = Depends(get_db)):
    """Queue across all devices (screen "Командалар кезегі")."""
    maintain_queue(db, time.time())
    rows = (db.query(m.Command, m.Agent.hostname, m.User.username)
            .join(m.Agent, m.Agent.id == m.Command.agent_id)
            .outerjoin(m.User, m.User.id == m.Command.created_by)
            .order_by(m.Command.id.desc()).limit(max(1, min(limit, 200))))
    return [command_out(c, h, u or "") for c, h, u in rows]


@router.get("/thresholds")
def get_thresholds(user: m.User = Depends(require("view_devices")), db: Session = Depends(get_db)):
    order = list(METRIC_NAMES)
    rows = sorted(db.query(m.Threshold), key=lambda t: order.index(t.metric) if t.metric in order else 99)
    return [{"metric": t.metric, "name": METRIC_NAMES.get(t.metric, t.metric), "warn": t.warn, "crit": t.crit,
             "consecutive": t.consecutive} for t in rows]


@router.put("/thresholds")
def put_thresholds(data: list[ThresholdIn], request: Request, user: m.User = Depends(require("manage_devices")), db: Session = Depends(get_db)):
    changes = []
    for t in data:
        row = db.get(m.Threshold, t.metric)
        if not row:
            raise HTTPException(400, f"Белгісіз көрсеткіш: {t.metric}")
        if t.warn >= t.crit:
            raise HTTPException(400, f"{METRIC_NAMES[t.metric]}: «назар» мәні «қауіпті» мәнінен кіші болуы керек")
        if (row.warn, row.crit, row.consecutive) != (t.warn, t.crit, t.consecutive):
            changes.append(f"{t.metric}: {row.warn:g}/{row.crit:g}/{row.consecutive} -> {t.warn:g}/{t.crit:g}/{t.consecutive}")
            row.warn, row.crit, row.consecutive = t.warn, t.crit, t.consecutive
    db.commit()
    if changes:
        audit(db, request, user, "thresholds_update", "thresholds", "; ".join(changes))
    return {"ok": True, "changed": len(changes)}


@router.get("/audit")
def audit_log(limit: int = 100, user: m.User = Depends(require("view_audit")), db: Session = Depends(get_db)):
    rows = db.query(m.AuditLog).order_by(m.AuditLog.id.desc()).limit(max(1, min(limit, 500)))
    return [{"id": r.id, "ts": r.ts, "username": r.username, "action": r.action, "target": r.target,
             "details": r.details, "ip": r.ip} for r in rows]
