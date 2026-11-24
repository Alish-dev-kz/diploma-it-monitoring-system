import os, tempfile
_tmp = tempfile.mkdtemp()
os.environ["ITMON_DB_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["ITMON_ADMIN_PASSWORD"] = "adminpass"
os.environ["ITMON_ENROLL_KEY"] = "ek"

import time
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def login(c, u, p):
    r = c.post("/api/auth/login", json={"username": u, "password": p})
    return r


def H(c, u="admin", p="adminpass"):
    return {"Authorization": "Bearer " + login(c, u, p).json()["token"]}


def enroll(c):
    r = c.post("/api/agent/enroll", json={"hostname": "PC1", "os": "Windows 11"}, headers={"X-Enroll-Key": "ek"})
    assert r.status_code == 200
    return r.json()


def test_login_and_me(c):
    assert login(c, "admin", "wrong").status_code == 401
    r = login(c, "admin", "adminpass")
    assert r.status_code == 200 and "manage_users" in r.json()["user"]["permissions"]
    assert c.get("/api/agents").status_code == 401  # без токена нельзя


def test_enroll_requires_key(c):
    assert c.post("/api/agent/enroll", json={"hostname": "x"}, headers={"X-Enroll-Key": "bad"}).status_code == 401


def test_agent_flow_and_command(c):
    a = enroll(c)
    ah = {"X-Agent-Token": a["token"]}
    for _ in range(3):  # alert only after N = 3 samples in a row
        assert c.post("/api/agent/metrics", json={"cpu": 10, "ram": 97, "disk": 40}, headers=ah).status_code == 200
    assert c.post("/api/agent/metrics", json={"cpu": 10, "ram": 1, "disk": 1}, headers={"X-Agent-Token": "bad"}).status_code == 401
    lst = c.get("/api/agents", headers=H(c)).json()
    me = next(x for x in lst if x["id"] == a["agent_id"])
    assert me["status"] == "crit" and any("RAM" in i for i in me["issues"])
    # команда: белый список
    assert c.post(f"/api/agents/{a['agent_id']}/commands/rm_rf", headers=H(c)).status_code == 400
    cid = c.post(f"/api/agents/{a['agent_id']}/commands/uptime", headers=H(c)).json()["id"]
    assert c.get("/api/agent/pending", headers=ah).json() == [{"id": cid, "name": "uptime"}]
    assert c.post(f"/api/agent/commands/{cid}/result", json={"result": "1 d"}, headers=ah).status_code == 200
    assert c.get(f"/api/agents/{a['agent_id']}/commands", headers=H(c)).json()[0]["result"] == "1 d"


def test_agent_cannot_touch_foreign_command(c):
    a1, a2 = enroll(c), enroll(c)
    cid = c.post(f"/api/agents/{a1['agent_id']}/commands/uptime", headers=H(c)).json()["id"]
    r = c.post(f"/api/agent/commands/{cid}/result", json={"result": "x"}, headers={"X-Agent-Token": a2["token"]})
    assert r.status_code == 404


def test_roles_rbac(c):
    ah = H(c)
    roles = {r["name"]: r["id"] for r in c.get("/api/roles", headers=ah).json()}
    # роль «Наблюдатель» только с просмотром
    rid = c.post("/api/roles", json={"name": "Наблюдатель", "permissions": ["view_devices"]}, headers=ah).json()["id"]
    assert c.post("/api/users", json={"username": "viewer", "password": "secret1", "role_id": rid}, headers=ah).status_code == 201
    assert c.post("/api/users", json={"username": "staff", "password": "secret1", "role_id": roles["Сотрудник"]}, headers=ah).status_code == 201
    vh, sh = H(c, "viewer", "secret1"), H(c, "staff", "secret1")
    a = enroll(c)["agent_id"]
    assert c.get("/api/agents", headers=vh).status_code == 200
    assert c.post(f"/api/agents/{a}/commands/uptime", headers=vh).status_code == 403   # нет run_diagnostics
    assert c.post(f"/api/agents/{a}/commands/uptime", headers=sh).status_code == 200   # у сотрудника есть
    assert c.get("/api/users", headers=sh).status_code == 403                          # нет manage_users
    assert c.get("/api/audit", headers=sh).status_code == 403
    assert c.post("/api/roles", json={"name": "Bad", "permissions": ["nope"]}, headers=ah).status_code == 400
    # системную роль менять нельзя
    assert c.put(f"/api/roles/{roles['Администратор']}", json={"name": "XX", "permissions": []}, headers=ah).status_code == 400


def test_disabled_user_and_self_protection(c):
    ah = H(c)
    users = {u["username"]: u for u in c.get("/api/users", headers=ah).json()}
    assert c.patch(f"/api/users/{users['admin']['id']}", json={"active": False}, headers=ah).status_code == 400
    vh = H(c, "viewer", "secret1")
    c.patch(f"/api/users/{users['viewer']['id']}", json={"active": False}, headers=ah)
    assert c.get("/api/agents", headers=vh).status_code == 401  # уже выданный токен перестаёт работать
    assert login(c, "viewer", "secret1").status_code == 401


def test_revoke_and_audit(c):
    ah = H(c)
    a = enroll(c)
    assert c.post(f"/api/agents/{a['agent_id']}/revoke", headers=ah).status_code == 200
    assert c.post("/api/agent/metrics", json={"cpu": 1, "ram": 1, "disk": 1}, headers={"X-Agent-Token": a["token"]}).status_code == 401
    actions = {r["action"] for r in c.get("/api/audit?limit=500", headers=ah).json()}
    assert {"login", "login_failed", "command", "agent_enrolled", "agent_revoked", "user_create", "role_create"} <= actions


def test_bruteforce_lock(c):
    for _ in range(5):
        login(c, "ghost", "x")
    assert login(c, "ghost", "x").status_code == 429


# ---------- "difficult part": N in a row, TTL, retries ----------
from app import models as m
from app import routes_devices as rd
from app.db import SessionLocal


def _metrics(c, ah, *cpu_values):
    for v in cpu_values:
        assert c.post("/api/agent/metrics", json={"cpu": v, "ram": 10, "disk": 10}, headers=ah).status_code == 200


def _status(c, agent_id):
    return next(x for x in c.get("/api/agents", headers=H(c)).json() if x["id"] == agent_id)


def test_single_spike_is_ignored(c):
    a = enroll(c); ah = {"X-Agent-Token": a["token"]}
    _metrics(c, ah, 10, 10, 99)
    assert _status(c, a["agent_id"])["status"] == "ok"
    _metrics(c, ah, 97, 98)          # now 99, 97, 98 -> three in a row
    st = _status(c, a["agent_id"])
    assert st["status"] == "crit" and any("CPU" in i for i in st["issues"])


def test_metric_out_of_range_rejected(c):
    a = enroll(c)
    r = c.post("/api/agent/metrics", json={"cpu": 140, "ram": 1, "disk": 1}, headers={"X-Agent-Token": a["token"]})
    assert r.status_code == 422


def test_command_expires_when_agent_offline(c):
    a = enroll(c); ah = {"X-Agent-Token": a["token"]}
    cid = c.post(f"/api/agents/{a['agent_id']}/commands/uptime", headers=H(c)).json()["id"]
    with SessionLocal() as db:   # agent was offline longer than TTL
        db.get(m.Command, cid).expires_at = time.time() - 1; db.commit()
    assert c.get("/api/agent/pending", headers=ah).json() == []
    assert c.get(f"/api/agents/{a['agent_id']}/commands", headers=H(c)).json()[0]["status"] == "expired"
    assert c.post(f"/api/agent/commands/{cid}/result", json={"result": "x"}, headers=ah).status_code == 409


def test_hung_command_retried_then_failed(c):
    a = enroll(c); ah = {"X-Agent-Token": a["token"]}
    cid = c.post(f"/api/agents/{a['agent_id']}/commands/disk_usage", headers=H(c)).json()["id"]
    for attempt in range(rd.MAX_ATTEMPTS):
        assert [x["id"] for x in c.get("/api/agent/pending", headers=ah).json()] == [cid], attempt
        with SessionLocal() as db:   # agent crashed while executing
            db.get(m.Command, cid).started_at = time.time() - rd.COMMAND_TIMEOUT - 1; db.commit()
    assert c.get("/api/agent/pending", headers=ah).json() == []
    cmd = next(x for x in c.get("/api/commands", headers=H(c)).json() if x["id"] == cid)
    assert cmd["status"] == "failed" and cmd["attempts"] == rd.MAX_ATTEMPTS and cmd["hostname"] == "PC1"


def test_thresholds_edit_validation_and_rbac(c):
    ah = H(c)
    rows = c.get("/api/thresholds", headers=ah).json()
    assert {r["metric"] for r in rows} == {"cpu", "ram", "disk", "temp"}
    bad = [{"metric": "cpu", "warn": 95, "crit": 80, "consecutive": 3}]
    assert c.put("/api/thresholds", json=bad, headers=ah).status_code == 400
    ok = [{"metric": "cpu", "warn": 80, "crit": 95, "consecutive": 2}]
    assert c.put("/api/thresholds", json=ok, headers=ah).json()["changed"] == 1
    assert c.put("/api/thresholds", json=ok, headers=H(c, "staff", "secret1")).status_code == 403
    assert "thresholds_update" in {r["action"] for r in c.get("/api/audit?limit=500", headers=ah).json()}
    ok[0]["consecutive"] = 3
    c.put("/api/thresholds", json=ok, headers=ah)


def test_report_csv(c):
    r = c.get("/api/reports/summary?days=7&format=csv", headers=H(c))
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    assert r.text.splitlines()[0].lstrip("\ufeff").startswith("Құрылғы;")
    assert c.get("/api/reports/summary", headers=H(c, "staff", "secret1")).status_code == 403


def test_legacy_commands_without_ttl_do_not_loop(c):
    a = enroll(c); ah = {"X-Agent-Token": a["token"]}
    old = time.time() - 3600
    with SessionLocal() as db:   # rows from the first version: no expires_at / started_at
        db.add_all([m.Command(agent_id=a["agent_id"], name="uptime", status="pending", created=old),
                    m.Command(agent_id=a["agent_id"], name="uptime", status="running", created=old)])
        db.commit()
    assert c.get("/api/agent/pending", headers=ah).json() == []
    st = sorted(x["status"] for x in c.get(f"/api/agents/{a['agent_id']}/commands", headers=H(c)).json())
    assert st == ["expired", "failed"]
