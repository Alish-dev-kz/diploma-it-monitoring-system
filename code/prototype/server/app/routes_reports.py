"""Есептер: кезең бойынша құрылғылар жүктемесі және командалар статистикасы (JSON немесе CSV)."""
import csv, io, time
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session
from .db import get_db
from . import models as m
from .security import audit, require

router = APIRouter(prefix="/api")


def build_summary(db: Session, days: int) -> dict:
    since = time.time() - days * 86400
    rows = []
    for a in db.query(m.Agent).filter_by(revoked=False).order_by(m.Agent.hostname):
        agg = db.query(func.count(m.Metric.id), func.avg(m.Metric.cpu), func.max(m.Metric.cpu),
                       func.avg(m.Metric.ram), func.max(m.Metric.ram), func.max(m.Metric.disk)) \
            .filter(m.Metric.agent_id == a.id, m.Metric.ts >= since).one()
        cmd = dict(db.query(m.Command.status, func.count(m.Command.id))
                   .filter(m.Command.agent_id == a.id, m.Command.created >= since).group_by(m.Command.status).all())
        r = lambda v: round(v, 1) if v is not None else None
        rows.append({"hostname": a.hostname, "os": a.os, "samples": agg[0],
                     "cpu_avg": r(agg[1]), "cpu_max": r(agg[2]), "ram_avg": r(agg[3]), "ram_max": r(agg[4]),
                     "disk_max": r(agg[5]), "commands": sum(cmd.values()), "commands_done": cmd.get("done", 0),
                     "commands_expired": cmd.get("expired", 0), "commands_failed": cmd.get("failed", 0)})
    return {"days": days, "since": since, "generated": time.time(), "devices": rows}


@router.get("/reports/summary")
def summary(request: Request, days: int = 7, format: str = "json",
            user: m.User = Depends(require("export_reports")), db: Session = Depends(get_db)):
    days = max(1, min(days, 90))
    data = build_summary(db, days)
    if format != "csv":
        return data
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")  # ';' so that Excel with ru/kk locale opens columns correctly
    w.writerow(["Құрылғы", "ОЖ", "Өлшем саны", "CPU орт., %", "CPU макс., %", "RAM орт., %", "RAM макс., %",
                "Диск макс., %", "Команда", "Орындалды", "TTL өтті", "Қате"])
    for d in data["devices"]:
        w.writerow([d["hostname"], d["os"], d["samples"], d["cpu_avg"], d["cpu_max"], d["ram_avg"], d["ram_max"],
                    d["disk_max"], d["commands"], d["commands_done"], d["commands_expired"], d["commands_failed"]])
    audit(db, request, user, "report_export", f"{days} days", "csv")
    name = f"itmon-report-{datetime.now():%Y%m%d}-{days}d.csv"
    return Response(content="﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
