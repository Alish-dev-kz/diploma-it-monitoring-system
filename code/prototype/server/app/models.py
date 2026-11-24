"""Модели БД (основа для ER-диаграммы диплома)."""
import time
from sqlalchemy import ForeignKey, String, Float, Integer, Text, Boolean, Table, Column, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


role_permissions = Table(
    "role_permissions", Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True)
    description: Mapped[str] = mapped_column(String(200), default="")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)  # Admin нельзя менять/удалять
    permissions: Mapped[list[Permission]] = relationship(secondary=role_permissions, lazy="selectin")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created: Mapped[float] = mapped_column(Float, default=time.time)
    role: Mapped[Role] = relationship(lazy="selectin")


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(100))
    os: Mapped[str] = mapped_column(String(100), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created: Mapped[float] = mapped_column(Float, default=time.time)
    last_seen: Mapped[float] = mapped_column(Float, default=0)


class Metric(Base):
    __tablename__ = "metrics"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    ts: Mapped[float] = mapped_column(Float)
    cpu: Mapped[float] = mapped_column(Float)
    ram: Mapped[float] = mapped_column(Float)
    disk: Mapped[float] = mapped_column(Float)
    temp: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_sent: Mapped[float] = mapped_column(Float, default=0)
    net_recv: Mapped[float] = mapped_column(Float, default=0)
    __table_args__ = (Index("ix_metrics_agent_ts", "agent_id", "ts"),)


class Command(Base):
    __tablename__ = "commands"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending/running/done/expired/failed
    created: Mapped[float] = mapped_column(Float, default=time.time)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "difficult part": TTL for offline agents and limited retries
    expires_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    finished_at: Mapped[float | None] = mapped_column(Float, nullable=True)


class Threshold(Base):
    """Alert rule per metric: warn/crit and how many samples in a row must exceed it."""
    __tablename__ = "thresholds"
    metric: Mapped[str] = mapped_column(String(10), primary_key=True)  # cpu/ram/disk/temp
    warn: Mapped[float] = mapped_column(Float)
    crit: Mapped[float] = mapped_column(Float)
    consecutive: Mapped[int] = mapped_column(Integer, default=3)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[float] = mapped_column(Float, default=time.time, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(50), default="")
    action: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(100), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(45), default="")
