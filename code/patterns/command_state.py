"""State pattern: lifecycle of a remote command with TTL and retries ("difficult part").

Python 3.10+, standard library only.

    pending --deliver--> running --complete--> done
       |                    |
       | tick: TTL passed   | tick: timeout, attempts < max -> pending
       v                    | tick: timeout, attempts = max -> failed
    expired                 v
                          failed

Each state decides which transitions are allowed, so there are no long if/elif chains
over a status string, and a new state (e.g. "cancelled") is a new class.
"""
from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from typing import Optional


class InvalidTransition(Exception):
    pass


class CommandState(ABC):
    name = "abstract"

    def deliver(self, cmd: "Command", now: float) -> None:
        raise InvalidTransition(f"cannot deliver command in state '{self.name}'")

    def complete(self, cmd: "Command", result: str, now: float) -> None:
        raise InvalidTransition(f"cannot complete command in state '{self.name}'")

    def tick(self, cmd: "Command", now: float) -> None:
        """Periodic check (called when the queue is polled). Final states ignore it."""


class PendingState(CommandState):
    name = "pending"

    def deliver(self, cmd, now):
        if now > cmd.expires_at:
            cmd.set_state(ExpiredState(), now)
            raise InvalidTransition("command expired before delivery")
        cmd.attempts += 1
        cmd.started_at = now
        cmd.set_state(RunningState(), now)

    def tick(self, cmd, now):
        if now > cmd.expires_at:
            cmd.set_state(ExpiredState(), now)


class RunningState(CommandState):
    name = "running"

    def complete(self, cmd, result, now):
        cmd.result = result
        cmd.set_state(DoneState(), now)

    def tick(self, cmd, now):
        if now - cmd.started_at <= cmd.timeout:
            return
        if cmd.attempts < cmd.max_attempts and now <= cmd.expires_at:
            cmd.started_at = None
            cmd.set_state(PendingState(), now)      # retry: agent went offline mid-execution
        else:
            cmd.result = cmd.result or "timeout"
            cmd.set_state(FailedState(), now)


class DoneState(CommandState):
    name = "done"


class ExpiredState(CommandState):
    name = "expired"


class FailedState(CommandState):
    name = "failed"


@dataclass
class Command:
    code: str
    created_at: float
    ttl: float = 300
    timeout: float = 60
    max_attempts: int = 3
    attempts: int = 0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: Optional[str] = None
    history: list[str] = field(default_factory=list)
    _state: CommandState = field(default_factory=PendingState, repr=False)

    def __post_init__(self):
        self.history.append(self._state.name)

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl

    @property
    def status(self) -> str:
        return self._state.name

    def set_state(self, state: CommandState, now: float) -> None:
        self._state = state
        self.history.append(state.name)
        if state.name in ("done", "expired", "failed"):
            self.finished_at = now

    # the context delegates every operation to the current state
    def deliver(self, now: float) -> None:
        self._state.deliver(self, now)

    def complete(self, result: str, now: float) -> None:
        self._state.complete(self, result, now)

    def tick(self, now: float) -> None:
        self._state.tick(self, now)


if __name__ == "__main__":
    # 1) normal run
    c = Command("uptime", created_at=0)
    c.deliver(now=2)
    c.complete("0 d 3 h", now=3)
    print("normal :", " -> ".join(c.history))

    # 2) agent offline longer than TTL
    c = Command("disk_usage", created_at=0, ttl=300)
    c.tick(now=301)
    print("offline:", " -> ".join(c.history))

    # 3) agent crashes twice, third attempt succeeds
    c = Command("top_processes", created_at=0, timeout=60, max_attempts=3)
    c.deliver(now=1);  c.tick(now=70)
    c.deliver(now=80); c.tick(now=150)
    c.deliver(now=160); c.complete("ok", now=161)
    print("retry  :", " -> ".join(c.history), f"(attempts={c.attempts})")

    # 4) late result after failure is rejected
    c = Command("ping_test", created_at=0, max_attempts=1)
    c.deliver(now=1); c.tick(now=100)
    try:
        c.complete("late", now=101)
    except InvalidTransition as e:
        print("late   :", " -> ".join(c.history), f"| {e}")
