"""Strategy pattern: interchangeable anomaly detection algorithms for ITMon diagnostics.

Python 3.10+, standard library only.
DiagnosticService depends on the DetectionStrategy abstraction (OCP, DIP):
a new algorithm is added as a new class, DiagnosticService is not modified.
"""
from __future__ import annotations

import statistics
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Protocol

OK, WARN, CRIT = 0, 1, 2
LEVEL_NAMES = {OK: "ok", WARN: "warn", CRIT: "crit"}


@dataclass(frozen=True)
class Threshold:
    warn: float
    crit: float
    consecutive: int = 3

    def __post_init__(self):
        if self.warn >= self.crit:
            raise ValueError("warn must be less than crit")
        if self.consecutive < 1:
            raise ValueError("consecutive must be >= 1")

    def level_of(self, value: float) -> int:
        return CRIT if value >= self.crit else WARN if value >= self.warn else OK


class DetectionStrategy(ABC):
    """samples: newest first."""

    @abstractmethod
    def evaluate(self, samples: list[float], t: Threshold) -> int: ...


class SingleSampleStrategy(DetectionStrategy):
    """Old behaviour (prototype v1): only the latest sample matters -> false alerts on spikes."""

    def evaluate(self, samples, t):
        return t.level_of(samples[0]) if samples else OK


class ConsecutiveStrategy(DetectionStrategy):
    """Alert only if the threshold is exceeded in N latest samples in a row ("difficult part")."""

    def evaluate(self, samples, t):
        window = samples[: t.consecutive]
        if len(window) < t.consecutive:
            return OK
        return min(t.level_of(v) for v in window)


class ZScoreStrategy(DetectionStrategy):
    """Anomaly relative to the device's own history: |x - mean| > k * stdev.

    Useful when a fixed threshold does not fit (e.g. a server that is always at 70% CPU).
    """

    def __init__(self, k: float = 3.0, min_history: int = 10):
        self.k = k
        self.min_history = min_history

    def evaluate(self, samples, t):
        if len(samples) < self.min_history + 1:
            return OK
        latest, history = samples[0], samples[1:]
        stdev = statistics.pstdev(history)
        if stdev == 0:
            return OK
        z = abs(latest - statistics.fmean(history)) / stdev
        return CRIT if z > self.k * 1.5 else WARN if z > self.k else OK


class MetricRepository(Protocol):
    def latest(self, device: str, metric: str, n: int) -> list[float]: ...


@dataclass
class Alert:
    device: str
    metric: str
    level: int
    value: float

    def __str__(self):
        return f"[{LEVEL_NAMES[self.level]}] {self.device}: {self.metric} = {self.value:g}"


class DiagnosticService:
    def __init__(self, repo: MetricRepository, strategy: DetectionStrategy, history: int = 30):
        self.repo = repo
        self.strategy = strategy
        self.history = history

    def set_strategy(self, strategy: DetectionStrategy) -> None:
        self.strategy = strategy

    def check(self, device: str, metric: str, t: Threshold) -> Optional[Alert]:
        samples = self.repo.latest(device, metric, max(self.history, t.consecutive))
        level = self.strategy.evaluate(samples, t)
        return Alert(device, metric, level, samples[0]) if level else None


class InMemoryRepository:
    """Test double for MetricRepository."""

    def __init__(self):
        self._data: dict[tuple[str, str], list[float]] = {}

    def add(self, device: str, metric: str, *values: float) -> None:
        self._data.setdefault((device, metric), []).extend(values)  # oldest -> newest

    def latest(self, device, metric, n):
        return list(reversed(self._data.get((device, metric), [])))[:n]


if __name__ == "__main__":
    repo = InMemoryRepository()
    repo.add("LAB301-PC01", "cpu", 15, 18, 12, 99)          # single spike
    repo.add("BUH-PC02", "disk", 90, 96, 97, 97)            # persistent problem
    cpu = Threshold(warn=80, crit=95, consecutive=3)
    disk = Threshold(warn=85, crit=95, consecutive=3)

    for strategy in (SingleSampleStrategy(), ConsecutiveStrategy()):
        service = DiagnosticService(repo, strategy)
        print(type(strategy).__name__)
        print("  LAB301-PC01 cpu :", service.check("LAB301-PC01", "cpu", cpu) or "ok")
        print("  BUH-PC02 disk   :", service.check("BUH-PC02", "disk", disk) or "ok")
