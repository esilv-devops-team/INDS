"""Shared contracts for independent detection rules."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, TypeVar

Severity = Literal["Low", "Medium", "High", "Critical"]
Observation = TypeVar("Observation", contravariant=True)


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    description: str
    severity: Severity
    enabled: bool
    cooldown_seconds: int


@dataclass(frozen=True)
class Finding:
    rule_id: str
    source_device_id: int
    timestamp: datetime
    severity: Severity
    evidence: dict[str, str | int]
    measured: dict[str, int | float]


class Rule(Protocol[Observation]):
    @property
    def info(self) -> RuleInfo: ...

    def evaluate(self, observation: Observation) -> Finding | None: ...
