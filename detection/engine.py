"""Evaluate registered rules and suppress repeated findings per device."""

from datetime import timedelta
from typing import Generic, TypeVar

from detection.base import Finding, Rule

Observation = TypeVar("Observation")


class DetectionEngine(Generic[Observation]):
    def __init__(self, rules: tuple[Rule[Observation], ...]):
        ids = [rule.info.rule_id for rule in rules]
        if len(set(ids)) != len(ids):
            raise ValueError("Detection rule IDs must be unique.")
        self.rules = tuple(rule for rule in rules if rule.info.enabled)
        self.cooldowns = {}
        self.last_pruned_at = None

    def evaluate(self, observation: Observation) -> list[Finding]:
        findings = []
        for rule in self.rules:
            finding = rule.evaluate(observation)
            if finding is None:
                continue
            if self.last_pruned_at is None or finding.timestamp > self.last_pruned_at:
                self.cooldowns = {
                    key: expiry for key, expiry in self.cooldowns.items() if expiry > finding.timestamp
                }
                self.last_pruned_at = finding.timestamp
            key = (finding.rule_id, finding.source_device_id)
            if key not in self.cooldowns:
                self.cooldowns[key] = finding.timestamp + timedelta(seconds=rule.info.cooldown_seconds)
                findings.append(finding)
        return findings
