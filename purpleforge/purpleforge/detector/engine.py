"""
A small, dependency-light detection engine.

Rules are plain YAML files (see purpleforge/detector/rules/) using a
Sigma-inspired shorthand: each key in the `detection` block is a
field name plus an operator suffix, e.g.

    command_line_contains_any: ["-enc", "-EncodedCommand"]
    entropy_above: 7.0
    logon_type_equals: 10

A key with no suffix is treated as an exact-match on that field. All
conditions in a rule are AND-ed together — this intentionally stays
simple rather than trying to reimplement Sigma's full condition
grammar; see docs/ARCHITECTURE.md for why, and for how to extend it.
"""

import glob
import os
from dataclasses import dataclass, field

import yaml

_SUFFIXES = [
    ("_contains_any", "contains_any"),
    ("_equals", "equals"),
    ("_contains", "contains"),
    ("_below", "below"),
    ("_above", "above"),
    ("_in", "in"),
    ("_prefix", "prefix"),
]


def _parse_condition_key(key: str):
    for suffix, op in _SUFFIXES:
        if key.endswith(suffix):
            return key[: -len(suffix)], op
    return key, "equals"


def _apply(op: str, actual, expected) -> bool:
    if actual is None:
        return False
    if op == "equals":
        return actual == expected
    if op == "contains":
        return isinstance(actual, str) and expected in actual
    if op == "contains_any":
        return isinstance(actual, str) and any(v in actual for v in expected)
    if op == "below":
        return isinstance(actual, (int, float)) and actual < expected
    if op == "above":
        return isinstance(actual, (int, float)) and actual > expected
    if op == "in":
        return actual in expected
    if op == "prefix":
        return isinstance(actual, str) and actual.startswith(expected)
    raise ValueError(f"Unknown operator: {op}")


@dataclass
class Rule:
    id: str
    title: str
    technique_id: str
    level: str
    log_source: str
    detection: dict
    description: str = ""

    def matches(self, event: dict) -> bool:
        for key, expected in self.detection.items():
            field_name, op = _parse_condition_key(key)
            if not _apply(op, event.get(field_name), expected):
                return False
        return True


@dataclass
class Finding:
    rule: Rule
    event: dict


def load_rules(rules_dir: str) -> list:
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        rules.append(
            Rule(
                id=raw["id"],
                title=raw["title"],
                technique_id=raw["technique_id"],
                level=raw.get("level", "medium"),
                log_source=raw.get("log_source", ""),
                detection=raw["detection"],
                description=raw.get("description", "").strip(),
            )
        )
    return rules


def run_detection(events: list, rules: list) -> list:
    """Return a Finding for every (event, rule) pair that matches."""
    findings = []
    for event in events:
        for rule in rules:
            if rule.matches(event):
                findings.append(Finding(rule=rule, event=event))
    return findings
