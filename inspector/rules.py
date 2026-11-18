"""Alert rule definitions and evaluation over recent samples."""
from dataclasses import dataclass, field

import yaml

from inspector import expr

SEVERITIES = ("warning", "critical")


@dataclass(frozen=True)
class Rule:
    name: str
    expr: str
    severity: str = "warning"
    for_checks: int = 1              # condition must hold this many checks in a row
    summary: str | None = None       # e.g. "Disk {target} is {value:.0f}% full"
    node: expr.Node = field(default=None, compare=False, repr=False)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Rule {self.name}: severity must be one of {SEVERITIES}")
        if self.for_checks < 1:
            raise ValueError(f"Rule {self.name}: for_checks must be >= 1")
        try:
            object.__setattr__(self, "node", expr.parse(self.expr))
        except expr.ExprError as exc:
            raise ValueError(f"Rule {self.name}: {exc}") from exc

    def to_dict(self) -> dict:
        return {"name": self.name, "expr": self.expr, "severity": self.severity,
                "for_checks": self.for_checks, "summary": self.summary}


def load_rules(path) -> list[Rule]:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    rules = []
    for item in raw.get("rules", []):
        item = dict(item)
        if "for" in item:                       # allow Prometheus-style `for: 2`
            item["for_checks"] = item.pop("for")
        rules.append(Rule(**item))
    names = [r.name for r in rules]
    if len(names) != len(set(names)):
        raise ValueError("Rule names must be unique")
    return rules


def evaluate_rule(rule: Rule, samples: list[dict]) -> dict[str, tuple[bool | None, bool, str]]:
    """samples: newest first, each a {key: value} dict.

    Returns {target: (latest_state, firing, summary)}:
      latest_state  True / False / None (no data) for the newest sample
      firing        True when the condition held for `for_checks` samples in a row
    """
    if not samples:
        return {}
    latest = samples[0]
    targets = (expr.wildcard_targets(rule.node, latest.keys())
               if expr.has_wildcard(rule.node) else {""})
    result = {}
    for target in sorted(targets):
        window = samples[:rule.for_checks]
        states = [expr.evaluate(rule.node, s, target) for s in window]
        firing = len(window) == rule.for_checks and all(st is True for st in states)
        result[target] = (states[0], firing, _summary(rule, latest, target))
    return result


def _summary(rule: Rule, values: dict, target: str) -> str:
    first_key = expr.keys(rule.node)[0].replace("*", target)
    value = values.get(first_key)
    if rule.summary:
        try:
            return rule.summary.format(target=target, value=value if value is not None else "?")
        except (ValueError, KeyError, IndexError):
            pass
    shown = f"{value:g}" if isinstance(value, float) else value
    held = f" for {rule.for_checks} checks" if rule.for_checks > 1 else ""
    return f"{first_key} = {shown} ({rule.expr.replace('*', target)}){held}"
