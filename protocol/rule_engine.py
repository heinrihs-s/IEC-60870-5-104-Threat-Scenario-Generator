"""
YAML-based Protocol Rule Engine for IEC-104.

Loads rule definitions from YAML files and evaluates them against:
1. Individual IEC-104 events (event-level rules)
2. Feature windows (window-level rules)

Rules complement ML-based anomaly detection by catching protocol violations
and known attack patterns that statistical models cannot learn without
labeled training data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from protocol.iec104_knowledge import (
    ALL_VALID_TYPEIDS,
    ERROR_COTS,
    RESERVED_COTS,
    VALID_TYPEID_COT,
    classify_typeid,
    is_command_typeid,
    is_valid_typeid_cot,
    parse_cot,
)

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "rules"


@dataclass
class RuleMatch:
    """A single rule match result."""
    rule_id: str
    rule_name: str
    severity: str
    description: str
    mitre_ics: dict[str, str]
    matched_values: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)


@dataclass
class ProtocolRule:
    """Parsed protocol rule from YAML."""
    id: str
    name: str
    description: str
    severity: str
    mitre_ics: dict[str, str]
    rule_type: str  # "event" or "window"
    conditions: dict[str, Any]
    requires: dict[str, Any] | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.id,
            "rule_name": self.name,
            "severity": self.severity,
            "tags": self.tags,
        }


class RuleEngine:
    """Loads and evaluates IEC-104 protocol rules."""

    def __init__(self, rules_dir: Path | None = None):
        self.rules_dir = rules_dir or RULES_DIR
        self.event_rules: list[ProtocolRule] = []
        self.window_rules: list[ProtocolRule] = []
        self._load_rules()

    def _load_rules(self):
        """Load all YAML rule files from rules directory."""
        if not self.rules_dir.exists():
            logger.warning("Rules directory not found: %s", self.rules_dir)
            return

        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if not data or "rules" not in data:
                    continue
                for rule_data in data["rules"]:
                    rule = self._parse_rule(rule_data)
                    if rule.rule_type == "event":
                        self.event_rules.append(rule)
                    else:
                        self.window_rules.append(rule)
            except Exception as e:
                logger.error("Failed to load rule file %s: %s", yaml_file, e)

        logger.info(
            "Loaded %d event rules and %d window rules from %s",
            len(self.event_rules),
            len(self.window_rules),
            self.rules_dir,
        )

    def _parse_rule(self, data: dict) -> ProtocolRule:
        """Parse a single rule from YAML dict."""
        conditions = data.get("conditions") or data.get("condition", {})
        return ProtocolRule(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            mitre_ics=data.get("mitre_ics", {}),
            rule_type=data.get("type", "window"),
            conditions=conditions,
            requires=data.get("requires"),
            tags=data.get("tags", []),
        )

    # ------------------------------------------------------------------
    # Event-level evaluation (per IEC-104 event/packet)
    # ------------------------------------------------------------------

    def evaluate_event(self, event: dict) -> list[RuleMatch]:
        """Evaluate event-level rules against a single IEC-104 event.

        Args:
            event: dict with fields like type_id, cot, direction, etc.
                   type_id and cot can be string or int.

        Returns:
            List of RuleMatch for rules that fired.
        """
        matches = []
        type_id = self._parse_type_id(event.get("type_id"))
        cot = parse_cot(event.get("cot", event.get("ident.cot", "")))

        for rule in self.event_rules:
            match = self._check_event_rule(rule, event, type_id, cot)
            if match:
                matches.append(match)

        return matches

    def _parse_type_id(self, raw) -> int | None:
        """Parse TypeID from various formats."""
        if raw is None:
            return None
        if isinstance(raw, int):
            return raw
        if isinstance(raw, float):
            return int(raw) if raw == raw else None
        s = str(raw).strip()
        if s.isdigit():
            return int(s)
        return None

    def _check_event_rule(
        self,
        rule: ProtocolRule,
        event: dict,
        type_id: int | None,
        cot: int | None,
    ) -> RuleMatch | None:
        """Check a single event-level rule."""
        cond = rule.conditions

        # Function-based conditions
        func_name = cond.get("function")
        if func_name:
            if func_name == "invalid_typeid_cot":
                if type_id is not None and cot is not None:
                    if not is_valid_typeid_cot(type_id, cot):
                        return RuleMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            description=rule.description,
                            mitre_ics=rule.mitre_ics,
                            matched_values={"type_id": type_id, "cot": cot},
                            tags=rule.tags,
                        )
            elif func_name == "command_from_server":
                if type_id is not None and is_command_typeid(type_id):
                    direction = event.get("direction", "")
                    if direction in ("resp", "server", "response"):
                        return RuleMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            description=rule.description,
                            mitre_ics=rule.mitre_ics,
                            matched_values={"type_id": type_id, "direction": direction},
                            tags=rule.tags,
                        )
            return None

        # Set-based conditions
        field_name = cond.get("field", rule.conditions.get("field"))
        if not field_name:
            field_name = getattr(rule, "conditions", {}).get("field")

        not_in_set = cond.get("not_in_set")
        if not_in_set == "valid_typeids":
            if type_id is not None and type_id not in ALL_VALID_TYPEIDS:
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    mitre_ics=rule.mitre_ics,
                    matched_values={"type_id": type_id},
                    tags=rule.tags,
                )

        in_set = cond.get("in_set")
        if in_set == "reserved_cots":
            if cot is not None and cot in RESERVED_COTS:
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    mitre_ics=rule.mitre_ics,
                    matched_values={"cot": cot},
                    tags=rule.tags,
                )
        elif in_set == "error_cots":
            if cot is not None and cot in ERROR_COTS:
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    mitre_ics=rule.mitre_ics,
                    matched_values={"cot": cot},
                    tags=rule.tags,
                )

        return None

    # ------------------------------------------------------------------
    # Window-level evaluation (per feature window)
    # ------------------------------------------------------------------

    def evaluate_window(self, features: dict[str, float]) -> list[RuleMatch]:
        """Evaluate window-level rules against extracted features.

        Args:
            features: dict of feature_name -> value from feature extraction.

        Returns:
            List of RuleMatch for rules that fired.
        """
        matches = []
        for rule in self.window_rules:
            match = self._check_window_rule(rule, features)
            if match:
                matches.append(match)
        return matches

    def _check_window_rule(
        self,
        rule: ProtocolRule,
        features: dict[str, float],
    ) -> RuleMatch | None:
        """Check a single window-level rule."""
        if rule.requires:
            if not self._eval_condition(rule.requires, features):
                return None

        cond = rule.conditions
        if "all" in cond:
            if all(self._eval_condition(c, features) for c in cond["all"]):
                matched_vals = {}
                for c in cond["all"]:
                    fname = c.get("field", "")
                    if fname:
                        matched_vals[fname] = features.get(fname, 0)
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    mitre_ics=rule.mitre_ics,
                    matched_values=matched_vals,
                    tags=rule.tags,
                )
        elif "any" in cond:
            for c in cond["any"]:
                if self._eval_condition(c, features):
                    fname = c.get("field", "")
                    matched_vals = {fname: features.get(fname, 0)} if fname else {}
                    return RuleMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        description=rule.description,
                        mitre_ics=rule.mitre_ics,
                        matched_values=matched_vals,
                        tags=rule.tags,
                    )
        else:
            if self._eval_condition(cond, features):
                fname = cond.get("field", "")
                matched_vals = {fname: features.get(fname, 0)} if fname else {}
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    mitre_ics=rule.mitre_ics,
                    matched_values=matched_vals,
                    tags=rule.tags,
                )

        return None

    def _eval_condition(self, cond: dict, features: dict[str, float]) -> bool:
        """Evaluate a single condition dict against features."""
        field_name = cond.get("field", "")
        if not field_name:
            return False

        value = features.get(field_name, 0.0)
        threshold = cond.get("value", 0)
        op = cond.get("operator", ">")

        if op == ">":
            return value > threshold
        elif op == ">=":
            return value >= threshold
        elif op == "<":
            return value < threshold
        elif op == "<=":
            return value <= threshold
        elif op == "==":
            return abs(value - threshold) < 1e-9
        elif op == "!=":
            return abs(value - threshold) >= 1e-9
        else:
            logger.warning("Unknown operator: %s", op)
            return False

    # ------------------------------------------------------------------
    # Batch evaluation helpers
    # ------------------------------------------------------------------

    def evaluate_events_batch(
        self,
        events: list[dict],
    ) -> dict[str, list[RuleMatch]]:
        """Evaluate event rules on a batch, returning matches per rule_id."""
        all_matches: dict[str, list[RuleMatch]] = {}
        for event in events:
            for match in self.evaluate_event(event):
                all_matches.setdefault(match.rule_id, []).append(match)
        return all_matches

    def evaluate_window_with_events(
        self,
        features: dict[str, float],
        events: list[dict] | None = None,
    ) -> list[RuleMatch]:
        """Evaluate both window and event rules, returning combined matches.

        Args:
            features: Window-level features.
            events: Optional list of raw IEC-104 events in this window.

        Returns:
            Combined list of unique rule matches.
        """
        matches = self.evaluate_window(features)

        if events:
            event_match_counts: dict[str, tuple[RuleMatch, int]] = {}
            for event in events:
                for match in self.evaluate_event(event):
                    if match.rule_id in event_match_counts:
                        _, count = event_match_counts[match.rule_id]
                        event_match_counts[match.rule_id] = (match, count + 1)
                    else:
                        event_match_counts[match.rule_id] = (match, 1)

            for match, count in event_match_counts.values():
                match.matched_values["event_count"] = count
                matches.append(match)

        return matches

    def get_rule_summary(self) -> dict:
        """Return summary of loaded rules."""
        return {
            "event_rules": len(self.event_rules),
            "window_rules": len(self.window_rules),
            "total": len(self.event_rules) + len(self.window_rules),
            "rule_ids": [r.id for r in self.event_rules + self.window_rules],
            "severity_counts": {
                "critical": sum(
                    1 for r in self.event_rules + self.window_rules
                    if r.severity == "critical"
                ),
                "high": sum(
                    1 for r in self.event_rules + self.window_rules
                    if r.severity == "high"
                ),
                "medium": sum(
                    1 for r in self.event_rules + self.window_rules
                    if r.severity == "medium"
                ),
            },
        }


# Module-level singleton for convenience
_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    """Get or create the singleton rule engine."""
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine
