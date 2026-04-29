#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_RTU_RULES = {
    "COMMAND_WITHOUT_VALID_SELECT",
    "DIRECT_FIELD_INTERFACE_CONTROL",
}
REQUIRED_SCADA_RULE_ALTERNATIVES = {
    "UNKNOWN_CORRELATION_ID",
    "UNMATCHED_BREAKER_TRANSITION",
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        raise AssertionError(f"missing JSONL file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AssertionError(f"{path}:{line_number} is not valid JSON: {exc}") from exc
            records.append(record)
    return records


def collect_rule_ids(items: list[Any]) -> set[str]:
    rule_ids: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("rule_id"):
            rule_ids.add(str(item["rule_id"]))
        for nested in item.get("detections") or []:
            if isinstance(nested, dict) and nested.get("rule_id"):
                rule_ids.add(str(nested["rule_id"]))
        details = item.get("details")
        if isinstance(details, dict):
            for nested in details.get("detections") or []:
                if isinstance(nested, dict) and nested.get("rule_id"):
                    rule_ids.add(str(nested["rule_id"]))
    return rule_ids


def main() -> int:
    evidence_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evidence/phase1-spoofed-direct-rtu-attack")
    failures: list[str] = []

    try:
        attacker_output = load_text(evidence_dir / "attacker-output.txt")
        status = load_json(evidence_dir / "status.json")
        events_response = load_json(evidence_dir / "events.json")
        rtu_logs = load_jsonl(evidence_dir / "rtu.jsonl")
        scada_logs = load_jsonl(evidence_dir / "scada.jsonl")
        detection_logs = load_jsonl(evidence_dir / "detections.jsonl")
    except Exception as exc:
        print(f"FAIL: could not load attack evidence: {exc}")
        return 1

    if "Mode: spoof-scada" not in attacker_output:
        failures.append("attacker output does not show Mode: spoof-scada")
    if "scada-master" not in attacker_output or "SCADA_MASTER" not in attacker_output:
        failures.append("attacker output does not show spoofed SCADA identity")

    breaker = status.get("breaker") or {}
    if breaker.get("state") != "OPEN":
        failures.append("status does not show breaker OPEN after attack")

    telemetry = status.get("telemetry") or {}
    if float(telemetry.get("current_a", 9999)) > 2.0:
        failures.append("current did not drop near zero after breaker open")
    if float(telemetry.get("load_mw", 9999)) > 0.1:
        failures.append("load did not drop near zero after breaker open")

    attack_events = [
        event
        for event in (events_response.get("events") or [])
        if event.get("event_type") == "breaker_command"
        and event.get("message_type") == "EXECUTE_BREAKER"
        and (event.get("details") or {}).get("command_status") == "ACCEPTED"
        and (event.get("details") or {}).get("select_token_valid") is False
    ]
    if not attack_events:
        failures.append("no accepted spoofed direct RTU breaker command event found")
    else:
        event = attack_events[-1]
        source = event.get("claimed_source") or {}
        details = event.get("details") or {}
        if source.get("id") != "scada-master" or source.get("role") != "SCADA_MASTER":
            failures.append("attack event does not claim spoofed SCADA identity")
        if source.get("role") == "ATTACKER":
            failures.append("attack event depends on honest ATTACKER role")
        if details.get("vulnerable_mode") is not True:
            failures.append("attack event does not show vulnerable_mode=true")
        if details.get("command_status") != "ACCEPTED":
            failures.append("RTU did not accept the attack command")
        if details.get("select_token_present") is not False:
            failures.append("attack event unexpectedly includes a select token")

    all_rule_ids = set()
    all_rule_ids |= collect_rule_ids(status.get("detections") or [])
    all_rule_ids |= collect_rule_ids(events_response.get("detections") or [])
    all_rule_ids |= collect_rule_ids(events_response.get("events") or [])
    all_rule_ids |= collect_rule_ids(rtu_logs)
    all_rule_ids |= collect_rule_ids(scada_logs)
    all_rule_ids |= collect_rule_ids(detection_logs)

    missing_rtu_rules = sorted(REQUIRED_RTU_RULES - all_rule_ids)
    if missing_rtu_rules:
        failures.append(f"missing required RTU workflow detections: {', '.join(missing_rtu_rules)}")
    if not (REQUIRED_SCADA_RULE_ALTERNATIVES & all_rule_ids):
        failures.append("missing SCADA correlation detection: expected UNKNOWN_CORRELATION_ID or UNMATCHED_BREAKER_TRANSITION")

    reasons = "\n".join(
        str(item.get("reason", ""))
        for item in (status.get("detections") or []) + (events_response.get("detections") or []) + detection_logs
        if isinstance(item, dict)
    )
    if "source.role=ATTACKER" in reasons or "role=ATTACKER" in reasons:
        failures.append("detection reason appears to depend on source.role=ATTACKER")

    if failures:
        print("FAIL: spoofed direct RTU attack evidence is invalid")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("PASS: spoofed direct RTU attack evidence is valid")
    print("- attacker used spoof-scada mode and claimed SCADA identity")
    print("- RTU accepted the command in vulnerable mode")
    print("- breaker opened and current/load dropped near zero")
    print("- detections show workflow, select-token, and correlation failures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
