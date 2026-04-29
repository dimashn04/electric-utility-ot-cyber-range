#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path
from typing import Any


REQUIRED_RULES = {
    "EXCESSIVE_GENERAL_INTERROGATION",
    "DIRECT_FIELD_INTERFACE_INTERROGATION",
}
SCADA_RULES = {
    "GENERAL_INTERROGATION_BURST",
    "RTU_INTERROGATION_WITHOUT_LOCAL_POLLING_CONTEXT",
    "INTERROGATION_RATE_ANOMALY",
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AssertionError(f"{path}:{line_number} is not valid JSON: {exc}") from exc
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
    evidence_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evidence/phase2-general-interrogation-abuse")
    failures: list[str] = []

    try:
        attacker_output = (evidence_dir / "attacker-output.txt").read_text(encoding="utf-8")
        status = load_json(evidence_dir / "status.json")
        events_response = load_json(evidence_dir / "events.json")
        rtu_logs = load_jsonl(evidence_dir / "rtu.jsonl")
        scada_logs = load_jsonl(evidence_dir / "scada.jsonl")
        detection_logs = load_jsonl(evidence_dir / "detections.jsonl")
    except Exception as exc:
        print(f"FAIL: could not load GENERAL_INTERROGATION evidence: {exc}")
        return 1

    if "GENERAL_INTERROGATION abuse completed" not in attacker_output:
        failures.append("attacker output does not show GENERAL_INTERROGATION abuse completion")
    match = re.search(r"Requests sent:\s*(\d+)", attacker_output)
    request_count = int(match.group(1)) if match else 0
    if request_count < 5:
        failures.append("attacker output does not show multiple interrogation requests")
    if "Mode: spoof-scada" not in attacker_output:
        failures.append("attacker output does not show spoof-scada mode")
    if "ATTACKER" in attacker_output:
        failures.append("default GENERAL_INTERROGATION attack output should not depend on honest ATTACKER role")

    if (status.get("breaker") or {}).get("state") != "CLOSED":
        failures.append("breaker state changed during GENERAL_INTERROGATION evidence; expected CLOSED")

    gi_events = [
        event
        for event in (events_response.get("events") or [])
        if event.get("event_type") == "general_interrogation" and event.get("message_type") == "GENERAL_INTERROGATION"
    ]
    if len(gi_events) < 5:
        failures.append("events evidence does not include multiple GENERAL_INTERROGATION RTU events")
    for event in gi_events[-3:]:
        source = event.get("claimed_source") or {}
        if source.get("role") == "ATTACKER":
            failures.append("GENERAL_INTERROGATION event depends on honest ATTACKER role")

    all_rule_ids = set()
    all_rule_ids |= collect_rule_ids(status.get("detections") or [])
    all_rule_ids |= collect_rule_ids(events_response.get("detections") or [])
    all_rule_ids |= collect_rule_ids(events_response.get("events") or [])
    all_rule_ids |= collect_rule_ids(rtu_logs)
    all_rule_ids |= collect_rule_ids(scada_logs)
    all_rule_ids |= collect_rule_ids(detection_logs)

    missing_required = sorted(REQUIRED_RULES - all_rule_ids)
    if missing_required:
        failures.append(f"missing required interrogation detections: {', '.join(missing_required)}")
    if not (SCADA_RULES & all_rule_ids):
        failures.append("missing rate/burst or SCADA-context interrogation detection")

    reasons = "\n".join(
        str(item.get("reason", ""))
        for item in (status.get("detections") or []) + (events_response.get("detections") or []) + detection_logs
        if isinstance(item, dict)
    )
    if "source.role=ATTACKER" in reasons or "role=ATTACKER" in reasons:
        failures.append("detection reason appears to depend on source.role=ATTACKER")

    if failures:
        print("FAIL: GENERAL_INTERROGATION abuse evidence is invalid")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("PASS: GENERAL_INTERROGATION abuse evidence is valid")
    print("- multiple GENERAL_INTERROGATION requests were sent")
    print("- breaker state remained unchanged")
    print("- detections show excessive/direct field-interface interrogation behavior")
    print("- detection does not depend on source.role=ATTACKER")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
