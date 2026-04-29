#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from typing import Any


CRITICAL_RULES = {
    "COMMAND_WITHOUT_VALID_SELECT",
    "UNKNOWN_CORRELATION_ID",
    "DIRECT_FIELD_INTERFACE_CONTROL",
    "UNMATCHED_BREAKER_TRANSITION",
    "CLAIMED_SOURCE_MISMATCH",
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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


def command_detections(response: dict[str, Any]) -> list[Any]:
    return ((response.get("result") or {}).get("detections")) or []


def collect_rule_ids(items: list[Any]) -> set[str]:
    rule_ids: set[str] = set()
    for item in items:
        if isinstance(item, dict):
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
    evidence_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evidence/phase1-normal-scada-workflow")
    failures: list[str] = []

    try:
        close_response = load_json(evidence_dir / "close-response.json")
        open_response = load_json(evidence_dir / "open-response.json")
        status = load_json(evidence_dir / "status.json")
        events_response = load_json(evidence_dir / "events.json")
        rtu_logs = load_jsonl(evidence_dir / "rtu.jsonl")
        scada_logs = load_jsonl(evidence_dir / "scada.jsonl")
        detection_logs = load_jsonl(evidence_dir / "detections.jsonl")
    except Exception as exc:
        print(f"FAIL: could not load normal evidence: {exc}")
        return 1

    if command_detections(close_response):
        failures.append("close command response contains detections")
    if command_detections(open_response):
        failures.append("open command response contains detections")

    breaker_events = [
        event
        for event in (events_response.get("events") or [])
        if event.get("event_type") == "breaker_command" and event.get("message_type") == "EXECUTE_BREAKER"
    ]
    if not breaker_events:
        failures.append("no normal EXECUTE_BREAKER RTU events found")

    for event in breaker_events:
        details = event.get("details") or {}
        if details.get("select_token_present") is not True:
            failures.append(f"event {event.get('event_index')} missing select token")
        if details.get("select_token_valid") is not True:
            failures.append(f"event {event.get('event_index')} select token is not valid")
        if details.get("select_token_status") != "valid":
            failures.append(f"event {event.get('event_index')} select token status is not valid")
        if event.get("detections") != []:
            failures.append(f"event {event.get('event_index')} contains detections")

    all_rule_ids = set()
    all_rule_ids |= collect_rule_ids(status.get("detections") or [])
    all_rule_ids |= collect_rule_ids(events_response.get("detections") or [])
    all_rule_ids |= collect_rule_ids(events_response.get("events") or [])
    all_rule_ids |= collect_rule_ids(rtu_logs)
    all_rule_ids |= collect_rule_ids(scada_logs)
    all_rule_ids |= collect_rule_ids(detection_logs)
    forbidden = sorted(CRITICAL_RULES & all_rule_ids)
    if forbidden:
        failures.append(f"critical workflow-bypass detections appeared in normal evidence: {', '.join(forbidden)}")

    if failures:
        print("FAIL: normal SCADA workflow evidence is invalid")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("PASS: normal SCADA workflow evidence is valid")
    print("- command responses have detections: []")
    print("- normal EXECUTE_BREAKER events used valid select-before-operate tokens")
    print("- critical workflow-bypass detections are absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
