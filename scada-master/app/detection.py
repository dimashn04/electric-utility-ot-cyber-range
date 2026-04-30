from typing import Any


def detection(rule_id: str, reason: str, event: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "matched": True,
        "reason": reason,
        "event_index": event.get("event_index") if event else None,
        "correlation_id": event.get("correlation_id") if event else None,
    }


def detect_event_correlation(event: dict[str, Any], command_records: dict[str, Any]) -> list[dict[str, Any]]:
    if event.get("event_type") == "general_interrogation":
        detections = [
            detection(
                "RTU_INTERROGATION_WITHOUT_LOCAL_POLLING_CONTEXT",
                "RTU reported GENERAL_INTERROGATION activity outside the SCADA Master's normal telemetry polling context",
                event,
            )
        ]
        for rtu_detection in event.get("detections", []):
            detections.append(
                {
                    "rule_id": rtu_detection.get("rule_id"),
                    "matched": True,
                    "reason": rtu_detection.get("reason"),
                    "event_index": event.get("event_index"),
                    "correlation_id": event.get("correlation_id"),
                }
            )
        return detections

    if event.get("event_type") != "breaker_command":
        return []

    detections: list[dict[str, Any]] = []
    correlation_id = event.get("correlation_id")
    details = event.get("details") or {}
    local_record = command_records.get(correlation_id) if correlation_id else None

    if not correlation_id or local_record is None:
        detections.append(detection("UNKNOWN_CORRELATION_ID", "No matching SCADA command record exists", event))
        detections.append(detection("RTU_EVENT_WITHOUT_LOCAL_PENDING_COMMAND", "RTU breaker event has no local pending command", event))

    if details.get("previous_state") != details.get("new_state") and local_record is None:
        detections.append(
            detection(
                "UNMATCHED_BREAKER_TRANSITION",
                "Breaker changed state without a matching SCADA command record",
                event,
            )
        )

    for rtu_detection in event.get("detections", []):
        detections.append(
            {
                "rule_id": rtu_detection.get("rule_id"),
                "matched": True,
                "reason": rtu_detection.get("reason"),
                "event_index": event.get("event_index"),
                "correlation_id": correlation_id,
            }
        )

    return detections


def detect_unexpected_breaker_state(
    current_state: str,
    previous_state: str | None,
    recent_known_command: bool,
) -> list[dict[str, Any]]:
    if previous_state and current_state != previous_state and not recent_known_command:
        return [
            {
                "rule_id": "UNEXPECTED_BREAKER_STATE_AFTER_POLLING",
                "matched": True,
                "reason": "Breaker state changed after polling without a recent SCADA command",
                "event_index": None,
                "correlation_id": None,
            }
        ]
    return []
