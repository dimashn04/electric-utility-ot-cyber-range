from datetime import datetime, timezone
from typing import Any

from .config import AUTHORIZED_SCADA_SOURCE_ID


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def detection(rule_id: str, reason: str) -> dict[str, Any]:
    return {"rule_id": rule_id, "matched": True, "reason": reason}


def detect_timestamp_anomaly(message: dict[str, Any], receive_time: datetime) -> list[dict[str, Any]]:
    sent = _parse_ts(message.get("timestamp"))
    if sent is None:
        return [detection("TIMESTAMP_ANOMALY", "Message timestamp is missing or invalid")]
    delta = abs((receive_time - sent).total_seconds())
    if delta > 60:
        return [detection("TIMESTAMP_ANOMALY", "Message timestamp differs from RTU receive time by more than 60 seconds")]
    return []


def detect_sequence_anomaly(
    message: dict[str, Any],
    peer_key: str,
    expected_by_peer: dict[str, int],
    expected_by_claim: dict[str, int],
) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    sequence = message.get("sequence")
    source = message.get("source") or {}
    claim_key = f"{source.get('id', 'unknown')}:{source.get('role', 'unknown')}"

    if not isinstance(sequence, int):
        return [detection("SEQUENCE_ANOMALY", "Message sequence is missing or not an integer")]

    previous_peer = expected_by_peer.get(peer_key)
    previous_claim = expected_by_claim.get(claim_key)
    if previous_peer is not None and sequence <= previous_peer:
        detections.append(detection("SEQUENCE_ANOMALY", "Sequence did not increase for network peer"))
    if previous_claim is not None and sequence <= previous_claim:
        detections.append(detection("SEQUENCE_ANOMALY", "Sequence did not increase for claimed source identity"))

    expected_by_peer[peer_key] = max(sequence, previous_peer or sequence)
    expected_by_claim[claim_key] = max(sequence, previous_claim or sequence)
    return detections


def detect_execute_workflow(
    message: dict[str, Any],
    select_token_valid: bool,
    claims_authorized_scada: bool,
    peer_has_select_history: bool,
) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    if not select_token_valid:
        detections.append(
            detection(
                "COMMAND_WITHOUT_VALID_SELECT",
                "EXECUTE_BREAKER did not include a valid select-before-operate token",
            )
        )
        detections.append(
            detection(
                "DIRECT_FIELD_INTERFACE_CONTROL",
                "Breaker command arrived without normal select-before-operate workflow evidence",
            )
        )

    source = message.get("source") or {}
    if claims_authorized_scada and not peer_has_select_history:
        detections.append(
            detection(
                "CLAIMED_SOURCE_MISMATCH",
                f"Message claims {AUTHORIZED_SCADA_SOURCE_ID} but peer has no recent select workflow",
            )
        )
    elif source.get("id") != AUTHORIZED_SCADA_SOURCE_ID and not select_token_valid:
        detections.append(
            detection(
                "DIRECT_FIELD_INTERFACE_CONTROL",
                "Breaker command came from a claimed source outside the normal SCADA identity",
            )
        )
    return detections
