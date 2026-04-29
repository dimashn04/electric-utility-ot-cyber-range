import json
import uuid
from datetime import datetime, timezone
from typing import Any


PROTOCOL_NAME = "IEC104_INSPIRED_LAB"
BREAKER_ID = "feeder-01-main-breaker"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_correlation_id(prefix: str = "cmd") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def encode_message(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


def decode_message(line: bytes | str) -> dict[str, Any]:
    if isinstance(line, bytes):
        line = line.decode("utf-8")
    data = json.loads(line.strip())
    if not isinstance(data, dict):
        raise ValueError("message must be a JSON object")
    return data


def envelope(
    message_type: str,
    sequence: int,
    correlation_id: str | None = None,
    operation: str | None = None,
    select_token: str | None = None,
    session_id: str | None = None,
    command_origin: str | None = None,
    cause: str = "REQUEST",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = payload.copy() if payload else {}
    if operation:
        body["operation"] = operation
    if select_token:
        body["select_token"] = select_token
    return {
        "protocol": PROTOCOL_NAME,
        "message_type": message_type,
        "sequence": sequence,
        "timestamp": utc_now(),
        "correlation_id": correlation_id,
        "session_id": session_id,
        "command_origin": command_origin,
        "source": {"id": "scada-master", "role": "SCADA_MASTER"},
        "target": {"asset_type": "BREAKER", "asset_id": BREAKER_ID},
        "addressing": {
            "originator_address": 1,
            "common_address": 100,
            "information_object_address": 2001,
        },
        "cause_of_transmission": cause,
        "payload": body,
    }
