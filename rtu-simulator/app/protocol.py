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


def base_message(
    message_type: str,
    sequence: int,
    source_id: str,
    source_role: str,
    cause: str,
    correlation_id: str | None = None,
    payload: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_NAME,
        "message_type": message_type,
        "sequence": sequence,
        "timestamp": utc_now(),
        "correlation_id": correlation_id,
        "session_id": None,
        "command_origin": None,
        "source": {"id": source_id, "role": source_role},
        "target": target or {"asset_type": "BREAKER", "asset_id": BREAKER_ID},
        "addressing": {
            "originator_address": 1,
            "common_address": 100,
            "information_object_address": 2001,
        },
        "cause_of_transmission": cause,
        "payload": payload or {},
    }
