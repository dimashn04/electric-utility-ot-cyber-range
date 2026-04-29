import json
import uuid
from datetime import datetime, timezone
from typing import Any


PROTOCOL_NAME = "IEC104_INSPIRED_LAB"
BREAKER_ID = "feeder-01-main-breaker"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def encode_message(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


def decode_message(line: bytes | str) -> dict[str, Any]:
    if isinstance(line, bytes):
        line = line.decode("utf-8")
    return json.loads(line.strip())


def attack_execute_breaker(mode: str, sequence: int = 1) -> dict[str, Any]:
    if mode == "honest-attacker":
        source = {"id": "attacker-node", "role": "ATTACKER"}
        correlation_id = f"attack-{uuid.uuid4().hex[:8]}"
        select_token = None
    elif mode == "missing-select-token":
        source = {"id": "scada-master", "role": "SCADA_MASTER"}
        correlation_id = f"cmd-missing-token-{uuid.uuid4().hex[:8]}"
        select_token = None
    else:
        source = {"id": "scada-master", "role": "SCADA_MASTER"}
        correlation_id = f"cmd-spoofed-{uuid.uuid4().hex[:8]}"
        select_token = None

    payload = {"operation": "OPEN"}
    if select_token:
        payload["select_token"] = select_token

    return {
        "protocol": PROTOCOL_NAME,
        "message_type": "EXECUTE_BREAKER",
        "sequence": sequence,
        "timestamp": utc_now(),
        "correlation_id": correlation_id,
        "session_id": "operator-session-spoofed" if mode != "honest-attacker" else None,
        "command_origin": "HMI_OPERATOR" if mode != "honest-attacker" else None,
        "source": source,
        "target": {"asset_type": "BREAKER", "asset_id": BREAKER_ID},
        "addressing": {
            "originator_address": 1,
            "common_address": 100,
            "information_object_address": 2001,
        },
        "cause_of_transmission": "ACTIVATION",
        "payload": payload,
    }
