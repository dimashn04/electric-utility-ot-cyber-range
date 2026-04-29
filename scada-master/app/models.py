from dataclasses import dataclass
from typing import Any


@dataclass
class CommandRecord:
    correlation_id: str
    operation: str
    target_asset_id: str
    status: str
    created_at: str
    select_token: str | None = None
    completed_at: str | None = None


def empty_status() -> dict[str, Any]:
    return {
        "rtu_connected": False,
        "telemetry": None,
        "breaker": {"asset_id": "feeder-01-main-breaker", "state": "UNKNOWN"},
        "alarms": [{"severity": "critical", "message": "RTU not connected"}],
        "detections": [],
        "last_update": None,
    }
