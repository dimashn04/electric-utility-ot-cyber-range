import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import SELECT_TOKEN_TTL_SECONDS
from .protocol import BREAKER_ID, utc_now


@dataclass
class SelectToken:
    token: str
    target_id: str
    operation: str
    correlation_id: str | None
    peer_key: str
    expires_at: datetime


@dataclass
class RtuState:
    breaker_state: str = "CLOSED"
    alarm_active: bool = False
    alarm_message: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    active_select_tokens: dict[str, SelectToken] = field(default_factory=dict)
    expected_sequence_by_peer: dict[str, int] = field(default_factory=dict)
    expected_sequence_by_claim: dict[str, int] = field(default_factory=dict)
    peers_with_select_history: set[str] = field(default_factory=set)
    interrogation_times_by_peer: dict[str, list[datetime]] = field(default_factory=dict)
    interrogation_times_by_claim: dict[str, list[datetime]] = field(default_factory=dict)

    def telemetry(self) -> dict[str, Any]:
        voltage = 20.0 + random.uniform(-0.25, 0.25)
        frequency = 50.0 + random.uniform(-0.03, 0.03)
        if self.breaker_state == "CLOSED":
            load = 6.0 + random.uniform(-0.35, 0.35)
            current = load * 30.0 + random.uniform(-4.0, 4.0)
        else:
            load = max(0.0, random.uniform(0.0, 0.05))
            current = max(0.0, random.uniform(0.0, 1.5))
        return {
            "voltage_kv": round(voltage, 2),
            "current_a": round(current, 2),
            "load_mw": round(load, 2),
            "frequency_hz": round(frequency, 3),
            "timestamp": utc_now(),
        }

    def create_select_token(self, target_id: str, operation: str, correlation_id: str | None, peer_key: str) -> str:
        self.expire_tokens()
        token = f"sel-{secrets.token_hex(12)}"
        self.active_select_tokens[token] = SelectToken(
            token=token,
            target_id=target_id,
            operation=operation,
            correlation_id=correlation_id,
            peer_key=peer_key,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=SELECT_TOKEN_TTL_SECONDS),
        )
        self.peers_with_select_history.add(peer_key)
        return token

    def validate_select_token(
        self,
        token: str | None,
        target_id: str,
        operation: str,
        correlation_id: str | None,
        peer_key: str,
    ) -> tuple[bool, str]:
        self.expire_tokens()
        if not token:
            return False, "missing"
        record = self.active_select_tokens.get(token)
        if record is None:
            return False, "unknown"
        if record.expires_at < datetime.now(timezone.utc):
            self.active_select_tokens.pop(token, None)
            return False, "expired"
        if record.target_id != target_id or record.operation != operation:
            return False, "target_or_operation_mismatch"
        if record.correlation_id != correlation_id:
            return False, "correlation_mismatch"
        if record.peer_key != peer_key:
            return False, "peer_mismatch"
        self.active_select_tokens.pop(token, None)
        return True, "valid"

    def peer_has_select_history(self, peer_key: str) -> bool:
        return peer_key in self.peers_with_select_history

    def apply_breaker_operation(self, operation: str) -> tuple[str, str]:
        previous = self.breaker_state
        if operation == "OPEN":
            self.breaker_state = "OPEN"
        elif operation == "CLOSE":
            self.breaker_state = "CLOSED"
        else:
            raise ValueError(f"unsupported breaker operation: {operation}")
        return previous, self.breaker_state

    def add_event(self, event: dict[str, Any]) -> dict[str, Any]:
        event = {"event_index": len(self.events) + 1, "rtu_event_timestamp": utc_now(), **event}
        self.events.append(event)
        self.events = self.events[-100:]
        return event

    def events_since(self, after_index: int) -> list[dict[str, Any]]:
        return [event for event in self.events if int(event.get("event_index", 0)) > after_index]

    def point_summary(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "feeder_01_main_breaker_state",
                "type": "single_point",
                "common_address": 100,
                "information_object_address": 2001,
                "value": self.breaker_state,
            },
            {
                "name": "feeder_01_voltage_kv",
                "type": "measured_value",
                "common_address": 100,
                "information_object_address": 2101,
            },
            {
                "name": "feeder_01_current_a",
                "type": "measured_value",
                "common_address": 100,
                "information_object_address": 2102,
            },
            {
                "name": "feeder_01_load_mw",
                "type": "measured_value",
                "common_address": 100,
                "information_object_address": 2103,
            },
            {
                "name": "feeder_01_frequency_hz",
                "type": "measured_value",
                "common_address": 100,
                "information_object_address": 2104,
            },
        ]

    def record_general_interrogation(self, peer_key: str, claim_key: str, window_seconds: int = 10) -> tuple[int, int]:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        peer_times = [item for item in self.interrogation_times_by_peer.get(peer_key, []) if item >= cutoff]
        claim_times = [item for item in self.interrogation_times_by_claim.get(claim_key, []) if item >= cutoff]
        peer_times.append(now)
        claim_times.append(now)
        self.interrogation_times_by_peer[peer_key] = peer_times
        self.interrogation_times_by_claim[claim_key] = claim_times
        return len(peer_times), len(claim_times)

    def expire_tokens(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [token for token, record in self.active_select_tokens.items() if record.expires_at < now]
        for token in expired:
            self.active_select_tokens.pop(token, None)


def default_target(message: dict[str, Any]) -> dict[str, Any]:
    return message.get("target") or {"asset_type": "BREAKER", "asset_id": BREAKER_ID}
