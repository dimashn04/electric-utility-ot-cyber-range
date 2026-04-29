import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rtu-simulator"))

from app.state import RtuState


def test_breaker_state_affects_telemetry():
    state = RtuState()
    state.breaker_state = "CLOSED"
    closed = state.telemetry()
    state.breaker_state = "OPEN"
    opened = state.telemetry()
    assert closed["load_mw"] > 1.0
    assert closed["current_a"] > 10.0
    assert opened["load_mw"] < 0.1
    assert opened["current_a"] < 2.0


def test_select_token_bound_to_peer_and_correlation():
    state = RtuState()
    token = state.create_select_token("feeder-01-main-breaker", "OPEN", "cmd-1", "peer-a")
    valid, status = state.validate_select_token(token, "feeder-01-main-breaker", "OPEN", "cmd-1", "peer-b")
    assert not valid
    assert status == "peer_mismatch"
