import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rtu-simulator"))

from app.detection import detect_execute_workflow, detect_general_interrogation


def test_spoofed_scada_without_select_fires_workflow_detections():
    message = {"source": {"id": "scada-master", "role": "SCADA_MASTER"}}
    detections = detect_execute_workflow(
        message,
        select_token_valid=False,
        claims_authorized_scada=True,
        peer_has_select_history=False,
    )
    rule_ids = {item["rule_id"] for item in detections}
    assert "COMMAND_WITHOUT_VALID_SELECT" in rule_ids
    assert "DIRECT_FIELD_INTERFACE_CONTROL" in rule_ids
    assert "CLAIMED_SOURCE_MISMATCH" in rule_ids


def test_general_interrogation_burst_fires_workflow_detections():
    message = {"source": {"id": "scada-master", "role": "SCADA_MASTER"}}
    detections = detect_general_interrogation(
        message,
        claims_authorized_scada=True,
        peer_has_select_history=False,
        recent_peer_count=5,
        recent_claim_count=5,
    )
    rule_ids = {item["rule_id"] for item in detections}
    assert "EXCESSIVE_GENERAL_INTERROGATION" in rule_ids
    assert "INTERROGATION_RATE_ANOMALY" in rule_ids
    assert "DIRECT_FIELD_INTERFACE_INTERROGATION" in rule_ids
    assert "CLAIMED_SOURCE_MISMATCH" in rule_ids
