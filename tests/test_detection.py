import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rtu-simulator"))

from app.detection import detect_execute_workflow


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
