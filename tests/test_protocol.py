import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scada-master"))

from app.protocol import decode_message, encode_message, envelope


def test_json_lines_round_trip():
    message = envelope("READ_TELEMETRY", 1)
    encoded = encode_message(message)
    assert encoded.endswith(b"\n")
    decoded = decode_message(encoded)
    assert decoded["protocol"] == "IEC104_INSPIRED_LAB"
    assert decoded["message_type"] == "READ_TELEMETRY"
    assert decoded["sequence"] == 1
