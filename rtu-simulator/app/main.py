import asyncio
from datetime import datetime, timezone
from typing import Any

from .config import AUTHORIZED_SCADA_SOURCE_ID, LOG_DIR, RTU_HOST, RTU_PORT, RTU_VULNERABLE_MODE
from .detection import detect_execute_workflow, detect_sequence_anomaly, detect_timestamp_anomaly
from .logging_utils import JsonlLogger
from .protocol import BREAKER_ID, PROTOCOL_NAME, decode_message, encode_message, utc_now
from .state import RtuState, default_target


state = RtuState()
rtu_logger = JsonlLogger(LOG_DIR, "rtu.jsonl", "rtu-simulator")
detection_logger = JsonlLogger(LOG_DIR, "detections.jsonl", "rtu-simulator")


def peer_key(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if not peer:
        return "unknown"
    return str(peer[0])


def network_peer(writer: asyncio.StreamWriter) -> dict[str, Any]:
    peer = writer.get_extra_info("peername")
    if not peer:
        return {"host": "unknown", "port": 0}
    return {"host": peer[0], "port": peer[1]}


def response(message_type: str, request: dict[str, Any], payload: dict[str, Any], ok: bool = True) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_NAME,
        "message_type": message_type,
        "sequence": request.get("sequence"),
        "timestamp": utc_now(),
        "correlation_id": request.get("correlation_id"),
        "source": {"id": "rtu-simulator", "role": "RTU"},
        "target": request.get("target"),
        "cause_of_transmission": "RESPONSE" if ok else "ERROR",
        "payload": payload,
    }


def log_detection_events(event: dict[str, Any]) -> None:
    for item in event.get("detections", []):
        detection_logger.write(
            {
                "event_type": "detection",
                "severity": "warning",
                "rule_id": item["rule_id"],
                "correlation_id": event.get("correlation_id"),
                "details": {
                    "reason": item["reason"],
                    "rtu_event_index": event.get("event_index"),
                    "claimed_source": event.get("claimed_source"),
                    "network_peer": event.get("network_peer"),
                },
            }
        )


def handle_read_telemetry(message: dict[str, Any]) -> dict[str, Any]:
    return response(
        "TELEMETRY_RESPONSE",
        message,
        {
            "breaker": {"asset_id": BREAKER_ID, "state": state.breaker_state},
            "telemetry": state.telemetry(),
            "alarm": {"active": state.alarm_active, "message": state.alarm_message},
        },
    )


def handle_select_breaker(message: dict[str, Any], peer: str) -> dict[str, Any]:
    target = default_target(message)
    payload = message.get("payload") or {}
    operation = payload.get("operation")
    token = state.create_select_token(target.get("asset_id", BREAKER_ID), operation, message.get("correlation_id"), peer)
    event = state.add_event(
        {
            "event_type": "select_breaker",
            "severity": "info",
            "message_type": "SELECT_BREAKER",
            "sequence": message.get("sequence"),
            "correlation_id": message.get("correlation_id"),
            "session_id": message.get("session_id"),
            "command_origin": message.get("command_origin"),
            "claimed_source": message.get("source"),
            "target": target,
            "details": {"operation": operation, "select_token_issued": True},
            "detections": [],
        }
    )
    rtu_logger.write(event)
    return response("COMMAND_RESPONSE", message, {"status": "SELECTED", "select_token": token})


def handle_execute_breaker(message: dict[str, Any], peer: str, peer_info: dict[str, Any]) -> dict[str, Any]:
    target = default_target(message)
    payload = message.get("payload") or {}
    operation = payload.get("operation")
    select_token = payload.get("select_token")
    token_valid, token_status = state.validate_select_token(
        select_token,
        target.get("asset_id", BREAKER_ID),
        operation,
        message.get("correlation_id"),
        peer,
    )

    source = message.get("source") or {}
    claims_authorized_scada = source.get("id") == AUTHORIZED_SCADA_SOURCE_ID
    detections = detect_execute_workflow(
        message,
        token_valid,
        claims_authorized_scada,
        state.peer_has_select_history(peer),
    )

    execute_allowed = token_valid or RTU_VULNERABLE_MODE
    previous = state.breaker_state
    new_state = previous
    status = "REJECTED"
    if execute_allowed:
        previous, new_state = state.apply_breaker_operation(operation)
        status = "ACCEPTED"
        if detections:
            state.alarm_active = True
            state.alarm_message = "Suspicious breaker control workflow detected"

    event = state.add_event(
        {
            "event_type": "breaker_command",
            "severity": "warning" if detections else "info",
            "message_type": "EXECUTE_BREAKER",
            "sequence": message.get("sequence"),
            "message_timestamp": message.get("timestamp"),
            "rtu_receive_timestamp": utc_now(),
            "correlation_id": message.get("correlation_id"),
            "session_id": message.get("session_id"),
            "command_origin": message.get("command_origin"),
            "claimed_source": source,
            "network_peer": peer_info,
            "target": target,
            "details": {
                "operation": operation,
                "previous_state": previous,
                "new_state": new_state,
                "select_token_present": bool(select_token),
                "select_token_valid": token_valid,
                "select_token_status": token_status,
                "vulnerable_mode": RTU_VULNERABLE_MODE,
                "command_status": status,
            },
            "detections": detections,
        }
    )
    rtu_logger.write(event)
    log_detection_events(event)
    return response(
        "COMMAND_RESPONSE",
        message,
        {
            "status": status,
            "breaker": {"asset_id": BREAKER_ID, "state": state.breaker_state},
            "detections": detections,
        },
        ok=execute_allowed,
    )


def handle_event_log_request(message: dict[str, Any]) -> dict[str, Any]:
    after_index = int((message.get("payload") or {}).get("after_index", 0))
    return response("EVENT_LOG_RESPONSE", message, {"events": state.events_since(after_index)})


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = peer_key(writer)
    peer_info = network_peer(writer)
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not line:
            return
        receive_time = datetime.now(timezone.utc)
        message = decode_message(line)
        timestamp_detections = detect_timestamp_anomaly(message, receive_time)
        sequence_detections = detect_sequence_anomaly(
            message,
            peer,
            state.expected_sequence_by_peer,
            state.expected_sequence_by_claim,
        )
        pre_detections = timestamp_detections + sequence_detections
        for item in pre_detections:
            detection_logger.write(
                {
                    "event_type": "detection",
                    "severity": "warning",
                    "rule_id": item["rule_id"],
                    "correlation_id": message.get("correlation_id"),
                    "details": {"reason": item["reason"], "claimed_source": message.get("source"), "network_peer": peer_info},
                }
            )

        message_type = message.get("message_type")
        if message_type in {"READ_TELEMETRY", "GENERAL_INTERROGATION", "HEARTBEAT"}:
            reply = handle_read_telemetry(message)
        elif message_type == "SELECT_BREAKER":
            reply = handle_select_breaker(message, peer)
        elif message_type == "EXECUTE_BREAKER":
            reply = handle_execute_breaker(message, peer, peer_info)
        elif message_type == "EVENT_LOG_REQUEST":
            reply = handle_event_log_request(message)
        else:
            reply = response("ERROR", message, {"error": f"unsupported message_type: {message_type}"}, ok=False)
        if pre_detections and isinstance(reply.get("payload"), dict):
            reply["payload"].setdefault("detections", []).extend(pre_detections)
        writer.write(encode_message(reply))
        await writer.drain()
    except Exception as exc:
        request = {"sequence": None, "correlation_id": None, "target": None}
        writer.write(encode_message(response("ERROR", request, {"error": str(exc)}, ok=False)))
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def main() -> None:
    server = await asyncio.start_server(handle_client, RTU_HOST, RTU_PORT)
    rtu_logger.write(
        {
            "event_type": "service_start",
            "severity": "info",
            "details": {"host": RTU_HOST, "port": RTU_PORT, "vulnerable_mode": RTU_VULNERABLE_MODE},
        }
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
