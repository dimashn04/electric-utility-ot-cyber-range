import asyncio
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI

from .config import LOG_DIR, POLL_INTERVAL_SECONDS
from .detection import detect_event_correlation, detect_unexpected_breaker_state
from .logging_utils import JsonlLogger
from .models import CommandRecord, empty_status
from .protocol import BREAKER_ID, new_correlation_id, utc_now
from .rtu_client import RtuClient


app = FastAPI(title="SCADA Master")
client = RtuClient()
scada_logger = JsonlLogger(LOG_DIR, "scada.jsonl", "scada-master")
detection_logger = JsonlLogger(LOG_DIR, "detections.jsonl", "scada-master")

latest_status: dict[str, Any] = empty_status()
recent_events: list[dict[str, Any]] = []
recent_detections: list[dict[str, Any]] = []
command_records: dict[str, CommandRecord] = {}
last_event_index = 0
previous_breaker_state: str | None = None
recent_scada_command_countdown = 0


def add_detection(item: dict[str, Any]) -> None:
    recent_detections.append({**item, "timestamp": utc_now()})
    del recent_detections[:-30]
    detection_logger.write({"event_type": "detection", "severity": "warning", **item})


def add_event(event: dict[str, Any]) -> None:
    recent_events.append(event)
    del recent_events[:-30]


async def poll_loop() -> None:
    global latest_status, last_event_index, previous_breaker_state, recent_scada_command_countdown
    while True:
        try:
            telemetry_response = await client.read_telemetry()
            payload = telemetry_response.get("payload") or {}
            breaker = payload.get("breaker") or {"asset_id": BREAKER_ID, "state": "UNKNOWN"}
            alarm = payload.get("alarm") or {}
            current_state = breaker.get("state", "UNKNOWN")

            poll_detections = detect_unexpected_breaker_state(
                current_state,
                previous_breaker_state,
                recent_scada_command_countdown > 0,
            )
            for item in poll_detections:
                add_detection(item)
            previous_breaker_state = current_state
            if recent_scada_command_countdown > 0:
                recent_scada_command_countdown -= 1

            event_response = await client.event_log(last_event_index)
            events = ((event_response.get("payload") or {}).get("events")) or []
            for event in events:
                last_event_index = max(last_event_index, int(event.get("event_index", 0)))
                add_event(event)
                scada_logger.write({"event_type": "rtu_event_observed", "severity": event.get("severity", "info"), "details": event})
                for item in detect_event_correlation(event, command_records):
                    add_detection(item)

            alarms = []
            if alarm.get("active"):
                alarms.append({"severity": "critical", "message": alarm.get("message") or "RTU alarm active"})
            if recent_detections:
                alarms.append({"severity": "warning", "message": "Recent SCADA/RTU detections present"})

            latest_status = {
                "rtu_connected": True,
                "telemetry": payload.get("telemetry"),
                "breaker": breaker,
                "alarms": alarms,
                "detections": recent_detections[-10:],
                "last_update": utc_now(),
            }
        except Exception as exc:
            latest_status = empty_status()
            latest_status["alarms"] = [{"severity": "critical", "message": f"RTU connection error: {exc}"}]
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


@app.on_event("startup")
async def startup() -> None:
    scada_logger.write({"event_type": "service_start", "severity": "info", "details": {"poll_interval": POLL_INTERVAL_SECONDS}})
    asyncio.create_task(poll_loop())


@app.get("/api/status")
async def api_status() -> dict[str, Any]:
    return latest_status


@app.get("/api/events")
async def api_events() -> dict[str, Any]:
    return {"events": recent_events[-20:], "detections": recent_detections[-20:]}


async def command_breaker(operation: str) -> dict[str, Any]:
    global recent_scada_command_countdown
    correlation_id = new_correlation_id()
    session_id = "operator-session-phase1"
    record = CommandRecord(
        correlation_id=correlation_id,
        operation=operation,
        target_asset_id=BREAKER_ID,
        status="PENDING_SELECT",
        created_at=utc_now(),
    )
    command_records[correlation_id] = record
    select_response = await client.select_breaker(correlation_id, operation, session_id)
    select_payload = select_response.get("payload") or {}
    select_token = select_payload.get("select_token")
    record.select_token = select_token
    record.status = "PENDING_EXECUTE"

    execute_response = await client.execute_breaker(correlation_id, operation, select_token, session_id)
    record.status = (execute_response.get("payload") or {}).get("status", "UNKNOWN")
    record.completed_at = utc_now()
    recent_scada_command_countdown = 3
    scada_logger.write(
        {
            "event_type": "operator_breaker_command",
            "severity": "info",
            "correlation_id": correlation_id,
            "details": {"record": asdict(record), "rtu_response": execute_response},
        }
    )
    return {"correlation_id": correlation_id, "result": execute_response.get("payload"), "record": asdict(record)}


@app.post("/api/commands/breaker/open")
async def open_breaker() -> dict[str, Any]:
    return await command_breaker("OPEN")


@app.post("/api/commands/breaker/close")
async def close_breaker() -> dict[str, Any]:
    return await command_breaker("CLOSE")
