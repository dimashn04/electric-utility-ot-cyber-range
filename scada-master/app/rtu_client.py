import asyncio
from typing import Any

from .config import RTU_HOST, RTU_PORT
from .protocol import decode_message, encode_message, envelope


class RtuClient:
    def __init__(self) -> None:
        self.sequence = 0

    def next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence

    async def send(self, message: dict[str, Any]) -> dict[str, Any]:
        reader, writer = await asyncio.open_connection(RTU_HOST, RTU_PORT)
        writer.write(encode_message(message))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=5)
        writer.close()
        await writer.wait_closed()
        return decode_message(line)

    async def read_telemetry(self) -> dict[str, Any]:
        return await self.send(envelope("READ_TELEMETRY", self.next_sequence()))

    async def event_log(self, after_index: int) -> dict[str, Any]:
        return await self.send(envelope("EVENT_LOG_REQUEST", self.next_sequence(), payload={"after_index": after_index}))

    async def select_breaker(self, correlation_id: str, operation: str, session_id: str) -> dict[str, Any]:
        return await self.send(
            envelope(
                "SELECT_BREAKER",
                self.next_sequence(),
                correlation_id=correlation_id,
                operation=operation,
                session_id=session_id,
                command_origin="HMI_OPERATOR",
                cause="ACTIVATION",
            )
        )

    async def execute_breaker(
        self,
        correlation_id: str,
        operation: str,
        select_token: str,
        session_id: str,
    ) -> dict[str, Any]:
        return await self.send(
            envelope(
                "EXECUTE_BREAKER",
                self.next_sequence(),
                correlation_id=correlation_id,
                operation=operation,
                select_token=select_token,
                session_id=session_id,
                command_origin="HMI_OPERATOR",
                cause="ACTIVATION",
            )
        )
