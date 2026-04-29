import json
import os
from pathlib import Path
from typing import Any

from .protocol import utc_now


class JsonlLogger:
    def __init__(self, log_dir: str, file_name: str, service: str):
        self.path = Path(log_dir) / file_name
        self.service = service
        os.makedirs(log_dir, exist_ok=True)

    def write(self, event: dict[str, Any]) -> None:
        record = {"timestamp": utc_now(), "service": self.service, **event}
        line = json.dumps(record, separators=(",", ":"))
        print(line, flush=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
