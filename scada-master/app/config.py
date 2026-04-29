import os


SCADA_HOST = os.getenv("SCADA_HOST", "0.0.0.0")
SCADA_PORT = int(os.getenv("SCADA_PORT", "8000"))
RTU_HOST = os.getenv("RTU_HOST", "rtu-simulator")
RTU_PORT = int(os.getenv("RTU_PORT", "2404"))
LOG_DIR = os.getenv("LOG_DIR", "/logs")
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "1.0"))
