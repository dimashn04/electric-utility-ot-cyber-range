import os


RTU_HOST = os.getenv("RTU_HOST", "0.0.0.0")
RTU_PORT = int(os.getenv("RTU_PORT", "2404"))
RTU_VULNERABLE_MODE = os.getenv("RTU_VULNERABLE_MODE", "true").lower() == "true"
LOG_DIR = os.getenv("LOG_DIR", "/logs")
AUTHORIZED_SCADA_SOURCE_ID = os.getenv("AUTHORIZED_SCADA_SOURCE_ID", "scada-master")
SELECT_TOKEN_TTL_SECONDS = int(os.getenv("SELECT_TOKEN_TTL_SECONDS", "20"))
