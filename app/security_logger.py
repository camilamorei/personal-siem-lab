import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# logs/ fica na raiz do projeto, um nível acima da pasta app/
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_FILE = LOG_DIR / "auth.log"

LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("auth")
logger.setLevel(logging.INFO)

handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


def log_auth_event(username, result, src_ip, user_agent, reason=None):
    """Grava um evento de autenticação como uma linha JSON em logs/auth.log."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "app": "personal-siem-lab",
        "event_type": "authentication",
        "action": "login",
        "result": result,
        "reason": reason,
        "user": username,
        "src_ip": src_ip,
        "user_agent": user_agent,
    }
    logger.info(json.dumps(event, ensure_ascii=False))
