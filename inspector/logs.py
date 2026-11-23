"""Logging setup: human-readable text by default, JSON lines for log shippers (LOG_FORMAT=json).

Every log line written while handling a web request carries that request's ID, which is also
returned to the client in the X-Request-ID header and in error responses, so a user's report
("request 3f2a... failed") leads straight to the matching server logs.
"""

import contextvars
import json
import logging
import os
import sys
from datetime import datetime, timezone

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
EXTRA_FIELDS = ("method", "path", "status", "duration_ms", "user", "ip", "collector")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get() or "-"
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        rid = getattr(record, "request_id", None)
        if rid and rid != "-":
            entry["request_id"] = rid
        for key in EXTRA_FIELDS:
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(level: str | None = None, fmt: str | None = None) -> None:
    level = (level or os.environ.get("LOG_LEVEL", "INFO")).upper()
    fmt = (fmt or os.environ.get("LOG_FORMAT", "text")).lower()
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RequestIdFilter())
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(request_id)s]: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
