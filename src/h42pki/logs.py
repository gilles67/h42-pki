"""Logging of the server: format chosen at start (``logging.format``), level applied hot."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Literal

LogFormat = Literal["text", "json"]
LogLevel = Literal["debug", "info", "warning", "error"]

# Loggers driven by the ``logging.level`` setting.
SERVER_LOGGERS = ("h42pki", "uvicorn", "uvicorn.error", "uvicorn.access")
_HANDLER_NAME = "h42pki"
TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """One JSON object per line: timestamp, level, logger, message (and exception)."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(log_format: LogFormat, level: LogLevel) -> None:
    """Install one stderr handler on the root logger (idempotent) and set the level."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if handler.get_name() == _HANDLER_NAME:
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.set_name(_HANDLER_NAME)
    formatter = JsonFormatter() if log_format == "json" else logging.Formatter(TEXT_FORMAT)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        # Uvicorn's own handlers are not installed (log_config=None): use the root handler.
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    set_log_level(level)


def set_log_level(level: LogLevel) -> None:
    for name in SERVER_LOGGERS:
        logging.getLogger(name).setLevel(level.upper())
