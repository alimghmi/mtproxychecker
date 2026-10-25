from __future__ import annotations

import hashlib
import json
import logging as py_logging
import sys
from collections.abc import Mapping
from typing import Any, TextIO

LOGGER_NAME = "mtproxy_checker"

_BASE_RECORD = py_logging.LogRecord(
    name="",
    level=0,
    pathname="",
    lineno=0,
    msg="",
    args=(),
    exc_info=None,
)
_RESERVED_RECORD_KEYS = set(_BASE_RECORD.__dict__)


def key_fingerprint(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()[:12]


def get_logger(name: str | None = None) -> py_logging.Logger:
    if name is None or name == LOGGER_NAME:
        return py_logging.getLogger(LOGGER_NAME)

    if name.startswith(f"{LOGGER_NAME}."):
        return py_logging.getLogger(name)

    return py_logging.getLogger(f"{LOGGER_NAME}.{name}")


def configure_cli_logging(
    level: int,
    *,
    json_logs: bool = False,
    stream: TextIO | None = None,
) -> None:
    logger = get_logger()
    logger.handlers.clear()
    logger.setLevel(level)
    logger.propagate = False

    handler = py_logging.StreamHandler(stream or sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(StructuredFormatter(json_logs=json_logs))
    logger.addHandler(handler)


class StructuredFormatter(py_logging.Formatter):
    def __init__(self, *, json_logs: bool = False):
        super().__init__()
        self.json_logs = json_logs

    def format(self, record: py_logging.LogRecord) -> str:
        fields = self._fields(record)

        if self.json_logs:
            return json.dumps(fields, default=str, sort_keys=True)

        prefix = (
            f"{self.formatTime(record, '%H:%M:%S')} "
            f"{record.levelname:<5s} "
            f"logger={record.name}"
        )
        key_values = " ".join(
            f"{key}={self._format_value(value)}"
            for key, value in fields.items()
            if key not in {"time", "level", "logger", "message"}
        )
        message = f"message={self._format_value(record.getMessage())}"

        if key_values:
            return f"{prefix} {key_values} {message}"

        return f"{prefix} {message}"

    def _fields(self, record: py_logging.LogRecord) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields.update(self._extras(record.__dict__))
        return fields

    @staticmethod
    def _extras(record_data: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in record_data.items()
            if key not in _RESERVED_RECORD_KEYS and not key.startswith("_")
        }

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, str):
            if not value:
                return '""'

            if any(ch.isspace() for ch in value):
                return json.dumps(value)

            return value

        return json.dumps(value, default=str)
