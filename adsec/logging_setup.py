"""Configuration du logging structure JSON pour ADSEC.

Tous les logs passent par un formatter qui masque systematiquement les
motifs ressemblant a des secrets (password/token/ticket/hash/secret/private
key), en complement du masquage applique dans l'audit log dedie."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

from adsec.core.events.audit_log import redact


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "component": record.name,
            "message": redact(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        extra = getattr(record, "extra_data", None)
        if isinstance(extra, dict):
            payload["data"] = {k: redact(str(v)) for k, v in extra.items()}
        return json.dumps(payload, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        return redact(base)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure le logger racine `adsec`. A appeler une seule fois, tot
    dans le cycle de vie du process (typiquement dans la CLI)."""
    root = logging.getLogger("adsec")
    root.setLevel(level.upper())
    root.handlers.clear()

    handler = logging.StreamHandler(stream=sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(ConsoleFormatter("[%(levelname)s] %(name)s: %(message)s"))
    root.addHandler(handler)
    root.propagate = False


def get_logger(component: str) -> logging.Logger:
    return logging.getLogger(f"adsec.{component}")


def log_with_data(logger: logging.Logger, level: int, message: str, **data: object) -> None:
    logger.log(level, message, extra={"extra_data": data})
