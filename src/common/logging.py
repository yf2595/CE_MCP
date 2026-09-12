"""Simple structured logging helpers."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("aidc_ce_mcp")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def log_json(logger: logging.Logger, event: str, **payload: Any) -> None:
    logger.info("%s %s", event, json.dumps(payload, default=str))
