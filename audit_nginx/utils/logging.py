from __future__ import annotations

import logging
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"  # DEBUG/INFO/WARN/ERROR
    to_file: bool = False
    file_path: str = "./logs/audit.log"


def setup_logging(cfg: LoggingConfig) -> None:
    level = getattr(logging, (cfg.level or "INFO").upper(), logging.INFO)

    handlers: list[logging.Handler] = []
    stream = logging.StreamHandler()
    stream.setLevel(level)
    handlers.append(stream)

    if cfg.to_file:
        os.makedirs(os.path.dirname(cfg.file_path) or ".", exist_ok=True)
        fh = logging.FileHandler(cfg.file_path, encoding="utf-8")
        fh.setLevel(level)
        handlers.append(fh)

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        handlers=handlers,
    )

