from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .config import AppConfig
from .normalizers.nginx_normalizer import NormalizedEvent
from .utils.timeutil import TimeWindow


@dataclass(frozen=True)
class FetchResult:
    raw_hits: list[dict[str, Any]]


@dataclass(frozen=True)
class AnalyzeResult:
    # 用于 HTML 展示的 AI 汇总（可选）
    per_event_ai: dict[str, Any] | None
    # 用于报告正文的自然语言总结（可选）
    llm_summary: str | None
    # 元信息（可选）
    meta: dict[str, Any]


class Source(Protocol):
    def fetch(self, cfg: AppConfig, window: TimeWindow, max_docs: int) -> FetchResult: ...


class Normalizer(Protocol):
    def normalize(self, cfg: AppConfig, window: TimeWindow, raw_hits: list[dict[str, Any]]) -> list[NormalizedEvent]: ...


class Analyzer(Protocol):
    def analyze(self, cfg: AppConfig, window: TimeWindow, events: list[NormalizedEvent]) -> AnalyzeResult: ...

