from __future__ import annotations

from elastic_transport import ConnectionError as ESConnectionError

from .config import AppConfig
from .interfaces import AnalyzeResult, FetchResult
from .sources.es_source import fetch_events_from_es
from .normalizers.nginx_normalizer import normalize_events
from .analyzers.basic_stats import basic_audit
from .analyzers.ai_summary import maybe_summarize_with_llm
from .analyzers.ai_per_event import analyze_all_events_with_llm
from .utils.timeutil import TimeWindow


def run_pipeline(cfg: AppConfig, window: TimeWindow, max_docs: int, page_size: int) -> tuple[FetchResult, list, AnalyzeResult]:
    """
    主流程（便于后期扩展）：
    - fetch（ES） -> normalize -> AI analyze（全量）+ AI summary（可选） -> 返回结构化结果
    """
    try:
        raw_hits = fetch_events_from_es(
            es_cfg=cfg.elasticsearch,
            window=window,
            page_size=page_size,
            max_docs=max_docs,
        )
    except ESConnectionError as e:
        raise RuntimeError(
            "无法连接 Elasticsearch。请检查 config/audit.yaml 中的 elasticsearch.url/user/password/verify_certs。"
        ) from e

    events = normalize_events(raw_hits, cfg.elasticsearch.time_field, cfg.query.timezone)

    # 仅基础统计（不做规则判断）
    audit = basic_audit(events)
    llm_summary = maybe_summarize_with_llm(audit, cfg.llm)

    per_event = analyze_all_events_with_llm(events, cfg.llm, window)

    per_event_ai = None
    if per_event.results:
        per_event_ai = {
            "jsonl_path": per_event.jsonl_path,
            "risk_level_counts": _top_counts([r.get("ai", {}).get("risk_level") for r in per_event.results]),
            "category_counts": _top_counts([r.get("ai", {}).get("category") for r in per_event.results]),
            "top_tags": _top_counts([t for r in per_event.results for t in (r.get("ai", {}).get("tags") or [])], limit=20),
            "samples": per_event.results[:200],
            "sample_size": min(200, len(per_event.results)),
        }

    analyze = AnalyzeResult(
        per_event_ai=per_event_ai,
        llm_summary=llm_summary,
        meta={
            "fetched_docs": len(raw_hits),
            "normalized_events": len(events),
            "per_event_ai_total": len(per_event.results),
        },
    )

    return FetchResult(raw_hits=raw_hits), events, analyze


def _top_counts(values: list[object], limit: int = 10) -> list[tuple[str, int]]:
    from collections import Counter

    c = Counter(str(v) for v in values if v not in (None, "", "None"))
    return c.most_common(limit)

