from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from ..config import LLMConfig
from ..normalizers.nginx_normalizer import NormalizedEvent
from ..utils.openai_client import build_openai_client
from ..utils.timeutil import TimeWindow, fmt_compact


@dataclass(frozen=True)
class PerEventAIResult:
    results: list[dict[str, Any]]
    jsonl_path: str | None


def _truncate(s: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 20] + " ...[truncated]..."


def _event_for_llm(e: NormalizedEvent, max_chars: int) -> dict[str, Any]:
    src = (e.raw.get("_source") or {}) if isinstance(e.raw, dict) else {}
    msg = src.get("message")
    msg_s = _truncate(str(msg), max_chars) if msg is not None else None
    return {
        "ts": e.ts.isoformat(),
        "ip": e.ip,
        "method": e.method,
        "path": e.path,
        "status": e.status,
        "host": e.host,
        "ua": e.user_agent,
        "request_time": e.request_time,
        "upstream_time": e.upstream_time,
        "message": msg_s,
        "_id": e.raw.get("_id"),
        "_index": e.raw.get("_index"),
    }


def analyze_all_events_with_llm(
    events: list[NormalizedEvent],
    llm_cfg: LLMConfig,
    window: TimeWindow,
) -> PerEventAIResult:
    if not llm_cfg.enabled or not llm_cfg.per_event_enabled:
        return PerEventAIResult(results=[], jsonl_path=None)
    if not llm_cfg.api_key or not llm_cfg.model:
        return PerEventAIResult(results=[], jsonl_path=None)
    if not events:
        return PerEventAIResult(results=[], jsonl_path=None)

    client = build_openai_client(llm_cfg)

    batch_size = max(1, int(llm_cfg.per_event_batch_size)) if llm_cfg.per_event_batching_enabled else 1
    max_chars = int(llm_cfg.per_event_max_chars) if llm_cfg.per_event_truncate_enabled else 10**9

    run_ts = fmt_compact(window.end)
    jsonl_path = llm_cfg.per_event_jsonl_path.format(run_ts=run_ts) if llm_cfg.per_event_jsonl_path else ""
    jsonl_fp = None
    if jsonl_path:
        os.makedirs(os.path.dirname(jsonl_path) or ".", exist_ok=True)
        jsonl_fp = open(jsonl_path, "w", encoding="utf-8")

    out: list[dict[str, Any]] = []
    try:
        for i in range(0, len(events), batch_size):
            chunk = events[i : i + batch_size]
            payload = [_event_for_llm(e, max_chars=max_chars) for e in chunk]

            prompt = (
                "你是 Nginx/HTTP 访问日志审计分析助手。下面给你一批事件（JSON 数组），请对每条事件输出一个结果，"
                "要求：\n"
                "- 输出必须是 JSON 数组，长度与输入一致（一一对应）\n"
                "- 每个元素至少包含字段：risk_level（low/medium/high/critical）、category（security/compliance/ops）、"
                "summary（简短结论）、tags（字符串数组）\n"
                "- 不要输出除 JSON 以外的任何文字\n\n"
                f"输入事件(JSON)：\n{json.dumps(payload, ensure_ascii=False)}"
            )

            resp = client.chat.completions.create(
                model=llm_cfg.model,
                messages=[{"role": "user", "content": prompt}],
            )
            content = (resp.choices[0].message.content or "").strip()
            try:
                arr = json.loads(content)
                if not isinstance(arr, list) or len(arr) != len(payload):
                    raise ValueError("LLM output shape mismatch")
            except Exception:
                arr = [
                    {
                        "risk_level": "low",
                        "category": "ops",
                        "summary": "LLM 输出不可解析/格式不符合要求（已降级）",
                        "tags": ["llm_parse_error"],
                        "_raw": content[:2000],
                    }
                    for _ in payload
                ]

            for ev, r in zip(payload, arr, strict=False):
                row = {"event": ev, "ai": r}
                out.append(row)
                if jsonl_fp:
                    jsonl_fp.write(json.dumps(row, ensure_ascii=False) + "\n")
    finally:
        if jsonl_fp:
            jsonl_fp.close()

    return PerEventAIResult(results=out, jsonl_path=jsonl_path or None)

