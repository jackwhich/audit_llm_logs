from __future__ import annotations

import json
import os
from typing import Any

from ..config import AppConfig
from ..interfaces import AnalyzeResult
from ..utils.openai_client import build_openai_client
from ..utils.timeutil import TimeWindow


def generate_html_report_with_llm(
    cfg: AppConfig,
    window: TimeWindow,
    analyzed: AnalyzeResult,
) -> str | None:
    """
    让 LLM 直接生成完整 HTML 报告（单文件）。
    """
    llm = cfg.llm
    if not llm.enabled or not llm.report_html_enabled:
        return None
    if not llm.api_key or not llm.model:
        return None

    client = build_openai_client(llm)

    per_event = analyzed.per_event_ai or {}
    jsonl_path = per_event.get("jsonl_path")

    payload: dict[str, Any] = {
        "time_window": {"start": window.start.isoformat(), "end": window.end.isoformat(), "timezone": window.timezone},
        "meta": analyzed.meta,
        "llm_summary": analyzed.llm_summary,
        "per_event_ai_summary": {
            "risk_level_counts": per_event.get("risk_level_counts"),
            "category_counts": per_event.get("category_counts"),
            "top_tags": per_event.get("top_tags"),
            "jsonl_path": jsonl_path,
        },
    }

    # 先让 AI 生成 HTML 骨架（不包含明细行）
    prompt_head = (
        "你是日志审计报告生成器。请基于输入 JSON 生成一份“完整可打开的 HTML 单文件审计报告”。要求：\n"
        "- 输出必须是完整 HTML（包含 <html><head><body>），不要输出任何多余解释文字\n"
        "- 使用中文\n"
        "- 报告包含：标题、时间窗口、关键统计、风险分布、Top tags、结论与建议、以及一个事件明细表（表格需要有 <tbody id=\"eventRows\"></tbody> 占位）\n"
        "- 页面样式尽量简洁现代，表格可滚动\n"
        "- 如数据不足要在报告中明确标注“需要补充哪些字段/日志”\n\n"
        f"输入(JSON)：\n{json.dumps(payload, ensure_ascii=False)}"
    )
    resp = client.chat.completions.create(model=llm.model, messages=[{"role": "user", "content": prompt_head}])
    html = (resp.choices[0].message.content or "").strip()
    if "<tbody" not in html.lower() or "eventrows" not in html.lower():
        return None

    # 如果没有 jsonl，就只能返回骨架（至少是完整 HTML）
    if not jsonl_path or not os.path.exists(jsonl_path):
        return html

    if not llm.report_html_batching_enabled:
        # 不分批时：一次性把 jsonl 的内容拼起来发给 AI（可能很大，按你的要求允许）
        rows = _read_jsonl_rows(jsonl_path)
        rows_html = _rows_to_html_with_llm(client, llm.model, rows)
        return html.replace('<tbody id="eventRows"></tbody>', f'<tbody id="eventRows">{rows_html}</tbody>')

    batch_size = max(1, int(llm.report_html_batch_size))
    rows_html_parts: list[str] = []
    for batch in _iter_jsonl_batches(jsonl_path, batch_size=batch_size):
        rows_html_parts.append(_rows_to_html_with_llm(client, llm.model, batch))
    rows_html = "".join(rows_html_parts)
    return html.replace('<tbody id="eventRows"></tbody>', f'<tbody id="eventRows">{rows_html}</tbody>')


def _iter_jsonl_batches(path: str, batch_size: int) -> list[list[dict[str, Any]]]:
    batches: list[list[dict[str, Any]]] = []
    cur: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                cur.append(json.loads(line))
            except Exception:
                continue
            if len(cur) >= batch_size:
                batches.append(cur)
                cur = []
    if cur:
        batches.append(cur)
    return batches


def _read_jsonl_rows(path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def _rows_to_html_with_llm(client, model: str, rows: list[dict[str, Any]]) -> str:
    """
    让 AI 把一批 rows 转成 <tr>...</tr> 的 HTML（不包含 table/tbody 标签）。
    """
    prompt = (
        "把输入 JSON 数组转换为 HTML 表格行。要求：\n"
        "- 只输出若干个 <tr>...</tr>，不要包含 <table>/<tbody>，不要输出任何解释文字\n"
        "- 每行列：ts, ip, path, status, risk_level, category, summary, tags\n"
        "- ts/ip/path/status 从 event 里取，risk_level/category/summary/tags 从 ai 里取；tags 用逗号拼接\n\n"
        f"输入(JSON)：\n{json.dumps(rows, ensure_ascii=False)}"
    )
    resp = client.chat.completions.create(model=model, messages=[{"role": "user", "content": prompt}])
    return (resp.choices[0].message.content or "").strip()

