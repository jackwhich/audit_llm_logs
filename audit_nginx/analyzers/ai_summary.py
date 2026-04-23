from __future__ import annotations

import json
from typing import Any

from ..config import LLMConfig
from ..rules import AuditResult
from ..utils.openai_client import build_openai_client


def maybe_summarize_with_llm(audit: AuditResult, llm_cfg: LLMConfig) -> str | None:
    if not llm_cfg.enabled:
        return None
    if not llm_cfg.api_key or not llm_cfg.model:
        return None

    client = build_openai_client(llm_cfg)

    payload: dict[str, Any] = {
        "stats": {
            "total_events": audit.stats.total_events,
            "status_counts": audit.stats.status_counts,
            "top_ips": audit.stats.top_ips[:10],
            "top_paths": audit.stats.top_paths[:10],
            "suspicious_path_hits": audit.stats.suspicious_path_hits[:10],
            "top_5xx_paths": audit.stats.top_5xx_paths[:10],
            "slow_requests_samples": audit.stats.slow_requests[: min(10, len(audit.stats.slow_requests))],
        },
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "evidence_samples": f.evidence[: llm_cfg.max_evidence_samples],
            }
            for f in audit.findings
        ],
    }

    prompt = (
        "你是安全与运维审计分析助手。给定 Nginx/HTTP 日志审计的聚合结果与少量证据样本，"
        "请生成一段可直接写进审计报告的中文内容，包含：\n"
        "1) 执行摘要（3-6 句，面向管理者）\n"
        "2) 关键风险与优先级（按严重程度排序，最多 6 条）\n"
        "3) 运维与稳定性观察（最多 5 条）\n"
        "4) 建议的下一步行动清单（可执行、可落地，最多 8 条）\n"
        "注意：不要编造不存在的数据；如果信息不足请明确说明“需要补充哪些字段/日志”。\n\n"
        f"审计数据(JSON)：\n{json.dumps(payload, ensure_ascii=False)}"
    )

    resp = client.chat.completions.create(
        model=llm_cfg.model,
        messages=[{"role": "user", "content": prompt}],
    )
    return (resp.choices[0].message.content or "").strip() or None

