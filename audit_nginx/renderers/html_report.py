from __future__ import annotations

import os
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import ElasticsearchConfig, OutputConfig
from ..rules import AuditStats, Finding
from ..utils.timeutil import TimeWindow, fmt_compact


def _env() -> Environment:
    base_dir = os.path.dirname(__file__)
    loader = FileSystemLoader(os.path.join(base_dir, "..", "templates"))
    return Environment(loader=loader, autoescape=select_autoescape(["html", "xml"]))


def render_report_html(
    report_time: TimeWindow,
    es_cfg: ElasticsearchConfig,
    stats: AuditStats,
    findings: list[Finding],
    llm_summary: str | None,
    per_event_ai: dict[str, Any] | None,
    meta: dict[str, Any],
) -> str:
    env = _env()
    tpl = env.get_template("report.html.j2")

    status_counts_top = sorted(stats.status_counts.items(), key=lambda kv: kv[1], reverse=True)[:12]

    return tpl.render(
        report_time={"start": report_time.start.isoformat(), "end": report_time.end.isoformat(), "timezone": report_time.timezone},
        es_cfg={"url": es_cfg.url, "index_pattern": es_cfg.index_pattern, "time_field": es_cfg.time_field},
        stats={
            "total_events": stats.total_events,
            "status_counts_top": status_counts_top,
            "top_ips": stats.top_ips,
            "top_paths": stats.top_paths,
            "top_user_agents": stats.top_user_agents,
            "suspicious_path_hits": stats.suspicious_path_hits,
            "top_5xx_paths": stats.top_5xx_paths,
            "slow_requests": stats.slow_requests,
        },
        findings=[
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "evidence": f.evidence,
            }
            for f in findings
        ],
        llm_summary=llm_summary,
        per_event_ai=per_event_ai,
        meta=meta,
    )


def write_report(html: str, out_cfg: OutputConfig, report_time: TimeWindow) -> str:
    os.makedirs(out_cfg.dir, exist_ok=True)
    run_ts = fmt_compact(report_time.end)
    start = fmt_compact(report_time.start)
    end = fmt_compact(report_time.end)
    filename = out_cfg.filename_pattern.format(start=start, end=end, run_ts=run_ts)
    path = os.path.join(out_cfg.dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path

