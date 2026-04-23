from __future__ import annotations

import argparse
import logging
from typing import Any

from .config import load_config
from .pipeline import run_pipeline
from .renderers.html_report import render_report_html, write_report
from .analyzers.ai_report_html import generate_html_report_with_llm
from .utils.logging import setup_logging
from .utils.timeutil import compute_window


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit_nginx", description="Nginx/ES 日志审计并生成 HTML 报告")
    p.add_argument("--config", required=True, help="YAML 配置文件路径，例如 config/audit.yaml")
    p.add_argument("--dry-run", action="store_true", help="只拉取少量数据用于验证（会覆盖 max_docs）")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg.logging)
    log = logging.getLogger("audit_nginx")

    window = compute_window(cfg.query.timezone, cfg.query.window_hours)
    max_docs = 2000 if args.dry_run else cfg.query.max_docs
    log.info("start window=%s~%s tz=%s dry_run=%s", window.start.isoformat(), window.end.isoformat(), window.timezone, bool(args.dry_run))
    log.info("es url=%s index=%s time_field=%s", cfg.elasticsearch.url, cfg.elasticsearch.index_pattern, cfg.elasticsearch.time_field)
    log.info("llm base_url=%s per_event=%s report_html=%s proxy=%s", cfg.llm.base_url, cfg.llm.per_event_enabled, cfg.llm.report_html_enabled, cfg.llm.proxy_enabled)

    try:
        fetched, events, analyzed = run_pipeline(
            cfg=cfg,
            window=window,
            max_docs=max_docs,
            page_size=cfg.query.page_size,
        )
    except RuntimeError as e:
        log.exception("pipeline failed: %s", e)
        return 2

    log.info("fetched_docs=%s normalized=%s per_event_ai_total=%s", analyzed.meta.get("fetched_docs"), analyzed.meta.get("normalized_events"), analyzed.meta.get("per_event_ai_total"))

    html = render_report_html(
        report_time=window,
        es_cfg=cfg.elasticsearch,
        stats=__basic_stats(events),
        findings=[],
        llm_summary=analyzed.llm_summary,
        per_event_ai=analyzed.per_event_ai,
        meta={"dry_run": bool(args.dry_run), **analyzed.meta},
    )

    # 如果启用“AI 直接生成 HTML”，则覆盖模板渲染结果
    ai_html = generate_html_report_with_llm(cfg=cfg, window=window, analyzed=analyzed)
    if ai_html:
        log.info("using llm-generated html report")
        html = ai_html

    out_path = write_report(html, cfg.output, window)
    log.info("report written to %s", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

def __basic_stats(events: list[Any]):
    # 延续原来的展示结构：直接复用 basic_audit 的 stats 形状
    from .analyzers.basic_stats import basic_audit

    return basic_audit(events).stats

