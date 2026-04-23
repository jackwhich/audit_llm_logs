from __future__ import annotations

import argparse
from typing import Any

from .config import load_config
from .pipeline import run_pipeline
from .renderers.html_report import render_report_html, write_report
from .analyzers.ai_report_html import generate_html_report_with_llm
from .utils.timeutil import compute_window


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit_nginx", description="Nginx/ES 日志审计并生成 HTML 报告")
    p.add_argument("--config", required=True, help="YAML 配置文件路径，例如 config/audit.yaml")
    p.add_argument("--dry-run", action="store_true", help="只拉取少量数据用于验证（会覆盖 max_docs）")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    cfg = load_config(args.config)

    window = compute_window(cfg.query.timezone, cfg.query.window_hours)
    max_docs = 2000 if args.dry_run else cfg.query.max_docs

    try:
        fetched, events, analyzed = run_pipeline(
            cfg=cfg,
            window=window,
            max_docs=max_docs,
            page_size=cfg.query.page_size,
        )
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return 2

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
        html = ai_html

    out_path = write_report(html, cfg.output, window)
    print(f"OK: report written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

def __basic_stats(events: list[Any]):
    # 延续原来的展示结构：直接复用 basic_audit 的 stats 形状
    from .analyzers.basic_stats import basic_audit

    return basic_audit(events).stats

