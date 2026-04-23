from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml


@dataclass(frozen=True)
class ElasticsearchConfig:
    url: str
    user: str | None
    password: str | None
    index_pattern: str
    time_field: str
    verify_certs: bool = True


@dataclass(frozen=True)
class QueryConfig:
    timezone: str = "Asia/Shanghai"
    window_hours: int = 24
    max_docs: int = 200_000
    page_size: int = 2000


@dataclass(frozen=True)
class OutputConfig:
    dir: str = "./reports"
    filename_pattern: str = "nginx_audit_{run_ts}.html"


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool = True
    base_url: str = "https://llm.siraya.ai/v1"
    api_key: str = ""
    model: str = ""
    max_evidence_samples: int = 30
    # 是否对 LLM 请求走代理（例如需要访问外网域名）
    proxy_enabled: bool = False
    # 单一代理地址，例如：http://127.0.0.1:7890 或 socks5://127.0.0.1:7890
    proxy_url: str = ""
    # 分协议代理（可选）：当 base_url 是 https 时优先用 proxy_https_url
    proxy_http_url: str = ""
    proxy_https_url: str = ""
    # 对每一条日志都调用 LLM（会很慢/很贵，但你说延迟无所谓）
    per_event_enabled: bool = False
    # 让 LLM 直接生成整份 HTML 报告（开启后将绕过 templates/renderers）
    report_html_enabled: bool = False
    # 生成 HTML 报告时，是否分批生成（推荐，避免 token 爆炸）
    report_html_batching_enabled: bool = True
    # 分批大小：每次给 AI 多少条“逐条审计结果”来生成表格行
    report_html_batch_size: int = 50
    # 每次发给 LLM 的事件条数（批量分类，减少请求次数）
    per_event_batch_size: int = 20
    # 是否启用批量（关闭则每条事件单独请求）
    per_event_batching_enabled: bool = True
    # 每条事件的 prompt 最大字符（避免超长 message）
    per_event_max_chars: int = 2000
    # 是否启用截断（关闭则尽量发送完整 message；但可能超长/更贵）
    per_event_truncate_enabled: bool = True
    # 附加输出：把每条事件的 LLM 结果落到 jsonl，便于全量留存
    per_event_jsonl_path: str = "./reports/ai_event_audit_{run_ts}.jsonl"


@dataclass(frozen=True)
class RulesConfig:
    enabled: bool = True
    sensitive_path_keywords: list[str] | None = None
    auth_path_keywords: list[str] | None = None


@dataclass(frozen=True)
class AppConfig:
    elasticsearch: ElasticsearchConfig
    query: QueryConfig
    output: OutputConfig
    llm: LLMConfig
    rules: RulesConfig


def _get(d: dict[str, Any], key: str, default: Any = None) -> Any:
    return d.get(key, default)


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    es = data.get("elasticsearch", {}) or {}
    q = data.get("query", {}) or {}
    out = data.get("output", {}) or {}
    llm = data.get("llm", {}) or {}
    rules = data.get("rules", {}) or {}

    es_cfg = ElasticsearchConfig(
        url=str(es["url"]),
        user=str(es.get("user")) if es.get("user") is not None else None,
        password=str(es.get("password")) if es.get("password") is not None else None,
        index_pattern=str(es.get("index_pattern", "nginx-*")),
        time_field=str(es.get("time_field", "@timestamp")),
        verify_certs=bool(es.get("verify_certs", True)),
    )

    query_cfg = QueryConfig(
        timezone=str(_get(q, "timezone", "Asia/Shanghai")),
        window_hours=int(_get(q, "window_hours", 24)),
        max_docs=int(_get(q, "max_docs", 200_000)),
        page_size=int(_get(q, "page_size", 2000)),
    )

    output_cfg = OutputConfig(
        dir=str(_get(out, "dir", "./reports")),
        filename_pattern=str(_get(out, "filename_pattern", "nginx_audit_{run_ts}.html")),
    )

    llm_cfg = LLMConfig(
        enabled=bool(_get(llm, "enabled", True)),
        base_url=str(_get(llm, "base_url", "https://llm.siraya.ai/v1")),
        api_key=str(_get(llm, "api_key", "")),
        model=str(_get(llm, "model", "")),
        max_evidence_samples=int(_get(llm, "max_evidence_samples", 30)),
        proxy_enabled=bool(_get(llm, "proxy_enabled", False)),
        proxy_url=str(_get(llm, "proxy_url", "")),
        proxy_http_url=str(_get(llm, "proxy_http_url", "")),
        proxy_https_url=str(_get(llm, "proxy_https_url", "")),
        per_event_enabled=bool(_get(llm, "per_event_enabled", False)),
        report_html_enabled=bool(_get(llm, "report_html_enabled", False)),
        report_html_batching_enabled=bool(_get(llm, "report_html_batching_enabled", True)),
        report_html_batch_size=int(_get(llm, "report_html_batch_size", 50)),
        per_event_batch_size=int(_get(llm, "per_event_batch_size", 20)),
        per_event_batching_enabled=bool(_get(llm, "per_event_batching_enabled", True)),
        per_event_max_chars=int(_get(llm, "per_event_max_chars", 2000)),
        per_event_truncate_enabled=bool(_get(llm, "per_event_truncate_enabled", True)),
        per_event_jsonl_path=str(_get(llm, "per_event_jsonl_path", "./reports/ai_event_audit_{run_ts}.jsonl")),
    )

    rules_cfg = RulesConfig(
        enabled=bool(_get(rules, "enabled", True)),
        sensitive_path_keywords=list(_get(rules, "sensitive_path_keywords", [])) or [],
        auth_path_keywords=list(_get(rules, "auth_path_keywords", [])) or [],
    )

    return AppConfig(
        elasticsearch=es_cfg,
        query=query_cfg,
        output=output_cfg,
        llm=llm_cfg,
        rules=rules_cfg,
    )

