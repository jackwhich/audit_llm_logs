from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from .config import RulesConfig
from .normalizers.nginx_normalizer import NormalizedEvent


@dataclass(frozen=True)
class Finding:
    severity: str  # low/medium/high/critical
    category: str  # security/compliance/ops
    title: str
    description: str
    evidence: list[dict[str, Any]]
    recommendation: str


@dataclass(frozen=True)
class AuditStats:
    total_events: int
    status_counts: dict[str, int]
    top_ips: list[tuple[str, int]]
    top_paths: list[tuple[str, int]]
    top_user_agents: list[tuple[str, int]]
    suspicious_path_hits: list[tuple[str, int]]
    top_5xx_paths: list[tuple[str, int]]
    slow_requests: list[dict[str, Any]]


@dataclass(frozen=True)
class AuditResult:
    stats: AuditStats
    findings: list[Finding]


def _event_brief(e: NormalizedEvent) -> dict[str, Any]:
    return {
        "ts": e.ts.isoformat(),
        "ip": e.ip,
        "method": e.method,
        "path": e.path,
        "status": e.status,
        "ua": e.user_agent,
        "host": e.host,
        "request_time": e.request_time,
        "upstream_time": e.upstream_time,
        "_id": e.raw.get("_id"),
        "_index": e.raw.get("_index"),
    }


def run_audit(events: list[NormalizedEvent], rules_cfg: RulesConfig) -> AuditResult:
    # ---- 聚合统计 ----
    total = len(events)
    status_counts = Counter(str(e.status) if e.status is not None else "unknown" for e in events)
    ip_counts = Counter(e.ip for e in events if e.ip)
    path_counts = Counter(e.path for e in events if e.path)
    ua_counts = Counter(e.user_agent for e in events if e.user_agent)

    sensitive_keywords = [k.lower() for k in (rules_cfg.sensitive_path_keywords or [])]
    auth_keywords = [k.lower() for k in (rules_cfg.auth_path_keywords or [])]

    suspicious_paths = Counter()
    for p, c in path_counts.items():
        pl = p.lower()
        if any(k in pl for k in sensitive_keywords):
            suspicious_paths[p] += c

    top_5xx_paths = Counter()
    slow_samples: list[dict[str, Any]] = []

    for e in events:
        if e.status is not None and 500 <= e.status <= 599 and e.path:
            top_5xx_paths[e.path] += 1
        if e.request_time is not None and e.request_time >= 2.0:
            slow_samples.append(_event_brief(e))

    slow_samples.sort(key=lambda x: (x.get("request_time") or 0.0), reverse=True)
    slow_samples = slow_samples[:50]

    stats = AuditStats(
        total_events=total,
        status_counts=dict(status_counts),
        top_ips=ip_counts.most_common(20),
        top_paths=path_counts.most_common(20),
        top_user_agents=ua_counts.most_common(15),
        suspicious_path_hits=suspicious_paths.most_common(20),
        top_5xx_paths=top_5xx_paths.most_common(20),
        slow_requests=slow_samples,
    )

    # ---- 规则检测 ----
    findings: list[Finding] = []
    if not rules_cfg.enabled:
        return AuditResult(stats=stats, findings=findings)

    # 1) 敏感路径访问
    if stats.suspicious_path_hits:
        evidence = []
        wanted = set(p for p, _ in stats.suspicious_path_hits[:10])
        for e in events:
            if e.path in wanted:
                evidence.append(_event_brief(e))
                if len(evidence) >= 30:
                    break
        findings.append(
            Finding(
                severity="high",
                category="security",
                title="疑似探测敏感路径",
                description="发现对常见敏感路径的访问命中，可能是扫描或弱点探测。",
                evidence=evidence,
                recommendation="在 WAF/NGINX 层对敏感路径做阻断或限速；检查是否存在暴露的管理入口；对命中 IP 做封禁/灰度挑战。",
            )
        )

    # 2) 爆破（按 IP 聚合：登录相关路径 + 401/403/429）
    brute_counter = Counter()
    brute_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if not e.ip or not e.path or e.status is None:
            continue
        pl = e.path.lower()
        if auth_keywords and not any(k in pl for k in auth_keywords):
            continue
        if e.status in (401, 403, 429):
            brute_counter[e.ip] += 1
            if len(brute_samples[e.ip]) < 10:
                brute_samples[e.ip].append(_event_brief(e))

    top_brute = brute_counter.most_common(10)
    if top_brute and top_brute[0][1] >= 50:
        evidence = []
        for ip, _ in top_brute:
            evidence.extend(brute_samples[ip])
            if len(evidence) >= 50:
                break
        findings.append(
            Finding(
                severity="critical",
                category="security",
                title="疑似账号爆破/撞库行为",
                description="登录相关路径出现大量 401/403/429，疑似爆破或撞库。",
                evidence=evidence,
                recommendation="开启登录限速/验证码/2FA；对可疑 IP 段封禁；检查账号安全与异常登录告警。",
            )
        )

    # 3) 注入/遍历关键词（简单特征）
    suspicious_q = re_suspicious_payload()
    payload_hits: list[dict[str, Any]] = []
    for e in events:
        if not e.path:
            continue
        if suspicious_q.search(e.path):
            payload_hits.append(_event_brief(e))
            if len(payload_hits) >= 50:
                break

    if payload_hits:
        findings.append(
            Finding(
                severity="high",
                category="security",
                title="疑似注入/遍历探测 Payload",
                description="在请求路径中检测到常见 SQLi/XSS/路径遍历等特征片段。",
                evidence=payload_hits,
                recommendation="检查应用参数化与输入校验；在 WAF 增加规则；对命中请求做回溯分析并确认是否存在漏洞。",
            )
        )

    # 4) 运维：5xx 比例过高
    total_5xx = sum(c for s, c in status_counts.items() if s.isdigit() and 500 <= int(s) <= 599)
    if total and total_5xx / total >= 0.02 and total_5xx >= 50:
        evidence = []
        hot = set(p for p, _ in stats.top_5xx_paths[:10])
        for e in events:
            if e.status is not None and 500 <= e.status <= 599 and e.path in hot:
                evidence.append(_event_brief(e))
                if len(evidence) >= 30:
                    break
        findings.append(
            Finding(
                severity="medium",
                category="ops",
                title="5xx 异常比例偏高",
                description=f"最近窗口内 5xx 数量 {total_5xx}/{total}（{total_5xx/total:.2%}），可能存在上游故障或发布问题。",
                evidence=evidence,
                recommendation="按 Top 5xx 路径排查上游服务与错误日志；检查最近发布；增加熔断/超时与告警阈值。",
            )
        )

    # 5) 运维：慢请求
    if stats.slow_requests:
        findings.append(
            Finding(
                severity="low",
                category="ops",
                title="存在慢请求样本（>=2s）",
                description="窗口内存在 request_time 较高的请求（若字段可用）。",
                evidence=stats.slow_requests[:30],
                recommendation="按热点路径做性能分析与缓存；检查数据库慢查询；为关键接口加超时、限流与 APM 追踪。",
            )
        )

    return AuditResult(stats=stats, findings=findings)


def re_suspicious_payload():
    import re

    # 轻量规则：覆盖常见攻击关键词；尽量避免过多误报
    parts = [
        r"\.\./",  # traversal
        r"%2e%2e%2f",
        r"(?i)\bunion\b.*\bselect\b",
        r"(?i)\bor\b\s+1=1",
        r"(?i)<script\b",
        r"(?i)\bselect\b.+\bfrom\b",
        r"(?i)\bxp_cmdshell\b",
        r"(?i)\bbenchmark\(",
        r"(?i)\bsleep\(",
    ]
    return re.compile("|".join(parts))

