from __future__ import annotations

from collections import Counter

from ..normalizers.nginx_normalizer import NormalizedEvent
from ..rules import AuditResult, AuditStats


def basic_audit(events: list[NormalizedEvent]) -> AuditResult:
    total = len(events)
    status_counts = Counter(str(e.status) if e.status is not None else "unknown" for e in events)
    ip_counts = Counter(e.ip for e in events if e.ip)
    path_counts = Counter(e.path for e in events if e.path)
    ua_counts = Counter(e.user_agent for e in events if e.user_agent)

    top_5xx_paths = Counter()
    slow_samples = []
    for e in events:
        if e.status is not None and 500 <= e.status <= 599 and e.path:
            top_5xx_paths[e.path] += 1
        if e.request_time is not None and e.request_time >= 2.0:
            slow_samples.append(
                {
                    "ts": e.ts.isoformat(),
                    "ip": e.ip,
                    "path": e.path,
                    "status": e.status,
                    "request_time": e.request_time,
                    "upstream_time": e.upstream_time,
                }
            )
    slow_samples.sort(key=lambda x: (x.get("request_time") or 0.0), reverse=True)

    stats = AuditStats(
        total_events=total,
        status_counts=dict(status_counts),
        top_ips=ip_counts.most_common(20),
        top_paths=path_counts.most_common(20),
        top_user_agents=ua_counts.most_common(15),
        suspicious_path_hits=[],
        top_5xx_paths=top_5xx_paths.most_common(20),
        slow_requests=slow_samples[:50],
    )
    return AuditResult(stats=stats, findings=[])

