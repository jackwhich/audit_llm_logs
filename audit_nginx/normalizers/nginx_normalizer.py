from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from dateutil import parser as dtparser
from dateutil import tz


@dataclass(frozen=True)
class NormalizedEvent:
    ts: datetime
    ip: str | None
    method: str | None
    path: str | None
    status: int | None
    user_agent: str | None
    host: str | None
    request_time: float | None
    upstream_time: float | None
    raw: dict[str, Any]


_combined_re = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)(?: \S+)?" (?P<status>\d{3}) (?P<body_bytes>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"(?: (?P<rest>.*))?$'
)


def _first(d: dict[str, Any], paths: list[str]) -> Any:
    for p in paths:
        cur: Any = d
        ok = True
        for part in p.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None:
            return cur
    return None


def _parse_ts(val: Any, timezone: str) -> datetime | None:
    if val is None:
        return None
    try:
        dt = dtparser.isoparse(str(val))
    except Exception:
        return None
    if dt.tzinfo is None:
        zone = tz.gettz(timezone)
        if zone is None:
            return None
        dt = dt.replace(tzinfo=zone)
    return dt


def _parse_message(message: str, timezone: str) -> dict[str, Any] | None:
    msg = message.strip()
    if not msg:
        return None

    if msg.startswith("{") and msg.endswith("}"):
        try:
            return json.loads(msg)
        except Exception:
            pass

    m = _combined_re.match(msg)
    if not m:
        return None

    gd = m.groupdict()
    ts = None
    try:
        ts = dtparser.parse(gd["time"])
        if ts.tzinfo is None:
            zone = tz.gettz(timezone)
            if zone is not None:
                ts = ts.replace(tzinfo=zone)
    except Exception:
        ts = None

    return {
        "@parsed": True,
        "@timestamp": ts.isoformat() if ts else None,
        "source": {"ip": gd.get("ip")},
        "http": {"request": {"method": gd.get("method")}, "response": {"status_code": int(gd["status"])}},
        "url": {"path": gd.get("path")},
        "user_agent": {"original": gd.get("ua")},
    }


def normalize_events(
    hits: list[dict[str, Any]],
    time_field: str,
    timezone: str,
) -> list[NormalizedEvent]:
    zone = tz.gettz(timezone)
    if zone is None:
        raise ValueError(f"invalid timezone: {timezone}")

    out: list[NormalizedEvent] = []
    for h in hits:
        src = h.get("_source", {}) or {}

        parsed = None
        if "message" in src and not any(k in src for k in ("url", "http", "source", "client")):
            parsed = _parse_message(str(src.get("message", "")), timezone)
            if parsed:
                merged = dict(src)
                for k, v in parsed.items():
                    if k not in merged:
                        merged[k] = v
                src = merged

        ts_val = _first(src, [time_field, "@timestamp", "timestamp", "event.created", "event.ingested"])
        ts = _parse_ts(ts_val, timezone) or datetime.now(tz=zone)

        # 兼容 ECS + 你这类自定义字段（remote_addr/request_method/uri/http_user_agent 等）
        ip = _first(
            src,
            [
                "source.ip",
                "client.ip",
                "nginx.access.remote_ip",
                "clientRealIp",
                "remote_addr",
                "http_x_forwarded_for",
            ],
        )
        method = _first(src, ["http.request.method", "nginx.access.method", "request.method", "request_method", "method"])
        path = _first(
            src,
            [
                "url.path",
                "nginx.access.url",
                "request.path",
                "uri",
                "request_uri",
                "path",
            ],
        )
        status_val = _first(src, ["http.response.status_code", "nginx.access.status", "status"])
        try:
            status = int(status_val) if status_val is not None else None
        except Exception:
            status = None

        ua = _first(
            src,
            [
                "user_agent.original",
                "nginx.access.user_agent",
                "http.user_agent",
                "http_user_agent",
                "ua.name",
                "ua",
            ],
        )
        host = _first(src, ["host.name", "server.domain", "nginx.access.host", "url.domain"])

        rt_val = _first(src, ["event.duration", "nginx.access.request_time", "request_time"])
        request_time = None
        if rt_val is not None:
            try:
                fv = float(rt_val)
                request_time = fv / 1e9 if "event" in str(rt_val) else fv
            except Exception:
                request_time = None

        ut_val = _first(src, ["nginx.access.upstream_response_time", "upstream_response_time", "upstream.time", "upstream_time"])
        upstream_time = None
        if ut_val is not None:
            try:
                upstream_time = float(str(ut_val).split(",")[0].strip())
            except Exception:
                upstream_time = None

        out.append(
            NormalizedEvent(
                ts=ts,
                ip=str(ip) if ip is not None else None,
                method=str(method) if method is not None else None,
                path=str(path) if path is not None else None,
                status=status,
                user_agent=str(ua) if ua is not None else None,
                host=str(host) if host is not None else None,
                request_time=request_time,
                upstream_time=upstream_time,
                raw={"_id": h.get("_id"), "_index": h.get("_index"), "_source": src},
            )
        )
    return out

