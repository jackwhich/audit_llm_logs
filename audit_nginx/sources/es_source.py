from __future__ import annotations

from typing import Any

from elasticsearch import Elasticsearch

from ..config import ElasticsearchConfig
from ..utils.timeutil import TimeWindow, isoformat_z


def _client(es_cfg: ElasticsearchConfig) -> Elasticsearch:
    kwargs: dict[str, Any] = {
        "hosts": [es_cfg.url],
        "verify_certs": bool(es_cfg.verify_certs),
    }
    if es_cfg.user and es_cfg.password:
        kwargs["basic_auth"] = (es_cfg.user, es_cfg.password)
    return Elasticsearch(**kwargs)


def fetch_events_from_es(
    es_cfg: ElasticsearchConfig,
    window: TimeWindow,
    page_size: int,
    max_docs: int,
) -> list[dict[str, Any]]:
    """
    拉取 ES 文档（source + 部分 meta），返回原始 hits（用于后续 normalize）。
    使用 PIT + search_after 方式分页（优于 scroll）。
    """
    if page_size <= 0:
        raise ValueError("page_size must be > 0")
    if max_docs <= 0:
        return []

    client = _client(es_cfg)
    time_field = es_cfg.time_field

    query = {
        "bool": {
            "filter": [
                {"range": {time_field: {"gte": isoformat_z(window.start), "lte": isoformat_z(window.end)}}}
            ]
        }
    }

    # 默认包含 ECS + 常见 nginx 自定义字段（适配你贴出来的 ES 文档结构）
    default_includes = [
        time_field,
        "@timestamp",
        "message",
        "event.*",
        "log.*",
        "host.*",
        "source.*",
        "client.*",
        "user.*",
        "url.*",
        "http.*",
        "user_agent.*",
        "agent.*",
        "nginx.*",
        # custom nginx fields (non-ECS)
        "remote_addr",
        "clientRealIp",
        "http_x_forwarded_for",
        "request_method",
        "request_uri",
        "uri",
        "status",
        "request_time",
        "upstream_time",
        "upstream_host",
        "upstream_status",
        "http_user_agent",
        "tags",
        "host_name",
        "server_name",
        "scheme",
        "args",
        "bytes_sent",
        "body_bytes_sent",
    ]
    source_includes = es_cfg.source_includes if es_cfg.source_includes is not None else default_includes

    docs: list[dict[str, Any]] = []
    pit = client.open_point_in_time(index=es_cfg.index_pattern, keep_alive="2m")
    pit_id = pit["id"]
    try:
        search_after = None
        sort = [{time_field: "asc"}, {"_shard_doc": "asc"}]

        while len(docs) < max_docs:
            body: dict[str, Any] = {
                "size": min(page_size, max_docs - len(docs)),
                "query": query,
                "sort": sort,
                "pit": {"id": pit_id, "keep_alive": "2m"},
                # source_includes=None 表示全量 _source；否则做 includes
                "_source": True if source_includes is None else {"includes": source_includes},
                "track_total_hits": False,
            }
            if search_after is not None:
                body["search_after"] = search_after

            resp = client.search(body=body)
            hits = resp.get("hits", {}).get("hits", []) or []
            if not hits:
                break

            for h in hits:
                docs.append(h)
                if len(docs) >= max_docs:
                    break

            search_after = hits[-1].get("sort")
            if not search_after:
                break
    finally:
        try:
            client.close_point_in_time(body={"id": pit_id})
        except Exception:
            pass
        client.close()

    return docs

