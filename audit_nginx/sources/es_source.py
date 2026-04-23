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

    source_includes = [
        time_field,
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
    ]

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
                "_source": {"includes": source_includes},
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

