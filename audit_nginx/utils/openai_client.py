from __future__ import annotations

import httpx
from openai import OpenAI

from ..config import LLMConfig


def build_openai_client(llm_cfg: LLMConfig) -> OpenAI:
    """
    统一创建 OpenAI 兼容 client。
    - proxy_enabled=true 时走代理
    """
    if llm_cfg.proxy_enabled:
        # httpx 0.28 的 proxy 参数不支持 dict，因此我们按 base_url scheme 选择对应代理
        scheme = "https" if str(llm_cfg.base_url).lower().startswith("https://") else "http"
        proxy = ""
        if scheme == "https" and llm_cfg.proxy_https_url:
            proxy = llm_cfg.proxy_https_url
        elif scheme == "http" and llm_cfg.proxy_http_url:
            proxy = llm_cfg.proxy_http_url
        elif llm_cfg.proxy_url:
            proxy = llm_cfg.proxy_url
        elif llm_cfg.proxy_https_url or llm_cfg.proxy_http_url:
            proxy = llm_cfg.proxy_https_url or llm_cfg.proxy_http_url

        if not proxy:
            raise ValueError(
                "llm.proxy_enabled=true 但未配置代理地址：请设置 llm.proxy_url 或 llm.proxy_https_url/llm.proxy_http_url"
            )

        http_client = httpx.Client(proxy=proxy, timeout=300.0)
        return OpenAI(base_url=llm_cfg.base_url, api_key=llm_cfg.api_key, http_client=http_client)
    return OpenAI(base_url=llm_cfg.base_url, api_key=llm_cfg.api_key)

