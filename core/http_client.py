"""Shared HTTP helpers (curl_cffi) with proxy fallback."""

from __future__ import annotations

from core.config import config
from core.runtime import normalize_proxy_for_runtime

try:
    from curl_cffi import requests
except ModuleNotFoundError:
    requests = None

def get_proxies():
    proxy = config.get("proxy", "")
    if proxy:
        normalized = normalize_proxy_for_runtime(proxy)
        return {"http": normalized, "https": normalized}
    return {}


def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def http_get(url, **kwargs):
    if requests is None:
        raise RuntimeError("curl_cffi 未安装，无法发起 HTTP 请求")
    try:
        return requests.get(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        # 代理不可用时自动回退为直连，避免整个流程直接失败
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.get(url, **_build_request_kwargs(**retry_kwargs))
        raise


def http_post(url, **kwargs):
    if requests is None:
        raise RuntimeError("curl_cffi 未安装，无法发起 HTTP 请求")
    try:
        return requests.post(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.post(url, **_build_request_kwargs(**retry_kwargs))
        raise


def http_delete(url, **kwargs):
    if requests is None:
        raise RuntimeError("curl_cffi 未安装，无法发起 HTTP 请求")
    try:
        return requests.delete(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.delete(url, **_build_request_kwargs(**retry_kwargs))
        raise


