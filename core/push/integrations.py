"""Account push/export integrations: sub2api, grok2api, CPA, OAuth device flow."""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import json
import os
import random
import re
import secrets
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile

from concurrent.futures import ThreadPoolExecutor, as_completed

from core.accounts.store import (
    _extract_sub2api_account_id,
    _normalize_sso_token,
    _sub2api_error_text,
    is_account_blocked_error,
    is_refresh_token_revoked_error,
    is_xai_refresh_token_client_error,
    list_registered_accounts,
    persist_account_health_status,
    persist_cpa_push_status,
    persist_grok2api_push_status,
    persist_sub2api_push_status,
    replace_registered_account_refresh_token,
)
from core.cancel import raise_if_cancelled as _raise_if_cancelled_impl
from core.cancel import sleep_with_cancel as _sleep_with_cancel_impl
from core.config import DEFAULT_CONFIG, config, _parse_positive_int
from core.http_client import get_proxies as _get_proxies_impl
from core.paths import get_data_dir
from core.runtime import _env_truthy, normalize_proxy_for_runtime
from core.xai.protocol import _parse_jwt_payload

try:
    from curl_cffi import CurlMime as _CurlMimeImpl
    from curl_cffi import requests as _requests_impl
except ModuleNotFoundError:
    _CurlMimeImpl = None
    _requests_impl = None


def _facade():
    return sys.modules.get("grok_register_ttk")


def _resolve(name, default):
    fac = _facade()
    if fac is not None and hasattr(fac, name):
        val = getattr(fac, name)
        # Avoid infinite recursion when facade re-exports this module's symbol.
        if callable(default) and callable(val) and getattr(val, "__module__", "") == __name__:
            return default
        if val is not None:
            return val
    return default


def sleep_with_cancel(seconds, cancel_callback=None):
    return _resolve("sleep_with_cancel", _sleep_with_cancel_impl)(seconds, cancel_callback)


def raise_if_cancelled(cancel_callback=None):
    return _resolve("raise_if_cancelled", _raise_if_cancelled_impl)(cancel_callback)


def _active_config():
    return _resolve("config", config)


def get_proxies():
    return _resolve("get_proxies", _get_proxies_impl)()


def http_get(url, **kwargs):
    from core.http_client import http_get as _http_get
    return _resolve("http_get", _http_get)(url, **kwargs)


def http_post(url, **kwargs):
    from core.http_client import http_post as _http_post
    return _resolve("http_post", _http_post)(url, **kwargs)


def http_delete(url, **kwargs):
    from core.http_client import http_delete as _http_delete
    return _resolve("http_delete", _http_delete)(url, **kwargs)


# curl_cffi handles — prefer facade monkeypatches
def _requests_mod():
    fac = _facade()
    if fac is not None and getattr(fac, "requests", None) is not None:
        return fac.requests
    return _requests_impl


def _CurlMime():
    return _resolve("CurlMime", _CurlMimeImpl)


def get_user_agent():
    fac = _facade()
    if fac is not None:
        fn = getattr(fac, "get_user_agent", None)
        if callable(fn) and getattr(fn, "__module__", "") != __name__:
            return fn()
    return _active_config().get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def _get_page():
    return _resolve("_get_page", lambda: None)()


def _get_browser():
    return _resolve("_get_browser", lambda: None)()


def _click_xai_oauth_consent_if_present(page):
    fn = _resolve("_click_xai_oauth_consent_if_present", None)
    if callable(fn) and getattr(fn, "__module__", "") != __name__:
        return fn(page)
    return False


def start_browser(log_callback=None):
    fn = _resolve("start_browser", None)
    if callable(fn) and getattr(fn, "__module__", "") != __name__:
        return fn(log_callback=log_callback)
    raise RuntimeError("start_browser unavailable")


def stop_browser():
    fn = _resolve("stop_browser", None)
    if callable(fn) and getattr(fn, "__module__", "") != __name__:
        return fn()


def refresh_active_page():
    fn = _resolve("refresh_active_page", None)
    if callable(fn) and getattr(fn, "__module__", "") != __name__:
        return fn()
    return _get_page()


def _set_page(value):
    fn = _resolve("_set_page", None)
    if callable(fn) and getattr(fn, "__module__", "") != __name__:
        return fn(value)
    return None


def _set_browser(value):
    fn = _resolve("_set_browser", None)
    if callable(fn) and getattr(fn, "__module__", "") != __name__:
        return fn(value)
    return None


# Compatibility aliases used by moved code
CurlMime = _CurlMimeImpl
requests = _requests_impl


XAI_GROK_OAUTH_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
XAI_GROK_OAUTH_AUTHORIZE_URL = "https://auth.x.ai/oauth2/authorize"
XAI_GROK_OAUTH_TOKEN_URL = "https://auth.x.ai/oauth2/token"
# 对齐 grokcli-2api/sso_to_auth_json 默认 OIDC scopes（缺 conversations 时 device approve
# 可能“看起来成功”但 /oauth2/token 返回 invalid_grant）
XAI_GROK_OAUTH_SCOPE = (
    "openid profile email offline_access grok-cli:access api:access "
    "conversations:read conversations:write"
)
XAI_GROK_OAUTH_REDIRECT_URI = "http://127.0.0.1:56121/callback"
# 计费 API 通道（API Key）；OAuth/Device Flow 账号应走 cli-chat-proxy
XAI_GROK_API_BASE_URL = "https://api.x.ai/v1"
# grok-cli / Device Flow OAuth 实际聊天代理（对齐 grokcli-2api 导出）
XAI_GROK_CLI_CHAT_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CPA_DEFAULT_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CPA_CLIENT_HEADERS = {
    "x-grok-client-version": "0.2.93",
    "x-xai-token-auth": "xai-grok-cli",
    "x-authenticateresponse": "authenticate-response",
    "x-grok-client-identifier": "grok-shell",
    "User-Agent": "grok-shell/0.2.93 (linux; x86_64)",
}



def resolve_grok2api_local_token_file():
    configured = str(_active_config().get("grok2api_local_token_file", "") or "").strip()
    if configured:
        return configured
    if os.name != "nt":
        return ""
    return r"D:\注册机\3255d5ee6e702db9220a897df64635a1ec9df644\vendor\grok2api\data\token.json"


def _parse_int_list(value):
    ids = []
    if isinstance(value, (list, tuple)):
        candidates = value
    else:
        candidates = str(value or "").split(",")
    for candidate in candidates:
        try:
            parsed = int(str(candidate).strip())
        except Exception:
            continue
        if parsed > 0:
            ids.append(parsed)
    return ids


def _optional_positive_int(value, default=None):
    try:
        parsed = int(value)
    except Exception:
        return default
    return parsed if parsed > 0 else default


def _sub2api_api_base(settings):
    base = str(settings.get("sub2api_base") or "").strip().rstrip("/")
    if not base:
        raise ValueError("sub2api Base 未配置")
    if not base.endswith("/api/v1"):
        base = f"{base}/api/v1"
    return base


def _sub2api_headers(settings):
    token = str(settings.get("sub2api_admin_token") or "").strip()
    if not token:
        raise ValueError("sub2api 管理 Token 未配置")
    auth_mode = str(settings.get("sub2api_auth_mode") or "x-api-key").strip().lower()
    headers = {"Content-Type": "application/json"}
    if auth_mode == "bearer":
        headers["Authorization"] = f"Bearer {token}"
    else:
        headers["x-api-key"] = token
    return headers


def _sub2api_response_data(resp):
    resp.raise_for_status()
    try:
        payload = resp.json()
    except Exception:
        return {"raw": resp.text[:1000]}
    if isinstance(payload, dict) and "code" in payload and payload.get("code") not in (0, 200, "0", "200", None):
        message = payload.get("message") or payload.get("msg") or payload.get("error") or payload
        raise Exception(f"sub2api 返回错误: {message}")
    if isinstance(payload, dict) and "data" in payload:
        return payload.get("data")
    return payload


def _grok2api_admin_base(settings=None):
    settings = {**_active_config(), **dict(settings or {})}
    base = str(settings.get("grok2api_remote_base") or "").strip().rstrip("/")
    if not base:
        raise ValueError("grok2api 远端 Base 未配置")
    if base.endswith("/admin/api"):
        return base
    if base.endswith("/admin"):
        return f"{base}/api"
    return f"{base}/admin/api"


def _grok2api_pool_name(settings=None):
    settings = {**_active_config(), **dict(settings or {})}
    pool_name = str(settings.get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip() or "ssoBasic"
    pool_map = {"ssoBasic": "basic", "ssoSuper": "super"}
    return pool_map.get(pool_name, pool_name)


def _grok2api_auth(settings=None):
    settings = {**_active_config(), **dict(settings or {})}
    app_key = str(settings.get("grok2api_remote_app_key") or "").strip()
    if not app_key:
        raise ValueError("grok2api 远端 app_key 未配置")
    return {"Content-Type": "application/json"}, {"app_key": app_key}


def _grok2api_response_data(resp):
    resp.raise_for_status()
    try:
        payload = resp.json()
    except Exception:
        return {"raw": resp.text[:1000]}
    if isinstance(payload, dict) and "code" in payload and payload.get("code") not in (0, 200, "0", "200", None):
        message = payload.get("message") or payload.get("msg") or payload.get("error") or payload
        raise Exception(f"grok2api 返回错误: {message}")
    return payload


def import_accounts_to_grok2api(accounts, settings=None, log_callback=None):
    settings = {**_active_config(), **dict(settings or {})}
    base = _grok2api_admin_base(settings)
    headers, params = _grok2api_auth(settings)
    pool = _grok2api_pool_name(settings)
    valid_accounts = []
    missing = []
    for account in accounts or []:
        token = _normalize_sso_token(account.get("sso", ""))
        if token:
            item = dict(account)
            item["sso"] = token
            valid_accounts.append(item)
        else:
            missing.append(str(account.get("email") or account.get("id") or "").strip())
    if not valid_accounts:
        raise ValueError("没有可推送的账号：选中账号缺少 sso token")
    if missing:
        missing = [item for item in missing if item]
        raise ValueError(f"账号 {', '.join(missing)} 缺少 sso token，不能推送到 grok2api")

    tokens = [account["sso"] for account in valid_accounts]
    payload = {"tokens": tokens, "pool": pool, "tags": ["auto-register"]}
    items = []
    try:
        response = _grok2api_response_data(
            http_post(
                f"{base}/tokens/add",
                headers=headers,
                params=params,
                json=payload,
                timeout=30,
                proxies={},
            )
        )
        for account in valid_accounts:
            items.append(
                {
                    "email": account.get("email", ""),
                    "status": "pushed",
                    "response": {"pool": pool, "result": response},
                }
            )
    except Exception as exc:
        error_text = _sub2api_error_text(exc, step="grok2api")
        for account in valid_accounts:
            items.append(
                {
                    "email": account.get("email", ""),
                    "status": "failed",
                    "error": error_text,
                }
            )
        if log_callback:
            log_callback(f"[!] 推送 grok2api 失败: {error_text}")

    success_count = len([item for item in items if item.get("status") == "pushed"])
    failed_count = len(items) - success_count
    if log_callback:
        log_callback(f"[+] grok2api 推送完成: 成功 {success_count} / 失败 {failed_count}")
    return {
        "imported": failed_count == 0,
        "total": success_count,
        "failed": failed_count,
        "items": items,
        "warning": "已按 SSO token 导入 grok2api 远端池。",
    }


def _sub2api_account_name(account, settings=None, index=1):
    settings = {**_active_config(), **dict(settings or {})}
    email = str((account or {}).get("email") or "").strip()
    base_name = str(settings.get("sub2api_account_name") or "Grok Auto").strip() or "Grok Auto"
    return f"{base_name} - {email}" if email else f"{base_name} #{index}"


def build_sub2api_grok_refresh_token_check_payload(account, settings=None):
    settings = {**_active_config(), **dict(settings or {})}
    refresh_token = str((account or {}).get("refresh_token") or "").strip()
    if not refresh_token:
        raise ValueError(f"账号 {account.get('email', '') or ''} 缺少 refresh_token，不能推送到 sub2api")
    payload = {
        "refresh_token": refresh_token,
        "client_id": str(settings.get("sub2api_grok_client_id") or XAI_GROK_OAUTH_CLIENT_ID).strip(),
    }
    email = str((account or {}).get("email") or "").strip()
    if email:
        payload["email"] = email
    proxy_id = _optional_positive_int(settings.get("sub2api_proxy_id"), None)
    if proxy_id is not None:
        payload["proxy_id"] = proxy_id
    return payload


def build_sub2api_grok_refresh_token_payload(account, token_info=None, settings=None, index=1):
    settings = {**_active_config(), **dict(settings or {})}
    refresh_token = str((account or {}).get("refresh_token") or "").strip()
    if not refresh_token:
        raise ValueError(f"账号 {account.get('email', '') or index} 缺少 refresh_token，不能推送到 sub2api")
    token_info = token_info if isinstance(token_info, dict) else {}
    credentials = dict(token_info)
    credentials["refresh_token"] = str(credentials.get("refresh_token") or refresh_token).strip()
    credentials["client_id"] = str(credentials.get("client_id") or settings.get("sub2api_grok_client_id") or XAI_GROK_OAUTH_CLIENT_ID).strip()
    # 关键：Device Flow OAuth 必须走 cli-chat-proxy，不能用 api.x.ai（会 403 chat denied）
    default_base = XAI_GROK_CLI_CHAT_BASE_URL
    raw_base = str(
        credentials.get("base_url")
        or settings.get("sub2api_grok_base_url")
        or default_base
    ).strip()
    if "api.x.ai" in raw_base and not str(settings.get("sub2api_grok_base_url") or "").strip():
        raw_base = default_base
    credentials["base_url"] = raw_base
    # cli-chat-proxy 聊天必需的 grok-cli headers（对齐 grokcli-2api / CPA 导出）
    # 缺这些时 billing 可能 200，但 chat/Responses 会 403 permission-denied
    cli_headers = {
        "X-XAI-Token-Auth": "xai-grok-cli",
        "x-xai-token-auth": "xai-grok-cli",
        "x-grok-client-version": str(
            settings.get("sub2api_grok_client_version")
            or CPA_CLIENT_HEADERS.get("x-grok-client-version")
            or "0.2.93"
        ),
        "x-grok-client-identifier": str(
            settings.get("sub2api_grok_client_identifier")
            or CPA_CLIENT_HEADERS.get("x-grok-client-identifier")
            or "grok-shell"
        ),
        "x-authenticateresponse": "authenticate-response",
    }
    existing_headers = credentials.get("headers")
    if not isinstance(existing_headers, dict):
        existing_headers = {}
    merged_headers = {**cli_headers, **{k: v for k, v in existing_headers.items() if v}}
    credentials["headers"] = merged_headers
    email = str((account or {}).get("email") or "").strip()
    if email and not credentials.get("email"):
        credentials["email"] = email
    payload = {
        "name": _sub2api_account_name(account, settings, index=index),
        "platform": "grok",
        "type": "oauth",
        "credentials": credentials,
    }
    group_ids = _parse_int_list(settings.get("sub2api_group_ids", ""))
    if group_ids:
        payload["group_ids"] = group_ids
    concurrency = _optional_positive_int(settings.get("sub2api_concurrency"), None)
    if concurrency is not None:
        payload["concurrency"] = concurrency
    priority = _optional_positive_int(settings.get("sub2api_priority"), None)
    if priority is not None:
        payload["priority"] = priority
    return payload


def _sub2api_test_models(settings=None):
    """探测只用 1 个模型，避免连打触发 oauth refresh account state changed。"""
    settings = settings or {}
    preferred = str(settings.get("sub2api_test_model") or "").strip()
    return [preferred] if preferred else ["grok-4.5"]


def _parse_sub2api_test_sse(text):
    """解析 sub2api /test SSE，返回 (ok, message)。"""
    text = str(text or "")
    if not text.strip():
        return None, "empty body"
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            if data.get("success") is True or data.get("ok") is True:
                return True, "json success"
            if data.get("success") is False:
                return False, str(data.get("error") or data.get("message") or data)[:300]
    except Exception:
        pass

    last_err = ""
    saw_event = False
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if not raw or raw == "[DONE]":
            continue
        saw_event = True
        try:
            event = json.loads(raw)
        except Exception:
            continue
        if not isinstance(event, dict):
            continue
        et = str(event.get("type") or event.get("event") or "").strip().lower()
        if et in {"test_complete", "complete", "done"}:
            if event.get("success") is True or event.get("ok") is True:
                return True, "test_complete success"
            err = str(event.get("error") or event.get("text") or event.get("message") or "test failed")
            return False, err[:300]
        if et in {"error", "test_error", "failed"}:
            last_err = str(event.get("error") or event.get("text") or event.get("message") or "error")[:300]
            continue
        if event.get("success") is True:
            return True, "event success"
        if event.get("success") is False:
            last_err = str(event.get("error") or event.get("message") or "failed")[:300]
    if last_err:
        return False, last_err
    if saw_event:
        return True, "sse events received"
    return None, f"unrecognized body: {text[:160]}"


def _is_sub2api_rate_limited_msg(msg):
    text = str(msg or "").lower()
    return any(
        k in text
        for k in ("429", "resource-exhausted", "too many request", "rate limit", "rate_limit", "0/0")
    )


def _is_sub2api_oauth_state_msg(msg):
    text = str(msg or "").lower()
    return "account state changed" in text or "oauth refresh" in text


def _sub2api_post_refresh_account(base, headers, account_id, log_callback=None):
    """创建后 refresh 一次（少路径，避免连打）。"""
    account_id = str(account_id or "").strip()
    if not account_id:
        return False, "missing account_id"
    urls = [
        f"{base}/admin/accounts/{account_id}/refresh",
        f"{base}/admin/grok/accounts/{account_id}/refresh",
    ]
    last_err = ""
    for url in urls:
        try:
            resp = http_post(url, headers=headers, json={}, timeout=60, proxies={})
            code = int(getattr(resp, "status_code", 0) or 0)
            body = getattr(resp, "text", "") or ""
            if code in {200, 201, 204}:
                low = body.lower()
                if any(x in low for x in ("\"success\":false", "invalid_grant", "unauthorized")):
                    last_err = f"HTTP {code}: {body[:200]}"
                    continue
                if log_callback:
                    log_callback(f"[*] sub2api refresh 成功 id={account_id}")
                return True, body[:200] or "refreshed"
            last_err = f"HTTP {code}: {body[:200]}"
        except Exception as exc:
            last_err = str(exc)
            continue
    return False, last_err or "refresh failed"


def _is_sub2api_access_denied_msg(msg):
    text = str(msg or "").lower()
    return any(
        k in text
        for k in (
            "access denied",
            "403",
            "forbidden",
            "not allowed",
            "permission",
        )
    )


def _sub2api_post_test_account(base, headers, account_id, settings=None, log_callback=None):
    """探测：单次请求 + 解析 SSE。"""
    account_id = str(account_id or "").strip()
    if not account_id:
        return False, "missing account_id"
    settings = settings or {}
    model_id = _sub2api_test_models(settings)[0]
    url = f"{base}/admin/accounts/{account_id}/test"
    try:
        resp = http_post(
            url,
            headers=headers,
            json={"model_id": model_id, "model": model_id},
            timeout=120,
            proxies={},
        )
        code = int(getattr(resp, "status_code", 0) or 0)
        body = getattr(resp, "text", "") or ""
        if code not in {200, 201, 204}:
            return False, f"HTTP {code}: {body[:220]}"
        ok, msg = _parse_sub2api_test_sse(body)
        if ok is True:
            if log_callback:
                log_callback(f"[*] sub2api 探测成功 id={account_id} model={model_id}")
            return True, msg
        if log_callback:
            log_callback(f"[Debug] sub2api 探测未通过 id={account_id}: {str(msg)[:220]}")
        return False, msg or "test failed"
    except Exception as exc:
        return False, str(exc)


_SUB2API_INIT_LOCK = threading.RLock()
_SUB2API_INIT_LAST_TS = 0.0


def _sub2api_initialize_account(base, headers, account_id, settings=None, log_callback=None):
    """创建后初始化：全局串行，只做探测（不再 refresh）。

    创建账号时已带 token；refresh 容易和探测并发触发 oauth state / 429。
    """
    global _SUB2API_INIT_LAST_TS
    account_id = str(account_id or "").strip()
    if not account_id:
        return {"account_id": "", "refresh": None, "test": None, "ok": False}
    settings = settings or {}
    auto_probe = bool(settings.get("sub2api_auto_probe", True))
    result = {"account_id": account_id, "refresh": None, "test": None, "ok": False}

    with _SUB2API_INIT_LOCK:
        try:
            gap = max(2.0, float(settings.get("sub2api_init_gap_seconds") or 8.0))
        except Exception:
            gap = 8.0
        wait = (_SUB2API_INIT_LAST_TS + gap) - time.time()
        if wait > 0:
            if log_callback:
                log_callback(f"[*] sub2api 初始化节流等待 {wait:.1f}s")
            time.sleep(wait)

        if not auto_probe:
            result["test"] = {"ok": None, "msg": "auto_probe disabled"}
            result["ok"] = True
            _SUB2API_INIT_LAST_TS = time.time()
            if log_callback:
                log_callback(f"[*] sub2api 已跳过自动探测 id={account_id}")
            return result

        # 创建后稍等再探测，给 sub2api 落库时间
        time.sleep(4.0)
        ok_t, msg_t = _sub2api_post_test_account(
            base, headers, account_id, settings=settings, log_callback=log_callback
        )
        # 403：等一会再测 1 次（不 refresh）
        if not ok_t and _is_sub2api_access_denied_msg(msg_t):
            if log_callback:
                log_callback(f"[*] 探测 403，等待 15s 后重试 id={account_id}")
            time.sleep(15)
            ok_t2, msg_t2 = _sub2api_post_test_account(
                base, headers, account_id, settings=settings, log_callback=log_callback
            )
            result["test"] = {"ok": ok_t2, "msg": msg_t2, "retry_from": msg_t}
            ok_t, msg_t = ok_t2, msg_t2
        # 429：等一会再测 1 次
        elif not ok_t and _is_sub2api_rate_limited_msg(msg_t):
            if log_callback:
                log_callback(f"[*] 探测限流，等待 20s 后重试 id={account_id}")
            time.sleep(20)
            ok_t2, msg_t2 = _sub2api_post_test_account(
                base, headers, account_id, settings=settings, log_callback=log_callback
            )
            result["test"] = {"ok": ok_t2, "msg": msg_t2, "retry_from": msg_t}
            ok_t, msg_t = ok_t2, msg_t2
        else:
            result["test"] = {"ok": ok_t, "msg": msg_t}

        result["ok"] = bool(ok_t)
        _SUB2API_INIT_LAST_TS = time.time()

        if log_callback:
            if ok_t:
                log_callback(f"[+] sub2api 账号已初始化 id={account_id}（探测通过）")
            else:
                log_callback(
                    f"[!] sub2api 账号已入库但探测失败 id={account_id}："
                    f"{str(msg_t)[:120]}；请稍后在 UI 手动点「探测」"
                )
        return result


def _sub2api_find_account_id_by_name(base, headers, account_name, log_callback=None):
    """创建响应无 id 时，按名称回查账号列表。"""
    name = str(account_name or "").strip()
    if not name:
        return ""
    try:
        resp = http_get(
            f"{base}/admin/accounts",
            headers=headers,
            params={"page": 1, "page_size": 50, "keyword": name},
            timeout=30,
            proxies={},
        )
        data = _sub2api_response_data(resp)
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] sub2api 回查账号失败: {exc}")
        return ""
    items = []
    if isinstance(data, dict):
        items = data.get("items") or data.get("list") or data.get("accounts") or []
        if not items and isinstance(data.get("data"), dict):
            items = data["data"].get("items") or []
    if not isinstance(items, list):
        return ""
    for item in items:
        if not isinstance(item, dict):
            continue
        if str(item.get("name") or "").strip() == name:
            return str(item.get("id") or "").strip()
    # 宽松：名称包含
    for item in items:
        if not isinstance(item, dict):
            continue
        if name in str(item.get("name") or ""):
            return str(item.get("id") or "").strip()
    return ""


def _push_one_account_to_sub2api(account, settings, base, headers, index, log_callback=None):
    token_info = _sub2api_response_data(
        http_post(
            f"{base}/admin/grok/oauth/refresh-token",
            headers=headers,
            json=build_sub2api_grok_refresh_token_check_payload(account, settings),
            timeout=60,
            proxies={},
        )
    )
    token_refresh = str((token_info or {}).get("refresh_token") or "").strip()
    if token_refresh and token_refresh != str(account.get("refresh_token") or "").strip():
        replace_registered_account_refresh_token(account, token_refresh)
    payload = build_sub2api_grok_refresh_token_payload(account, token_info, settings, index=index)
    created = _sub2api_response_data(
        http_post(
            f"{base}/admin/accounts",
            headers=headers,
            json=payload,
            timeout=60,
            proxies={},
        )
    )

    # 创建后完整初始化：refresh → 等待 → test（解析 SSE），避免用量窗口 forbidden
    account_id = _extract_sub2api_account_id(created)
    if not account_id:
        account_id = _sub2api_find_account_id_by_name(
            base, headers, payload.get("name"), log_callback=log_callback
        )
    if account_id:
        post_actions = _sub2api_initialize_account(
            base, headers, account_id, settings=settings, log_callback=log_callback
        )
    else:
        post_actions = {"account_id": "", "refresh": None, "test": None, "ok": False}
        if log_callback:
            log_callback(
                f"[!] sub2api 创建成功但未拿到 account_id，无法自动初始化: {account.get('email','')}"
            )

    probe_ok = bool((post_actions or {}).get("ok"))
    remote_id = str((post_actions or {}).get("account_id") or account_id or "").strip()
    status = "pushed" if probe_ok or not remote_id else "probe_failed"
    # auto_probe 关闭时 post_actions.ok=True，仍记 pushed
    if not bool((settings or {}).get("sub2api_auto_probe", True)):
        status = "pushed"
    elif remote_id and (post_actions or {}).get("test") is not None:
        test = (post_actions or {}).get("test") or {}
        if test.get("ok") is True:
            status = "pushed"
        elif test.get("ok") is False:
            status = "probe_failed"
        elif test.get("ok") is None:
            status = "pushed"

    item = {
        "email": account.get("email", ""),
        "status": status,
        "response": created,
        "post_actions": post_actions,
        "remote_id": remote_id,
        "account_id": remote_id,
    }
    if status == "probe_failed":
        test = (post_actions or {}).get("test") or {}
        item["probe_error"] = str(test.get("msg") or "probe failed")[:400]
        item["error"] = item["probe_error"]
    return item


def import_accounts_to_sub2api(accounts, settings=None, log_callback=None):
    settings = {**_active_config(), **dict(settings or {})}
    base = _sub2api_api_base(settings)
    headers = _sub2api_headers(settings)

    valid_accounts = [account for account in (accounts or []) if str(account.get("refresh_token") or "").strip()]
    if not valid_accounts:
        raise ValueError("没有可推送的账号：选中账号缺少 refresh_token")
    missing = [
        str(account.get("email") or account.get("id") or "").strip()
        for account in (accounts or [])
        if not str(account.get("refresh_token") or "").strip()
    ]
    missing = [item for item in missing if item]
    if missing:
        raise ValueError(f"账号 {', '.join(missing)} 缺少 refresh_token，不能推送到 sub2api")

    items = []
    for index, account in enumerate(valid_accounts, start=1):
        step = "refresh-token"
        try:
            items.append(
                _push_one_account_to_sub2api(
                    account, settings, base, headers, index, log_callback=log_callback
                )
            )
        except Exception as exc:
            error_text = _sub2api_error_text(exc, step=step)
            if step == "refresh-token" and is_refresh_token_revoked_error(error_text) and account.get("sso"):
                try:
                    if log_callback:
                        log_callback(f"[*] Refresh Token 已失效，尝试用 SSO 重新获取: {account.get('email', '')}")
                    new_refresh_token = _resolve("fetch_xai_oauth_refresh_token", fetch_xai_oauth_refresh_token)(
                        account.get("sso"),
                        log_callback=log_callback,
                    )
                    replace_registered_account_refresh_token(account, new_refresh_token)
                    items.append(
                        _push_one_account_to_sub2api(
                            account, settings, base, headers, index, log_callback=log_callback
                        )
                    )
                    continue
                except Exception as retry_exc:
                    error_text = f"{error_text}; retry_with_sso_failed: {_sub2api_error_text(retry_exc)}"
            items.append(
                {
                    "email": account.get("email", ""),
                    "status": "failed",
                    "step": step,
                    "error": error_text,
                }
            )
            if log_callback:
                log_callback(f"[!] 推送 sub2api 失败: {account.get('email', '')} {items[-1]['error']}")
    success_count = len([item for item in items if item.get("status") in {"pushed", "probe_failed"}])
    probe_failed_count = len([item for item in items if item.get("status") == "probe_failed"])
    failed_count = len([item for item in items if item.get("status") == "failed"])
    if log_callback:
        extra = f"，探测失败 {probe_failed_count}" if probe_failed_count else ""
        log_callback(
            f"[+] sub2api 推送完成: 入库 {success_count} / 推送失败 {failed_count}{extra}"
        )
    return {
        "imported": failed_count == 0,
        "total": success_count,
        "failed": failed_count,
        "probe_failed": probe_failed_count,
        "items": items,
        "warning": "已按 Refresh Token 直接导入 sub2api；历史仅有 sso 的账号不能推送。探测失败可筛选「sub2api 探测失败」后重探或删远端。",
    }


def _resolve_sub2api_remote_id(account, base=None, headers=None, settings=None, log_callback=None):
    """解析远端 id：状态字段 → response → 按账号名回查。"""
    remote_id = str((account or {}).get("sub2api_remote_id") or "").strip()
    if remote_id:
        return remote_id
    remote_id = _extract_sub2api_remote_id_from_item(
        {
            "response": (account or {}).get("sub2api_response"),
            "account_id": (account or {}).get("sub2api_remote_id"),
        }
    )
    if remote_id:
        return remote_id
    if not base or not headers:
        return ""
    try:
        name = _sub2api_account_name(account, settings=settings)
        found = _sub2api_find_account_id_by_name(base, headers, name, log_callback=log_callback)
        if found and log_callback:
            log_callback(f"[*] sub2api 按名称回查到 id={found} ({(account or {}).get('email','')})")
        return str(found or "").strip()
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] sub2api 按名称回查失败: {exc}")
        return ""


def probe_accounts_on_sub2api(accounts, settings=None, log_callback=None):
    """对已入库账号重新探测（不重复创建）。

    历史号若只有「已推送」无 remote id，会按命名规则回查 sub2api；
    查不到则报错，不会把历史 pushed 批量改成 probe_failed。
    """
    settings = {**_active_config(), **dict(settings or {})}
    base = _sub2api_api_base(settings)
    headers = _sub2api_headers(settings)
    items = []
    for account in accounts or []:
        email = str(account.get("email") or "").strip()
        remote_id = _resolve_sub2api_remote_id(
            account, base=base, headers=headers, settings=settings, log_callback=log_callback
        )
        if not remote_id:
            items.append(
                {
                    "email": email,
                    "status": "failed",
                    "step": "probe",
                    "error": "缺少 sub2api 远端 id，且按名称未找到（历史号未记 id 时可到 sub2api 后台核对名称）",
                }
            )
            continue
        try:
            post_actions = _sub2api_initialize_account(
                base,
                headers,
                remote_id,
                settings={**settings, "sub2api_auto_probe": True},
                log_callback=log_callback,
            )
            ok = bool((post_actions or {}).get("ok"))
            test = (post_actions or {}).get("test") or {}
            if ok and test.get("ok") is not False:
                items.append(
                    {
                        "email": email,
                        "status": "pushed",
                        "remote_id": remote_id,
                        "account_id": remote_id,
                        "post_actions": post_actions,
                        "response": account.get("sub2api_response"),
                    }
                )
            else:
                msg = str(test.get("msg") or "probe failed")[:400]
                items.append(
                    {
                        "email": email,
                        "status": "probe_failed",
                        "remote_id": remote_id,
                        "account_id": remote_id,
                        "probe_error": msg,
                        "error": msg,
                        "post_actions": post_actions,
                        "response": account.get("sub2api_response"),
                    }
                )
        except Exception as exc:
            items.append(
                {
                    "email": email,
                    "status": "probe_failed",
                    "remote_id": remote_id,
                    "account_id": remote_id,
                    "error": _sub2api_error_text(exc, step="probe")[:400],
                    "probe_error": _sub2api_error_text(exc, step="probe")[:400],
                    "response": account.get("sub2api_response"),
                }
            )
    ok_n = len([i for i in items if i.get("status") == "pushed"])
    fail_n = len(items) - ok_n
    if log_callback:
        log_callback(f"[+] sub2api 重新探测完成: 通过 {ok_n} / 失败 {fail_n}")
    return {"total": ok_n, "failed": fail_n, "items": items}


def delete_accounts_from_sub2api(accounts, settings=None, log_callback=None):
    """删除 sub2api 远端账号，并回写本地状态为未推送。"""
    settings = {**_active_config(), **dict(settings or {})}
    base = _sub2api_api_base(settings)
    headers = _sub2api_headers(settings)
    items = []
    for account in accounts or []:
        email = str(account.get("email") or "").strip()
        remote_id = _resolve_sub2api_remote_id(
            account, base=base, headers=headers, settings=settings, log_callback=log_callback
        )
        if not remote_id:
            items.append(
                {
                    "email": email,
                    "status": "failed",
                    "step": "delete-remote",
                    "error": "缺少 sub2api 远端 id，无法删除",
                }
            )
            continue
        try:
            last_err = ""
            for method in ("delete", "post"):
                try:
                    if method == "delete":
                        resp = http_delete(
                            f"{base}/admin/accounts/{remote_id}",
                            headers=headers,
                            timeout=30,
                            proxies={},
                        )
                    else:
                        # 部分部署用 POST /delete
                        resp = http_post(
                            f"{base}/admin/accounts/{remote_id}/delete",
                            headers=headers,
                            json={},
                            timeout=30,
                            proxies={},
                        )
                    code = int(getattr(resp, "status_code", 0) or 0)
                    if code in {200, 201, 204, 404}:
                        items.append(
                            {
                                "email": email,
                                "status": "deleted_remote",
                                "remote_id": remote_id,
                                "response": {"http_status": code},
                            }
                        )
                        if log_callback:
                            log_callback(f"[+] 已删除 sub2api 远端账号 id={remote_id} {email}")
                        last_err = ""
                        break
                    last_err = f"HTTP {code}: {(getattr(resp, 'text', '') or '')[:180]}"
                except Exception as exc:
                    last_err = str(exc)
            if last_err:
                items.append(
                    {
                        "email": email,
                        "status": "failed",
                        "step": "delete-remote",
                        "remote_id": remote_id,
                        "error": last_err[:400],
                    }
                )
                if log_callback:
                    log_callback(f"[!] 删除 sub2api 远端失败 id={remote_id}: {last_err[:160]}")
        except Exception as exc:
            items.append(
                {
                    "email": email,
                    "status": "failed",
                    "step": "delete-remote",
                    "remote_id": remote_id,
                    "error": _sub2api_error_text(exc, step="delete-remote")[:400],
                }
            )
    deleted = len([i for i in items if i.get("status") == "deleted_remote"])
    failed = len(items) - deleted
    if log_callback:
        log_callback(f"[+] sub2api 远端删除完成: 成功 {deleted} / 失败 {failed}")
    return {"total": deleted, "failed": failed, "items": items}


def check_registered_accounts_health(accounts, settings=None, log_callback=None):
    settings = {**_active_config(), **dict(settings or {})}
    items = []
    for account in accounts or []:
        email = str(account.get("email") or "").strip()
        refresh_token = str(account.get("refresh_token") or "").strip()
        if not refresh_token:
            items.append(
                {
                    "email": email,
                    "status": "incomplete",
                    "error": "缺少 refresh_token",
                }
            )
            continue
        try:
            token_info = _resolve("exchange_xai_refresh_token", exchange_xai_refresh_token)(refresh_token, settings=settings)
            token_refresh = str((token_info or {}).get("refresh_token") or "").strip()
            if token_refresh and token_refresh != refresh_token:
                replace_registered_account_refresh_token(account, token_refresh)
            response = {
                "token_type": token_info.get("token_type", ""),
                "expires_in": token_info.get("expires_in", ""),
                "scope": token_info.get("scope", ""),
            }
            items.append({"email": email, "status": "healthy", "response": response})
        except Exception as exc:
            items.append(
                {
                    "email": email,
                    "status": "unhealthy",
                    "error": _sub2api_error_text(exc, step="refresh-token"),
                }
            )
    healthy_count = len([item for item in items if item.get("status") == "healthy"])
    failed_count = len(items) - healthy_count
    if log_callback:
        log_callback(f"[+] 健康检查完成: 可用 {healthy_count} / 异常 {failed_count}")
    return {
        "checked": len(items),
        "healthy": healthy_count,
        "failed": failed_count,
        "items": items,
    }


def auto_push_registered_account(account, settings=None, log_callback=None):
    settings = {**_active_config(), **dict(settings or {})}
    if settings.get("grok2api_auto_add_remote"):
        try:
            result = _resolve("import_accounts_to_grok2api", import_accounts_to_grok2api)([account], settings, log_callback=log_callback)
            persist_grok2api_push_status([account], result)
            if log_callback:
                log_callback(f"[*] 已自动推送到远程 grok2api: {account.get('email', '')}")
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 自动推送远程 grok2api 失败: {exc}")
    if settings.get("sub2api_auto_import_remote"):
        try:
            result = _resolve("import_accounts_to_sub2api", import_accounts_to_sub2api)([account], settings, log_callback=log_callback)
            persist_sub2api_push_status([account], result)
            if log_callback:
                log_callback(f"[*] 已自动推送到 sub2api: {account.get('email', '')}")
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 自动推送 sub2api 失败: {exc}")


def add_token_to_grok2api_local_pool(raw_token, email="", log_callback=None):
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    token_file = resolve_grok2api_local_token_file()
    pool_name = str(_active_config().get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip()
    if not pool_name:
        pool_name = "ssoBasic"
    if not token_file:
        if log_callback:
            log_callback("[Debug] grok2api 本地 token.json 未配置，跳过")
        return False
    token_dir = os.path.dirname(token_file)
    if token_dir:
        os.makedirs(token_dir, exist_ok=True)
    data = {}
    if os.path.exists(token_file):
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            data = {}
    if not isinstance(data, dict):
        data = {}
    pool = data.get(pool_name)
    if not isinstance(pool, list):
        pool = []
    existing = set()
    for item in pool:
        if isinstance(item, str):
            existing.add(_normalize_sso_token(item))
        elif isinstance(item, dict):
            existing.add(_normalize_sso_token(item.get("token", "")))
    if token in existing:
        if log_callback:
            log_callback(f"[*] grok2api 本地池已存在 token: {pool_name}")
        return True
    entry = {"token": token, "tags": ["auto-register"], "note": email}
    pool.append(entry)
    data[pool_name] = pool
    with open(token_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    if log_callback:
        log_callback(f"[+] 已写入 grok2api 本地池: {pool_name} ({token_file})")
    return True


def add_token_to_grok2api_remote_pool(raw_token, email="", log_callback=None):
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    try:
        base = _grok2api_admin_base(config)
        headers, query = _grok2api_auth(config)
    except ValueError:
        if log_callback:
            log_callback("[Debug] grok2api 远端未配置 base/app_key，跳过")
        return False
    pool_name = str(_active_config().get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip() or "ssoBasic"
    remote_pool = _grok2api_pool_name(config)
    # 优先使用 add 接口，避免全量覆盖远端池
    try:
        add_payload = {"tokens": [token], "pool": remote_pool, "tags": ["auto-register"]}
        resp_add = http_post(
            f"{base}/tokens/add",
            headers=headers,
            params=query,
            json=add_payload,
            timeout=30,
            proxies={},
        )
        resp_add.raise_for_status()
        if log_callback:
            log_callback(f"[+] 已写入 grok2api 远端池: {pool_name} ({base}/tokens/add)")
        return True
    except Exception as add_exc:
        if log_callback:
            log_callback(f"[Debug] /tokens/add 写入失败，尝试 /tokens 全量模式: {add_exc}")

    # 兜底：旧版全量保存接口
    current = {}
    try:
        resp = http_get(f"{base}/tokens", headers=headers, params=query, timeout=20, proxies={})
        if resp.status_code == 200:
            payload = resp.json()
            current = payload.get("tokens", {}) if isinstance(payload, dict) else {}
    except Exception:
        current = {}
    if not isinstance(current, dict):
        current = {}
    pool = current.get(pool_name)
    if not isinstance(pool, list):
        pool = []
    existing = set()
    for item in pool:
        if isinstance(item, str):
            existing.add(_normalize_sso_token(item))
        elif isinstance(item, dict):
            existing.add(_normalize_sso_token(item.get("token", "")))
    if token not in existing:
        pool.append({"token": token, "tags": ["auto-register"], "note": email})
    current[pool_name] = pool
    resp2 = http_post(f"{base}/tokens", headers=headers, params=query, json=current, timeout=30, proxies={})
    resp2.raise_for_status()
    if log_callback:
        log_callback(f"[+] 已写入 grok2api 远端池: {pool_name} ({base}/tokens)")
    return True


def add_token_to_grok2api_pools(raw_token, email="", log_callback=None):
    if _active_config().get("grok2api_auto_add_local", True):
        try:
            add_token_to_grok2api_local_pool(raw_token, email=email, log_callback=log_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 写入 grok2api 本地池失败: {exc}")
    if _active_config().get("grok2api_auto_add_remote", False):
        try:
            add_token_to_grok2api_remote_pool(raw_token, email=email, log_callback=log_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] 写入 grok2api 远端池失败: {exc}")


def _base64_urlsafe_no_padding(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_xai_oauth_authorize_url(state, code_challenge, nonce, redirect_uri=None):
    params = {
        "response_type": "code",
        "client_id": XAI_GROK_OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri or XAI_GROK_OAUTH_REDIRECT_URI,
        "scope": XAI_GROK_OAUTH_SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "plan": "generic",
        "referrer": "sub2api",
    }
    return f"{XAI_GROK_OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def parse_xai_oauth_callback_url(url):
    parsed = urllib.parse.urlparse(str(url or ""))
    values = urllib.parse.parse_qs(parsed.query)
    code = (values.get("code") or [""])[0].strip()
    state = (values.get("state") or [""])[0].strip()
    error = (values.get("error") or [""])[0].strip()
    if not code and parsed.fragment:
        fragment_values = urllib.parse.parse_qs(parsed.fragment)
        code = (fragment_values.get("code") or [""])[0].strip()
        state = state or (fragment_values.get("state") or [""])[0].strip()
        error = error or (fragment_values.get("error") or [""])[0].strip()
    return {"code": code, "state": state, "error": error, "url": str(url or "")}


def build_xai_oauth_consent_click_script():
    return r"""
const isConsentPage = String(location.href || '').includes('oauth2/consent');
if (!isConsentPage) {
  return {
    clicked: false,
    skipped: true,
    isConsentPage,
    url: String(location.href || ''),
    text: document.body ? String(document.body.innerText || '').slice(0, 300) : ''
  };
}
const denyWords = ['cancel', 'deny', 'decline', 'reject', '拒绝', '取消'];
const allowWords = [
  'allow', 'authorize', 'authorise', 'continue', 'approve', 'accept',
  'agree', 'yes', 'confirm', 'submit', '同意', '授权', '继续', '允许', '确认'
];
const textOf = (node) => String(
  node.innerText || node.textContent || node.value ||
  node.getAttribute?.('aria-label') || node.getAttribute?.('title') || ''
).replace(/\s+/g, ' ').trim().toLowerCase();
const visible = (node) => {
  try {
    const rect = node.getBoundingClientRect();
    const style = getComputedStyle(node);
    return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
  } catch (e) {
    return true;
  }
};
const disabled = (node) => !!(node.disabled || node.getAttribute?.('disabled') !== null || node.getAttribute?.('aria-disabled') === 'true');
const allNodes = [];
const visit = (root) => {
  if (!root) return;
  try {
    const nodes = Array.from(root.querySelectorAll('*'));
    for (const node of nodes) {
      allNodes.push(node);
      if (node.shadowRoot) visit(node.shadowRoot);
    }
  } catch (e) {}
};
visit(document);
const clickables = allNodes.filter((node) => {
  const tag = String(node.tagName || '').toLowerCase();
  const role = String(node.getAttribute?.('role') || '').toLowerCase();
  const type = String(node.getAttribute?.('type') || '').toLowerCase();
  return tag === 'button' || tag === 'a' || role === 'button' || type === 'submit' || node.onclick;
}).filter((node) => visible(node) && !disabled(node));
const buttons = clickables;
const score = (node) => {
  const text = textOf(node);
  if (denyWords.some((word) => text.includes(word))) return -100;
  let value = 0;
  if (allowWords.some((word) => text.includes(word))) value += 100;
  const cls = String(node.className || '').toLowerCase();
  if (cls.includes('primary') || cls.includes('submit') || cls.includes('continue')) value += 10;
  const rect = node.getBoundingClientRect?.();
  if (rect) value += Math.min(20, Math.max(0, rect.left / 100));
  return value;
};
const ranked = clickables.map((node) => ({ node, score: score(node), text: textOf(node) }))
  .filter((item) => item.score >= 0)
  .sort((a, b) => b.score - a.score);
const buttonDiagnostics = ranked.slice(0, 8).map((item) => ({
  text: item.text,
  score: item.score,
  tag: String(item.node.tagName || '').toLowerCase(),
  type: String(item.node.getAttribute?.('type') || '').toLowerCase(),
  role: String(item.node.getAttribute?.('role') || '').toLowerCase()
}));
const target = ranked.find((item) => item.score >= 100)?.node;
if (target) {
  target.scrollIntoView?.({ block: 'center', inline: 'center' });
  const rect = target.getBoundingClientRect();
  const centerX = Math.round(rect.left + rect.width / 2);
  const centerY = Math.round(rect.top + rect.height / 2);
  target.click();
  const form = target.closest?.('form');
  if (form) {
    try {
      form.requestSubmit ? form.requestSubmit(target) : form.submit();
    } catch (e) {
      try { form.submit(); } catch (ignored) {}
    }
  }
  return {
    clicked: true,
    text: textOf(target),
    count: clickables.length,
    isConsentPage,
    centerX,
    centerY,
    submitted: !!form,
    buttonDiagnostics
  };
}
return {
  clicked: false,
  count: clickables.length,
  isConsentPage,
  buttonDiagnostics,
  text: document.body ? String(document.body.innerText || '').slice(0, 300) : ''
};
"""


def save_xai_oauth_debug_snapshot(page, log_callback=None):
    if not page:
        return []
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    base = os.path.join(get_data_dir(), f"oauth_debug_{stamp}")
    saved = []
    try:
        html = str(getattr(page, "html", "") or "")
        html_path = f"{base}.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        saved.append(html_path)
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] OAuth HTML 快照保存失败: {str(exc)[:160]}")
    png_path = f"{base}.png"
    screenshot_methods = [
        lambda: page.get_screenshot(path=png_path),
        lambda: page.get_screenshot(png_path),
        lambda: page.save_screenshot(png_path),
        lambda: page.screenshot(path=png_path),
    ]
    for method in screenshot_methods:
        try:
            method()
            if os.path.exists(png_path):
                saved.append(png_path)
                break
        except Exception:
            continue
    if log_callback and saved:
        log_callback(f"[Debug] OAuth 调试快照已保存: {', '.join(saved)}")
    return saved


def set_xai_sso_cookies_for_oauth(page, sso, log_callback=None):
    """把 API 拿到的 sso 注入浏览器，供后续 OAuth 使用。

    CDP Network.setCookie 对 domain/.x.ai 不稳定时，用 url= 多站写入。
    """
    token = _normalize_sso_token(sso)
    if not page or not token:
        return False
    ok = False
    specs = []
    for url in (
        "https://auth.x.ai/",
        "https://accounts.x.ai/",
        "https://grok.com/",
    ):
        for name in ("sso", "sso-rw"):
            specs.append(
                {
                    "name": name,
                    "value": token,
                    "url": url,
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "None",
                }
            )
    for domain in (".x.ai", ".grok.com", "auth.x.ai", "accounts.x.ai"):
        for name in ("sso", "sso-rw"):
            specs.append(
                {
                    "name": name,
                    "value": token,
                    "domain": domain,
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                }
            )
    for cookie in specs:
        try:
            page.run_cdp("Network.setCookie", **cookie)
            ok = True
        except Exception:
            continue
    try:
        setter = getattr(getattr(page, "set", None), "cookies", None)
        if setter:
            setter(
                [
                    {"name": "sso", "value": token, "domain": ".x.ai", "path": "/"},
                    {"name": "sso-rw", "value": token, "domain": ".x.ai", "path": "/"},
                ]
            )
            ok = True
    except Exception:
        pass
    # 校验 cookie 是否在 jar
    present = False
    try:
        raw = page.cookies(all_domains=True, all_info=True) or []
        for item in raw:
            name = item.get("name") if isinstance(item, dict) else getattr(item, "name", "")
            value = item.get("value") if isinstance(item, dict) else getattr(item, "value", "")
            if str(name) == "sso" and str(value or "").strip():
                present = True
                break
    except Exception:
        pass
    if log_callback:
        payload = _parse_jwt_payload(token) or {}
        log_callback(
            f"[Debug] 注入 sso 到浏览器: ok={ok} present={present} "
            f"len={len(token)} session_id={str(payload.get('session_id') or '')[:24]}"
        )
    return ok and present


def exchange_xai_oauth_code_for_token(code, code_verifier, redirect_uri=None):
    payload = {
        "grant_type": "authorization_code",
        "client_id": XAI_GROK_OAUTH_CLIENT_ID,
        "code": code,
        "redirect_uri": redirect_uri or XAI_GROK_OAUTH_REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    resp = http_post(
        XAI_GROK_OAUTH_TOKEN_URL,
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "sub2api-grok-oauth/1.0",
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict) or not str(data.get("refresh_token") or "").strip():
        raise Exception(f"xAI OAuth token 返回缺少 refresh_token: {str(data)[:300]}")
    return data


def exchange_xai_refresh_token(refresh_token, settings=None):
    settings = {**_active_config(), **dict(settings or {})}
    token = str(refresh_token or "").strip()
    if not token:
        raise ValueError("缺少 refresh_token")
    payload = {
        "grant_type": "refresh_token",
        "client_id": str(settings.get("sub2api_grok_client_id") or XAI_GROK_OAUTH_CLIENT_ID).strip(),
        "refresh_token": token,
    }
    resp = http_post(
        XAI_GROK_OAUTH_TOKEN_URL,
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "grok-register-health/1.0",
        },
        timeout=60,
    )
    status_code = getattr(resp, "status_code", None)
    if status_code is not None and int(status_code) >= 400:
        detail = str(getattr(resp, "text", "") or "").strip()
        if detail:
            raise ValueError(f"xAI OAuth refresh HTTP {status_code}: {detail[:1000]}")
        raise ValueError(f"xAI OAuth refresh HTTP {status_code}")
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict) or not str(data.get("access_token") or "").strip():
        raise Exception(f"xAI OAuth refresh 返回缺少 access_token: {str(data)[:300]}")
    return data


def normalize_cpa_management_auth_files_url(base):
    value = str(base or "").strip().rstrip("/")
    if not value:
        raise ValueError("CPA 管理地址不能为空")
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = f"http://{value}"
    value = re.sub(r"/v0/management(?:/auth-files)?$", "", value, flags=re.IGNORECASE)
    return f"{value}/v0/management/auth-files"


def _cpa_credential_file_name(email):
    safe_email = re.sub(r"[^A-Za-z0-9@._-]", "-", str(email or "").strip()).strip("-")
    if not safe_email:
        raise ValueError("CPA 凭证缺少邮箱")
    return f"xai-{safe_email}.json"


def _cpa_access_token_metadata(access_token):
    try:
        parts = str(access_token or "").split(".")
        if len(parts) < 2:
            raise ValueError("not a JWT")
        payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_segment))
        expires_at = int(claims["exp"])
        issued_at = int(claims.get("iat") or expires_at - 21600)
        expired = datetime.datetime.fromtimestamp(
            expires_at, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return expired, max(expires_at - issued_at, 0), str(
            claims.get("sub") or claims.get("principal_id") or ""
        ).strip()
    except Exception:
        return "", 21600, ""


def _write_cpa_credential(auth_dir, filename, payload):
    os.makedirs(auth_dir, exist_ok=True)
    path = os.path.join(auth_dir, filename)
    fd, temp_path = tempfile.mkstemp(prefix=".xai-", suffix=".tmp", dir=auth_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return path


def export_and_push_cpa_credential(email, refresh_token, settings=None, log_callback=None):
    resolved_settings = {**_active_config(), **dict(settings or {})}
    log = log_callback or (lambda message: None)
    token_data = _resolve("exchange_xai_refresh_token", exchange_xai_refresh_token)(refresh_token, settings=resolved_settings)
    access_token = str(token_data.get("access_token") or "").strip()
    resolved_refresh_token = str(token_data.get("refresh_token") or refresh_token or "").strip()
    if not access_token or not resolved_refresh_token:
        raise ValueError("xAI OAuth 返回缺少 CPA 凭证所需 token")

    expired, token_expires_in, subject = _cpa_access_token_metadata(access_token)
    auth_dir = str(resolved_settings.get("cpa_auth_dir") or "cpa_auths").strip()
    if not os.path.isabs(auth_dir):
        auth_dir = os.path.join(get_data_dir(), auth_dir)
    filename = _cpa_credential_file_name(email)
    payload = {
        "type": "xai",
        "access_token": access_token,
        "refresh_token": resolved_refresh_token,
        "token_type": str(token_data.get("token_type") or "Bearer"),
        "expires_in": int(token_data.get("expires_in") or token_expires_in),
        "expired": expired,
        "last_refresh": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "email": str(email or "").strip(),
        "sub": subject,
        "base_url": str(resolved_settings.get("cpa_base_url") or CPA_DEFAULT_BASE_URL).rstrip("/"),
        "redirect_uri": XAI_GROK_OAUTH_REDIRECT_URI,
        "token_endpoint": XAI_GROK_OAUTH_TOKEN_URL,
        "auth_kind": "oauth",
        "headers": dict(CPA_CLIENT_HEADERS),
    }
    if token_data.get("id_token"):
        payload["id_token"] = str(token_data["id_token"])
    local_path = _write_cpa_credential(auth_dir, filename, payload)
    result = {
        "ok": True,
        "path": local_path,
        "filename": filename,
        "refresh_token": resolved_refresh_token,
    }

    if not resolved_settings.get("cpa_auto_push_remote"):
        return result

    management_base = str(resolved_settings.get("cpa_management_base") or "").strip()
    management_key = str(resolved_settings.get("cpa_management_key") or "").strip()
    if not management_base or not management_key:
        result["upload_error"] = "CPA 自动推送缺少管理地址或管理密钥"
        return result

    multipart = None
    try:
        if CurlMime is None:
            raise RuntimeError("curl_cffi 未安装，无法上传 CPA 凭证")
        multipart = _CurlMime()()
        multipart.addpart(
            name="file",
            content_type="application/json",
            filename=filename,
            local_path=local_path,
        )
        response = http_post(
            normalize_cpa_management_auth_files_url(management_base),
            headers={"Authorization": f"Bearer {management_key}"},
            multipart=multipart,
            timeout=30,
            proxies={},
        )
        response.raise_for_status()
        result["uploaded"] = True
        result["upload_status"] = getattr(response, "status_code", None)
        log(f"[cpa] 已推送凭证到 CPA: {filename}")
    except Exception as exc:
        result["upload_error"] = str(exc)[:500]
        log(f"[cpa] 推送 CPA 凭证失败: {result['upload_error']}")
    finally:
        if multipart is not None:
            multipart.close()
    return result


def build_native_account_export_line(account):
    email = str((account or {}).get("email") or "").strip()
    password = str((account or {}).get("password") or "").strip()
    sso = _normalize_sso_token((account or {}).get("sso") or "")
    refresh_token = str((account or {}).get("refresh_token") or "").strip()
    if not email or not sso:
        return ""
    if refresh_token:
        return f"{email}----{password}----{sso}----{refresh_token}"
    return f"{email}----{password}----{sso}"


def build_grok2api_export_payload(accounts):
    """导出 grok2api 可导入的 token 列表（SSO）。"""
    tokens = []
    for account in accounts or []:
        sso = _normalize_sso_token(account.get("sso") or "")
        if not sso:
            continue
        tokens.append(
            {
                "token": sso,
                "email": str(account.get("email") or "").strip(),
                "tags": ["export", "auto-register"],
                "note": str(account.get("email") or "").strip(),
            }
        )
    pool_name = str(_active_config().get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip() or "ssoBasic"
    return {
        "exported_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pool": pool_name,
        "tokens": tokens,
        "count": len(tokens),
    }


def build_sub2api_export_account(account, settings=None, index=1, log_callback=None):
    """导出单个 sub2api oauth 账号（含 cli-chat-proxy headers）。"""
    settings = {**_active_config(), **dict(settings or {})}
    refresh_token = str((account or {}).get("refresh_token") or "").strip()
    if not refresh_token:
        raise ValueError(f"{account.get('email') or index}: 缺少 refresh_token")
    token_info = {}
    # 尽量换成新 access_token，失败则只带 refresh_token
    try:
        token_info = _resolve("exchange_xai_refresh_token", exchange_xai_refresh_token)(refresh_token, settings=settings) or {}
        new_rt = str(token_info.get("refresh_token") or "").strip()
        if new_rt:
            refresh_token = new_rt
            try:
                replace_registered_account_refresh_token(account, new_rt)
            except Exception:
                pass
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 导出 sub2api 时 refresh 失败，仅导出 refresh_token: {exc}")
        token_info = {"refresh_token": refresh_token}
    payload = build_sub2api_grok_refresh_token_payload(
        account, token_info=token_info, settings=settings, index=index
    )
    # sub2api 批量导入常见结构：accounts[]
    return {
        "name": payload.get("name"),
        "platform": payload.get("platform") or "grok",
        "type": payload.get("type") or "oauth",
        "credentials": payload.get("credentials") or {},
        "concurrency": payload.get("concurrency"),
        "priority": payload.get("priority"),
        "group_ids": payload.get("group_ids") or [],
    }


def build_cpa_export_payload(account, settings=None, log_callback=None):
    """生成 CPA xai-*.json 内容（不上传）。"""
    settings = {**_active_config(), **dict(settings or {})}
    email = str((account or {}).get("email") or "").strip()
    refresh_token = str((account or {}).get("refresh_token") or "").strip()
    if not email or not refresh_token:
        raise ValueError(f"{email or 'unknown'}: 缺少 email/refresh_token")
    token_data = _resolve("exchange_xai_refresh_token", exchange_xai_refresh_token)(refresh_token, settings=settings)
    access_token = str(token_data.get("access_token") or "").strip()
    resolved_refresh_token = str(token_data.get("refresh_token") or refresh_token or "").strip()
    if not access_token or not resolved_refresh_token:
        raise ValueError(f"{email}: OAuth 返回缺少 access/refresh token")
    expired, token_expires_in, subject = _cpa_access_token_metadata(access_token)
    payload = {
        "type": "xai",
        "access_token": access_token,
        "refresh_token": resolved_refresh_token,
        "token_type": str(token_data.get("token_type") or "Bearer"),
        "expires_in": int(token_data.get("expires_in") or token_expires_in),
        "expired": expired,
        "last_refresh": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "email": email,
        "sub": subject,
        "base_url": str(settings.get("cpa_base_url") or CPA_DEFAULT_BASE_URL).rstrip("/"),
        "redirect_uri": XAI_GROK_OAUTH_REDIRECT_URI,
        "token_endpoint": XAI_GROK_OAUTH_TOKEN_URL,
        "auth_kind": "oauth",
        "headers": dict(CPA_CLIENT_HEADERS),
    }
    if token_data.get("id_token"):
        payload["id_token"] = str(token_data["id_token"])
    return _cpa_credential_file_name(email), payload


def export_accounts_zip(accounts, formats, settings=None, log_callback=None):
    """按格式导出账号，每种格式一个 zip；多种格式时再包一层 outer zip。

    formats: iterable of native|grok2api|sub2api|cpa
    返回: {filename, content_type, content: bytes, summary: {...}}
    """
    settings = {**_active_config(), **dict(settings or {})}
    log = log_callback or (lambda m: None)
    wanted = []
    for item in formats or []:
        key = str(item or "").strip().lower()
        if key in {"native", "raw", "accounts"}:
            key = "native"
        if key in {"native", "grok2api", "sub2api", "cpa"} and key not in wanted:
            wanted.append(key)
    if not wanted:
        raise ValueError("请至少选择一种导出格式：native / grok2api / sub2api / cpa")
    accounts = list(accounts or [])
    if not accounts:
        raise ValueError("没有可导出的账号")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    summary = {fmt: {"ok": 0, "failed": 0, "errors": []} for fmt in wanted}
    packages = {}  # fmt -> bytes of zip

    # native
    if "native" in wanted:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            lines = []
            for account in accounts:
                line = build_native_account_export_line(account)
                if not line:
                    summary["native"]["failed"] += 1
                    summary["native"]["errors"].append(
                        f"{account.get('email') or '?'}: 缺少 email/sso"
                    )
                    continue
                lines.append(line)
                summary["native"]["ok"] += 1
            zf.writestr("accounts.txt", "\n".join(lines) + ("\n" if lines else ""))
            zf.writestr(
                "manifest.json",
                json.dumps(
                    {
                        "format": "native",
                        "count": len(lines),
                        "exported_at": stamp,
                        "line_format": "email----password----sso----refresh_token",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
            )
        packages["native"] = buf.getvalue()
        log(f"[*] 导出 native: {summary['native']['ok']} 个")

    # grok2api
    if "grok2api" in wanted:
        payload = build_grok2api_export_payload(accounts)
        summary["grok2api"]["ok"] = int(payload.get("count") or 0)
        summary["grok2api"]["failed"] = max(0, len(accounts) - summary["grok2api"]["ok"])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "grok2api_tokens.json",
                json.dumps(payload, ensure_ascii=False, indent=2),
            )
            # 也给一份纯 token 列表，方便粘贴
            plain = "\n".join(item["token"] for item in payload.get("tokens") or [])
            zf.writestr("tokens.txt", plain + ("\n" if plain else ""))
        packages["grok2api"] = buf.getvalue()
        log(f"[*] 导出 grok2api: {summary['grok2api']['ok']} 个")

    # sub2api
    if "sub2api" in wanted:
        exported = []
        for index, account in enumerate(accounts, start=1):
            try:
                exported.append(
                    build_sub2api_export_account(
                        account, settings=settings, index=index, log_callback=log
                    )
                )
                summary["sub2api"]["ok"] += 1
            except Exception as exc:
                summary["sub2api"]["failed"] += 1
                summary["sub2api"]["errors"].append(
                    f"{account.get('email') or index}: {exc}"
                )
        payload = {
            "exported_at": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "proxies": [],
            "accounts": exported,
            "count": len(exported),
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                f"sub2api-accounts-{stamp}.json",
                json.dumps(payload, ensure_ascii=False, indent=2),
            )
            # 每个账号单独一份，便于挑着用
            for item in exported:
                email = str((item.get("credentials") or {}).get("email") or item.get("name") or "account")
                safe = re.sub(r"[^A-Za-z0-9@._-]", "-", email).strip("-") or "account"
                zf.writestr(
                    f"accounts/{safe}.json",
                    json.dumps(item, ensure_ascii=False, indent=2),
                )
        packages["sub2api"] = buf.getvalue()
        log(f"[*] 导出 sub2api: {summary['sub2api']['ok']} 个 / 失败 {summary['sub2api']['failed']}")

    # cpa
    if "cpa" in wanted:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for account in accounts:
                try:
                    filename, payload = build_cpa_export_payload(
                        account, settings=settings, log_callback=log
                    )
                    zf.writestr(
                        filename,
                        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                    )
                    summary["cpa"]["ok"] += 1
                except Exception as exc:
                    summary["cpa"]["failed"] += 1
                    summary["cpa"]["errors"].append(
                        f"{account.get('email') or '?'}: {exc}"
                    )
            zf.writestr(
                "manifest.json",
                json.dumps(
                    {
                        "format": "cpa",
                        "count": summary["cpa"]["ok"],
                        "failed": summary["cpa"]["failed"],
                        "exported_at": stamp,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
            )
        packages["cpa"] = buf.getvalue()
        log(f"[*] 导出 CPA: {summary['cpa']['ok']} 个 / 失败 {summary['cpa']['failed']}")

    # 单格式：直接返回该 zip；多格式：再包 outer zip
    if len(packages) == 1:
        fmt = next(iter(packages))
        return {
            "filename": f"export_{fmt}_{stamp}.zip",
            "content_type": "application/zip",
            "content": packages[fmt],
            "summary": summary,
            "formats": [fmt],
        }

    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fmt, data in packages.items():
            zf.writestr(f"export_{fmt}_{stamp}.zip", data)
        zf.writestr(
            "export_summary.json",
            json.dumps(
                {
                    "exported_at": stamp,
                    "formats": wanted,
                    "account_count": len(accounts),
                    "summary": summary,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
    return {
        "filename": f"export_accounts_{stamp}.zip",
        "content_type": "application/zip",
        "content": outer.getvalue(),
        "summary": summary,
        "formats": wanted,
    }


def import_accounts_to_cpa(accounts, settings=None, log_callback=None):
    resolved_settings = {**_active_config(), **dict(settings or {})}
    management_base = str(resolved_settings.get("cpa_management_base") or "").strip()
    management_key = str(resolved_settings.get("cpa_management_key") or "").strip()
    if not management_base or not management_key:
        raise ValueError("推送到 CPA 需要先填写 CPA 管理地址和管理密钥")
    resolved_settings["cpa_auto_push_remote"] = True

    accounts = list(accounts or [])
    items = [None] * len(accounts)
    pending = []
    for index, account in enumerate(accounts):
        email = str(account.get("email") or account.get("id") or "").strip()
        refresh_token = str(account.get("refresh_token") or "").strip()
        if not refresh_token:
            items[index] = {
                "email": email,
                "status": "failed",
                "step": "credential",
                "error": "缺少 refresh_token",
            }
            continue

        pending.append((index, account, email, refresh_token))

    worker_count = _parse_positive_int(
        resolved_settings.get("cpa_push_workers"), 3, minimum=1, maximum=10
    )
    log_lock = threading.Lock()

    def safe_log(message):
        if log_callback:
            with log_lock:
                log_callback(message)

    def push_once(task):
        index, account, email, refresh_token = task
        try:
            result = _resolve("export_and_push_cpa_credential", export_and_push_cpa_credential)(
                email,
                refresh_token,
                resolved_settings,
                log_callback=safe_log,
            )
            return index, account, email, refresh_token, result, None
        except Exception as exc:
            return index, account, email, refresh_token, None, exc

    def result_item(account, email, refresh_token, result):
        rotated_refresh_token = str(result.get("refresh_token") or "").strip()
        if rotated_refresh_token and rotated_refresh_token != refresh_token:
            replace_registered_account_refresh_token(account, rotated_refresh_token)
        upload_error = str(result.get("upload_error") or "").strip()
        if upload_error or not result.get("uploaded"):
            return {
                "email": email,
                "status": "failed",
                "step": "upload",
                "error": upload_error or "CPA 未确认上传成功",
            }
        return {
            "email": email,
            "status": "pushed",
            "response": {
                "filename": result.get("filename", ""),
                "uploaded": True,
                "upload_status": result.get("upload_status"),
            },
        }

    outcomes = []
    if pending:
        actual_workers = min(worker_count, len(pending))
        safe_log(f"[*] CPA 批量推送: {len(pending)} 个账号，{actual_workers} 路并发")
        with ThreadPoolExecutor(max_workers=actual_workers, thread_name_prefix="cpa-push") as executor:
            outcomes = list(executor.map(push_once, pending))

    retry_with_sso = []
    for index, account, email, refresh_token, result, error in outcomes:
        if error is None:
            items[index] = result_item(account, email, refresh_token, result)
            continue

        error_text = _sub2api_error_text(error)
        if account.get("sso") and is_xai_refresh_token_client_error(error):
            retry_with_sso.append((index, account, email, refresh_token, error_text))
            continue
        items[index] = {
            "email": email,
            "status": "failed",
            "step": "credential",
            "error": error_text,
        }

    # SSO recovery opens browser tabs and mutates source account files, so keep it serialized.
    for index, account, email, refresh_token, error_text in retry_with_sso:
        try:
            safe_log(f"[*] CPA Refresh Token 不可用，尝试用 SSO 重新获取: {email}")
            refresh_token = _resolve("fetch_xai_oauth_refresh_token", fetch_xai_oauth_refresh_token)(
                account.get("sso"),
                log_callback=safe_log,
            )
            replace_registered_account_refresh_token(account, refresh_token)
            result = _resolve("export_and_push_cpa_credential", export_and_push_cpa_credential)(
                email,
                refresh_token,
                resolved_settings,
                log_callback=safe_log,
            )
            items[index] = result_item(account, email, refresh_token, result)
        except Exception as retry_exc:
            items[index] = {
                "email": email,
                "status": "failed",
                "step": "credential",
                "error": f"{error_text}; retry_with_sso_failed: {_sub2api_error_text(retry_exc)}"[:1000],
            }

    success_count = len([item for item in items if item.get("status") == "pushed"])
    failed_count = len(items) - success_count
    if log_callback:
        log_callback(f"[+] CPA 推送完成: 成功 {success_count} / 失败 {failed_count}")
    return {
        "imported": failed_count == 0,
        "total": success_count,
        "failed": failed_count,
        "items": items,
        "warning": "CPA 推送使用账号保存的第四段 Refresh Token。",
    }


# 并发注册时 Device Flow 全局串行，避免 xAI rate_limited（对齐 2api）
_DEVICE_FLOW_LOCK = threading.RLock()
_DEVICE_FLOW_LAST_TS = 0.0


def _device_flow_gap_sec():
    try:
        return max(0.0, float(_active_config().get("device_flow_gap_seconds", 2.0) or 2.0))
    except Exception:
        return 2.0


def exchange_sso_to_refresh_token_via_device_flow(
    sso,
    log_callback=None,
    cancel_callback=None,
    retries=3,
    browser_cookies=None,
):
    """对齐 grokcli-2api/sso_to_auth_json：纯 HTTP Device Flow，sso → refresh_token。

    流程：
      1) cookie sso 访问 accounts.x.ai 校验会话
      2) POST /oauth2/device/code
      3) GET verification_uri_complete + POST device/verify
      4) POST device/approve
      5) 轮询 /oauth2/token 拿 refresh_token

    并发时全局串行 + 最小间隔，降低 rate_limited。
    """
    global _DEVICE_FLOW_LAST_TS
    req = _requests_mod()
    if req is None:
        raise RuntimeError("curl_cffi 未安装，无法 Device Flow")
    token = _normalize_sso_token(sso)
    if not token:
        raise ValueError("账号缺少 sso cookie，无法 Device Flow")

    proxies = get_proxies()
    proxy_kw = {"proxies": proxies} if proxies else {}
    timeout = 20
    issuer = "https://auth.x.ai"
    client_id = XAI_GROK_OAUTH_CLIENT_ID
    scopes = XAI_GROK_OAUTH_SCOPE
    # 与 grokcli-2api 一致：每次请求带 impersonate=chrome（不要锁死 chrome131）
    impersonate = "chrome"

    def log(msg):
        if log_callback:
            log_callback(msg)

    # 对齐 grokcli-2api：approve 始终传空 principal_id。
    # CreateSession 的 sso JWT 通常只有 session_id，没有 user sub；
    # 误把 session_id 当 principal_id 会导致 token 端 invalid_grant (Access denied)。
    principal_id = ""

    # 整段 Device Flow 串行，避免两线程同时 verify/approve 触发限流
    with _DEVICE_FLOW_LOCK:
        gap = _device_flow_gap_sec()
        wait = (_DEVICE_FLOW_LAST_TS + gap) - time.time()
        if wait > 0:
            log(f"[*] Device Flow 节流等待 {wait:.1f}s（防 rate_limited）")
            sleep_with_cancel(wait, cancel_callback)
        _DEVICE_FLOW_LAST_TS = time.time()

        session = req.Session()
        try:
            # 多域种 sso（与 CreateSession 后 CookieSetter 推广一致）
            for domain in (
                "accounts.x.ai",
                ".x.ai",
                "auth.x.ai",
                ".grok.com",
                "grok.com",
                "auth.grokusercontent.com",
            ):
                try:
                    session.cookies.set("sso", token, domain=domain)
                except Exception:
                    continue
            try:
                session.cookies.set("sso", token)
            except Exception:
                pass
            for domain in ("accounts.x.ai", ".x.ai", ".grok.com"):
                try:
                    session.cookies.set("sso-rw", token, domain=domain)
                except Exception:
                    continue

            # 优先使用建号阶段 CookieSetter 后的完整 jar（含 auth.x.ai 等）
            for c in browser_cookies or []:
                try:
                    session.cookies.set(
                        c.get("name"),
                        c.get("value"),
                        domain=c.get("domain") or ".x.ai",
                        path=c.get("path") or "/",
                    )
                except Exception:
                    try:
                        session.cookies.set(c.get("name"), c.get("value"))
                    except Exception:
                        pass

            # 1) 校验 sso
            raise_if_cancelled(cancel_callback)
            try:
                r = session.get(
                    "https://accounts.x.ai/",
                    impersonate=impersonate,
                    timeout=timeout,
                    **proxy_kw,
                )
                final_url = str(getattr(r, "url", "") or "")
            except Exception as exc:
                raise RuntimeError(f"Device Flow 校验 sso 网络错误: {exc}") from exc
            if "sign-in" in final_url or "sign-up" in final_url:
                raise RuntimeError(f"sso 无效（校验落到登录页）: {final_url}")
            log(f"[*] Device Flow: sso 有效（校验 URL={final_url[:80]}）")

            # 若调用方已传入 CookieSetter 后的 cookies，则不再二次 CreateCookieSetterLink
            # （二次调用易 403，且会丢掉第一次推广结果）
            if browser_cookies:
                log(f"[*] Device Flow 复用建号 CookieSetter jar（{len(browser_cookies)} cookies）")
            else:
                try:
                    from core.xai.protocol import promote_sso_session_cookies

                    raise_if_cancelled(cancel_callback)
                    promo = promote_sso_session_cookies(
                        token,
                        session=session,
                        proxies=proxies,
                        success_url="https://accounts.x.ai/account",
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                    )
                    ok = bool(isinstance(promo, dict) and promo.get("ok"))
                    log(f"[*] Device Flow CookieSetter 推广: {'ok' if ok else 'skip/fail'}")
                    if ok and promo.get("cookies"):
                        for c in promo.get("cookies") or []:
                            try:
                                session.cookies.set(
                                    c.get("name"),
                                    c.get("value"),
                                    domain=c.get("domain") or ".x.ai",
                                    path=c.get("path") or "/",
                                )
                            except Exception:
                                pass
                except Exception as exc:
                    log(f"[Debug] Device Flow CookieSetter 推广异常: {exc}")

            # 纯 HTTP 刚 CreateSession 的新号：给 IdP 一点时间把会话同步到 auth.x.ai
            try:
                settle = float(
                    (_active_config() or {}).get("device_flow_settle_seconds", 1.5) or 1.5
                )
            except Exception:
                settle = 1.5
            settle = max(0.0, min(settle, 15.0))
            if settle > 0:
                log(f"[*] Device Flow 会话预热 {settle:.1f}s（auth.x.ai）")
                sleep_with_cancel(settle, cancel_callback)
                try:
                    session.get(
                        f"{issuer}/",
                        impersonate=impersonate,
                        timeout=timeout,
                        **proxy_kw,
                    )
                except Exception:
                    pass

            last_err = ""
            for attempt in range(1, max(1, int(retries)) + 1):
                raise_if_cancelled(cancel_callback)
                log(f"[*] Device Flow 第 {attempt}/{retries} 次...")

                # 2) device/code
                try:
                    r = session.post(
                        f"{issuer}/oauth2/device/code",
                        data={"client_id": client_id, "scope": scopes},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        impersonate=impersonate,
                        timeout=timeout,
                        **proxy_kw,
                    )
                    if int(getattr(r, "status_code", 0) or 0) >= 400:
                        last_err = f"device/code HTTP {r.status_code}: {(r.text or '')[:200]}"
                        log(f"[Debug] {last_err}")
                        sleep_with_cancel(2.0 * attempt, cancel_callback)
                        continue
                    dc = r.json() if hasattr(r, "json") else {}
                except Exception as exc:
                    last_err = f"device/code 异常: {exc}"
                    log(f"[Debug] {last_err}")
                    sleep_with_cancel(2.0 * attempt, cancel_callback)
                    continue
                if not isinstance(dc, dict) or not dc.get("device_code") or not dc.get("user_code"):
                    last_err = f"device/code 响应异常: {str(dc)[:160]}"
                    log(f"[Debug] {last_err}")
                    sleep_with_cancel(2.0 * attempt, cancel_callback)
                    continue
                user_code = str(dc.get("user_code") or "")
                device_code = str(dc.get("device_code") or "")
                verify_url = str(dc.get("verification_uri_complete") or "")
                try:
                    poll_interval = float(dc.get("interval") or 1)
                except Exception:
                    poll_interval = 1.0
                # approve 后可以更积极轮询（对齐 2api）
                poll_interval = max(0.4, min(poll_interval, 1.5))
                log(f"[*] Device Flow user_code={user_code}")

                # 3) verify
                try:
                    if verify_url:
                        session.get(
                            verify_url,
                            impersonate=impersonate,
                            timeout=timeout,
                            **proxy_kw,
                        )
                    r = session.post(
                        f"{issuer}/oauth2/device/verify",
                        data={"user_code": user_code},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        impersonate=impersonate,
                        timeout=timeout,
                        allow_redirects=True,
                        **proxy_kw,
                    )
                    vurl = str(getattr(r, "url", "") or "")
                    if "consent" not in vurl:
                        last_err = f"verify 未到 consent: {vurl[:160]}"
                        log(f"[Debug] {last_err}")
                        backoff = 4.0 * attempt if "rate_limited" in vurl else 2.0 * attempt
                        sleep_with_cancel(backoff, cancel_callback)
                        continue
                except Exception as exc:
                    last_err = f"verify 异常: {exc}"
                    log(f"[Debug] {last_err}")
                    sleep_with_cancel(2.0 * attempt, cancel_callback)
                    continue

                # 4) approve（字段与 grokcli-2api 完全一致）
                try:
                    r = session.post(
                        f"{issuer}/oauth2/device/approve",
                        data={
                            "user_code": user_code,
                            "action": "allow",
                            "principal_type": "User",
                            "principal_id": principal_id,
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        impersonate=impersonate,
                        timeout=timeout,
                        allow_redirects=True,
                        **proxy_kw,
                    )
                    aurl = str(getattr(r, "url", "") or "")
                    astatus = int(getattr(r, "status_code", 0) or 0)
                    # 仅认路径段 /done 或 query，避免误匹配其它含 done 的 URL
                    aurl_l = aurl.lower()
                    approved = (
                        "/done" in aurl_l
                        or aurl_l.rstrip("/").endswith("done")
                        or "device/done" in aurl_l
                        or "status=done" in aurl_l
                    )
                    if not approved:
                        last_err = (
                            f"approve 未到 done: HTTP {astatus} url={aurl[:180]} "
                            f"body={(getattr(r, 'text', None) or '')[:120]}"
                        )
                        log(f"[Debug] {last_err}")
                        backoff = 4.0 * attempt if "rate_limited" in aurl_l else 2.0 * attempt
                        sleep_with_cancel(backoff, cancel_callback)
                        continue
                    log(f"[*] Device Flow 已 approve (HTTP {astatus})")
                except Exception as exc:
                    last_err = f"approve 异常: {exc}"
                    log(f"[Debug] {last_err}")
                    sleep_with_cancel(2.0 * attempt, cancel_callback)
                    continue

                # 5) poll token（approve 后立即第一枪，不要先 sleep）
                poll_deadline = time.time() + 45
                interval = poll_interval
                form = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": client_id,
                    "device_code": device_code,
                }
                first = True
                while time.time() < poll_deadline:
                    raise_if_cancelled(cancel_callback)
                    if not first:
                        sleep_with_cancel(interval, cancel_callback)
                    first = False
                    try:
                        r = session.post(
                            f"{issuer}/oauth2/token",
                            data=form,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            impersonate=impersonate,
                            timeout=timeout,
                            **proxy_kw,
                        )
                        code = int(getattr(r, "status_code", 0) or 0)
                        if code < 400:
                            data = r.json() if hasattr(r, "json") else {}
                            refresh = str((data or {}).get("refresh_token") or "").strip()
                            if refresh:
                                log(f"[*] Device Flow 成功，refresh_token 长度={len(refresh)}")
                                return refresh
                            last_err = f"token 响应无 refresh_token: {str(data)[:200]}"
                            break
                        try:
                            err = r.json() if getattr(r, "content", None) else {}
                        except Exception:
                            err = {}
                        error = str((err or {}).get("error") or "")
                        err_desc = str((err or {}).get("error_description") or "").strip()
                        if error == "authorization_pending":
                            continue
                        if error == "slow_down":
                            interval = min(8.0, interval + 1.0)
                            continue
                        body_preview = (getattr(r, "text", None) or "")[:200]
                        last_err = (
                            f"token 错误: {error or f'HTTP {code}'}"
                            + (f" ({err_desc})" if err_desc else "")
                            + (f" body={body_preview}" if body_preview and not err_desc else "")
                        )
                        # Access denied：新会话偶发未同步；本轮 device_code 作废，外层重试
                        if error == "invalid_grant" and "access denied" in (err_desc or "").lower():
                            log(
                                "[Debug] token Access denied：会话/权限可能未就绪，"
                                "将换新 device_code 重试"
                            )
                            sleep_with_cancel(min(6.0, 2.0 * attempt + 1.0), cancel_callback)
                        break
                    except Exception as exc:
                        last_err = f"token 轮询异常: {exc}"
                        continue
                log(f"[Debug] Device Flow 本轮未拿到 token: {last_err}")
                sleep_with_cancel(2.0 * attempt, cancel_callback)

            raise RuntimeError(f"Device Flow 失败: {last_err or 'unknown'}")
        finally:
            try:
                session.close()
            except Exception:
                pass


def fetch_xai_oauth_refresh_token(sso, timeout=90, log_callback=None, cancel_callback=None):
    """优先 Device Flow（与 2api 一致）；失败再回退浏览器 OAuth consent。"""
    token = _normalize_sso_token(sso)
    if not token:
        raise ValueError("账号缺少 sso cookie，无法获取 Refresh Token")

    # API 建号路径：纯 HTTP Device Flow；若测试已注入浏览器（_get_browser 有值）则跳过直连网络。
    browser_ready = _get_browser() is not None
    if not browser_ready:
        try:
            if log_callback:
                log_callback("[*] 获取 Refresh Token：优先 Device Flow（对齐 grokcli-2api）...")
            device_fn = _resolve(
                "exchange_sso_to_refresh_token_via_device_flow",
                exchange_sso_to_refresh_token_via_device_flow,
            )
            promo_cookies = None
            try:
                from core.xai.protocol import promote_sso_session_cookies as _promo

                last = getattr(_promo, "_last_promo", None)
                if isinstance(last, dict) and last.get("cookies"):
                    promo_cookies = last.get("cookies")
            except Exception:
                promo_cookies = None
            return device_fn(
                token,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
                browser_cookies=promo_cookies,
            )
        except Exception as device_exc:
            if log_callback:
                log_callback(f"[!] Device Flow 失败，回退浏览器 OAuth: {device_exc}")
    elif log_callback:
        log_callback("[*] 检测到已有浏览器会话，跳过 Device Flow，走 OAuth 页面")

    browser = _get_browser()
    page = _get_page()
    if browser is None or page is None:
        browser, page = start_browser(log_callback=log_callback)
    try:
        page = browser.new_tab("https://auth.x.ai")
        _set_page(page)
    except Exception:
        page = refresh_active_page()

    code_verifier = _base64_urlsafe_no_padding(secrets.token_bytes(32))
    challenge = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = _base64_urlsafe_no_padding(challenge)
    state = secrets.token_hex(32)
    nonce = secrets.token_hex(16)
    auth_url = build_xai_oauth_authorize_url(state, code_challenge, nonce)
    if log_callback:
        log_callback("[*] 获取 xAI OAuth Refresh Token...")
    # 先落到 auth 域再种 cookie，避免仍停在 sign-up 时空种
    try:
        page.get("https://auth.x.ai/")
        sleep_with_cancel(0.8, cancel_callback)
    except Exception:
        pass
    injected = set_xai_sso_cookies_for_oauth(page, token, log_callback=log_callback)
    if not injected and log_callback:
        log_callback("[!] sso cookie 注入未确认成功，OAuth 可能落到登录页")
    # 种 cookie 后再打开 authorize
    page.get(auth_url)
    sleep_with_cancel(1.0, cancel_callback)
    # 若落到 sign-in，再种一次并重开
    try:
        cur = str(getattr(page, "url", "") or "")
        if "sign-in" in cur or "login" in cur.lower():
            if log_callback:
                log_callback("[*] OAuth 落到登录页，重新注入 sso 并重开 authorize")
            set_xai_sso_cookies_for_oauth(page, token, log_callback=log_callback)
            page.get(auth_url)
            sleep_with_cancel(1.2, cancel_callback)
    except Exception:
        pass

    deadline = time.time() + timeout
    last_url = ""
    next_diag_at = 0
    consent_submitted_at = 0
    consent_submitted_url = ""
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        current_url = str(getattr(page, "url", "") or "")
        last_url = current_url or last_url
        parsed = parse_xai_oauth_callback_url(current_url)
        if parsed.get("error"):
            raise Exception(f"xAI OAuth 返回错误: {parsed['error']}")
        if parsed.get("code"):
            if parsed.get("state") and parsed.get("state") != state:
                raise Exception("xAI OAuth state 不匹配")
            token_data = _resolve("exchange_xai_oauth_code_for_token", exchange_xai_oauth_code_for_token)(parsed["code"], code_verifier)
            refresh_token = str(token_data.get("refresh_token") or "").strip()
            if log_callback:
                log_callback(f"[*] 已获取 xAI OAuth Refresh Token，长度={len(refresh_token)}")
            return refresh_token
        click_result = {"skipped": "waiting_after_submit"}
        waiting_after_submit = (
            consent_submitted_at
            and "oauth2/consent" in current_url
            and current_url == consent_submitted_url
        )
        if not waiting_after_submit:
            # 登录页时再尝试注入
            if "sign-in" in current_url:
                set_xai_sso_cookies_for_oauth(page, token, log_callback=None)
            click_result = _click_xai_oauth_consent_if_present(page)
            if isinstance(click_result, dict) and (click_result.get("clicked") or click_result.get("submitted")):
                consent_submitted_at = time.time()
                consent_submitted_url = current_url
        if log_callback and time.time() >= next_diag_at:
            log_callback(f"[Debug] xAI OAuth consent 点击结果: {click_result}")
            next_diag_at = time.time() + 5
        sleep_with_cancel(1.2 if waiting_after_submit else 0.8, cancel_callback)
    snapshot_paths = save_xai_oauth_debug_snapshot(page, log_callback=log_callback)
    snapshot_text = f"，调试快照: {', '.join(snapshot_paths)}" if snapshot_paths else ""
    raise Exception(f"xAI OAuth 未在 {timeout}s 内返回 code，最后URL: {last_url}{snapshot_text}")


