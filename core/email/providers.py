"""Email providers, domain pool bridge, and verification code polling."""

from __future__ import annotations

import datetime
import json
import os
import re
import secrets
import string
import tempfile
import threading
import time

from core.cancel import raise_if_cancelled as _raise_if_cancelled_impl
from core.cancel import sleep_with_cancel as _sleep_with_cancel_impl
from core.config import DEFAULT_CONFIG, _EMAIL_PROVIDERS, config
from core.exceptions import EmailDomainRejected, EmailProviderUnavailable, RegistrationCancelled
from core.http_client import http_get, http_post
from core.paths import get_data_dir, get_rejected_email_domains_file
import sys


_cf_domain_index = 0
_yyds_domain_index = 0
_rejected_email_domains = set()
_rejected_email_domains_lock = threading.Lock()
_cloudmail_public_token = None
_cloudmail_public_token_lock = threading.Lock()

DUCKMAIL_API_BASE = "https://api.duckmail.sbs"


def _facade():
    """``grok_register_ttk`` when loaded; tests monkeypatch symbols there."""
    return sys.modules.get("grok_register_ttk")


def _resolve(name, default):
    fac = _facade()
    if fac is not None and hasattr(fac, name):
        return getattr(fac, name)
    return default


def _now():
    fac = _facade()
    if fac is not None:
        tmod = getattr(fac, "time", None)
        if tmod is not None and hasattr(tmod, "time"):
            return tmod.time()
    return time.time()


def sleep_with_cancel(seconds, cancel_callback=None):
    return _resolve("sleep_with_cancel", _sleep_with_cancel_impl)(seconds, cancel_callback)


def raise_if_cancelled(cancel_callback=None):
    return _resolve("raise_if_cancelled", _raise_if_cancelled_impl)(cancel_callback)


def _call_yyds_get_token(*args, **kwargs):
    return _resolve("yyds_get_token", yyds_get_token)(*args, **kwargs)


def _call_yyds_get_messages(*args, **kwargs):
    return _resolve("yyds_get_messages", yyds_get_messages)(*args, **kwargs)


def _call_yyds_get_message_detail(*args, **kwargs):
    return _resolve("yyds_get_message_detail", yyds_get_message_detail)(*args, **kwargs)


def get_duckmail_api_key():
    return config.get("duckmail_api_key", "")


def get_cloudflare_api_base():
    return str(config.get("cloudflare_api_base", "") or "").rstrip("/")


def get_cloudflare_api_key():
    return config.get("cloudflare_api_key", "")


def get_cloudflare_auth_mode():
    return str(config.get("cloudflare_auth_mode", "bearer") or "bearer").lower()


def get_cloudflare_path(key, default_path):
    raw = str(config.get(key, default_path) or default_path).strip()
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def cloudflare_build_headers(content_type=False):
    headers = {"Content-Type": "application/json"} if content_type else {}
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key:
        if mode == "x-api-key":
            headers["X-API-Key"] = key
        elif mode != "none":
            headers["Authorization"] = f"Bearer {key}"
    return headers


def cloudflare_apply_auth_params(params=None):
    merged = dict(params or {})
    key = get_cloudflare_api_key()
    mode = get_cloudflare_auth_mode()
    if key and mode == "query-key":
        merged["key"] = key
    return merged


def _pick_list_payload(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data.get("results")
        if isinstance(data.get("hydra:member"), list):
            return data.get("hydra:member")
        if isinstance(data.get("data"), list):
            return data.get("data")
        if isinstance(data.get("messages"), list):
            return data.get("messages")
        if isinstance(data.get("data"), dict):
            nested = data.get("data")
            if isinstance(nested.get("messages"), list):
                return nested.get("messages")
    return []


def _mail_pool_settings():
    """读取域名池完整配置（对齐 openai-cpa）。"""
    import mail_domain_pool as mdp

    return mdp.settings_from_config(config)


def pick_configured_mail_domain(log_callback=None):
    """从 mail_domains/defaultDomains 选主域（分组/冷却/黄金矿工/低失败）。"""
    import mail_domain_pool as mdp

    settings = _mail_pool_settings()
    domains = settings.get("main_domains") or []
    if not domains:
        raise Exception("未配置 mail_domains / defaultDomains，无法生成邮箱域名")
    # 不读永久拒收黑名单；仅依赖域名池冷却/禁用主域（对齐 openai-cpa）
    main = mdp.pick_main_domain(settings, rejected=set())
    if log_callback:
        mode_bits = []
        if settings.get("enable_sub_domains"):
            mode_bits.append("子域开")
        if settings.get("pinpoint"):
            mode_bits.append("黄金矿工")
        if settings.get("low_failure"):
            mode_bits.append("低失败优先")
        if settings.get("enable_grouping"):
            mode_bits.append(f"分组:{settings.get('group_strategy')}")
        extra = ("，" + "/".join(mode_bits)) if mode_bits else ""
        log_callback(f"[*] 域名池选中主域 {main}{extra}")
    return main


def compose_mail_address(main_domain=None, log_callback=None):
    """生成 local@ [sub.]main 地址。"""
    import mail_domain_pool as mdp

    settings = _mail_pool_settings()
    main = main_domain or pick_configured_mail_domain(log_callback=log_callback)
    address = mdp.compose_email_address(
        main,
        enable_sub_domains=bool(settings.get("enable_sub_domains")),
        sub_domain_level=int(settings.get("sub_domain_level") or 1),
        random_sub_domain_level=bool(settings.get("random_sub_domain_level")),
    )
    if log_callback and settings.get("enable_sub_domains"):
        log_callback(f"[*] 多级域名邮箱: {address}")
    return address, main


def note_mail_domain_outcome(email_or_domain, success=True, reason="discarded_email", log_callback=None):
    """注册成功/域名拒收时回写域名池统计。"""
    try:
        import mail_domain_pool as mdp

        settings = _mail_pool_settings()
        if not settings.get("enable_runtime"):
            return
        main = mdp.main_domain_of(email_or_domain, settings.get("main_domains") or [email_or_domain])
        if not main:
            return
        if success:
            mdp.record_success(main, settings)
            return
        info = mdp.record_failure(main, reason, settings)
        if log_callback and info.get("cooled"):
            left = max(0, int(float(info.get("cooldown_until") or 0) - _now()))
            log_callback(
                f"[!] 主域 {main} 失败过多，冷却约 {left}s "
                f"(reason={info.get('reason') or reason})"
            )
        elif log_callback and info.get("already_cooling"):
            log_callback(f"[Debug] 主域 {main} 仍在冷却中")
    except Exception:
        pass

def cloudflare_create_temp_address(api_base, log_callback=None):
    """适配 cloudflare_temp_email：优先指定 domain/name，支持多级子域。

    多级子域依赖 CF Email Routing / Worker 的 catch-all，与 openai-cpa 一致，
    用于摊薄「同主域日创建量」触发的 10w 类限制。
    """
    url = f"{api_base.rstrip('/')}/admin/new_address"
    # 兼容旧路径
    alt_url = f"{api_base.rstrip('/')}/api/new_address"
    settings = _mail_pool_settings()
    payload = {"enablePrefix": False}
    address_hint = ""
    main = ""
    try:
        if settings["domains"]:
            address_hint, main = compose_mail_address(log_callback=log_callback)
            local, host = address_hint.split("@", 1)
            payload["name"] = local
            payload["domain"] = host
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 域名池生成失败，回退服务端随机: {exc}")

    headers = cloudflare_build_headers(content_type=True)
    # admin_auth 常见：x-admin-auth 或 Authorization
    admin = str(config.get("cloudflare_api_key") or "").strip()
    if admin and "x-admin-auth" not in {k.lower() for k in headers}:
        headers = {**headers, "x-admin-auth": admin}

    last_err = None
    for try_url in (url, alt_url):
        try:
            resp = http_post(try_url, json=payload, headers=headers)
            if resp.status_code >= 400 and try_url == url:
                # 旧部署只有 /api/new_address
                last_err = f"HTTP {resp.status_code}: {(resp.text or '')[:200]}"
                continue
            resp.raise_for_status()
            try:
                data = resp.json()
            except Exception:
                raise Exception(f"Cloudflare new_address 返回非JSON: {resp.text[:300]}")
            address = data.get("address") or address_hint
            jwt = data.get("jwt") or data.get("token")
            if not address or not jwt:
                raise Exception(f"Cloudflare new_address 缺少 address/jwt: {data}")
            return address, jwt
        except Exception as exc:
            last_err = exc
            continue
    # 失败记主域
    if main:
        note_mail_domain_outcome(main, success=False, reason="cloudflare_temp_email_network", log_callback=log_callback)
    raise Exception(f"Cloudflare 创建临时邮箱失败: {last_err}")

def get_domains(api_key=None):
    headers = {}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    resp = http_get(f"{DUCKMAIL_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def create_account(address, password, api_key=None, expires_in=0):
    headers = {"Content-Type": "application/json"}
    key = api_key or get_duckmail_api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = {"address": address, "password": password, "expiresIn": expires_in}
    resp = http_post(f"{DUCKMAIL_API_BASE}/accounts", json=data, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_token(address, password):
    data = {"address": address, "password": password}
    resp = http_post(f"{DUCKMAIL_API_BASE}/token", json=data)
    resp.raise_for_status()
    return resp.json().get("token")


def get_messages(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages", headers=headers)
    resp.raise_for_status()
    return resp.json().get("hydra:member", [])


def get_message_detail(token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    resp = http_get(f"{DUCKMAIL_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_domains(api_base, api_key=None):
    headers = cloudflare_build_headers(content_type=False)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    path = get_cloudflare_path("cloudflare_path_domains", "/domains")
    params = cloudflare_apply_auth_params()
    resp = http_get(f"{api_base}{path}", headers=headers, params=params)
    resp.raise_for_status()
    return _pick_list_payload(resp.json())


def cloudflare_create_account(api_base, address, password, api_key=None, expires_in=0):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    payload = {"address": address, "password": password, "expiresIn": expires_in}
    path = get_cloudflare_path("cloudflare_path_accounts", "/accounts")
    params = cloudflare_apply_auth_params()
    resp = http_post(f"{api_base}{path}", json=payload, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()


def cloudflare_get_token(api_base, address, password, api_key=None):
    headers = cloudflare_build_headers(content_type=True)
    if api_key and "Authorization" in headers:
        headers["Authorization"] = f"Bearer {api_key}"
    if api_key and "X-API-Key" in headers:
        headers["X-API-Key"] = api_key
    path = get_cloudflare_path("cloudflare_path_token", "/token")
    resp = http_post(
        f"{api_base}{path}",
        json={"address": address, "password": password},
        headers=headers,
        params=cloudflare_apply_auth_params(),
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        if data.get("token"):
            return data.get("token")
        if isinstance(data.get("data"), dict) and data["data"].get("token"):
            return data["data"].get("token")
    return None


def cloudflare_get_messages(api_base, token):
    headers = {"Authorization": f"Bearer {token}"}
    path = get_cloudflare_path("cloudflare_path_messages", "/messages")
    params = {"limit": 20, "offset": 0}
    params = cloudflare_apply_auth_params(params)
    resp = http_get(f"{api_base}{path}", headers=headers, params=params)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"Cloudflare messages 返回非JSON: {resp.text[:300]}")
    return _pick_list_payload(data)


def cloudflare_get_message_detail(api_base, token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    candidates = [
        f"{api_base}/api/mail/{message_id}",
        f"{api_base}{get_cloudflare_path('cloudflare_path_messages', '/messages')}/{message_id}",
    ]
    last_err = None
    for url in candidates:
        try:
            resp = http_get(
                url,
                headers=headers,
                params=cloudflare_apply_auth_params(),
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                return data["data"]
            return data
        except Exception as exc:
            last_err = exc
            continue
    raise Exception(f"Cloudflare 获取邮件详情失败: {last_err}")


YYDS_API_BASE = "https://maliapi.215.im/v1"


def get_yyds_api_key():
    return config.get("yyds_api_key", "")


def get_yyds_jwt():
    return config.get("yyds_jwt", "")


def yyds_get_domains(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/domains", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", []) if data.get("success") else []


def yyds_create_account(address=None, domain=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    payload = {}
    if address:
        payload["address"] = address
    if domain:
        payload["domain"] = domain
    elif key or token:
        payload["autoDomainStrategy"] = "prefer_owned"
    resp = http_post(f"{YYDS_API_BASE}/accounts", json=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 创建邮箱失败: {data}")


def yyds_get_token(address, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_post(
        f"{YYDS_API_BASE}/token", json={"address": address}, headers=headers
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("token")
    raise Exception(f"YYDS 获取 token 失败: {data}")


def yyds_get_messages(address, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(
        f"{YYDS_API_BASE}/messages",
        params={"address": address},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {}).get("messages", [])
    return []


def yyds_get_message_detail(message_id, token=None, api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    temp_token = token or jwt or get_yyds_jwt()
    headers = {}
    if temp_token:
        headers["Authorization"] = f"Bearer {temp_token}"
    elif key:
        headers["X-API-Key"] = key
    resp = http_get(f"{YYDS_API_BASE}/messages/{message_id}", headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success"):
        return data.get("data", {})
    raise Exception(f"YYDS 获取邮件详情失败: {data}")


def yyds_generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def yyds_pick_domain(api_key=None, jwt=None):
    domains = yyds_get_domains(api_key=api_key, jwt=jwt)
    if not domains:
        raise Exception("YYDS 没有返回任何可用域名")
    # 仅跳过域名池冷却中的主域，不使用永久拒收黑名单
    import mail_domain_pool as mdp
    candidates = [
        d for d in domains
        if d.get("domain") and not mdp.is_domain_cooling(str(d.get("domain") or ""))
    ] or list(domains)
    if not candidates:
        raise EmailProviderUnavailable("YYDS 无可用域名（可能均在冷却）")
    private = [d for d in candidates if d.get("isVerified") and not d.get("isPublic")]
    if private:
        return pick_rotating_domain(private, "_yyds_domain_index")
    public = [d for d in candidates if d.get("isVerified") and d.get("isPublic")]
    if public:
        return pick_rotating_domain(public, "_yyds_domain_index")
    verified = [d for d in candidates if d.get("isVerified")]
    if verified:
        return pick_rotating_domain(verified, "_yyds_domain_index")
    raise Exception("YYDS 无已验证域名可用")


def yyds_get_email_and_token(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    if not token and not key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = yyds_pick_domain(api_key=key, jwt=token)
    username = yyds_generate_username(10)
    result = yyds_create_account(
        address=username, domain=domain, api_key=key, jwt=token
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = yyds_get_token(address, api_key=key, jwt=token)
    if not temp_token:
        raise Exception("获取 YYDS token 失败")
    print(f"[*] 已创建 YYDS 邮箱: {address}")
    return address, temp_token


def _yyds_is_auth_error(exc):
    """识别 YYDS HTTP 401/403（token 失效/无权限）。"""
    text = str(exc or "")
    lower = text.lower()
    if "401" in text or "403" in text:
        return True
    if "unauthorized" in lower or "forbidden" in lower:
        return True
    # curl_cffi / requests: HTTPError('401 ...') / status_code
    code = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
    try:
        if int(code) in (401, 403):
            return True
    except Exception:
        pass
    return False


def yyds_get_oai_code(
    token,
    address,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    jwt=None,
    cancel_callback=None,
    resend_callback=None,
):
    """轮询 YYDS 收件箱提取验证码。

    - 401/403：刷新 mailbox token 后重试；连续鉴权失败则快速失败（避免刷屏等满 timeout）
    - 其它瞬时错误：降噪日志（首次 + 每 N 次），继续轮询到 deadline
    """
    deadline = _now() + timeout
    seen_ids = set()
    next_resend_at = _now() + 60
    current_token = token
    auth_fail_streak = 0
    soft_fail_streak = 0
    last_list_err = ""
    token_refreshed = False
    # 刷新后仍 401 超过该次数 → 换号更快
    max_auth_fails_after_refresh = 4
    log_every_n_soft = 8

    def _log(msg):
        if log_callback:
            log_callback(msg)

    def _refresh_mailbox_token():
        nonlocal current_token, token_refreshed
        try:
            new_token = _call_yyds_get_token(address, jwt=jwt)
        except Exception as refresh_exc:
            _log(f"[!] YYDS 刷新邮箱 token 失败: {refresh_exc}")
            return False
        if not new_token:
            _log("[!] YYDS 刷新邮箱 token 返回空")
            return False
        if new_token == current_token and token_refreshed:
            return False
        current_token = new_token
        token_refreshed = True
        _log("[*] YYDS 已刷新邮箱 token，继续收信")
        return True

    while _now() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and _now() >= next_resend_at:
            try:
                resend_callback()
                _log("[*] 已触发重新发送验证码")
            except Exception as exc:
                _log(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = _now() + 60

        messages = None
        try:
            messages = _call_yyds_get_messages(address, token=current_token, jwt=jwt)
        except Exception as exc:
            err_text = str(exc)
            if _yyds_is_auth_error(exc):
                auth_fail_streak += 1
                # 首次（或尚未成功刷新过）时尝试刷新 mailbox token
                if not token_refreshed:
                    if _refresh_mailbox_token():
                        try:
                            messages = _call_yyds_get_messages(address, token=current_token, jwt=jwt)
                        except Exception as retry_exc:
                            exc = retry_exc
                            err_text = str(retry_exc)
                            messages = None
                            if _yyds_is_auth_error(retry_exc):
                                auth_fail_streak += 1
                            else:
                                soft_fail_streak += 1
                        else:
                            auth_fail_streak = 0
                            soft_fail_streak = 0
                            last_list_err = ""

                if messages is None:
                    if auth_fail_streak == 1 or auth_fail_streak % 3 == 0:
                        _log(
                            f"[Debug] YYDS list mail 401/403 "
                            f"(streak={auth_fail_streak}, refreshed={token_refreshed}): {err_text}"
                        )
                    if token_refreshed and auth_fail_streak >= max_auth_fails_after_refresh:
                        raise Exception(
                            f"YYDS 邮箱鉴权持续失败 (HTTP 401/403)，已刷新 token 仍无效: {err_text}"
                        )
                    sleep_with_cancel(poll_interval, cancel_callback)
                    continue
            else:
                soft_fail_streak += 1
                if (
                    soft_fail_streak == 1
                    or soft_fail_streak % log_every_n_soft == 0
                    or err_text != last_list_err
                ):
                    _log(f"[Debug] YYDS list mail failed (#{soft_fail_streak}): {err_text}")
                last_list_err = err_text
                sleep_with_cancel(poll_interval, cancel_callback)
                continue

        # 列表成功
        auth_fail_streak = 0
        soft_fail_streak = 0
        last_list_err = ""

        for msg in messages or []:
            msg_id = msg.get("id")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            to_addrs = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if address.lower() not in to_addrs:
                continue
            try:
                detail = _call_yyds_get_message_detail(msg_id, token=current_token, jwt=jwt)
            except Exception as exc:
                if _yyds_is_auth_error(exc) and _refresh_mailbox_token():
                    try:
                        detail = _call_yyds_get_message_detail(msg_id, token=current_token, jwt=jwt)
                    except Exception as retry_exc:
                        _log(f"[Debug] YYDS get mail detail failed: {retry_exc}")
                        continue
                else:
                    _log(f"[Debug] YYDS get mail detail failed: {exc}")
                    continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            _log(f"[Debug] YYDS mail: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                _log(f"[*] YYDS code: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"YYDS 在 {timeout}s 内未收到验证码邮件")


def generate_username(length=10):
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def normalize_rejected_email_domain(domain):
    """只规范化为精确邮箱后缀，不自动提升父域。

    例：user@07210d00.dpdns.org -> 07210d00.dpdns.org
    不会额外写入 dpdns.org / eu.org。
    """
    normalized = str(domain or "").strip().lower().lstrip("@.")
    if not normalized:
        return ""
    if "@" in normalized:
        normalized = normalized.split("@", 1)[1].strip().lower().lstrip(".")
    # 去掉尾部点
    normalized = normalized.strip(".")
    if not normalized or "." not in normalized:
        return ""
    # 过滤明显不是域名的内容
    if any(ch.isspace() for ch in normalized):
        return ""
    return normalized


def rejected_email_domain_variants(domain):
    """兼容旧调用：现在只返回精确域名集合。"""
    exact = normalize_rejected_email_domain(domain)
    return {exact} if exact else set()


def load_rejected_email_domains(force=False):
    """从 data 目录加载历史拒收域名，进程内缓存。"""
    global _rejected_email_domains
    path = get_rejected_email_domains_file()
    with _rejected_email_domains_lock:
        loaded = set()
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
                if isinstance(raw, list):
                    items = raw
                elif isinstance(raw, dict):
                    items = raw.get("domains") or raw.get("rejected") or []
                else:
                    items = []
                for item in items:
                    exact = normalize_rejected_email_domain(item)
                    if exact:
                        loaded.add(exact)
            except Exception:
                loaded = set()
        if force:
            _rejected_email_domains = loaded
        else:
            _rejected_email_domains |= loaded
        return set(_rejected_email_domains)


def save_rejected_email_domains():
    path = get_rejected_email_domains_file()
    with _rejected_email_domains_lock:
        domains = sorted(_rejected_email_domains)
    payload = {
        "updated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "domains": domains,
    }
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix=".rejected-domains-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except Exception:
                pass
    return path


def remember_rejected_email_domain(domain, log_callback=None):
    """域名被 x.ai 拒收时：只做域名池临时冷却，不写永久黑名单。

    对齐 openai-cpa：不把后缀永久写入 rejected_email_domains.json。
    """
    exact = normalize_rejected_email_domain(domain)
    if not exact:
        return set()
    try:
        note_mail_domain_outcome(
            exact, success=False, reason="discarded_email", log_callback=log_callback
        )
    except Exception:
        pass
    if log_callback:
        log_callback(f"[!] 域名被拒，仅冷却主域（不写永久黑名单）: {exact}")
    # 返回当前运行时冷却快照（兼容旧调用方期望 set）
    try:
        import mail_domain_pool as mdp

        settings = _mail_pool_settings()
        cooling = {
            row["domain"]
            for row in (mdp.runtime_summary(settings).get("domains") or [])
            if row.get("cooldown_remaining_sec", 0) > 0
        }
        return cooling
    except Exception:
        return {exact}


def is_email_domain_rejected(domain):
    """精确匹配黑名单。

    - 存的是 07210d00.dpdns.org 时，只跳过这个后缀
    - 若将来主域 dpdns.org 自己也被拒并写入，则 foo.dpdns.org 会因后缀命中而跳过
    """
    load_rejected_email_domains()
    normalized = normalize_rejected_email_domain(domain)
    if not normalized:
        return False
    with _rejected_email_domains_lock:
        if normalized in _rejected_email_domains:
            return True
        # 仅当黑名单里显式存在父域时，才拦截其子域
        for rejected in _rejected_email_domains:
            if normalized.endswith("." + rejected):
                return True
    return False


def list_rejected_email_domains():
    load_rejected_email_domains()
    with _rejected_email_domains_lock:
        return sorted(_rejected_email_domains)


def _rotator_namespace():
    """Prefer facade module globals so monkeypatch on ``reg._yyds_domain_index`` works."""
    import sys

    reg = sys.modules.get("grok_register_ttk")
    if reg is not None:
        return vars(reg)
    return globals()


def pick_rotating_domain(candidates, index_name):
    if not candidates:
        return None
    ns = _rotator_namespace()
    current = int(ns.get(index_name, 0) or 0)
    domain = candidates[current % len(candidates)].get("domain")
    ns[index_name] = current + 1
    return domain


def pick_domain(api_key=None):
    domains = get_domains(api_key=api_key)
    if not domains:
        raise Exception("DuckMail 没有返回任何可用域名")
    import mail_domain_pool as mdp
    candidates = [
        d for d in domains
        if d.get("domain") and not mdp.is_domain_cooling(str(d.get("domain") or ""))
    ] or list(domains)
    if not candidates:
        raise EmailProviderUnavailable("DuckMail 无可用域名（可能均在冷却）")
    private = [d for d in candidates if d.get("ownerId")]
    verified_private = [d for d in private if d.get("isVerified")]
    if verified_private:
        return pick_rotating_domain(verified_private, "_cf_domain_index")
    public = [d for d in candidates if d.get("isVerified")]
    if public:
        return pick_rotating_domain(public, "_cf_domain_index")
    raise Exception("DuckMail 无已验证域名可用")


# ──────────────────────── CloudMail (maillab/cloud-mail) ────────────────────────
# API 前缀: /api/（所有接口均挂载在 /api/ 下）
# 认证格式: Authorization: <token>（不带 Bearer 前缀）
# 公开 token 通过 /api/public/genToken 获取（需管理员账号）

def get_cloudmail_url():
    return str(config.get("cloudmail_url", "") or "").rstrip("/")


def get_cloudmail_password():
    return config.get("cloudmail_password", "")


def get_cloudmail_admin_email():
    return str(config.get("cloudmail_admin_email", "") or "").strip()


def cloudmail_login(url, email, password):
    """POST /api/login -> JWT string"""
    resp = http_post(
        f"{url}/api/login",
        json={"email": email, "password": password},
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("code") == 200:
        token_data = data.get("data", {})
        if isinstance(token_data, dict):
            jwt = token_data.get("token")
            if jwt:
                return jwt
    raise Exception(f"CloudMail 登录失败: {str(data)[:200]}")


def cloudmail_register(url, email, password, turnstile_token=""):
    """POST /api/register -> 注册用户+账号"""
    payload = {"email": email, "password": password}
    if turnstile_token:
        payload["token"] = turnstile_token
    resp = http_post(
        f"{url}/api/register",
        json=payload,
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("code") != 200:
        raise Exception(f"CloudMail 注册失败: {data.get('message', str(data))}")
    return data


def cloudmail_gen_public_token(url, admin_email, admin_password):
    """POST /api/public/genToken -> 公开 API token (UUID)"""
    resp = http_post(
        f"{url}/api/public/genToken",
        json={"email": admin_email, "password": admin_password},
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("code") == 200:
        token_data = data.get("data", {})
        if isinstance(token_data, dict):
            return token_data.get("token")
    raise Exception(f"CloudMail 获取公开 token 失败: {str(data)[:200]}")


def cloudmail_public_email_list(url, public_token, to_email="", size=20):
    """POST /api/public/emailList -> 公开邮件查询（需公开 token，Authorization: <token>）"""
    payload = {"size": size}
    if to_email:
        payload["toEmail"] = to_email
    resp = http_post(
        f"{url}/api/public/emailList",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": public_token,
        },
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        if data.get("code") == 200:
            return data.get("data", [])
        raise Exception(f"CloudMail 邮件查询失败: {data.get('message', str(data))}")
    return []


def _cloudmail_get_shared_token(force_refresh=False):
    """获取或刷新共享的公开 token（线程安全单例）"""
    global _cloudmail_public_token
    with _cloudmail_public_token_lock:
        if _cloudmail_public_token and not force_refresh:
            return _cloudmail_public_token
        url = get_cloudmail_url()
        admin_email = get_cloudmail_admin_email()
        admin_password = get_cloudmail_password()
        if not url or not admin_email or not admin_password:
            raise Exception("CloudMail 配置不完整")
        token = cloudmail_gen_public_token(url, admin_email, admin_password)
        if not token:
            raise Exception("CloudMail 公开 token 为空")
        _cloudmail_public_token = token
        return token


def cloudmail_get_oai_code(
    dev_token,
    email,
    timeout=300,
    poll_interval=5,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    url = get_cloudmail_url()
    if not url:
        raise Exception("CloudMail URL 未配置")
    # 获取共享公开 token（所有线程共用同一个，避免并发覆盖）
    try:
        public_token = _cloudmail_get_shared_token()
    except Exception as exc:
        raise Exception(f"CloudMail 获取公开 token 失败: {exc}")
    if log_callback:
        log_callback("[Debug] CloudMail 公开 token 获取成功")
    deadline = _now() + timeout
    seen_attempts = {}
    next_resend_at = _now() + 60
    start_time = _now()
    while _now() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and _now() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = _now() + 60
        # 动态轮询间隔：前 30 秒用 2 秒，之后用 5 秒
        elapsed = _now() - start_time
        current_interval = 2 if elapsed < 30 else poll_interval
        # 用完整邮箱地址查询（公开 API 的 toEmail 需要完整地址）
        try:
            messages = cloudmail_public_email_list(url, public_token, to_email=email, size=20)
        except Exception as exc:
            err_msg = str(exc)
            if log_callback:
                log_callback(f"[Debug] CloudMail 邮件查询失败: {err_msg}")
            # token 失效时，刷新共享 token（加锁，多线程只刷新一次）
            if "token" in err_msg.lower() or "401" in err_msg:
                try:
                    public_token = _cloudmail_get_shared_token(force_refresh=True)
                    if log_callback:
                        log_callback("[Debug] CloudMail 公开 token 已刷新")
                except Exception:
                    pass
            sleep_with_cancel(current_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] CloudMail 本轮邮件数量: {len(messages)}")
        for msg in messages:
            msg_id = msg.get("emailId") or msg.get("id") or msg.get("messageId")
            if not msg_id:
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            # 提取邮件内容（公开接口返回 content 字段，为完整 HTML）
            parts = []
            for field in ("content", "text", "textContent", "text_content", "body", "snippet", "intro"):
                value = msg.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            html_val = msg.get("html") or msg.get("htmlContent") or msg.get("html_content")
            if isinstance(html_val, str):
                parts.append(re.sub(r"<[^>]+>", " ", html_val))
            elif isinstance(html_val, list):
                for h in html_val:
                    if isinstance(h, str):
                        parts.append(re.sub(r"<[^>]+>", " ", h))
            subject = str(msg.get("subject", "") or "")
            combined = "\n".join(parts)
            if log_callback:
                log_callback(f"[Debug] CloudMail 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] CloudMail 从邮件中提取到验证码: {code}")
                return code
            elif log_callback:
                log_callback(f"[Debug] 邮件已解析但未提取到验证码 id={msg_id} attempt={seen_attempts[msg_id]}")
        sleep_with_cancel(current_interval, cancel_callback)
    raise Exception(f"CloudMail 在 {timeout}s 内未收到验证码邮件")


# ──────────────────────── 公共邮箱工具 ────────────────────────

def get_email_provider():
    provider = str(config.get("email_provider") or "duckmail").strip().lower() or "duckmail"
    if provider not in _EMAIL_PROVIDERS:
        # 运行期兜底：不要把未知值当 duckmail 用
        raise Exception(
            f"未知邮箱服务商: {provider!r}（请在配置里选 duckmail/yyds/cloudflare/cloudmail）"
        )
    return provider


def _is_transient_http_error(exc):
    """403/429/502/503/504/超时等可重试错误（邮箱站限流常见 403）。"""
    text = str(exc or "")
    low = text.lower()
    if any(code in text for code in ("403", "429", "502", "503", "504")):
        return True
    if any(
        k in low
        for k in (
            "timeout",
            "timed out",
            "temporarily",
            "bad gateway",
            "gateway",
            "forbidden",
            "rate",
            "too many",
        )
    ):
        return True
    code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    try:
        if int(code) in {403, 429, 502, 503, 504}:
            return True
    except Exception:
        pass
    resp = getattr(exc, "response", None)
    try:
        if resp is not None and int(getattr(resp, "status_code", 0) or 0) in {
            403,
            429,
            502,
            503,
            504,
        }:
            return True
    except Exception:
        pass
    return False


def _get_email_and_token_once(api_key=None):
    provider = get_email_provider()
    if provider == "yyds":
        return yyds_get_email_and_token(api_key=api_key, jwt=get_yyds_jwt())
    if provider in {"cloudmail", "openai_cpa_email", "cpa_email"}:
        # catch-all / webhook 模式：本地生成地址，收信靠 webhook 或 CloudMail 公开查询
        try:
            address, main = compose_mail_address()
        except Exception as exc:
            raise Exception(f"需要配置 mail_domains/defaultDomains: {exc}") from exc
        if provider in {"openai_cpa_email", "cpa_email"} or bool(config.get("email_webhook_enabled")):
            return address, "webhook_mail"
        return address, "cloudmail_catch_all"
    if provider == "cloudflare":
        api_base = get_cloudflare_api_base()
        if not api_base:
            raise Exception("Cloudflare API Base 未配置")
        try:
            address, token = cloudflare_create_temp_address(api_base)
            return address, token
        except Exception as primary_exc:
            key = api_key or get_cloudflare_api_key()
            domains = cloudflare_get_domains(api_base, api_key=key)
            if not domains:
                raise Exception(f"Cloudflare 创建邮箱失败: {primary_exc}") from primary_exc
            # 仅跳过域名池冷却中的主域，不读永久拒收黑名单
            verified = [d for d in domains if d.get("isVerified")]
            candidates = verified or list(domains)
            filtered = []
            for d in candidates:
                root = str(d.get("domain") or "").strip()
                if root and not __import__("mail_domain_pool").is_domain_cooling(root):
                    filtered.append(d)
            candidates = filtered or candidates
            if not candidates:
                raise EmailProviderUnavailable(
                    f"Cloudflare 无可用域名（可能均在冷却）: {primary_exc}"
                )
            target = candidates[0]
            domain = target.get("domain")
            if not domain:
                raise Exception("Cloudflare 域名数据格式错误，缺少 domain 字段")
            username = generate_username(10)
            address = f"{username}@{domain}"
            password = secrets.token_urlsafe(12)
            cloudflare_create_account(
                api_base, address, password, api_key=key, expires_in=0
            )
            token = cloudflare_get_token(api_base, address, password, api_key=key)
            if not token:
                raise Exception("获取 Cloudflare 邮箱 token 失败")
            return address, token
    key = api_key or get_duckmail_api_key()
    domain = pick_domain(api_key=key)
    username = generate_username(10)
    address = f"{username}@{domain}"
    password = secrets.token_urlsafe(12)
    create_account(address, password, api_key=key, expires_in=0)
    token = get_token(address, password)
    if not token:
        raise Exception("获取 DuckMail token 失败")
    return address, token


def get_email_and_token(api_key=None, retries=3, log_callback=None):
    """创建临时邮箱；对 502/503/504 自动重试。"""
    provider = get_email_provider()
    last_exc = None
    attempts = max(1, int(retries or 1))
    for attempt in range(1, attempts + 1):
        try:
            return _get_email_and_token_once(api_key=api_key)
        except EmailProviderUnavailable:
            raise
        except EmailDomainRejected:
            raise
        except Exception as exc:
            last_exc = exc
            transient = _is_transient_http_error(exc)
            if log_callback:
                log_callback(
                    f"[!] 邮箱服务({provider}) 创建失败 "
                    f"({attempt}/{attempts}): {exc}"
                    + ("，将重试" if transient and attempt < attempts else "")
                )
            if not transient or attempt >= attempts:
                break
            # 502 时短暂退避；第二次起尝试直连邮箱 API（不走业务代理）
            time.sleep(0.8 * attempt)
            if attempt >= 2 and config.get("proxy"):
                try:
                    # 临时清空代理再试一轮邮箱（很多 502 是代理对邮箱站的网关错误）
                    old_proxy = config.get("proxy")
                    config["proxy"] = ""
                    try:
                        return _get_email_and_token_once(api_key=api_key)
                    finally:
                        config["proxy"] = old_proxy
                except Exception as exc2:
                    last_exc = exc2
                    if not _is_transient_http_error(exc2):
                        break
    raise Exception(
        f"邮箱服务({provider}) 创建失败: {last_exc}。"
        "若为 HTTP 502/503，一般是邮箱站或代理网关临时故障，稍后重试即可"
    ) from last_exc


def webhook_get_oai_code(
    email,
    timeout=180,
    poll_interval=2,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    """从 openai-cpa-email webhook 内存池取验证码。"""
    import webhook_mail_store as wms

    deadline = _now() + max(30, float(timeout or 180))
    next_resend_at = _now() + 60
    if log_callback:
        log_callback(f"[*] webhook 收件池等待验证码: {email}")
    while _now() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and _now() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = _now() + 60
        code = wms.pop_code_for_email(
            email,
            extract_fn=lambda raw: extract_verification_code(raw, "") or wms.extract_xai_code_from_raw(raw),
        )
        if code:
            if log_callback:
                log_callback(f"[*] webhook 收件池提取到验证码: {code}")
            return code
        sleep_with_cancel(max(1.0, float(poll_interval or 2)), cancel_callback)
    raise Exception(f"webhook 收件池在 {int(timeout)}s 内未收到验证码邮件")


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    """按当前邮箱服务商收验证码。

    webhook 仅用于：
    - provider=openai_cpa_email / cpa_email
    - 或本号建号 token 明确是 webhook_mail

    注意：配置里的 email_webhook_enabled 只是「允许 webhook 收件」，
    不能在 yyds/duckmail/cloudflare 时抢占收信路径。
    """
    provider = get_email_provider()
    token_hint = str(dev_token or "").strip()

    use_webhook = provider in {"openai_cpa_email", "cpa_email"} or token_hint == "webhook_mail"
    if use_webhook:
        if log_callback and provider not in {"openai_cpa_email", "cpa_email"}:
            log_callback(
                f"[!] 邮箱 token=webhook_mail，但 provider={provider}；仍按 webhook 收信"
            )
        return webhook_get_oai_code(
            email,
            timeout=timeout,
            poll_interval=min(2, float(poll_interval or 2)),
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )

    # 建号 token 类型与 provider 不一致时，按 token 纠偏
    if token_hint == "cloudmail_catch_all" and provider != "cloudmail":
        if log_callback:
            log_callback(
                f"[!] 邮箱 token 为 cloudmail_catch_all，但 provider={provider}，按 cloudmail 收信"
            )
        provider = "cloudmail"

    if provider == "yyds":
        if log_callback:
            log_callback(f"[*] 收信通道: YYDS（provider=yyds）")
        return yyds_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            jwt=get_yyds_jwt(),
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "cloudmail":
        if log_callback:
            log_callback(f"[*] 收信通道: CloudMail（provider=cloudmail）")
        return cloudmail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "cloudflare":
        if log_callback:
            log_callback(f"[*] 收信通道: Cloudflare temp-email（provider=cloudflare）")
        return cloudflare_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider != "duckmail":
        raise Exception(f"邮箱服务商 {provider!r} 无对应收信实现")
    if log_callback:
        log_callback(f"[*] 收信通道: DuckMail（provider=duckmail）")
    return duckmail_get_oai_code(
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )

def extract_verification_code(text, subject=""):
    if subject:
        match = re.search(r"^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI", subject, re.IGNORECASE)
        if match:
            return match.group(1)
    match = re.search(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", text, re.IGNORECASE)
    if match:
        return match.group(1)
    patterns = [
        r"verification\s+code[:\s]+(\d{4,8})",
        r"your\s+code[:\s]+(\d{4,8})",
        r"confirm(?:ation)?\s+code[:\s]+(\d{4,8})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def duckmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    deadline = _now() + timeout
    seen_ids = set()
    auth_fail_streak = 0
    soft_fail_streak = 0
    last_err = ""
    while _now() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            messages = get_messages(dev_token)
            auth_fail_streak = 0
            soft_fail_streak = 0
            last_err = ""
        except Exception as exc:
            err_text = str(exc)
            is_auth = "401" in err_text or "403" in err_text or "unauthorized" in err_text.lower()
            if is_auth:
                auth_fail_streak += 1
                if auth_fail_streak == 1 or auth_fail_streak % 4 == 0:
                    if log_callback:
                        log_callback(
                            f"[Debug] DuckMail list mail 401/403 "
                            f"(streak={auth_fail_streak}): {err_text}"
                        )
                # token 无效时再刷也没用，快速失败换号
                if auth_fail_streak >= 5:
                    raise Exception(
                        f"DuckMail 邮箱鉴权持续失败 (HTTP 401/403): {err_text}"
                    )
            else:
                soft_fail_streak += 1
                if (
                    soft_fail_streak == 1
                    or soft_fail_streak % 8 == 0
                    or err_text != last_err
                ):
                    if log_callback:
                        log_callback(
                            f"[Debug] DuckMail list mail failed (#{soft_fail_streak}): {err_text}"
                        )
                last_err = err_text
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            if email.lower() not in recipients:
                continue
            try:
                detail = get_message_detail(dev_token, msg_id)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] DuckMail get mail detail failed: {exc}")
                continue
            parts = []
            text_body = detail.get("text") or ""
            if text_body:
                parts.append(text_body)
            html_list = detail.get("html") or []
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            combined = "\n".join(parts)
            subject = detail.get("subject", "")
            if log_callback:
                log_callback(f"[Debug] DuckMail mail: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] DuckMail code: {code}")
                return code
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"在 {timeout}s 内未收到验证码邮件")


def cloudflare_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    api_base = get_cloudflare_api_base()
    if not api_base:
        raise Exception("Cloudflare API Base 未配置")
    deadline = _now() + timeout
    # 同一封邮件正文可能延迟可读，允许多次重试解析，避免偶发漏码
    seen_attempts = {}
    next_resend_at = _now() + 35
    while _now() < deadline:
        raise_if_cancelled(cancel_callback)
        if resend_callback and _now() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = _now() + 35
        try:
            messages = cloudflare_get_messages(api_base, dev_token)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Cloudflare 拉取邮件列表失败: {exc}")
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        if log_callback:
            log_callback(f"[Debug] Cloudflare 本轮邮件数量: {len(messages)}")

        for msg in messages:
            msg_id = msg.get("id") or msg.get("msgid")
            if not msg_id:
                continue
            attempt = int(seen_attempts.get(msg_id, 0))
            if attempt >= 5:
                continue
            seen_attempts[msg_id] = attempt + 1
            recipients = [t.get("address", "").lower() for t in (msg.get("to") or [])]
            msg_addr = str(msg.get("address", "")).lower()
            # 优先匹配目标邮箱；若结构不一致也允许继续解析，避免接口字段漂移导致漏码
            address_matched = True
            if recipients:
                address_matched = email.lower() in recipients
            elif msg_addr:
                address_matched = msg_addr == email.lower()
            if not address_matched and log_callback:
                log_callback(f"[Debug] 跳过疑似非目标邮件 id={msg_id} address={msg_addr} to={recipients}")
                continue
            parts = []
            # 先直接从列表项取内容，避免 detail 接口差异导致漏码
            for field in ("text", "raw", "content", "intro", "body", "snippet"):
                value = msg.get(field)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
            html_list = msg.get("html") or []
            if isinstance(html_list, str):
                html_list = [html_list]
            for h in html_list:
                parts.append(re.sub(r"<[^>]+>", " ", h))
            subject = str(msg.get("subject", "") or "")
            combined = "\n".join(parts)
            # 再尝试 detail 接口补全内容
            try:
                detail = cloudflare_get_message_detail(api_base, dev_token, msg_id)
                for field in ("text", "raw", "content", "intro", "body", "snippet"):
                    value = detail.get(field)
                    if isinstance(value, str) and value.strip():
                        combined += "\n" + value
                html_list2 = detail.get("html") or []
                if isinstance(html_list2, str):
                    html_list2 = [html_list2]
                for h in html_list2:
                    combined += "\n" + re.sub(r"<[^>]+>", " ", h)
                if not subject:
                    subject = str(detail.get("subject", "") or "")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] Cloudflare detail接口失败，改用列表内容解析: {exc}")
            if log_callback:
                log_callback(f"[Debug] Cloudflare 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] Cloudflare 从邮件中提取到验证码: {code}")
                return code
            elif log_callback:
                log_callback(f"[Debug] 邮件已解析但未提取到验证码 id={msg_id} attempt={seen_attempts[msg_id]}")
        sleep_with_cancel(poll_interval, cancel_callback)
    raise Exception(f"Cloudflare 在 {timeout}s 内未收到验证码邮件")


