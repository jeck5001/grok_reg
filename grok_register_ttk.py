#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Grok 注册机 - TTK GUI 版本
整合 DrissionPage_example.py, openai_register.py, batch_open_nsfw.py
"""

import threading
import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
import queue
import secrets
import struct
import random
import re
import string
import tempfile
import json
import uuid
import subprocess
import hashlib
import base64
import urllib.parse
import io
import zipfile

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
except ImportError:
    tk = None
    ttk = None
    messagebox = None
    scrolledtext = None

try:
    from DrissionPage import Chromium, ChromiumOptions
    from DrissionPage.errors import PageDisconnectedError
except ModuleNotFoundError:
    Chromium = None
    ChromiumOptions = None

    class PageDisconnectedError(Exception):
        pass

try:
    from curl_cffi import CurlMime, requests
except ModuleNotFoundError:
    CurlMime = None
    requests = None

from core.exceptions import (
    EmailDomainRejected,
    EmailProviderUnavailable,
    ProfileSessionLost,
    RegistrationCancelled,
    StaleNextActionError,
)
from core.paths import (
    APP_DIR,
    get_account_status_file,
    get_config_file,
    get_data_dir,
    get_rejected_email_domains_file,
)
from core.runtime import (
    _env_truthy,
    normalize_proxy_for_runtime,
    should_apply_container_chrome_flags,
    should_run_headless,
)
from core.config import (
    DEFAULT_CONFIG,
    _EMAIL_PROVIDERS,
    _parse_positive_int,
    config,
    load_config,
    replace_config,
    save_config,
    validate_registration_config,
)
from core.accounts.store import (
    _ACCOUNT_FILE_TS_RE,
    _account_id,
    _account_list_cache,
    _account_list_cache_lock,
    _account_matches_filter,
    _account_search_haystack,
    _account_sort_key,
    _account_status_by_email_index,
    _account_status_cache,
    _account_status_lock,
    _accounts_files_signature,
    _extract_sub2api_account_id,
    _extract_sub2api_remote_id_from_item,
    _file_mtime_ns,
    _mask_token,
    _normalize_sso_token,
    _registered_accounts_lock,
    _sub2api_error_text,
    _write_registered_account_lines,
    account_health_status_text,
    account_status_text,
    attach_account_status,
    delete_registered_accounts,
    find_registered_accounts,
    invalidate_account_list_cache,
    is_account_blocked_error,
    is_refresh_token_revoked_error,
    is_xai_refresh_token_client_error,
    list_registered_accounts,
    load_account_statuses,
    parse_account_file_created_at,
    parse_registered_account_line,
    persist_account_created_at,
    persist_account_health_status,
    persist_cpa_push_status,
    persist_grok2api_push_status,
    persist_sub2api_push_status,
    query_registered_accounts,
    replace_registered_account_refresh_token,
    save_account_statuses,
    update_account_status_records,
)
from core.http_client import (
    _build_request_kwargs,
    get_proxies,
    http_delete,
    http_get,
    http_post,
)
from core.cancel import raise_if_cancelled, sleep_with_cancel
from core.email.providers import (
    DUCKMAIL_API_BASE,
    YYDS_API_BASE,
    _cf_domain_index,
    _cloudmail_public_token,
    _cloudmail_public_token_lock,
    _get_email_and_token_once,
    _is_transient_http_error,
    _mail_pool_settings,
    _pick_list_payload,
    _rejected_email_domains,
    _rejected_email_domains_lock,
    _yyds_domain_index,
    _yyds_is_auth_error,
    cloudflare_apply_auth_params,
    cloudflare_build_headers,
    cloudflare_create_account,
    cloudflare_create_temp_address,
    cloudflare_get_domains,
    cloudflare_get_message_detail,
    cloudflare_get_messages,
    cloudflare_get_oai_code,
    cloudflare_get_token,
    cloudmail_gen_public_token,
    cloudmail_get_oai_code,
    cloudmail_login,
    cloudmail_public_email_list,
    cloudmail_register,
    compose_mail_address,
    create_account,
    duckmail_get_oai_code,
    extract_verification_code,
    generate_username,
    get_cloudflare_api_base,
    get_cloudflare_api_key,
    get_cloudflare_auth_mode,
    get_cloudflare_path,
    get_cloudmail_admin_email,
    get_cloudmail_password,
    get_cloudmail_url,
    get_domains,
    get_duckmail_api_key,
    get_email_and_token,
    get_email_provider,
    get_message_detail,
    get_messages,
    get_oai_code,
    get_token,
    get_yyds_api_key,
    get_yyds_jwt,
    is_email_domain_rejected,
    list_rejected_email_domains,
    load_rejected_email_domains,
    normalize_rejected_email_domain,
    note_mail_domain_outcome,
    pick_configured_mail_domain,
    pick_domain,
    pick_rotating_domain,
    rejected_email_domain_variants,
    remember_rejected_email_domain,
    save_rejected_email_domains,
    webhook_get_oai_code,
    yyds_create_account,
    yyds_generate_username,
    yyds_get_domains,
    yyds_get_email_and_token,
    yyds_get_message_detail,
    yyds_get_messages,
    yyds_get_oai_code,
    yyds_get_token,
    yyds_pick_domain,
)
from core.turnstile.solver import (
    _TURNSTILE_SITEKEY_RE,
    _is_transient_solver_transport_error,
    _proxy_for_turnstile_solver,
    _redact_proxy_for_log,
    _solver_http_json,
    _turnstile_solver_fail_until,
    _turnstile_solver_probe_cache,
    _turnstile_solver_sem,
    getTurnstileToken,
    inject_turnstile_token_to_page,
    normalize_turnstile_solver_url,
    probe_local_turnstile_solver,
    scrape_turnstile_context_from_page,
    scrape_turnstile_sitekey_text,
    solve_turnstile_via_local_solver,
)
from core.xai.protocol import (
    SIGNUP_URL,
    _NEXT_ACTION_CACHE,
    _NEXT_ACTION_CACHE_LOCK,
    _NEXT_ACTION_CACHE_TTL,
    _NEXT_ACTION_CHUNK_HINTS,
    _RSC_PUSH_RE,
    _collect_set_cookie_hop_urls,
    _cookie_header_from_list,
    _default_router_state_tree_header,
    _extract_any_sso_from_set_cookies,
    _grpc_decode_fields,
    _grpc_encode_bytes,
    _grpc_encode_string,
    _grpc_encode_varint,
    _grpc_frame_request,
    _grpc_parse_response,
    _html_action_signature,
    _load_next_action_disk_cache,
    _looks_like_sso_session_jwt,
    _next_action_cache_path,
    _normalize_rsc_text,
    _normalize_set_cookie_hop_url,
    _parse_jwt_payload,
    _save_next_action_disk_cache,
    _solve_turnstile_quiet,
    _xai_grpc_call,
    _xai_http_session,
    create_xai_account_via_http,
    encode_create_session_request,
    export_browser_cookies,
    extract_signup_hard_error,
    extract_sso_from_http_result,
    extract_sso_via_set_cookie_chain,
    invalidate_next_action_cache,
    obtain_sso_via_create_session,
    register_via_api_after_otp,
    register_via_pure_http,
    resolve_signup_mode,
    scrape_signup_next_headers,
)
from core.browser.lifecycle import (
    EXTENSION_PATH,
    TURNSTILE_PAGE_HOOK_PATH,
    _browser_launch_semaphore,
    _get_browser,
    _get_page,
    _set_browser,
    _set_page,
    _thread_ctx,
    _xvfb_lock,
    _xvfb_process,
    _click_turnstile_challenge_if_visible,
    _click_turnstile_via_shadow_dom,
    _dispatch_cdp_click,
    _dispatch_cdp_keypress,
    _dispatch_cdp_text,
    _fill_otp_code_native,
    _click_otp_submit_native,
    _click_point_on_page,
    _locate_turnstile_box_on_page,
    _locate_turnstile_target_via_cdp,
    _locate_turnstile_target_via_js,
    _parse_element_rect,
    _read_turnstile_token_from_page,
    _safe_element_click,
    _cdp_click_element_left,
    _cdp_click_page_box_left,
    _is_page_absolute_turnstile_rect,
    _turnstile_page_hook_source_cache,
    click_email_signup_button,
    create_browser_options,
    ensure_virtual_display,
    fill_code_and_submit,
    fill_email_and_submit,
    fill_profile_and_submit,
    has_profile_form,
    humanize_page_activity,
    install_light_stealth_script,
    install_turnstile_page_hook,
    open_signup_page,
    override_user_agent_for_docker,
    probe_browser_stealth,
    read_turnstile_token_len,
    refresh_active_page,
    restart_browser,
    start_browser,
    stop_browser,
    turnstile_page_hook_source,
    wait_for_sso_cookie,
    build_profile,
    _click_xai_oauth_consent_if_present,
)
from core.push.integrations import (
    CurlMime,
    XAI_GROK_OAUTH_CLIENT_ID,
    XAI_GROK_OAUTH_AUTHORIZE_URL,
    XAI_GROK_OAUTH_TOKEN_URL,
    XAI_GROK_OAUTH_SCOPE,
    XAI_GROK_OAUTH_REDIRECT_URI,
    XAI_GROK_API_BASE_URL,
    XAI_GROK_CLI_CHAT_BASE_URL,
    CPA_DEFAULT_BASE_URL,
    CPA_CLIENT_HEADERS,
    resolve_grok2api_local_token_file,
    import_accounts_to_grok2api,
    import_accounts_to_sub2api,
    probe_accounts_on_sub2api,
    delete_accounts_from_sub2api,
    check_registered_accounts_health,
    auto_push_registered_account,
    add_token_to_grok2api_local_pool,
    add_token_to_grok2api_remote_pool,
    add_token_to_grok2api_pools,
    build_xai_oauth_authorize_url,
    parse_xai_oauth_callback_url,
    build_xai_oauth_consent_click_script,
    save_xai_oauth_debug_snapshot,
    set_xai_sso_cookies_for_oauth,
    exchange_xai_oauth_code_for_token,
    exchange_xai_refresh_token,
    normalize_cpa_management_auth_files_url,
    export_and_push_cpa_credential,
    build_native_account_export_line,
    build_grok2api_export_payload,
    build_sub2api_export_account,
    build_cpa_export_payload,
    export_accounts_zip,
    import_accounts_to_cpa,
    exchange_sso_to_refresh_token_via_device_flow,
    fetch_xai_oauth_refresh_token,
    _parse_int_list,
    _optional_positive_int,
    _base64_urlsafe_no_padding,
)







CONFIG_FILE = get_config_file()

def ensure_stable_python_runtime():
    if sys.version_info < (3, 14) or os.environ.get("DPE_REEXEC_DONE") == "1":
        return

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, "Programs", "Python", "Python312", "python.exe"),
        os.path.join(local_app_data, "Programs", "Python", "Python313", "python.exe"),
    ]

    current_python = os.path.normcase(os.path.abspath(sys.executable))
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        if os.path.normcase(os.path.abspath(candidate)) == current_python:
            return

        print(
            f"[*] 检测到 Python {sys.version.split()[0]}，自动切换到更稳定的解释器: {candidate}"
        )
        env = os.environ.copy()
        env["DPE_REEXEC_DONE"] = "1"
        os.execve(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]], env)


def warn_runtime_compatibility():
    if sys.version_info >= (3, 14):
        print(
            "[提示] 当前 Python 为 3.14+；若出现 Mail.tm TLS 异常，建议改用 Python 3.12 或 3.13。"
        )


ensure_stable_python_runtime()
warn_runtime_compatibility()

load_config()

def get_cf_global_email(settings=None):
    src = settings if isinstance(settings, dict) else config
    return str((src or {}).get("cf_api_email") or "").strip()


def get_cf_global_api_key(settings=None):
    src = settings if isinstance(settings, dict) else config
    return str((src or {}).get("cf_api_key") or "").strip()


def cf_global_auth_headers(settings=None, content_type=True):
    """Cloudflare 官方 v4 全局鉴权头：X-Auth-Email + X-Auth-Key（Global API Key）。"""
    email = get_cf_global_email(settings)
    key = get_cf_global_api_key(settings)
    if not email or not key:
        raise ValueError("未配置 Cloudflare 全局身份鉴权：请填写 CF 登录账号 + Global API Key")
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": key,
    }
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def _cf_global_request(
    method,
    path,
    settings=None,
    params=None,
    json_body=None,
    files=None,
    timeout=30,
    content_type=True,
):
    """调用 https://api.cloudflare.com/client/v4/...

    files 为 multipart 时不要带 Content-Type（由客户端生成 boundary）。
    """
    if requests is None:
        raise RuntimeError("curl_cffi 未安装，无法请求 Cloudflare API")
    url = f"https://api.cloudflare.com/client/v4{path}"
    use_ct = bool(content_type) and not files
    headers = cf_global_auth_headers(settings=settings, content_type=use_ct)
    kwargs = _build_request_kwargs(headers=headers, timeout=timeout, proxies=get_proxies() or {})
    if params:
        kwargs["params"] = params
    if files is not None:
        kwargs["files"] = files
    elif json_body is not None:
        kwargs["json"] = json_body
    method = str(method or "GET").upper()
    if method == "GET":
        resp = requests.get(url, **kwargs)
    elif method == "POST":
        resp = requests.post(url, **kwargs)
    elif method == "PUT":
        if hasattr(requests, "put"):
            resp = requests.put(url, **kwargs)
        else:
            # curl_cffi 无 put 时退化
            resp = requests.post(url, **kwargs)
    elif method == "DELETE":
        resp = http_delete(url, **kwargs)
    else:
        raise ValueError(f"unsupported method: {method}")
    try:
        data = resp.json()
    except Exception:
        data = {"success": False, "errors": [{"message": (getattr(resp, "text", "") or "")[:300]}]}
    if not isinstance(data, dict):
        data = {"success": False, "errors": [{"message": "non-json response"}], "raw": data}
    data.setdefault("http_status", int(getattr(resp, "status_code", 0) or 0))
    return data


def test_cf_global_auth(settings=None, log_callback=None):
    """验证 Global API Key：GET /accounts + /user。"""
    settings = {**config, **dict(settings or {})}
    email = get_cf_global_email(settings)
    if not email:
        return {"ok": False, "message": "未填写 CF 登录账号（cf_api_email）"}
    if not get_cf_global_api_key(settings):
        return {"ok": False, "message": "未填写 Global API Key（cf_api_key）"}
    try:
        user = _cf_global_request("GET", "/user", settings=settings, timeout=20)
        if not user.get("success"):
            errs = user.get("errors") or []
            msg = "; ".join(str(e.get("message") or e) for e in errs if e) or f"HTTP {user.get('http_status')}"
            return {"ok": False, "message": f"鉴权失败: {msg}", "response": user}
        accounts = _cf_global_request("GET", "/accounts", settings=settings, timeout=20)
        acc_list = accounts.get("result") if isinstance(accounts.get("result"), list) else []
        user_info = user.get("result") if isinstance(user.get("result"), dict) else {}
        result = {
            "ok": True,
            "message": f"鉴权成功：{user_info.get('email') or email}，账户 {len(acc_list)} 个",
            "user": {
                "id": user_info.get("id"),
                "email": user_info.get("email") or email,
            },
            "accounts": [
                {"id": a.get("id"), "name": a.get("name")}
                for a in acc_list[:20]
                if isinstance(a, dict)
            ],
        }
        if log_callback:
            log_callback(f"[+] Cloudflare 全局鉴权 OK: {result['message']}")
        return result
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


def list_cf_zones(domains=None, settings=None):
    """查询域名是否在 CF 账号中。domains: 逗号串或列表；空则只测连通。"""
    settings = {**config, **dict(settings or {})}
    if isinstance(domains, str):
        domain_list = [d.strip().lower().lstrip("@.") for d in domains.split(",") if d.strip()]
    else:
        domain_list = [str(d).strip().lower().lstrip("@.") for d in (domains or []) if str(d).strip()]
    if not domain_list:
        # 从 mail_domains 取
        raw = str(settings.get("mail_domains") or settings.get("defaultDomains") or "")
        domain_list = [d.strip().lower().lstrip("@.") for d in raw.split(",") if d.strip()]
    results = []
    for domain in domain_list[:50]:
        data = _cf_global_request(
            "GET",
            "/zones",
            settings=settings,
            params={"name": domain, "per_page": 5},
            timeout=20,
        )
        items = data.get("result") if isinstance(data.get("result"), list) else []
        if data.get("success") and items:
            z = items[0]
            results.append(
                {
                    "domain": domain,
                    "found": True,
                    "zone_id": z.get("id"),
                    "status": z.get("status"),
                    "name_servers": z.get("name_servers") or [],
                    "paused": bool(z.get("paused")),
                }
            )
        else:
            errs = data.get("errors") or []
            results.append(
                {
                    "domain": domain,
                    "found": False,
                    "zone_id": "",
                    "status": "not_found",
                    "name_servers": [],
                    "error": "; ".join(str(e.get("message") or e) for e in errs if e)
                    if errs
                    else "",
                }
            )
    return {"ok": True, "total": len(results), "items": results}


def ensure_cf_zones(domains, settings=None, log_callback=None):
    """把域名加到 CF 托管（已存在则返回 NS）。对齐 openai-cpa add_zones。"""
    settings = {**config, **dict(settings or {})}
    if isinstance(domains, str):
        domain_list = [d.strip().lower().lstrip("@.") for d in domains.split(",") if d.strip()]
    else:
        domain_list = [str(d).strip().lower().lstrip("@.") for d in (domains or []) if str(d).strip()]
    if not domain_list:
        raise ValueError("请提供要托管的域名")

    acc = _cf_global_request("GET", "/accounts", settings=settings, timeout=20)
    if not acc.get("success") or not (acc.get("result") or []):
        errs = acc.get("errors") or []
        raise RuntimeError(
            f"无法获取 CF Account ID: "
            + ("; ".join(str(e.get("message") or e) for e in errs if e) or "empty")
        )
    account_id = acc["result"][0].get("id")
    items = []
    for domain in domain_list:
        check = _cf_global_request(
            "GET",
            "/zones",
            settings=settings,
            params={"name": domain, "per_page": 5},
            timeout=20,
        )
        existing = check.get("result") if isinstance(check.get("result"), list) else []
        if check.get("success") and existing:
            z = existing[0]
            item = {
                "domain": domain,
                "status": z.get("status"),
                "zone_id": z.get("id"),
                "name_servers": z.get("name_servers") or [],
                "msg": "已托管",
                "created": False,
            }
            items.append(item)
            if log_callback:
                log_callback(f"[*] CF zone 已存在: {domain} ns={','.join(item['name_servers'][:2])}")
            continue
        add = _cf_global_request(
            "POST",
            "/zones",
            settings=settings,
            json_body={
                "name": domain,
                "account": {"id": account_id},
                "type": "full",
                "jump_start": True,
            },
            timeout=40,
        )
        if add.get("success") and isinstance(add.get("result"), dict):
            z = add["result"]
            item = {
                "domain": domain,
                "status": z.get("status"),
                "zone_id": z.get("id"),
                "name_servers": z.get("name_servers") or [],
                "msg": "已添加，请到注册商改 NS",
                "created": True,
            }
            items.append(item)
            if log_callback:
                log_callback(
                    f"[+] CF zone 已添加: {domain} → NS {', '.join(item['name_servers'][:4])}"
                )
        else:
            errs = add.get("errors") or []
            msg = "; ".join(str(e.get("message") or e) for e in errs if e) or "unknown"
            items.append(
                {
                    "domain": domain,
                    "status": "error",
                    "zone_id": "",
                    "name_servers": [],
                    "msg": msg,
                    "created": False,
                }
            )
            if log_callback:
                log_callback(f"[!] CF zone 添加失败 {domain}: {msg}")
        time.sleep(0.3)
    ok_n = len([i for i in items if i.get("status") != "error"])
    return {"ok": ok_n == len(items), "total": ok_n, "failed": len(items) - ok_n, "items": items}


def ensure_cf_email_routing_dns(domains, settings=None, log_callback=None):
    """为域名补齐 Email Routing 所需的通配 MX + SPF TXT（对齐 openai-cpa add_wildcard_dns）。"""
    settings = {**config, **dict(settings or {})}
    if isinstance(domains, str):
        domain_list = [d.strip().lower().lstrip("@.") for d in domains.split(",") if d.strip()]
    else:
        domain_list = [str(d).strip().lower().lstrip("@.") for d in (domains or []) if str(d).strip()]
    if not domain_list:
        raise ValueError("请提供域名")

    records_template = (
        {"type": "MX", "name": "*", "content": "route3.mx.cloudflare.net", "priority": 36},
        {"type": "MX", "name": "*", "content": "route2.mx.cloudflare.net", "priority": 25},
        {"type": "MX", "name": "*", "content": "route1.mx.cloudflare.net", "priority": 51},
        {
            "type": "TXT",
            "name": "*",
            "content": '"v=spf1 include:_spf.mx.cloudflare.net ~all"',
        },
    )
    items = []
    for domain in domain_list:
        zone_q = _cf_global_request(
            "GET",
            "/zones",
            settings=settings,
            params={"name": domain, "per_page": 5},
            timeout=20,
        )
        zones = zone_q.get("result") if isinstance(zone_q.get("result"), list) else []
        if not zone_q.get("success") or not zones:
            items.append({"domain": domain, "ok": False, "msg": "zone 不存在，请先托管到 CF"})
            if log_callback:
                log_callback(f"[!] CF Email DNS 跳过 {domain}: zone 不存在")
            continue
        zone_id = zones[0].get("id")
        created = 0
        skipped = 0
        errors = []
        for rec in records_template:
            body = dict(rec)
            body["name"] = f"{rec['name']}.{domain}" if rec["name"] != "@" else domain
            # Cloudflare 接受 name=* 相对 zone
            body["name"] = rec["name"]
            resp = _cf_global_request(
                "POST",
                f"/zones/{zone_id}/dns_records",
                settings=settings,
                json_body=body,
                timeout=20,
            )
            if resp.get("success"):
                created += 1
            else:
                errs = resp.get("errors") or []
                codes = {e.get("code") for e in errs if isinstance(e, dict)}
                # 81057/81058 已存在
                if codes & {81057, 81058}:
                    skipped += 1
                else:
                    errors.append(
                        "; ".join(str(e.get("message") or e) for e in errs if e) or "error"
                    )
            time.sleep(0.2)
        ok = not errors
        msg = f"created={created} skipped={skipped}"
        if errors:
            msg += f" errors={errors[:2]}"
        items.append({"domain": domain, "ok": ok, "zone_id": zone_id, "msg": msg})
        if log_callback:
            log_callback(f"[{'+' if ok else '!'}] CF Email DNS {domain}: {msg}")
    ok_n = len([i for i in items if i.get("ok")])
    return {"ok": ok_n == len(items), "total": ok_n, "failed": len(items) - ok_n, "items": items}


OPENAI_CPA_EMAIL_WORKER_RAW_URL = (
    "https://raw.githubusercontent.com/wenfxl/openai-cpa-email/refs/heads/master/worker.js"
)


def _normalize_cf_worker_name(name: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        return "openai-cpa-email"
    # CF script name: letters, numbers, underscore, hyphen
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", raw).strip("-_")
    return cleaned or "openai-cpa-email"


def get_cf_email_worker_name(settings=None) -> str:
    src = settings if isinstance(settings, dict) else config
    return _normalize_cf_worker_name((src or {}).get("cf_email_worker_name") or "openai-cpa-email")


def _cf_primary_account_id(settings=None) -> str:
    acc = _cf_global_request("GET", "/accounts", settings=settings, timeout=20)
    if not acc.get("success") or not (acc.get("result") or []):
        errs = acc.get("errors") or []
        raise RuntimeError(
            "无法获取 CF Account ID: "
            + ("; ".join(str(e.get("message") or e) for e in errs if e) or "empty")
        )
    return str(acc["result"][0].get("id") or "")


def fetch_openai_cpa_email_worker_source(timeout=30) -> str:
    """从 GitHub 拉取 openai-cpa-email worker.js 源码。"""
    if requests is None:
        raise RuntimeError("curl_cffi 未安装")
    kwargs = _build_request_kwargs(timeout=timeout, proxies=get_proxies() or {})
    resp = requests.get(OPENAI_CPA_EMAIL_WORKER_RAW_URL, **kwargs)
    code = int(getattr(resp, "status_code", 0) or 0)
    text = getattr(resp, "text", "") or ""
    if code != 200 or len(text.strip()) < 50:
        raise RuntimeError(f"拉取 worker.js 失败 HTTP {code}: {text[:200]}")
    return text.strip()


def is_private_or_local_webhook_url(url: str) -> bool:
    """Worker 无法访问内网/本机地址。"""
    raw = str(url or "").strip()
    if not raw:
        return True
    try:
        parsed = urllib.parse.urlparse(raw if "://" in raw else f"http://{raw}")
    except Exception:
        return False
    host = str(parsed.hostname or "").strip().lower()
    if not host:
        return True
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True
    if host.endswith(".local") or host.endswith(".lan"):
        return True
    # 常见内网段
    if host.startswith("10.") or host.startswith("192.168.") or host.startswith("169.254."):
        return True
    if host.startswith("172."):
        parts = host.split(".")
        try:
            second = int(parts[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    return False


def deploy_cf_email_worker(
    settings=None,
    *,
    worker_name=None,
    webhook_url=None,
    webhook_secret=None,
    force=None,
    log_callback=None,
):
    """部署 / 更新 openai-cpa-email Worker（对齐 openai-cpa deploy_worker）。

    - 默认：Worker 已存在则跳过覆盖（防误覆盖自定义脚本）
    - force=True：覆盖部署并写入 EMAIL_WEBHOOK_* bindings
    """
    settings = {**config, **dict(settings or {})}
    name = _normalize_cf_worker_name(worker_name or get_cf_email_worker_name(settings))
    secret = str(
        webhook_secret
        if webhook_secret is not None
        else settings.get("email_webhook_secret") or ""
    ).strip()
    url = str(
        webhook_url
        if webhook_url is not None
        else settings.get("email_webhook_public_url") or ""
    ).strip().rstrip("/")
    if not url:
        raise ValueError(
            "webhook_url 不能为空：请填写公网可访问的 grok_reg 地址（email_webhook_public_url），"
            "不能是 127.0.0.1 / 192.168.x.x"
        )
    if is_private_or_local_webhook_url(url):
        raise ValueError(
            f"EMAIL_WEBHOOK_URL 不能是内网/本机地址：{url}。"
            "Cloudflare Worker 在公网，访问不到 192.168/10/172.16-31/127.0.0.1。"
            "请填域名或公网 IP（可用 frp/cloudflared/反代暴露 8787）。"
        )
    if not secret:
        raise ValueError("email_webhook_secret 不能为空（需与 Worker EMAIL_WEBHOOK_SECRET 一致）")
    if force is None:
        force = bool(settings.get("cf_email_worker_force"))

    account_id = _cf_primary_account_id(settings)
    if not account_id:
        raise RuntimeError("CF Account ID 为空")

    script_path = f"/accounts/{account_id}/workers/scripts/{name}"
    # 探测是否已存在
    exists = False
    try:
        check = _cf_global_request(
            "GET",
            script_path,
            settings=settings,
            timeout=20,
            content_type=False,
        )
        # 200 + success / 或非 404
        code = int(check.get("http_status") or 0)
        if code == 200 or check.get("success"):
            exists = True
        elif code not in {0, 404}:
            # 其它错误仍尝试部署
            exists = False
    except Exception:
        exists = False

    if exists and not force:
        msg = f"Worker [{name}] 已存在，已跳过覆盖（如需重写变量请 force=true）"
        if log_callback:
            log_callback(f"[*] {msg}")
        return {
            "ok": True,
            "skipped": True,
            "worker_name": name,
            "account_id": account_id,
            "message": msg,
        }

    if log_callback:
        log_callback(f"[*] 拉取 openai-cpa-email worker.js …")
    source = fetch_openai_cpa_email_worker_source()

    metadata = {
        "main_module": "worker.js",
        "compatibility_date": "2024-03-01",
        "bindings": [
            {"name": "EMAIL_WEBHOOK_URL", "type": "plain_text", "text": url},
            {"name": "EMAIL_WEBHOOK_TIMEOUT_MS", "type": "plain_text", "text": "10000"},
            {"name": "EMAIL_WEBHOOK_SECRET", "type": "secret_text", "text": secret},
        ],
    }
    # multipart: metadata + worker.js
    files = {
        "metadata": (None, json.dumps(metadata), "application/json"),
        "worker.js": ("worker.js", source, "application/javascript+module"),
    }
    if log_callback:
        log_callback(f"[*] 部署 Worker [{name}] → Account {account_id[:8]}…")
    deploy = _cf_global_request(
        "PUT",
        script_path,
        settings=settings,
        files=files,
        timeout=60,
        content_type=False,
    )
    if int(deploy.get("http_status") or 0) == 200 and deploy.get("success"):
        msg = f"Worker [{name}] 部署成功，已写入 EMAIL_WEBHOOK_URL/SECRET"
        if log_callback:
            log_callback(f"[+] {msg}")
        return {
            "ok": True,
            "skipped": False,
            "worker_name": name,
            "account_id": account_id,
            "message": msg,
            "webhook_url": url,
        }
    errs = deploy.get("errors") or []
    err_msg = "; ".join(str(e.get("message") or e) for e in errs if e) or (
        f"HTTP {deploy.get('http_status')}"
    )
    if log_callback:
        log_callback(f"[!] Worker 部署失败: {err_msg}")
    return {
        "ok": False,
        "skipped": False,
        "worker_name": name,
        "account_id": account_id,
        "message": err_msg,
        "response": deploy,
    }


def setup_cf_email_catch_all(
    domains=None,
    settings=None,
    *,
    worker_name=None,
    log_callback=None,
):
    """把域名 Email Routing catch-all 指到指定 Worker（对齐 openai-cpa setup_catch_all）。"""
    settings = {**config, **dict(settings or {})}
    name = _normalize_cf_worker_name(worker_name or get_cf_email_worker_name(settings))
    if isinstance(domains, str):
        domain_list = [d.strip().lower().lstrip("@.") for d in domains.split(",") if d.strip()]
    else:
        domain_list = [str(d).strip().lower().lstrip("@.") for d in (domains or []) if str(d).strip()]
    if not domain_list:
        raw = str(settings.get("mail_domains") or settings.get("defaultDomains") or "")
        domain_list = [d.strip().lower().lstrip("@.") for d in raw.split(",") if d.strip()]
    if not domain_list:
        raise ValueError("请提供域名（mail_domains）")

    items = []
    for domain in domain_list:
        zone_q = _cf_global_request(
            "GET",
            "/zones",
            settings=settings,
            params={"name": domain, "per_page": 5},
            timeout=20,
        )
        zones = zone_q.get("result") if isinstance(zone_q.get("result"), list) else []
        if not zone_q.get("success") or not zones:
            items.append({"domain": domain, "ok": False, "status": "not_found", "msg": "未找到域名 zone"})
            if log_callback:
                log_callback(f"[!] catch-all 跳过 {domain}: zone 不存在")
            continue
        zone = zones[0]
        zone_id = zone.get("id")
        ns_status = str(zone.get("status") or "")
        if ns_status and ns_status != "active":
            items.append(
                {
                    "domain": domain,
                    "ok": False,
                    "status": ns_status,
                    "zone_id": zone_id,
                    "msg": f"NS 未生效（status={ns_status}），无法配置路由",
                }
            )
            if log_callback:
                log_callback(f"[!] catch-all 跳过 {domain}: NS={ns_status}")
            continue

        # 尽量开启 Email Routing
        try:
            _cf_global_request(
                "POST",
                f"/zones/{zone_id}/email/routing/enable",
                settings=settings,
                json_body={},
                timeout=20,
            )
        except Exception:
            pass

        # 已正确指向则跳过
        already = False
        get_ca = _cf_global_request(
            "GET",
            f"/zones/{zone_id}/email/routing/rules/catch_all",
            settings=settings,
            timeout=20,
        )
        if get_ca.get("success") and isinstance(get_ca.get("result"), dict):
            rule = get_ca["result"]
            if rule.get("enabled"):
                for act in rule.get("actions") or []:
                    if not isinstance(act, dict):
                        continue
                    if act.get("type") == "worker" and name in (act.get("value") or []):
                        already = True
                        break
        if already:
            items.append(
                {
                    "domain": domain,
                    "ok": True,
                    "status": "active",
                    "zone_id": zone_id,
                    "msg": f"Catch-All 已指向 Worker [{name}]",
                    "skipped": True,
                }
            )
            if log_callback:
                log_callback(f"[*] catch-all 已正确: {domain} → {name}")
            continue

        payload = {
            "actions": [{"type": "worker", "value": [name]}],
            "matchers": [{"type": "catch_all"}],
            "enabled": True,
            "name": f"Catch-All to {name}",
        }
        put = _cf_global_request(
            "PUT",
            f"/zones/{zone_id}/email/routing/rules/catch_all",
            settings=settings,
            json_body=payload,
            timeout=30,
        )
        if put.get("success"):
            items.append(
                {
                    "domain": domain,
                    "ok": True,
                    "status": "active",
                    "zone_id": zone_id,
                    "msg": f"Catch-All 已指向 Worker [{name}]",
                    "skipped": False,
                }
            )
            if log_callback:
                log_callback(f"[+] catch-all 绑定成功: {domain} → {name}")
        else:
            errs = put.get("errors") or []
            err_msg = "; ".join(str(e.get("message") or e) for e in errs if e) or (
                f"HTTP {put.get('http_status')}"
            )
            items.append(
                {
                    "domain": domain,
                    "ok": False,
                    "status": "error",
                    "zone_id": zone_id,
                    "msg": err_msg,
                }
            )
            if log_callback:
                log_callback(f"[!] catch-all 失败 {domain}: {err_msg}")
        time.sleep(0.3)

    ok_n = len([i for i in items if i.get("ok")])
    return {
        "ok": ok_n == len(items) and bool(items),
        "worker_name": name,
        "total": ok_n,
        "failed": len(items) - ok_n,
        "items": items,
    }


def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def should_log_cloudflare_wait(state, scope, token_len, interval=5.0):
    now = time.time()
    key = str(scope or "default")
    token_len = str(token_len)
    last = state.get(key, {}) if isinstance(state, dict) else {}
    if last.get("token_len") != token_len or now - float(last.get("time", 0.0)) >= interval:
        state[key] = {"token_len": token_len, "time": now}
        return True
    return False


def detect_cloudflare_block_page(page_html):
    html = str(page_html or "").lower()
    return (
        "attention required! | cloudflare" in html
        or "sorry, you have been blocked" in html
        or "cf-error-code" in html
    )


EMAIL_INPUT_SELECTOR = ", ".join(
    [
        'input[data-testid="email"]',
        'input[name="email"]',
        'input[name="identifier"]',
        'input[id*="email" i]',
        'input[id*="identifier" i]',
        'input[type="email"]',
        'input[autocomplete="email"]',
        'input[placeholder*="email" i]',
        'input[placeholder*="邮箱"]',
        'input[aria-label*="email" i]',
        'input[aria-label*="邮箱"]',
        'input[type="text"]',
        "input:not([type])",
    ]
)

EMAIL_SUBMIT_KEYWORDS = (
    "注册",
    "继续",
    "下一步",
    "sign up",
    "signup",
    "continue",
    "next",
    "submit",
)


PROFILE_SUBMIT_KEYWORDS = (
    "完成注册",
    "创建账户",
    "创建账号",
    "注册",
    "继续",
    "下一步",
    "sign up",
    "signup",
    "create account",
    "createaccount",
    "create",
    "continue",
    "next",
    "submit",
)


def build_email_form_script(action):
    if action not in {"fill", "submit", "diagnose"}:
        raise ValueError(f"Unsupported email form action: {action}")
    selector = json.dumps(EMAIL_INPUT_SELECTOR, ensure_ascii=False)
    keywords = json.dumps(list(EMAIL_SUBMIT_KEYWORDS), ensure_ascii=False)
    action_json = json.dumps(action)
    return f"""
const action = {action_json};
const email = arguments[0] || '';
const emailSelector = {selector};
const submitKeywords = {keywords};
function isVisible(node) {{
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}}
function nodeText(node) {{
    return String(
        node.innerText ||
        node.textContent ||
        node.value ||
        node.getAttribute('aria-label') ||
        node.getAttribute('title') ||
        ''
    ).replace(/\\s+/g, ' ').trim();
}}
function inputScore(node) {{
    const attrs = [
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('type'),
        node.getAttribute('autocomplete'),
        node.getAttribute('placeholder'),
        node.getAttribute('aria-label'),
    ].join(' ').toLowerCase();
    if (attrs.includes('email') || attrs.includes('邮箱')) return 100;
    if (attrs.includes('identifier')) return 95;
    if (attrs.includes('login') || attrs.includes('account')) return 70;
    if ((node.getAttribute('type') || '').toLowerCase() === 'text') return 25;
    return 10;
}}
function pickEmailInput() {{
    const inputs = Array.from(document.querySelectorAll(emailSelector)).filter((node) => {{
        const type = (node.getAttribute('type') || 'text').toLowerCase();
        return isVisible(node) && !node.disabled && !node.readOnly && !['hidden', 'password', 'checkbox', 'radio', 'submit', 'button'].includes(type);
    }});
    return inputs.sort((a, b) => inputScore(b) - inputScore(a))[0] || null;
}}
function setInputValue(input, value) {{
    input.focus();
    input.click();
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (valueSetter) valueSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event('focus', {{ bubbles: true }}));
    input.dispatchEvent(new InputEvent('beforeinput', {{ bubbles: true, data: value, inputType: 'insertText' }}));
    input.dispatchEvent(new InputEvent('input', {{ bubbles: true, data: value, inputType: 'insertText' }}));
    input.dispatchEvent(new Event('change', {{ bubbles: true }}));
    input.dispatchEvent(new KeyboardEvent('keyup', {{ key: '@', bubbles: true }}));
    input.dispatchEvent(new Event('blur', {{ bubbles: true }}));
    return String(input.value || '').trim() === String(value || '').trim();
}}
function pickSubmitButton() {{
    const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {{
        return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
    }});
    return buttons.find((node) => {{
        const text = nodeText(node).toLowerCase().replace(/\\s+/g, '');
        return submitKeywords.some((keyword) => text.includes(String(keyword).toLowerCase().replace(/\\s+/g, '')));
    }}) || buttons.find((node) => {{
        const type = String(node.getAttribute('type') || '').toLowerCase();
        return type === 'submit';
    }}) || buttons[0] || null;
}}
if (action === 'diagnose') {{
    const inputs = Array.from(document.querySelectorAll('input')).filter(isVisible).slice(0, 8).map((node) => ({{
        type: node.getAttribute('type') || '',
        name: node.getAttribute('name') || '',
        id: node.getAttribute('id') || '',
        autocomplete: node.getAttribute('autocomplete') || '',
        placeholder: node.getAttribute('placeholder') || '',
        aria: node.getAttribute('aria-label') || '',
    }}));
    const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"]')).filter(isVisible).slice(0, 8).map(nodeText);
    return JSON.stringify({{
        url: location.href,
        title: document.title,
        hasEmailInput: !!pickEmailInput(),
        hasSubmitButton: !!pickSubmitButton(),
        inputs,
        buttons,
    }});
}}
const input = pickEmailInput();
if (!input) return 'not-ready';
if (action === 'fill') {{
    if (setInputValue(input, email)) return 'filled';
    input.value = '';
    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
    for (const ch of email) {{
        input.dispatchEvent(new KeyboardEvent('keydown', {{ key: ch, bubbles: true }}));
        input.value += ch;
        input.dispatchEvent(new InputEvent('input', {{ bubbles: true, data: ch, inputType: 'insertText' }}));
        input.dispatchEvent(new KeyboardEvent('keyup', {{ key: ch, bubbles: true }}));
    }}
    input.dispatchEvent(new Event('change', {{ bubbles: true }}));
    if (String(input.value || '').trim() === email) return 'filled';
    return input.value || 'empty-after-fill';
}}
if (!(input.value || '').trim()) return 'input-empty';
const submitButton = pickSubmitButton();
if (!submitButton) return 'no-submit-button';
submitButton.focus();
submitButton.click();
return true;
"""


def build_email_submission_state_script():
    return r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return String(node?.innerText || node?.textContent || node?.value || '').replace(/\s+/g, ' ').trim();
}
const inputs = Array.from(document.querySelectorAll('input')).filter(isVisible);
const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"]')).filter(isVisible);
const bodyText = textOf(document.body).slice(0, 1000);
const otpInput = inputs.find((node) => {
    const attrs = [
        node.getAttribute('name'),
        node.getAttribute('autocomplete'),
        node.getAttribute('inputmode'),
        node.getAttribute('aria-label'),
        node.getAttribute('data-input-otp'),
        node.getAttribute('placeholder'),
    ].join(' ').toLowerCase();
    return attrs.includes('one-time-code') ||
        attrs.includes('otp') ||
        attrs.includes('code') ||
        attrs.includes('verification') ||
        attrs.includes('验证码') ||
        attrs.includes('numeric') ||
        node.getAttribute('data-input-otp') === 'true';
});
const resendButton = buttons.find((node) => {
    const text = textOf(node).toLowerCase();
    return text.includes('resend') || text.includes('重新发送') || text.includes('再次发送');
});
const errorNode = Array.from(document.querySelectorAll('[role="alert"], [aria-live], .error, [data-testid*="error" i]'))
    .filter(isVisible)
    .map(textOf)
    .find(Boolean) || '';
let step = 'unknown';
if (otpInput || resendButton || /verification code|enter code|验证码|確認コード/i.test(bodyText)) {
    step = 'otp';
} else if (inputs.some((node) => {
    const attrs = [
        node.getAttribute('name'),
        node.getAttribute('type'),
        node.getAttribute('autocomplete'),
        node.getAttribute('placeholder'),
        node.getAttribute('aria-label'),
    ].join(' ').toLowerCase();
    return attrs.includes('email') || attrs.includes('identifier') || attrs.includes('邮箱');
})) {
    step = 'email';
}
return JSON.stringify({
    step,
    url: location.href,
    title: document.title,
    errorText: errorNode,
    bodySnippet: bodyText.slice(0, 240),
    inputs: inputs.slice(0, 6).map((node) => ({
        type: node.getAttribute('type') || '',
        name: node.getAttribute('name') || '',
        autocomplete: node.getAttribute('autocomplete') || '',
        placeholder: node.getAttribute('placeholder') || '',
        aria: node.getAttribute('aria-label') || '',
    })),
    buttons: buttons.slice(0, 6).map(textOf),
});
"""


def build_otp_native_target_script():
    return r"""
// otp-native-target
const codeLen = Number(arguments[0] || 6);
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function inputAttrs(node) {
    return [
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('type'),
        node.getAttribute('autocomplete'),
        node.getAttribute('inputmode'),
        node.getAttribute('placeholder'),
        node.getAttribute('aria-label'),
        node.getAttribute('data-input-otp'),
    ].join(' ').toLowerCase();
}
function centerOf(node) {
    const rect = node.getBoundingClientRect();
    return {
        centerX: Math.round(rect.left + rect.width / 2),
        centerY: Math.round(rect.top + rect.height / 2),
    };
}
const inputs = Array.from(document.querySelectorAll('input')).filter((node) => {
    if (!isVisible(node) || node.disabled || node.readOnly) return false;
    const type = String(node.getAttribute('type') || 'text').toLowerCase();
    return !['hidden', 'password', 'checkbox', 'radio', 'submit', 'button'].includes(type);
});
const scored = inputs.map((node) => {
    const attrs = inputAttrs(node);
    let score = 0;
    if (node.getAttribute('data-input-otp') === 'true') score += 120;
    if (attrs.includes('one-time-code')) score += 110;
    if (attrs.includes('otp')) score += 100;
    if (attrs.includes('verification')) score += 90;
    if (attrs.includes('code')) score += 80;
    if (attrs.includes('验证码')) score += 80;
    if (attrs.includes('numeric')) score += 40;
    if (Number(node.maxLength || 0) >= codeLen) score += 25;
    if (Number(node.maxLength || 0) === 1) score -= 15;
    return { node, score };
}).filter((item) => item.score > 0).sort((a, b) => b.score - a.score);
if (scored.length) {
    const target = scored[0].node;
    target.focus();
    const point = centerOf(target);
    return {
        state: 'otp-target',
        mode: Number(target.maxLength || 0) === 1 ? 'split-first' : 'aggregate',
        valueLen: String(target.value || '').length,
        maxLength: Number(target.maxLength || 0),
        ...point,
    };
}
return {
    state: 'otp-not-ready',
    inputs: inputs.slice(0, 6).map((node) => ({
        name: node.getAttribute('name') || '',
        type: node.getAttribute('type') || '',
        autocomplete: node.getAttribute('autocomplete') || '',
        inputmode: node.getAttribute('inputmode') || '',
        maxLength: Number(node.maxLength || 0),
        aria: node.getAttribute('aria-label') || '',
        dataInputOtp: node.getAttribute('data-input-otp') || '',
    })),
};
"""


def build_otp_submit_target_script():
    return r"""
// otp-submit-target
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return String(
        node?.innerText ||
        node?.textContent ||
        node?.value ||
        node?.getAttribute?.('aria-label') ||
        ''
    ).replace(/\s+/g, ' ').trim();
}
function centerOf(node) {
    const rect = node.getBoundingClientRect();
    return {
        centerX: Math.round(rect.left + rect.width / 2),
        centerY: Math.round(rect.top + rect.height / 2),
    };
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const target = buttons.find((node) => {
    const text = textOf(node).toLowerCase().replace(/\s+/g, '');
    return (
        text.includes('确认邮箱') ||
        text.includes('继续') ||
        text.includes('下一步') ||
        text.includes('confirm') ||
        text.includes('continue') ||
        text.includes('next')
    );
}) || buttons.find((node) => String(node.getAttribute('type') || '').toLowerCase() === 'submit');
if (!target) return { state: 'otp-submit-not-ready', count: buttons.length };
target.focus();
return {
    state: 'otp-submit-target',
    text: textOf(target),
    count: buttons.length,
    ...centerOf(target),
};
"""


def build_profile_submit_script(action):
    if action not in {"check", "submit", "trigger", "diagnose", "retry_error", "recover_entry"}:
        raise ValueError(f"Unsupported profile submit action: {action}")
    keywords = json.dumps(list(PROFILE_SUBMIT_KEYWORDS), ensure_ascii=False)
    action_json = json.dumps(action)
    return f"""
const action = {action_json};
const submitKeywords = {keywords};
function isVisible(node) {{
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}}
function nodeText(node) {{
    return String(
        node.innerText ||
        node.textContent ||
        node.value ||
        node.getAttribute('aria-label') ||
        node.getAttribute('title') ||
        ''
    ).replace(/\\s+/g, ' ').trim();
}}
function normalizedText(node) {{
    return nodeText(node).toLowerCase().replace(/\\s+/g, '');
}}
function pickSubmitButton() {{
    const buttons = Array.from(document.querySelectorAll(
        'button[type="submit"], button, [role="button"], input[type="submit"], a[href]'
    )).filter((node) => {{
        return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
    }});
    return buttons.find((node) => {{
        const text = normalizedText(node);
        return submitKeywords.some((keyword) => text.includes(String(keyword).toLowerCase().replace(/\\s+/g, '')));
    }}) || buttons.find((node) => {{
        return String(node.getAttribute('type') || '').toLowerCase() === 'submit';
    }}) || null;
}}
function submitProfileForm(submitBtn) {{
    if (!submitBtn) return false;
    submitBtn.focus();
    const form = submitBtn.form || submitBtn.closest('form');
    if (form && typeof form.requestSubmit === 'function') {{
        try {{
            form.requestSubmit(submitBtn);
            return true;
        }} catch (e) {{}}
    }}
    try {{
        submitBtn.click();
        return true;
    }} catch (e) {{}}
    return false;
}}
function cloudflareState() {{
    const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
    const cfPresent = !!cfInput
      || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
    if (!cfPresent) return 'none';
    const token = String((cfInput && cfInput.value) || '').trim();
    if (token.length >= 80) return 'solved';
    return 'wait-cloudflare:' + token.length;
}}
function hasResource(fragment) {{
    try {{
        return performance.getEntriesByType('resource').some((entry) => {{
            return String(entry && entry.name || '').includes(fragment);
        }});
    }} catch (e) {{
        return false;
    }}
}}
function triggerPasswordValidation() {{
    const passwordInput = document.querySelector('input[data-testid="password"], input[name="password"], input[type="password"], input[autocomplete="new-password"]');
    if (!passwordInput) return false;
    try {{
        passwordInput.focus();
        passwordInput.dispatchEvent(new InputEvent('input', {{ bubbles: true, data: '', inputType: 'insertText' }}));
        passwordInput.dispatchEvent(new Event('change', {{ bubbles: true }}));
        passwordInput.blur();
        return true;
    }} catch (e) {{
        return false;
    }}
}}
function turnstileDetail() {{
    const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
    const captured = (() => {{
        try {{
            const raw = window.__grokTurnstile || {{}};
            return {{
                hookInstalled: !!window.__grokTurnstileHookInstalled,
                renderCount: raw.renderCount || 0,
                executeCount: raw.executeCount || 0,
                callbackCount: raw.callbackCount || 0,
                lastTokenLen: String(raw.lastToken || '').trim().length,
                lastExecuteArgs: raw.lastExecuteArgs || [],
                widgets: Array.isArray(raw.widgets) ? raw.widgets.slice(-5) : [],
                errors: Array.isArray(raw.errors) ? raw.errors.slice(-5) : [],
            }};
        }} catch (e) {{
            return {{ error: String(e && e.message || e).slice(0, 160) }};
        }}
    }})();
    const widgets = Array.from(document.querySelectorAll('div.cf-turnstile, [data-sitekey]')).map((n) => ({{
        sitekey: n.getAttribute('data-sitekey') || '',
        theme: n.getAttribute('data-theme') || '',
        size: n.getAttribute('data-size') || '',
        action: n.getAttribute('data-action') || '',
        class: n.className || '',
    }}));
    const iframes = Array.from(document.querySelectorAll('iframe')).filter((f) => {{
        const s = f.getAttribute('src') || '';
        return s.includes('turnstile') || s.includes('challenges.cloudflare.com');
    }}).map((f) => ({{
        src: (f.getAttribute('src') || '').slice(0, 160),
        w: f.getBoundingClientRect().width,
        h: f.getBoundingClientRect().height,
        visible: isVisible(f),
    }}));
    return {{
        hasInput: !!cfInput,
        inputLen: String((cfInput && cfInput.value) || '').trim().length,
        turnstileApi: (typeof window.turnstile !== 'undefined'),
        captured,
        widgets,
        iframes,
        webdriver: navigator.webdriver,
    }};
}}
function networkDetail() {{
    const resources = (() => {{
        try {{
            return performance.getEntriesByType('resource').map((entry) => String(entry && entry.name || ''));
        }} catch (e) {{
            return [];
        }}
    }})();
    return {{
        validatePasswordSeen: resources.some((name) => name.includes('ValidatePassword')),
        signUpSeen: resources.some((name) => name.includes('/sign-up')),
    }};
}}
if (action === 'diagnose') {{
    const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"], a[href]'))
        .filter(isVisible)
        .slice(0, 10)
        .map((node) => ({{
            text: nodeText(node),
            tag: node.tagName,
            role: node.getAttribute('role') || '',
            type: node.getAttribute('type') || '',
            aria: node.getAttribute('aria-label') || '',
            disabled: !!node.disabled,
            ariaDisabled: node.getAttribute('aria-disabled') || '',
        }}));
    const inputs = Array.from(document.querySelectorAll('input'))
        .filter(isVisible)
        .slice(0, 10)
        .map((node) => ({{
            type: node.getAttribute('type') || '',
            name: node.getAttribute('name') || '',
            autocomplete: node.getAttribute('autocomplete') || '',
            aria: node.getAttribute('aria-label') || '',
        }}));
    return JSON.stringify({{
        url: location.href,
        title: document.title,
        cf: cloudflareState(),
        turnstile: turnstileDetail(),
        network: networkDetail(),
        hasSubmitButton: !!pickSubmitButton(),
        buttons,
        inputs,
        bodySnippet: nodeText(document.body).slice(0, 300),
    }});
}}
if (action === 'retry_error') {{
    const bodyText = nodeText(document.body);
    const compactBody = bodyText.toLowerCase().replace(/\\s+/g, '');
    const errorHints = [
        'An error occurred',
        'There was an error loading this page',
        '请验证你使用的网址是否正确',
    ];
    const isErrorPage = compactBody.includes('anerroroccurred')
        || compactBody.includes('therewasanerrorloadingthispage')
        || compactBody.includes('errorloadingthispage');
    if (!isErrorPage) return 'profile-error-page-not-detected';
    const retryBtn = Array.from(document.querySelectorAll('button, [role="button"], input[type="button"], a[href]'))
        .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
        .find((node) => {{
            const text = normalizedText(node);
            return text.includes('retry') || text.includes('重试') || text.includes('reload');
        }});
    if (!retryBtn) {{
        return {{
            state: 'profile-error-page-no-retry',
            title: document.title,
            hints: errorHints,
            bodySnippet: bodyText.slice(0, 240),
        }};
    }}
    retryBtn.focus();
    const rect = retryBtn.getBoundingClientRect();
    try {{ retryBtn.click(); }} catch (e) {{}}
    return {{
        state: 'profile-error-retry-target',
        centerX: Math.round(rect.left + rect.width / 2),
        centerY: Math.round(rect.top + rect.height / 2),
        text: nodeText(retryBtn).slice(0, 80),
        title: document.title,
        bodySnippet: bodyText.slice(0, 240),
    }};
}}
if (action === 'recover_entry') {{
    const bodyText = nodeText(document.body);
    const compactBody = bodyText.toLowerCase().replace(/\\s+/g, '');
    const hasProfileInputs = !!document.querySelector('input[name="givenName"], input[autocomplete="given-name"]')
        && !!document.querySelector('input[name="password"], input[type="password"]');
    if (hasProfileInputs) return 'profile-entry-has-profile-form';
    const isSignupEntry = compactBody.includes('createyouraccount')
        || compactBody.includes('signupwithemail')
        || compactBody.includes('youaresigninginto');
    if (!isSignupEntry) return 'profile-entry-page-not-detected';
    const emailBtn = Array.from(document.querySelectorAll('button, [role="button"], input[type="button"], a[href]'))
        .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
        .find((node) => {{
            const text = normalizedText(node);
            return text.includes('signupwithemail')
                || text.includes('continuewithemail')
                || text.includes('使用邮箱注册')
                || text.includes('email');
        }});
    if (!emailBtn) {{
        return {{
            state: 'profile-entry-page-no-email',
            title: document.title,
            hints: ['Create your account', 'Sign up with email'],
            bodySnippet: bodyText.slice(0, 240),
        }};
    }}
    emailBtn.focus();
    const rect = emailBtn.getBoundingClientRect();
    try {{ emailBtn.click(); }} catch (e) {{}}
    return {{
        state: 'profile-entry-email-target',
        centerX: Math.round(rect.left + rect.width / 2),
        centerY: Math.round(rect.top + rect.height / 2),
        text: nodeText(emailBtn).slice(0, 80),
        title: document.title,
        bodySnippet: bodyText.slice(0, 240),
    }};
}}
const cf = cloudflareState();
if (action === 'trigger') {{
    // xAI 已改为“提交时才触发”的隐形 Turnstile：脚本已加载但不预渲染组件，
    // 需主动执行并放行点击，让网站前端自行驱动 challenge 生成 token。
    let executed = false;
    const executedWidgets = [];
    try {{
        if (window.turnstile && typeof window.turnstile.execute === 'function') {{
            const capturedWidgets = Array.isArray(window.__grokTurnstile && window.__grokTurnstile.widgets)
                ? window.__grokTurnstile.widgets
                : [];
            for (const widget of capturedWidgets) {{
                const id = widget && widget.id;
                if (id !== undefined && id !== null && id !== '') {{
                    try {{
                        window.turnstile.execute(id);
                        executed = true;
                        executedWidgets.push(String(id));
                    }} catch (e) {{}}
                }}
            }}
            if (!executed) {{
                try {{ window.turnstile.execute(); executed = true; }} catch (e) {{}}
            }}
        }}
    }} catch (e) {{}}
    const submitBtn = pickSubmitButton();
    if (!submitBtn) return 'trigger-no-submit';
    // 仅在已有 token 时才点提交；token 仍为空时只触发 challenge，避免空 token 提交后卡死。
    if (cf === 'solved' || cf === 'none') {{
        submitProfileForm(submitBtn);
        return 'trigger-clicked:' + (executed ? '1' : '0') + ':' + executedWidgets.join(',');
    }}
    return 'trigger-wait-cf:' + (executed ? '1' : '0') + ':' + executedWidgets.join(',') + ':' + cf;
}}
const submitBtn = pickSubmitButton();
if (!submitBtn) return 'no-submit-button';
if (!hasResource('ValidatePassword')) {{
    triggerPasswordValidation();
    return 'wait-password-validation';
}}
if (cf.startsWith('wait-cloudflare')) {{
    // 只要存在 cf-turnstile-response 且 token 为空，就必须等待。
    // managed/flexible 模式经常没有可见 iframe，不能据此当成“无挑战”提前提交。
    return cf;
}}
if (action === 'check') return 'ready-to-submit';
submitProfileForm(submitBtn);
return 'submitted';
"""


def extract_rejected_email_domain(text, email=""):
    """从页面文案中提取被 x.ai 拒收的邮箱域名（中英文都支持）。"""
    combined = str(text or "")
    patterns = [
        # EN: email domain example.com has been rejected
        r"email\s*domain\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+has\s+been\s+rejected",
        # EN variants
        r"domain\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+(?:is|has been)\s+rejected",
        r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s+has\s+been\s+rejected",
        # ZH: 邮箱域名 xxx 已被拒绝 / 您的邮箱域名 xxx 已被拒绝
        r"邮箱域名\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*已被拒绝",
        r"域名\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*已被拒绝",
        r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*已被拒绝",
        # 宽松：出现“已被拒绝/拒绝”且附近有域名
        r"([A-Za-z0-9.-]+\.[A-Za-z]{2,}).{0,12}(?:已被拒绝|被拒绝|拒绝)",
    ]
    for pattern in patterns:
        match = re.search(pattern, combined, re.IGNORECASE)
        if match:
            return match.group(1).strip(".").lower()
    lowered = combined.lower()
    rejected_markers = (
        "has been rejected",
        "is rejected",
        "已被拒绝",
        "被拒绝",
        "请使用其他邮箱",
        "use a different email",
        "use another email",
    )
    if any(marker in combined or marker in lowered for marker in rejected_markers):
        # 优先从当前邮箱地址取后缀
        email_match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", str(email or ""))
        if email_match:
            return email_match.group(1).lower()
        # 再从正文里找域名
        body_match = re.search(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b", combined)
        if body_match:
            return body_match.group(1).lower()
    return ""


def wait_for_email_verification_step(
    page, email, timeout=20, log_callback=None, cancel_callback=None
):
    def _raise_if_domain_rejected(state):
        combined = " ".join(
            str(state.get(key) or "")
            for key in ("errorText", "bodySnippet", "raw", "title")
        )
        domain = extract_rejected_email_domain(combined, email=email)
        if domain:
            raise EmailDomainRejected(domain)

    deadline = time.time() + timeout
    last_state = {}
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        raw = page.run_js(build_email_submission_state_script(), email)
        try:
            state = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
        except Exception:
            state = {"step": "unknown", "raw": str(raw)}
        last_state = state
        _raise_if_domain_rejected(state)
        if state.get("step") == "otp":
            return "otp"
        error_text = str(state.get("errorText") or "").strip()
        if error_text:
            # 错误文案也可能是中文域名拒收
            domain = extract_rejected_email_domain(error_text, email=email)
            if domain:
                raise EmailDomainRejected(domain)
            raise Exception(f"x.ai 未接受该邮箱: {error_text}")
        sleep_with_cancel(0.8, cancel_callback)
    if log_callback:
        log_callback(
            "[Debug] 邮箱提交后页面状态: "
            + json.dumps(last_state, ensure_ascii=False)[:1200]
        )
    _raise_if_domain_rejected(last_state)
    # 超时兜底：正文里若有拒收语义，仍写入黑名单
    fallback = extract_rejected_email_domain(
        json.dumps(last_state, ensure_ascii=False), email=email
    )
    if fallback:
        raise EmailDomainRejected(fallback)
    raise Exception("邮箱已提交，但未进入验证码页面，x.ai 可能未发送验证码")


def wait_for_post_code_transition(
    page, email, timeout=60, log_callback=None, cancel_callback=None
):
    deadline = time.time() + timeout
    last_state = "not-started"
    # 验证成功后可能闪现错误页/入口页等瞬时过渡态；容忍连续 N 次再判失败，
    # 期间只要出现 profile-form 即成功。max_adverse_streak*~1.2s 为容忍窗口。
    adverse_streak = 0
    max_adverse_streak = 12
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        state = page.run_js(
            r"""
function visible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function resourceSummary() {
    try {
        const resources = performance.getEntriesByType('resource');
        const names = resources.map((entry) => String(entry && entry.name || ''));
        const interesting = resources.filter((entry) => {
            const name = String(entry && entry.name || '');
            return name.includes('VerifyEmailValidationCode') ||
                name.includes('ValidatePassword') ||
                /\/sign-up(?:\?|$)/.test(name) ||
                name.includes('/auth_mgmt.');
        }).slice(-8).map((entry) => {
            const name = String(entry && entry.name || '');
            let kind = 'other';
            if (name.includes('VerifyEmailValidationCode')) kind = 'verify-email';
            else if (name.includes('ValidatePassword')) kind = 'validate-password';
            else if (/\/sign-up(?:\?|$)/.test(name)) kind = 'sign-up';
            else if (name.includes('/auth_mgmt.')) kind = 'auth-mgmt';
            return {
                kind,
                responseStatus: Number(entry.responseStatus || 0),
                transferSize: Number(entry.transferSize || 0),
                encodedBodySize: Number(entry.encodedBodySize || 0),
                duration: Math.round(Number(entry.duration || 0)),
            };
        });
        return {
            verifyEmailSeen: names.some((name) => name.includes('VerifyEmailValidationCode')),
            validatePasswordSeen: names.some((name) => name.includes('ValidatePassword')),
            signupSeen: names.some((name) => /\/sign-up(?:\?|$)/.test(name)),
            authMgmtCount: names.filter((name) => name.includes('/auth_mgmt.')).length,
            matches: interesting,
            verifyEmailNet: (window.__grokNet && window.__grokNet.verifyEmail) || [],
        };
    } catch (e) {
        return {error: String(e && e.message || e).slice(0, 120)};
    }
}
function retryTarget() {
    const clickables = Array.from(document.querySelectorAll('button, [role="button"], a[href]')).filter(visible);
    const target = clickables.find((node) => {
        const text = String(node.innerText || node.textContent || node.getAttribute('aria-label') || '')
            .replace(/\s+/g, '').toLowerCase();
        return text.includes('retry') || text.includes('重试') || text.includes('再试');
    });
    if (!target) return null;
    const rect = target.getBoundingClientRect();
    return {
        centerX: Math.round(rect.left + rect.width / 2),
        centerY: Math.round(rect.top + rect.height / 2),
        text: String(target.innerText || target.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80),
    };
}
const bodyText = String(document.body?.innerText || document.body?.textContent || '').replace(/\s+/g, ' ').trim();
const compact = bodyText.toLowerCase().replace(/\s+/g, '');
const hasProfile = !!document.querySelector('input[name="givenName"], input[autocomplete="given-name"]')
    && !!document.querySelector('input[name="familyName"], input[autocomplete="family-name"]')
    && !!document.querySelector('input[name="password"], input[type="password"]');
if (hasProfile) return 'profile-form';
if (compact.includes('anerroroccurred') || compact.includes('therewasanerrorloadingthispage')) {
    return {state: 'post-code-error-page', bodySnippet: bodyText.slice(0, 240), resourceSummary: resourceSummary(), retryTarget: retryTarget()};
}
const hasEmailInput = !!Array.from(document.querySelectorAll('input[type="email"], input[name="email"], input[autocomplete="email"]')).find(visible);
if (hasEmailInput) return {state: 'post-code-email-step', bodySnippet: bodyText.slice(0, 240)};
const hasEntry = compact.includes('createyouraccount') || compact.includes('signupwithemail');
if (hasEntry) return {state: 'post-code-entry-page', bodySnippet: bodyText.slice(0, 240)};
return 'post-code-waiting';
// post-code-profile-form
            """
        )
        last_state = state
        if state == "profile-form":
            return "profile-form"
        if isinstance(state, dict):
            name = str(state.get("state") or "")
            snippet = str(state.get("bodySnippet") or "")
            if name == "post-code-error-page":
                resource_summary = state.get("resourceSummary")
                # 验证码已被服务端接受(grpc-status:0)。这个 "an error occurred"
                # 页面是成功后的瞬时过渡态，任何主动干预都会毁掉会话：
                #   - 点 "Retry" 会重启注册流程回到入口
                #   - refresh() 会丢掉存于前端内存的流程状态、回到入口
                # 对齐上游(38dc6eb 时可用)：什么都不做，容忍瞬时并继续轮询等资料页。
                adverse_streak += 1
                if adverse_streak <= max_adverse_streak:
                    if log_callback and adverse_streak == 1:
                        log_callback(
                            f"[Debug] 验证码校验后瞬时过渡页，静默等待资料页 snippet={snippet[:120]}"
                        )
                    sleep_with_cancel(1.2, cancel_callback)
                    continue
                detail = ""
                if resource_summary:
                    detail = "；资源摘要: " + json.dumps(resource_summary, ensure_ascii=False)[:500]
                raise ProfileSessionLost(f"验证码提交后 xAI 持续停在错误页: {snippet}{detail}")
            if name == "post-code-email-step":
                # 容忍过渡中的瞬时快照；仅在持续退回邮箱页时才判失败
                adverse_streak += 1
                if adverse_streak <= max_adverse_streak:
                    sleep_with_cancel(1.2, cancel_callback)
                    continue
                raise ProfileSessionLost(f"验证码提交后退回邮箱输入页，验证码会话已失效: {snippet}")
            if name == "post-code-entry-page":
                # 容忍过渡中的瞬时快照；仅在持续退回入口时才判失败
                adverse_streak += 1
                if adverse_streak <= max_adverse_streak:
                    if log_callback and adverse_streak == 1:
                        log_callback("[Debug] 验证码校验后短暂闪现入口页，继续等待资料页...")
                    sleep_with_cancel(1.2, cancel_callback)
                    continue
                raise ProfileSessionLost(f"验证码提交后退回注册入口，验证码会话已失效: {snippet}")
        else:
            adverse_streak = 0
        sleep_with_cancel(0.8, cancel_callback)
    if log_callback:
        log_callback(f"[Debug] 验证码提交后未进入资料页，最后状态: {last_state}")
    raise ProfileSessionLost("验证码提交后未进入资料页，验证码会话可能已失效")


def _jobs_dir():
    path = os.path.join(get_data_dir(), "jobs")
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass
    return path


def _job_log_path(job_id):
    return os.path.join(_jobs_dir(), f"{job_id}.log")


def _job_status_path(job_id):
    return os.path.join(_jobs_dir(), f"{job_id}.json")


def _current_job_meta_path():
    return os.path.join(_jobs_dir(), "current.json")


def save_current_job_meta(meta):
    path = _current_job_meta_path()
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(meta or {}, handle, ensure_ascii=False, indent=2)
    except Exception:
        pass


def load_current_job_meta():
    path = _current_job_meta_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_job_snapshot(job_id):
    job_id = str(job_id or "").strip()
    if not job_id:
        return None
    path = _job_status_path(job_id)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def save_job_snapshot(job_id, snapshot):
    job_id = str(job_id or "").strip()
    if not job_id or not isinstance(snapshot, dict):
        return
    path = _job_status_path(job_id)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, ensure_ascii=False, indent=2)
    except Exception:
        pass


def read_job_log_lines(job_id, offset=0, tail=None):
    """读任务日志。

    - offset: 从第几行开始（0-based）
    - tail: 若给定且 offset==0，只返回最后 tail 行（作战室用，避免整文件读入）
    """
    path = _job_log_path(job_id)
    if offset < 0:
        offset = 0
    try:
        # 只取尾部：从文件末尾倒读，省内存/IO
        if tail is not None and offset == 0:
            try:
                n = max(1, int(tail))
            except Exception:
                n = 200
            # 粗估每行 200 字节，多读一点再截
            read_bytes = min(8 * 1024 * 1024, max(64 * 1024, n * 240))
            with open(path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                start = max(0, size - read_bytes)
                handle.seek(start)
                chunk = handle.read()
            text = chunk.decode("utf-8", errors="replace")
            if start > 0:
                # 丢掉可能被截断的首行
                nl = text.find("\n")
                if nl >= 0:
                    text = text[nl + 1 :]
            lines = [ln.rstrip("\n") for ln in text.splitlines()]
            if len(lines) > n:
                lines = lines[-n:]
            return lines

        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            if offset == 0:
                lines = [line.rstrip("\n") for line in handle]
            else:
                lines = []
                for idx, line in enumerate(handle):
                    if idx < offset:
                        continue
                    lines.append(line.rstrip("\n"))
            return lines
    except Exception:
        return []


def append_job_log_line(job_id, line):
    path = _job_log_path(job_id)
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(str(line).rstrip("\n") + "\n")
    except Exception:
        pass
    # 新日志不直接影响账号列表；无需 invalidate_account_list_cache


class RegistrationJob:
    def __init__(self, settings=None, log_sink=None):
        self.id = uuid.uuid4().hex
        self.settings = validate_registration_config(settings or load_config())
        self.log_sink = log_sink
        self.status_value = "pending"
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.stop_requested = False
        self.fatal_error = False
        self.consecutive_blocks = 0
        self.block_stop_triggered = False
        self.created_at = datetime.datetime.now().isoformat(timespec="seconds")
        self.started_at = None
        self.finished_at = None
        self.output_file = ""
        self.thread = None
        self.stats_lock = threading.Lock()
        self._logs = []
        self._log_lock = threading.Lock()
        self._persist_status()

    def _persist_status(self):
        st = self.status()
        try:
            with open(_job_status_path(self.id), "w", encoding="utf-8") as handle:
                json.dump(st, handle, ensure_ascii=False, indent=2)
        except Exception:
            pass
        try:
            save_current_job_meta(
                {
                    "job_id": self.id,
                    "status": st.get("status"),
                    "success_count": st.get("success_count"),
                    "fail_count": st.get("fail_count"),
                    "updated_at": datetime.datetime.now().isoformat(timespec="seconds"),
                }
            )
        except Exception:
            pass

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        with self._log_lock:
            self._logs.append(line)
        append_job_log_line(self.id, line)
        if self.log_sink:
            self.log_sink(message)

    def logs(self, offset=0):
        with self._log_lock:
            if offset < 0:
                offset = 0
            mem = list(self._logs[offset:])
        # 内存若被裁剪，回落到文件
        if not mem and offset > 0:
            return read_job_log_lines(self.id, offset=offset)
        if offset == 0 and not mem:
            disk = read_job_log_lines(self.id, offset=0)
            if disk:
                return disk
        return mem

    def should_stop(self):
        # stopping 表示已收到停止请求，工作线程应尽快退出
        return self.stop_requested or self.status_value not in {"pending", "running"}

    def start(self):
        if self.thread and self.thread.is_alive():
            raise RuntimeError("job is already running")
        self.status_value = "running"
        self.started_at = datetime.datetime.now().isoformat(timespec="seconds")
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_file = f"accounts_{now}_{self.id[:8]}.txt"
        self._persist_status()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        try:
            import notify_hub

            notify_hub.emit(
                "job.started",
                title="注册任务已开始",
                body=(
                    f"目标 {self.settings.get('register_count', 1)} · "
                    f"并发 {self.settings.get('register_threads', 1)}"
                ),
                level="info",
                job_id=self.id,
                dedupe_key=f"job.started|{self.id}",
                settings=self.settings,
            )
        except Exception:
            pass
        return self

    def stop(self):
        """协作式停止：立即标记 stopping，工作线程在下一个可取消点退出。

        注意：不会强杀浏览器/HTTP；若卡在 page.get / requests / 启动浏览器等
        硬阻塞调用，仍需等到该调用返回（最长可达几十秒）。
        """
        self.stop_requested = True
        if self.status_value in {"pending", "running"}:
            self.status_value = "stopping"
        self.log("[!] 用户停止注册（等待当前步骤结束…）")
        self._persist_status()

    def status(self):
        with self.stats_lock:
            success_count = self.success_count
            fail_count = self.fail_count
            consecutive_blocks = self.consecutive_blocks
            block_stop_triggered = self.block_stop_triggered
        alive = False
        try:
            alive = bool(self.thread and self.thread.is_alive())
        except Exception:
            alive = self.status_value in {"pending", "running", "stopping"}
        return {
            "id": self.id,
            "status": self.status_value,
            "success_count": success_count,
            "fail_count": fail_count,
            "register_count": self.settings.get("register_count", 1),
            "register_threads": self.settings.get("register_threads", 1),
            "consecutive_blocks": consecutive_blocks,
            "block_stop_triggered": block_stop_triggered,
            "stop_requested": self.stop_requested,
            # 线程仍在收尾时 running=True，便于前端继续轮询、禁止重复启动
            "running": alive and self.status_value in {"pending", "running", "stopping"},
            "output_file": self.output_file,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    def _note_registration_outcome(self, success, error_text="", logf=None):
        threshold = int(self.settings.get("stop_on_consecutive_blocks", 3) or 0)
        with self.stats_lock:
            if success:
                self.consecutive_blocks = 0
                return False
            blocked = is_account_blocked_error(error_text)
            if blocked:
                self.consecutive_blocks += 1
            else:
                self.consecutive_blocks = 0
            hit_threshold = bool(threshold and blocked and self.consecutive_blocks >= threshold)
            if hit_threshold:
                self.block_stop_triggered = True
                self.fatal_error = True
                self.stop_requested = True
                consecutive = self.consecutive_blocks
            else:
                consecutive = self.consecutive_blocks
        if hit_threshold and logf:
            logf(
                f"[!] 连续 {consecutive} 个账号出现封禁信号，触发熔断停止剩余任务。"
                "请更换代理/出口 IP 或降低并发后重试。"
            )
            try:
                import notify_hub

                notify_hub.emit(
                    "job.circuit_break",
                    title="连续封禁熔断",
                    body=(
                        f"连续 {consecutive} 个账号出现封禁信号，任务已停止。"
                        "请更换代理/出口后重试。"
                    ),
                    level="danger",
                    job_id=self.id,
                    dedupe_key=f"job.circuit_break|{self.id}",
                    settings=self.settings,
                )
            except Exception:
                pass
        elif blocked and logf and threshold:
            logf(f"[!] 检测到账号封禁信号（连续 {consecutive}/{threshold}）")
        return hit_threshold

    def _account_pause_seconds(self):
        base = float(self.settings.get("account_interval_seconds", 12) or 0)
        jitter = float(self.settings.get("account_interval_jitter_seconds", 8) or 0)
        base = max(0.0, base)
        jitter = max(0.0, jitter)
        if base <= 0 and jitter <= 0:
            return 0.0
        delay = base
        if jitter > 0:
            delay += random.uniform(0.0, jitter)
        return max(0.0, delay)

    def _run_single_registration(self, idx, total, logf):
        email = ""
        dev_token = ""
        code = ""
        profile = None
        mail_ok = False
        max_mail_retry = 3
        signup_mode = resolve_signup_mode()
        # 进入单账号流程前先响应停止，避免再开一轮耗时操作
        raise_if_cancelled(self.should_stop)

        # 纯 HTTP：全程无浏览器
        if signup_mode == "http":
            for mail_try in range(1, max_mail_retry + 1):
                try:
                    logf(f"[*] 纯 HTTP 注册 (尝试 {mail_try}/{max_mail_retry})")
                    sso_http, profile = register_via_pure_http(
                        log_callback=logf, cancel_callback=self.should_stop
                    )
                    profile = dict(profile or {})
                    profile["sso"] = sso_http
                    profile["signup_mode"] = "http"
                    email = str(profile.get("email") or "")
                    mail_ok = True
                    break
                except EmailDomainRejected as rejected:
                    remember_rejected_email_domain(
                        getattr(rejected, "domain", None) or str(rejected),
                        log_callback=logf,
                    )
                    if mail_try < max_mail_retry:
                        logf(
                            f"[!] 邮箱域名被拒，换后缀重试: {getattr(rejected, 'domain', rejected)}"
                        )
                        sleep_with_cancel(1, self.should_stop)
                        continue
                    raise
                except Exception as mail_exc:
                    msg = str(mail_exc)
                    retriable = (
                        "未收到验证码" in msg
                        or "验证码" in msg
                        or "CreateEmailValidationCode" in msg
                        or "grpc=None" in msg
                        or any(c in msg for c in ("403", "429", "502", "503", "504"))
                        or "邮箱服务" in msg
                        or "TLS connect" in msg
                    )
                    if retriable and mail_try < max_mail_retry:
                        logf(f"[!] HTTP 注册失败，换邮箱重试: {msg[:160]}")
                        sleep_with_cancel(0.8 * mail_try, self.should_stop)
                        continue
                    raise
            if not mail_ok:
                raise Exception("HTTP 注册失败，已达最大重试次数")
            logf(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
            sso = str((profile or {}).get("sso") or "").strip()
            if not sso:
                raise Exception("HTTP 注册未返回 sso")
            logf("[*] 5. 已通过纯 HTTP 获取 sso")
        else:
            for mail_try in range(1, max_mail_retry + 1):
                raise_if_cancelled(self.should_stop)
                logf(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
                open_signup_page(log_callback=logf, cancel_callback=self.should_stop)
                logf("[*] 2. 创建邮箱并提交")
                try:
                    email, dev_token = fill_email_and_submit(
                        log_callback=logf, cancel_callback=self.should_stop
                    )
                except EmailDomainRejected as rejected:
                    remember_rejected_email_domain(rejected.domain, log_callback=logf)
                    if mail_try < max_mail_retry:
                        logf(
                            f"[!] 邮箱域名被 x.ai 拒收，冷却主域并换后缀重试: {rejected.domain}"
                        )
                        restart_browser(log_callback=logf)
                        sleep_with_cancel(1, self.should_stop)
                        continue
                    raise
                logf(f"[*] 邮箱: {email}")
                try:
                    with open(
                        os.path.join(get_data_dir(), "mail_credentials.txt"),
                        "a",
                        encoding="utf-8",
                    ) as f:
                        f.write(f"{email}\t{dev_token}\n")
                except Exception:
                    pass
                logf("[*] 3. 拉取验证码")
                try:
                    code = fill_code_and_submit(
                        email, dev_token, log_callback=logf, cancel_callback=self.should_stop
                    )
                    logf(f"[*] 验证码: {code}")
                    if signup_mode == "api":
                        logf("[*] 4. API 建号（浏览器OTP + HTTP create_account）")
                        sso_api, profile = register_via_api_after_otp(
                            email,
                            code,
                            log_callback=logf,
                            cancel_callback=self.should_stop,
                        )
                        profile = dict(profile or {})
                        profile["sso"] = sso_api
                        profile["signup_mode"] = "api"
                    else:
                        logf("[*] 4. 填写资料（浏览器 SPA）")
                        profile = fill_profile_and_submit(
                            log_callback=logf, cancel_callback=self.should_stop
                        )
                        profile = dict(profile or {})
                        profile["signup_mode"] = "browser"
                    mail_ok = True
                    break
                except ProfileSessionLost as profile_exc:
                    if mail_try < max_mail_retry:
                        logf(f"[!] 注册会话丢失，自动换邮箱重试: {profile_exc}")
                        restart_browser(log_callback=logf)
                        sleep_with_cancel(1, self.should_stop)
                        continue
                    raise
                except Exception as mail_exc:
                    msg = str(mail_exc)
                    if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                        logf(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                        restart_browser(log_callback=logf)
                        sleep_with_cancel(1, self.should_stop)
                        continue
                    raise
            if not mail_ok:
                raise Exception("验证码阶段失败，已达到最大重试次数")
            logf(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
            sso = str((profile or {}).get("sso") or "").strip()
            if sso:
                logf("[*] 5. 已通过 API create_account 获取 sso")
            else:
                logf("[*] 5. 等待 sso cookie")
                sso = wait_for_sso_cookie(log_callback=logf, cancel_callback=self.should_stop)
        raise_if_cancelled(self.should_stop)
        if self.settings.get("enable_nsfw"):
            logf("[*] 6. 开启 NSFW")
            nsfw_ok, nsfw_message = enable_nsfw_for_token(sso, log_callback=logf)
            if nsfw_ok:
                logf("[*] NSFW 已开启")
            else:
                logf(f"[!] NSFW 开启失败，继续注册流程: {nsfw_message}")
        raise_if_cancelled(self.should_stop)
        logf("[*] 7. 获取 Refresh Token")
        refresh_token = fetch_xai_oauth_refresh_token(
            sso, log_callback=logf, cancel_callback=self.should_stop
        )
        cpa_push_item = None
        if self.settings.get("cpa_auto_push_remote"):
            raise_if_cancelled(self.should_stop)
            logf("[*] 8. 推送 CPA 凭证")
            try:
                cpa_result = export_and_push_cpa_credential(
                    email, refresh_token, self.settings, log_callback=logf
                )
                rotated_refresh_token = str(cpa_result.get("refresh_token") or "").strip()
                if rotated_refresh_token:
                    refresh_token = rotated_refresh_token
                if cpa_result.get("upload_error"):
                    logf(f"[!] CPA 凭证推送失败，已保留本地文件: {cpa_result['upload_error']}")
                    cpa_push_item = {
                        "email": email,
                        "status": "failed",
                        "error": str(cpa_result.get("upload_error") or ""),
                    }
                elif cpa_result.get("uploaded"):
                    logf(f"[+] CPA 凭证已推送: {cpa_result.get('filename', '')}")
                    cpa_push_item = {"email": email, "status": "pushed", "response": cpa_result}
                else:
                    # 仅本地生成也算部分成功
                    cpa_push_item = {
                        "email": email,
                        "status": "pushed" if cpa_result else "failed",
                        "response": cpa_result,
                    }
            except Exception as cpa_exc:
                logf(f"[!] CPA 凭证生成或推送失败，继续注册流程: {cpa_exc}")
                cpa_push_item = {"email": email, "status": "failed", "error": str(cpa_exc)}
        account_created_at = datetime.datetime.now().isoformat(timespec="seconds")
        with self.stats_lock:
            # 用文件真实行号生成 account id，避免 success_count 与行号不一致导致状态对不上
            out_path = os.path.join(get_data_dir(), self.output_file)
            try:
                if os.path.isfile(out_path):
                    with open(out_path, "r", encoding="utf-8") as rf:
                        source_line_no = sum(1 for _ in rf) + 1
                else:
                    source_line_no = 1
            except Exception:
                source_line_no = self.success_count + 1
            self.results.append(
                {"email": email, "sso": sso, "refresh_token": refresh_token, "profile": profile}
            )
            self.success_count += 1
            line = f"{email}----{profile.get('password','')}----{sso}----{refresh_token}\n"
            try:
                with _registered_accounts_lock:
                    with open(out_path, "a", encoding="utf-8") as f:
                        f.write(line)
                invalidate_account_list_cache()
            except Exception as file_exc:
                logf(f"[Debug] 保存账号文件失败: {file_exc}")
        try:
            self._persist_status()
        except Exception:
            pass
        account = parse_registered_account_line(
            line,
            source=self.output_file,
            line_no=source_line_no,
            include_sso=True,
            created_at=account_created_at,
        ) or {
            "id": _account_id(self.output_file, source_line_no, email, sso),
            "email": email,
            "sso": sso,
            "refresh_token": refresh_token,
            "has_refresh_token": bool(refresh_token),
            "source_file": self.output_file,
            "line_no": source_line_no,
            "created_at": account_created_at,
        }
        try:
            persist_account_created_at(account, account_created_at)
        except Exception as st_exc:
            logf(f"[Debug] 写入账号创建时间失败: {st_exc}")
        # 保证 id 始终存在，便于状态落盘
        if not account.get("id"):
            account["id"] = _account_id(
                account.get("source_file") or self.output_file,
                int(account.get("line_no") or source_line_no or 0),
                email,
                sso,
            )

        # CPA：按实际推送结果写状态
        if cpa_push_item is not None:
            try:
                persist_cpa_push_status([account], {"items": [cpa_push_item]})
            except Exception as st_exc:
                logf(f"[Debug] 写入 CPA 推送状态失败: {st_exc}")

        # grok2api：无论走 pools 还是 auto_push，都落状态
        try:
            add_token_to_grok2api_pools(sso, email=email, log_callback=logf)
            if self.settings.get("grok2api_auto_add_remote") or self.settings.get(
                "grok2api_auto_add_local", True
            ):
                persist_grok2api_push_status(
                    [account],
                    {"items": [{"email": email, "status": "pushed"}]},
                )
        except Exception as grok_exc:
            logf(f"[Debug] grok2api 写入失败: {grok_exc}")
            try:
                persist_grok2api_push_status(
                    [account],
                    {"items": [{"email": email, "status": "failed", "error": str(grok_exc)}]},
                )
            except Exception:
                pass

        auto_push_registered_account(account, self.settings, log_callback=logf)
        self._note_registration_outcome(True, logf=logf)
        try:
            note_mail_domain_outcome(email, success=True, log_callback=logf)
        except Exception:
            pass
        logf(f"[+] 注册成功: {email}")
        try:
            import notify_hub

            notify_hub.maybe_milestone(
                self.id,
                int(self.success_count or 0),
                settings=self.settings,
            )
        except Exception:
            pass

    def _worker_loop(self, worker_id, total, task_queue):
        prefix = f"[T{worker_id}]"
        logf = lambda m: self.log(f"{prefix} {m}")
        signup_mode = resolve_signup_mode()
        need_browser = signup_mode != "http"
        try:
            if need_browser:
                start_browser(log_callback=logf)
                logf("[*] 浏览器已启动")
            else:
                logf("[*] 纯 HTTP 模式（不启动浏览器）")
            while not self.should_stop():
                try:
                    idx = task_queue.get_nowait()
                except queue.Empty:
                    break
                logf(f"--- 开始第 {idx}/{total} 个账号 ---")
                try:
                    self._run_single_registration(idx, total, logf)
                except RegistrationCancelled:
                    logf("[!] 注册被用户停止")
                    break
                except EmailProviderUnavailable as exc:
                    with self.stats_lock:
                        self.fail_count += 1
                    self.fatal_error = True
                    self.stop_requested = True
                    logf(f"[!] 邮箱服务商不可用，停止剩余任务: {exc}")
                    break
                except Exception as exc:
                    with self.stats_lock:
                        self.fail_count += 1
                    self._note_registration_outcome(False, str(exc), logf=logf)
                    logf(f"[-] 注册失败: {exc}")
                    try:
                        self._persist_status()
                    except Exception:
                        pass
                finally:
                    should_stop_after_task = self.should_stop()
                    has_more_tasks = (not task_queue.empty()) and (not should_stop_after_task)
                    if has_more_tasks:
                        pause_seconds = self._account_pause_seconds()
                        if pause_seconds > 0:
                            logf(f"[*] 账号间隔等待 {pause_seconds:.1f}s，降低批量节奏")
                            sleep_with_cancel(pause_seconds, self.should_stop)
                        if need_browser:
                            restart_browser(log_callback=logf)
                            sleep_with_cancel(1, self.should_stop)
                if should_stop_after_task:
                    break
        except Exception as exc:
            logf(f"[!] 线程异常: {exc}")
        finally:
            if need_browser:
                stop_browser()

    def _run(self):
        replace_config({**DEFAULT_CONFIG, **self.settings})
        count = self.settings["register_count"]
        worker_count = max(1, min(self.settings["register_threads"], count))
        task_queue = queue.Queue()
        for i in range(1, count + 1):
            task_queue.put(i)
        workers = []
        account_interval = float(self.settings.get("account_interval_seconds", 12) or 0)
        account_jitter = float(self.settings.get("account_interval_jitter_seconds", 8) or 0)
        block_threshold = int(self.settings.get("stop_on_consecutive_blocks", 3) or 0)
        provider = str(self.settings.get("email_provider") or config.get("email_provider") or "").strip()
        self.log(f"[*] 配置已保存，开始执行。目标数量: {count}，并发线程: {worker_count}")
        self.log(f"[*] 邮箱服务商: {provider or '未知'}（收信走该 provider，不是 DuckMail 标签就一定是 DuckMail）")
        self.log(
            f"[*] 风控节奏: 账号间隔 {account_interval:.1f}s ±{account_jitter:.1f}s，"
            f"连续封禁熔断 {block_threshold or '关闭'}，"
            f"注册后 NSFW={'开' if self.settings.get('enable_nsfw') else '关'}"
        )
        # 域名拒收只走内存池冷却，不加载永久黑名单（对齐 openai-cpa）
        self.log(f"[*] 成功账号将实时保存到: {os.path.join(get_data_dir(), self.output_file)}")
        try:
            start_interval = float(self.settings.get("thread_start_interval", 2.0))
        except Exception:
            start_interval = 2.0
        start_interval = max(0.0, start_interval)

        try:
            for wid in range(1, worker_count + 1):
                if self.stop_requested:
                    break
                worker = threading.Thread(
                    target=self._worker_loop,
                    args=(wid, count, task_queue),
                    daemon=True,
                )
                workers.append(worker)
                worker.start()
                if wid < worker_count and start_interval > 0:
                    sleep_with_cancel(start_interval, self.should_stop)
            for worker in workers:
                worker.join()
            if self.fatal_error:
                self.status_value = "failed"
            elif self.stop_requested:
                self.status_value = "stopped"
            elif self.fail_count and not self.success_count:
                self.status_value = "failed"
            else:
                self.status_value = "completed"
        except RegistrationCancelled:
            self.status_value = "stopped"
        except Exception as exc:
            self.status_value = "failed"
            self.log(f"[!] 任务异常: {exc}")
        finally:
            self.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
            self.log("[*] 任务结束")
            try:
                self._persist_status()
            except Exception:
                pass
            try:
                import notify_hub

                status = self.status_value
                body = (
                    f"成功 {self.success_count} / 失败 {self.fail_count}"
                    f" · 目标 {self.settings.get('register_count', 1)}"
                )
                if status == "completed":
                    notify_hub.emit(
                        "job.completed",
                        title="注册任务完成",
                        body=body,
                        level="info",
                        job_id=self.id,
                        dedupe_key=f"job.completed|{self.id}",
                        settings=self.settings,
                    )
                elif status == "stopped":
                    notify_hub.emit(
                        "job.stopped",
                        title="注册任务已停止",
                        body=body,
                        level="warn",
                        job_id=self.id,
                        dedupe_key=f"job.stopped|{self.id}",
                        settings=self.settings,
                    )
                elif status == "failed":
                    notify_hub.emit(
                        "job.failed",
                        title="注册任务失败",
                        body=body,
                        level="danger",
                        job_id=self.id,
                        dedupe_key=f"job.failed|{self.id}",
                        settings=self.settings,
                    )
            except Exception:
                pass


def generate_random_birthdate():
    import datetime as dt

    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def set_birth_date(session, log_callback=None):
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(
                f"[Debug] set_birth_date status: {res.status_code}, body: {res.text[:200]}"
            )
        return res.status_code == 200
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 寮傚父: {e}")
        return False


def set_tos_accepted(session, log_callback=None):
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        return res.status_code == 200
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 寮傚父: {e}")
        return False


def encode_grpc_nsfw_settings():
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None):
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] update_nsfw status: {res.status_code}")
        return res.status_code == 200
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 寮傚父: {e}")
        return False


def enable_nsfw_for_token(token, cf_clearance="", log_callback=None):
    proxies = get_proxies()
    user_agent = get_user_agent()
    try:
        with requests.Session(impersonate="chrome120", proxies=proxies) as session:
            session.headers.update(
                {
                    "user-agent": user_agent,
                    "cookie": f"sso={token}; sso-rw={token}; cf_clearance={cf_clearance}",
                }
            )
            if not set_tos_accepted(session, log_callback):
                return False, "set_tos_accepted 澶辫触!"
            if not set_birth_date(session, log_callback):
                return False, "set_birth_date 澶辫触!"
            if not update_nsfw_settings(session, log_callback):
                return False, "update_nsfw_settings 澶辫触!"
            return True, "鎴愬姛寮€鍚疦SFW"
    except Exception as e:
        return False, f"寮傚父: {str(e)}"


class GrokRegisterGUI:
    def __init__(self, root):
        if tk is None:
            raise RuntimeError("当前 Python 未安装 Tkinter，无法启动桌面 GUI；请使用 web_app.py")
        self.root = root
        self.root.title("Grok 注册机")
        self.root.geometry("980x860")
        self.root.minsize(900, 760)
        self.is_running = False
        self.batch_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.stop_requested = False
        self.ui_queue = queue.Queue()
        self.accounts_output_file = ""
        self.stats_lock = threading.Lock()
        self._tutorial_window = None
        self.current_job = None
        self.setup_ui()
        self.root.after(200, self._maybe_show_tutorial_on_start)

    def setup_ui(self):
        load_config()
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        config_frame = ttk.LabelFrame(main_frame, text="配置", padding=10)
        config_frame.pack(fill=tk.X, pady=5)
        ttk.Label(config_frame, text="邮箱服务商:").grid(row=0, column=0, sticky=tk.W)
        self.email_provider_var = tk.StringVar(value=config.get("email_provider", "duckmail"))
        self.email_provider_combo = ttk.Combobox(config_frame, textvariable=self.email_provider_var, values=["duckmail", "yyds", "cloudflare", "cloudmail"], width=12, state="readonly")
        self.email_provider_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="注册数量:").grid(row=0, column=2, sticky=tk.W, padx=10)
        self.count_var = tk.StringVar(value=str(config.get("register_count", 1)))
        self.count_spinbox = ttk.Spinbox(config_frame, from_=1, to=100, width=8, textvariable=self.count_var)
        self.count_spinbox.grid(row=0, column=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="并发线程:").grid(row=1, column=2, sticky=tk.W, padx=10)
        self.thread_var = tk.StringVar(value=str(config.get("register_threads", 1)))
        self.thread_spinbox = ttk.Spinbox(config_frame, from_=1, to=10, width=8, textvariable=self.thread_var)
        self.thread_spinbox.grid(row=1, column=3, sticky=tk.W, padx=5)
        self.nsfw_var = tk.BooleanVar(value=config.get("enable_nsfw", True))
        self.nsfw_check = ttk.Checkbutton(config_frame, text="注册后开启 NSFW", variable=self.nsfw_var)
        self.nsfw_check.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Label(config_frame, text="代理（可选）:").grid(row=2, column=0, sticky=tk.W)
        self.proxy_var = tk.StringVar(value=config.get("proxy", ""))
        self.proxy_entry = ttk.Entry(config_frame, textvariable=self.proxy_var, width=30)
        self.proxy_entry.grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="DuckMail API Key:").grid(row=3, column=0, sticky=tk.W)
        self.api_key_var = tk.StringVar(value=config.get("duckmail_api_key", ""))
        self.api_key_entry = ttk.Entry(config_frame, textvariable=self.api_key_var, width=30)
        self.api_key_entry.grid(row=3, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="Cloudflare API Base:").grid(row=4, column=0, sticky=tk.W)
        self.cloudflare_api_base_var = tk.StringVar(value=config.get("cloudflare_api_base", ""))
        self.cloudflare_api_base_entry = ttk.Entry(config_frame, textvariable=self.cloudflare_api_base_var, width=30)
        self.cloudflare_api_base_entry.grid(row=4, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="Cloudflare API Key:").grid(row=5, column=0, sticky=tk.W)
        self.cloudflare_api_key_var = tk.StringVar(value=config.get("cloudflare_api_key", ""))
        self.cloudflare_api_key_entry = ttk.Entry(config_frame, textvariable=self.cloudflare_api_key_var, width=30)
        self.cloudflare_api_key_entry.grid(row=5, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="Cloudflare 鉴权模式:").grid(row=6, column=0, sticky=tk.W)
        self.cloudflare_auth_mode_var = tk.StringVar(value=config.get("cloudflare_auth_mode", "bearer"))
        self.cloudflare_auth_mode_combo = ttk.Combobox(
            config_frame,
            textvariable=self.cloudflare_auth_mode_var,
            values=["query-key", "bearer", "x-api-key", "none"],
            width=12,
            state="readonly",
        )
        self.cloudflare_auth_mode_combo.grid(row=6, column=1, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="CF 路径(domains/accounts/token/messages):").grid(row=7, column=0, sticky=tk.W)
        self.cloudflare_paths_var = tk.StringVar(
            value=",".join(
                [
                    config.get("cloudflare_path_domains", "/domains"),
                    config.get("cloudflare_path_accounts", "/accounts"),
                    config.get("cloudflare_path_token", "/token"),
                    config.get("cloudflare_path_messages", "/messages"),
                ]
            )
        )
        self.cloudflare_paths_entry = ttk.Entry(config_frame, textvariable=self.cloudflare_paths_var, width=30)
        self.cloudflare_paths_entry.grid(row=7, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="CloudMail URL:").grid(row=8, column=0, sticky=tk.W)
        self.cloudmail_url_var = tk.StringVar(value=str(config.get("cloudmail_url", "")))
        self.cloudmail_url_entry = ttk.Entry(config_frame, textvariable=self.cloudmail_url_var, width=30)
        self.cloudmail_url_entry.grid(row=8, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="CloudMail 管理员邮箱:").grid(row=9, column=0, sticky=tk.W)
        self.cloudmail_admin_email_var = tk.StringVar(value=str(config.get("cloudmail_admin_email", "")))
        self.cloudmail_admin_email_entry = ttk.Entry(config_frame, textvariable=self.cloudmail_admin_email_var, width=30)
        self.cloudmail_admin_email_entry.grid(row=9, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="CloudMail 管理员密码:").grid(row=10, column=0, sticky=tk.W)
        self.cloudmail_password_var = tk.StringVar(value=str(config.get("cloudmail_password", "")))
        self.cloudmail_password_entry = ttk.Entry(config_frame, textvariable=self.cloudmail_password_var, width=30, show="*")
        self.cloudmail_password_entry.grid(row=10, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 本地自动入池:").grid(row=11, column=0, sticky=tk.W)
        self.grok2api_local_auto_var = tk.BooleanVar(value=bool(config.get("grok2api_auto_add_local", True)))
        self.grok2api_local_auto_check = ttk.Checkbutton(config_frame, variable=self.grok2api_local_auto_var)
        self.grok2api_local_auto_check.grid(row=11, column=1, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 本地 token.json:").grid(row=12, column=0, sticky=tk.W)
        self.grok2api_local_file_var = tk.StringVar(value=str(config.get("grok2api_local_token_file", "")))
        self.grok2api_local_file_entry = ttk.Entry(config_frame, textvariable=self.grok2api_local_file_var, width=30)
        self.grok2api_local_file_entry.grid(row=12, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 池名:").grid(row=13, column=0, sticky=tk.W)
        self.grok2api_pool_name_var = tk.StringVar(value=str(config.get("grok2api_pool_name", "ssoBasic")))
        self.grok2api_pool_name_combo = ttk.Combobox(
            config_frame,
            textvariable=self.grok2api_pool_name_var,
            values=["ssoBasic", "ssoSuper"],
            width=12,
            state="readonly",
        )
        self.grok2api_pool_name_combo.grid(row=13, column=1, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 远端自动入池:").grid(row=14, column=0, sticky=tk.W)
        self.grok2api_remote_auto_var = tk.BooleanVar(value=bool(config.get("grok2api_auto_add_remote", False)))
        self.grok2api_remote_auto_check = ttk.Checkbutton(config_frame, variable=self.grok2api_remote_auto_var)
        self.grok2api_remote_auto_check.grid(row=14, column=1, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 远端 Base:").grid(row=15, column=0, sticky=tk.W)
        self.grok2api_remote_base_var = tk.StringVar(value=str(config.get("grok2api_remote_base", "")))
        self.grok2api_remote_base_entry = ttk.Entry(config_frame, textvariable=self.grok2api_remote_base_var, width=30)
        self.grok2api_remote_base_entry.grid(row=15, column=1, columnspan=3, sticky=tk.W, padx=5)

        ttk.Label(config_frame, text="grok2api 远端 app_key:").grid(row=16, column=0, sticky=tk.W)
        self.grok2api_remote_key_var = tk.StringVar(value=str(config.get("grok2api_remote_app_key", "")))
        self.grok2api_remote_key_entry = ttk.Entry(config_frame, textvariable=self.grok2api_remote_key_var, width=30)
        self.grok2api_remote_key_entry.grid(row=16, column=1, columnspan=3, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="默认域名(defaultDomains):").grid(row=17, column=0, sticky=tk.W)
        self.default_domains_var = tk.StringVar(value=str(config.get("defaultDomains", "")))
        self.default_domains_entry = ttk.Entry(config_frame, textvariable=self.default_domains_var, width=30)
        self.default_domains_entry.grid(row=17, column=1, columnspan=3, sticky=tk.W, padx=5)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.start_btn = ttk.Button(btn_frame, text="开始注册", command=self.start_registration)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="停止", command=self.stop_registration, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = ttk.Button(btn_frame, text="清空日志", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        self.help_btn = ttk.Button(btn_frame, text="教程", command=self.show_tutorial)
        self.help_btn.pack(side=tk.LEFT, padx=5)
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, text="状态: ").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="green")
        self.status_label.pack(side=tk.LEFT)
        self.stats_var = tk.StringVar(value="成功: 0 | 失败: 0")
        ttk.Label(status_frame, textvariable=self.stats_var).pack(side=tk.RIGHT)
        log_frame = ttk.LabelFrame(main_frame, text="日志", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=60)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        # 仅当用户当前就在底部时自动跟随，避免手动上滑后被强制拉回底部
        yview = self.log_text.yview()
        at_bottom = bool(yview) and yview[1] >= 0.999
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        if at_bottom:
            self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def update_stats(self):
        self.stats_var.set(f"成功: {self.success_count} | 失败: {self.fail_count}")

    def _set_running_ui(self, running):
        self.is_running = running
        self.start_btn.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if running else tk.DISABLED)
        self.status_var.set("运行中..." if running else "就绪")
        self.status_label.config(foreground="blue" if running else "green")

    def _maybe_show_tutorial_on_start(self):
        if bool(config.get("show_tutorial_on_start", True)):
            self.show_tutorial()

    def _tutorial_text(self):
        return """欢迎使用 Grok 注册机。建议按下面顺序填写（从最关键到可选）：

【第一步：先确定邮箱后端信息从哪里来】
如果你使用 cloudflare 模式（你当前主要是这套），先去你的临时邮箱服务配置接口查信息：
- 常见接口: /open_api/settings、/api/settings、/health_check
- 重点字段:
  - api_base（对应本工具的 Cloudflare API Base）
  - domains / defaultDomains（可用域名）
  - needAuth（是否需要鉴权）
  - admin_password 或 api_key（需要鉴权时使用）
  - provider.type（应为 cloudflare_temp_email）

【第二步：先填最小可运行配置】
1) 邮箱服务商
- duckmail: 需要 DuckMail API Key
- yyds: 需要 YYDS API Key 或 JWT
- cloudflare: 需要 Cloudflare API Base（cloudflare_temp_email 临时邮箱）
- cloudmail: 需要 CloudMail URL + 密码 + defaultDomains（maillab/cloud-mail 完整邮箱）

2) Cloudflare API Base（cloudflare 模式必填）
- 示例: https://xxxx.pages.dev
- 填写规则: 与 settings 接口中的 api_base 保持一致

3) 默认域名(defaultDomains)
- 填写你要优先使用的域名
- 支持单域名或逗号分隔多域名轮换
- 示例: a.com,b.com

4) CF 路径(domains/accounts/token/messages)
- 必须与后端真实路由一致
- 常见新路径:
  - /api/domains,/api/new_address,/api/token,/api/mails
- 常见旧路径:
  - /domains,/accounts,/token,/messages

5) Cloudflare API Key / 鉴权模式
- needAuth=false: 通常鉴权模式选 none，key 可留空
- needAuth=true: 按后端要求填 key，并选择 bearer/x-api-key/query-key

6) CloudMail 模式配置（maillab/cloud-mail 部署）
- CloudMail URL: 你的 Worker 地址，如 https://mail.xxx.workers.dev
- CloudMail 管理员邮箱: 管理员账号，如 admin@yourdomain.com
- CloudMail 管理员密码: 管理员密码（用于获取公开 API token 查询邮件）
- defaultDomains: 必须填写可用域名，如 yourdomain.com
- 前提: CloudMail 管理面板需关闭注册验证码（Turnstile），或确保注册接口可用
- 邮件获取: 通过 /api/public/emailList 公开接口查询，自动刷新 token

【第三步：并发与稳定性】
6) 注册数量
- 本次要注册的总账号数

7) 并发线程
- 建议先 3-6 稳定后再升到 10

8) 代理（可选）
- 不填=直连
- 示例: http://127.0.0.1:7890
- 代理不稳会影响验证码和注册稳定性

9) 注册后开启 NSFW
- 勾选后成功账号会自动调用接口开启对应设置

【第四步：grok2api 入池（可选）】
10) grok2api 本地自动入池
- 开启后把成功 sso 自动写入本地池
- 本地 token.json 填 grok2api 的 token.json 路径

11) grok2api 池名
- ssoBasic 或 ssoSuper

12) grok2api 远端自动入池
- 开启后调用远端管理接口自动加 token
- 远端 Base 示例: https://xxx/admin/api
- app_key 按远端服务配置填写

【最后：快速自检】
1) 先设置: 注册数量=1，并发线程=1
2) 点开始后看日志是否出现：
- 已创建邮箱: xxx@你的域名
- Cloudflare/CloudMail 本轮邮件数量: ...
- 从邮件中提取到验证码: ...
3) 若第一步就失败：
- cloudflare 模式: 检查 API Base / CF 路径 / 鉴权模式
- cloudmail 模式: 检查 URL / 密码 / defaultDomains / 注册接口是否可用

提示:
- 点“开始注册”会自动保存当前配置到 config.json。
- 如果关闭了启动教程，可随时点主界面的“教程”按钮重新打开。"""

    def show_tutorial(self):
        if self._tutorial_window is not None and self._tutorial_window.winfo_exists():
            self._tutorial_window.lift()
            self._tutorial_window.focus_force()
            return

        win = tk.Toplevel(self.root)
        self._tutorial_window = win
        win.title("使用教程")
        win.geometry("760x620")
        win.minsize(680, 520)
        win.transient(self.root)

        frame = ttk.Frame(win, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        txt = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=26)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert("1.0", self._tutorial_text())
        txt.config(state=tk.DISABLED)

        footer = ttk.Frame(frame)
        footer.pack(fill=tk.X, pady=(8, 0))

        dont_show_var = tk.BooleanVar(value=not bool(config.get("show_tutorial_on_start", True)))
        chk = ttk.Checkbutton(
            footer,
            text="以后不再自动显示本教程",
            variable=dont_show_var,
        )
        chk.pack(side=tk.LEFT)

        def on_close():
            config["show_tutorial_on_start"] = not bool(dont_show_var.get())
            save_config()
            try:
                win.destroy()
            except Exception:
                pass

        close_btn = ttk.Button(footer, text="关闭", command=on_close)
        close_btn.pack(side=tk.RIGHT, padx=5)
        win.protocol("WM_DELETE_WINDOW", on_close)

    def should_stop(self):
        if self.current_job is not None:
            return self.current_job.should_stop()
        return self.stop_requested or not self.is_running

    def start_registration(self):
        if self.is_running:
            self.log("[!] 当前已有任务在运行")
            return

        settings = {
            "email_provider": self.email_provider_var.get().strip() or "duckmail",
            "proxy": self.proxy_var.get().strip(),
            "duckmail_api_key": self.api_key_var.get().strip(),
            "cloudflare_api_base": self.cloudflare_api_base_var.get().strip(),
            "cloudflare_api_key": self.cloudflare_api_key_var.get().strip(),
            "cloudflare_auth_mode": self.cloudflare_auth_mode_var.get().strip() or "bearer",
            "cloudmail_url": self.cloudmail_url_var.get().strip(),
            "cloudmail_admin_email": self.cloudmail_admin_email_var.get().strip(),
            "cloudmail_password": self.cloudmail_password_var.get().strip(),
            "grok2api_auto_add_local": bool(self.grok2api_local_auto_var.get()),
            "grok2api_local_token_file": self.grok2api_local_file_var.get().strip(),
            "grok2api_pool_name": self.grok2api_pool_name_var.get().strip() or "ssoBasic",
            "grok2api_auto_add_remote": bool(self.grok2api_remote_auto_var.get()),
            "grok2api_remote_base": self.grok2api_remote_base_var.get().strip(),
            "grok2api_remote_app_key": self.grok2api_remote_key_var.get().strip(),
            "defaultDomains": self.default_domains_var.get().strip(),
            "register_count": self.count_var.get(),
            "register_threads": self.thread_var.get(),
            "cloudflare_paths": self.cloudflare_paths_var.get(),
            "enable_nsfw": bool(self.nsfw_var.get()),
        }
        try:
            validated = validate_registration_config(settings)
        except ValueError as exc:
            self.log(f"[!] {exc}")
            return
        config.update(validated)
        save_config()
        self.stop_requested = False
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.update_stats()
        self._set_running_ui(True)
        self.current_job = RegistrationJob(validated, log_sink=self.log)
        self.accounts_output_file = self.current_job.output_file
        self.current_job.start()
        threading.Thread(
            target=self._watch_job,
            daemon=True,
        ).start()

    def stop_registration(self):
        self.stop_requested = True
        if self.current_job is not None:
            self.current_job.stop()
        self.log("[!] 用户停止注册")

    def _watch_job(self):
        if self.current_job is not None and self.current_job.thread is not None:
            self.current_job.thread.join()
            status = self.current_job.status()
            self.success_count = status["success_count"]
            self.fail_count = status["fail_count"]
            self.results = list(self.current_job.results)
            self.accounts_output_file = status["output_file"]
            self.update_stats()
        self._set_running_ui(False)

def main():
    root = tk.Tk()
    app = GrokRegisterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
