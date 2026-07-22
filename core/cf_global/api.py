"""Cloudflare global API: zones, email DNS, worker deploy, catch-all."""

from __future__ import annotations

import json
import os
import re
import sys

from core.config import config
from core.http_client import get_proxies
from core.runtime import normalize_proxy_for_runtime

try:
    from curl_cffi import requests as _requests_impl
except ModuleNotFoundError:
    _requests_impl = None


def _facade():
    return sys.modules.get("grok_register_ttk")


def _resolve(name, default):
    fac = _facade()
    if fac is not None and hasattr(fac, name):
        val = getattr(fac, name)
        if callable(default) and callable(val) and getattr(val, "__module__", "") == __name__:
            return default
        if val is not None:
            return val
    return default


def _active_config():
    return _resolve("config", config)


def _requests_mod():
    fac = _facade()
    if fac is not None and getattr(fac, "requests", None) is not None:
        return fac.requests
    return _requests_impl


def get_proxies_resolved():
    return _resolve("get_proxies", get_proxies)()


def _build_request_kwargs(**kwargs):
    fn = _resolve("_build_request_kwargs", None)
    if callable(fn) and getattr(fn, "__module__", "") != __name__:
        return fn(**kwargs)
    # local fallback matching core.http_client style
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies_resolved()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


requests = _requests_impl

def get_cf_global_email(settings=None):
    src = settings if isinstance(settings, dict) else _active_config()
    return str((src or {}).get("cf_api_email") or "").strip()


def get_cf_global_api_key(settings=None):
    src = settings if isinstance(settings, dict) else _active_config()
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
    kwargs = _build_request_kwargs(headers=headers, timeout=timeout, proxies=get_proxies_resolved() or {})
    if params:
        kwargs["params"] = params
    if files is not None:
        kwargs["files"] = files
    elif json_body is not None:
        kwargs["json"] = json_body
    method = str(method or "GET").upper()
    if method == "GET":
        resp = _requests_mod().get(url, **kwargs)
    elif method == "POST":
        resp = _requests_mod().post(url, **kwargs)
    elif method == "PUT":
        if hasattr(requests, "put"):
            resp = _requests_mod().put(url, **kwargs)
        else:
            # curl_cffi 无 put 时退化
            resp = _requests_mod().post(url, **kwargs)
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
    settings = {**_active_config(), **dict(settings or {})}
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
    settings = {**_active_config(), **dict(settings or {})}
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
    settings = {**_active_config(), **dict(settings or {})}
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
    settings = {**_active_config(), **dict(settings or {})}
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
    src = settings if isinstance(settings, dict) else _active_config()
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
    kwargs = _build_request_kwargs(timeout=timeout, proxies=get_proxies_resolved() or {})
    resp = _requests_mod().get(OPENAI_CPA_EMAIL_WORKER_RAW_URL, **kwargs)
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
    settings = {**_active_config(), **dict(settings or {})}
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
    settings = {**_active_config(), **dict(settings or {})}
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


