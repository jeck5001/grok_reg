import hashlib
import hmac
import os
import re
import secrets
import time
from collections import Counter
from pathlib import Path
from threading import Lock
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

import grok_register_ttk as reg


ROOT = Path(__file__).resolve().parent
SENSITIVE_KEYS = {
    "duckmail_api_key",
    "cloudflare_api_key",
    "cf_api_key",
    "cloudmail_password",
    "grok2api_remote_app_key",
    "sub2api_admin_token",
    "cpa_management_key",
    "yyds_api_key",
    "yyds_jwt",
    "email_webhook_secret",
    "notify_telegram_bot_token",
    "web_password",
}

# ---------- 公网访问密码（会话 Cookie）----------
# 优先级：环境变量 GROK_REG_WEB_PASSWORD > 配置 web_password > 默认 admin
# 设为空字符串可关闭登录校验（仅建议内网）。
_AUTH_COOKIE = "grok_reg_session"
_AUTH_SESSIONS = {}  # token -> {"exp": unix, "ua": str}
_AUTH_LOCK = Lock()
_AUTH_TTL_SEC = 7 * 24 * 3600
_AUTH_PUBLIC_PREFIXES = (
    "/healthz",
    "/api/auth/login",
    "/api/auth/status",
    "/api/webhook/email",  # Worker 推信用自己的 secret
    "/login",
    "/static/",
)
_login_fail_until = {}  # ip -> unix unlock time
_login_fail_count = {}

_FAIL_REASON_RULES = (
    ("domain_rejected", ("域名被拒", "EmailDomainRejected", "account_email_domain_rejected", "form_invalid_disposable_email", "已被拒绝")),
    ("otp_missing", ("未收到验证码", "获取验证码失败", "验证码阶段失败")),
    ("create_code", ("CreateEmailValidationCode",)),
    ("turnstile", ("Turnstile", "turnstile_failed", "Solver 不可达", "Solver 失败", "token 过短")),
    ("blocked", ("封禁", "blocked", "account_blocked", "access_denied")),
    ("rate_limited", ("rate_limited", "429", "rate limit")),
    ("session_lost", ("会话丢失", "ProfileSessionLost", "StaleNextAction")),
    ("network", ("TLS connect", "502", "503", "504", "网络错误", "timeout", "超时")),
    ("email_provider", ("邮箱服务", "EmailProviderUnavailable", "Cloudflare 无可用域名")),
)

app = FastAPI(title="Grok Register Web", version="1.0.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

_jobs = {}
_active_job_id = None
_job_lock = Lock()
# pending/running 正常执行；stopping 已请求停止但仍在收尾
_ACTIVE_JOB_STATUSES = frozenset({"pending", "running", "stopping"})


def get_web_password() -> str:
    """返回当前 Web 访问密码；空字符串表示关闭鉴权。"""
    env = os.environ.get("GROK_REG_WEB_PASSWORD")
    if env is not None:
        return str(env)
    try:
        cfg = reg.load_config() or {}
        if "web_password" in cfg:
            return str(cfg.get("web_password") or "")
    except Exception:
        pass
    return "admin"


def auth_enabled() -> bool:
    return bool(str(get_web_password() or "").strip())


def _purge_sessions(now=None):
    now = now if now is not None else time.time()
    dead = [t for t, meta in _AUTH_SESSIONS.items() if float(meta.get("exp") or 0) <= now]
    for t in dead:
        _AUTH_SESSIONS.pop(t, None)


def create_session(request: Request) -> str:
    token = secrets.token_urlsafe(32)
    ua = str(request.headers.get("user-agent") or "")[:180]
    with _AUTH_LOCK:
        _purge_sessions()
        _AUTH_SESSIONS[token] = {"exp": time.time() + _AUTH_TTL_SEC, "ua": ua}
    return token


def destroy_session(token: str) -> None:
    if not token:
        return
    with _AUTH_LOCK:
        _AUTH_SESSIONS.pop(str(token), None)


def session_valid(request: Request) -> bool:
    if not auth_enabled():
        return True
    token = str(request.cookies.get(_AUTH_COOKIE) or "").strip()
    if not token:
        # 兼容 Authorization: Bearer <token>
        auth = str(request.headers.get("authorization") or "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if not token:
        return False
    now = time.time()
    with _AUTH_LOCK:
        _purge_sessions(now)
        meta = _AUTH_SESSIONS.get(token)
        if not meta:
            return False
        if float(meta.get("exp") or 0) <= now:
            _AUTH_SESSIONS.pop(token, None)
            return False
        # 滑动续期
        meta["exp"] = now + _AUTH_TTL_SEC
        return True


def _client_ip(request: Request) -> str:
    xff = str(request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if xff:
        return xff
    if request.client:
        return str(request.client.host or "")
    return ""


def _login_rate_limited(ip: str) -> bool:
    now = time.time()
    until = float(_login_fail_until.get(ip) or 0)
    return until > now


def _note_login_failure(ip: str) -> None:
    n = int(_login_fail_count.get(ip) or 0) + 1
    _login_fail_count[ip] = n
    # 5 次起锁 30s，之后每次失败再加 30s，上限 10 分钟
    if n >= 5:
        lock = min(600, 30 * (n - 4))
        _login_fail_until[ip] = time.time() + lock


def _clear_login_failures(ip: str) -> None:
    _login_fail_count.pop(ip, None)
    _login_fail_until.pop(ip, None)


def _is_public_path(path: str) -> bool:
    p = path or "/"
    if p in {"/healthz", "/login", "/api/auth/login", "/api/auth/status", "/favicon.ico"}:
        return True
    for prefix in _AUTH_PUBLIC_PREFIXES:
        if p == prefix.rstrip("/") or p.startswith(prefix):
            return True
    return False


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path or "/"
        if not auth_enabled() or _is_public_path(path):
            return await call_next(request)
        if session_valid(request):
            return await call_next(request)
        # API → 401 JSON；页面 → 跳转登录
        if path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"detail": "未登录或会话已过期", "code": "auth_required"},
            )
        nxt = path
        if request.url.query:
            nxt = f"{path}?{request.url.query}"
        return RedirectResponse(url=f"/login?next={quote(nxt, safe='/?&=')}", status_code=302)


app.add_middleware(AuthMiddleware)


def mask_config(settings):
    masked = dict(settings)
    for key in SENSITIVE_KEYS:
        value = str(masked.get(key) or "")
        if value:
            masked[key] = "********"
    return masked


def merge_sensitive_values(new_settings):
    current = reg.load_config()
    merged = {**current, **dict(new_settings or {})}
    for key in SENSITIVE_KEYS:
        if merged.get(key) == "********":
            merged[key] = current.get(key, "")
    return merged


def active_job_running():
    if not _active_job_id:
        return False
    job = _jobs.get(_active_job_id)
    if not job:
        return False
    try:
        st = job.status()
        # stopping 仍视为占用中，避免重复启动
        if st.get("status") not in _ACTIVE_JOB_STATUSES and not st.get("running"):
            return False
        return bool(job.thread and job.thread.is_alive())
    except Exception:
        try:
            return job.status().get("status") in _ACTIVE_JOB_STATUSES
        except Exception:
            return False


@app.get("/")
def index(request: Request):
    if auth_enabled() and not session_valid(request):
        return RedirectResponse(url="/login?next=/", status_code=302)
    return FileResponse(ROOT / "templates" / "index.html")


@app.get("/login")
def login_page(request: Request):
    # 已登录则回首页
    if session_valid(request):
        return RedirectResponse(url="/", status_code=302)
    return FileResponse(ROOT / "templates" / "login.html")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "auth_enabled": auth_enabled()}


@app.get("/api/auth/status")
def auth_status(request: Request):
    enabled = auth_enabled()
    return {
        "ok": True,
        "auth_enabled": enabled,
        "authenticated": (not enabled) or session_valid(request),
    }


@app.post("/api/auth/login")
def auth_login(payload: dict, request: Request):
    ip = _client_ip(request)
    if _login_rate_limited(ip):
        left = int(max(1, float(_login_fail_until.get(ip) or 0) - time.time()))
        raise HTTPException(status_code=429, detail=f"尝试过多，请 {left}s 后再试")

    password = str((payload or {}).get("password") or "")
    expected = get_web_password()
    if not str(expected or "").strip():
        # 鉴权关闭时也允许“登录”，直接回成功
        token = create_session(request)
        resp = JSONResponse({"ok": True, "auth_enabled": False, "message": "鉴权已关闭"})
        resp.set_cookie(
            _AUTH_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            max_age=_AUTH_TTL_SEC,
            path="/",
        )
        return resp

    # 常量时间比较
    ok = hmac.compare_digest(
        hashlib.sha256(password.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )
    if not ok:
        _note_login_failure(ip)
        raise HTTPException(status_code=401, detail="密码错误")

    _clear_login_failures(ip)
    token = create_session(request)
    resp = JSONResponse({"ok": True, "auth_enabled": True, "message": "登录成功"})
    # 公网建议反代终止 TLS；Cookie 不强制 Secure，避免纯 HTTP 部署丢会话
    secure = str(request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower() == "https"
    resp.set_cookie(
        _AUTH_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=_AUTH_TTL_SEC,
        path="/",
    )
    return resp


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    token = str(request.cookies.get(_AUTH_COOKIE) or "").strip()
    destroy_session(token)
    resp = JSONResponse({"ok": True, "message": "已退出登录"})
    resp.delete_cookie(_AUTH_COOKIE, path="/")
    return resp


@app.get("/api/config")
def get_config():
    return mask_config(reg.load_config())


@app.put("/api/config")
def update_config(payload: dict):
    settings = merge_sensitive_values(payload)
    try:
        validated = reg.validate_registration_config(settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    reg.config = validated
    reg.save_config()
    return mask_config(validated)


@app.get("/api/mail-domain-pool")
def mail_domain_pool_status():
    """域名内存池运行时状态（对齐 openai-cpa 统计）。"""
    try:
        import mail_domain_pool as mdp

        settings = mdp.settings_from_config(reg.load_config())
        return {"ok": True, "summary": mdp.runtime_summary(settings)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/mail-domain-pool/reset")
def mail_domain_pool_reset():
    try:
        import mail_domain_pool as mdp

        mdp.reset_runtime()
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/mail-domain-pool/clear-domain")
def mail_domain_pool_clear_domain(payload: dict):
    domain = str((payload or {}).get("domain") or "").strip()
    if not domain:
        raise HTTPException(status_code=400, detail="domain required")
    try:
        import mail_domain_pool as mdp

        return {"ok": True, "result": mdp.clear_domain_counters(domain)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/cloudflare/global/test")
def cf_global_test_auth(payload: dict = None):
    """测试 Cloudflare 全局身份鉴权（CF 登录账号 + Global API Key）。"""
    settings = merge_sensitive_values(payload or {})
    result = reg.test_cf_global_auth(settings)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("message") or "鉴权失败")
    return result


@app.get("/api/cloudflare/global/zones")
def cf_global_list_zones(domains: str = Query("", max_length=4000)):
    """查询域名在 CF 账号中的托管状态。domains 逗号分隔；空则用 mail_domains。"""
    settings = reg.load_config()
    try:
        result = reg.list_cf_zones(domains=domains or None, settings=settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return result


@app.post("/api/cloudflare/global/zones")
def cf_global_ensure_zones(payload: dict):
    """把域名加到 CF 托管并返回 NS（已存在则直接返回）。"""
    settings = merge_sensitive_values(payload or {})
    domains = (payload or {}).get("domains") or settings.get("mail_domains") or settings.get("defaultDomains") or ""
    try:
        result = reg.ensure_cf_zones(domains, settings=settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return result


@app.post("/api/cloudflare/global/email-dns")
def cf_global_email_dns(payload: dict):
    """为域名补齐 Email Routing 通配 MX + SPF。"""
    settings = merge_sensitive_values(payload or {})
    domains = (payload or {}).get("domains") or settings.get("mail_domains") or settings.get("defaultDomains") or ""
    try:
        result = reg.ensure_cf_email_routing_dns(domains, settings=settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return result


@app.post("/api/cloudflare/global/deploy-email-worker")
def cf_global_deploy_email_worker(payload: dict, request: Request):
    """部署/更新 openai-cpa-email Worker，并写入 EMAIL_WEBHOOK_* 变量。"""
    settings = merge_sensitive_values(payload or {})
    body = dict(payload or {})
    worker_name = body.get("worker_name") or settings.get("cf_email_worker_name")
    force = body.get("force")
    if force is None:
        force = bool(settings.get("cf_email_worker_force"))
    webhook_url = str(body.get("webhook_url") or settings.get("email_webhook_public_url") or "").strip().rstrip("/")
    if not webhook_url:
        # 从请求 Host 推导（公网反代时 X-Forwarded-* 优先）
        host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
        proto = (
            (request.headers.get("x-forwarded-proto") or request.url.scheme or "http")
            .split(",")[0]
            .strip()
        )
        if host:
            webhook_url = f"{proto}://{host}".rstrip("/")
    webhook_secret = str(
        body.get("webhook_secret") or settings.get("email_webhook_secret") or ""
    ).strip()
    # 掩码占位不要传给 deploy（merge 后 settings 已有真实 secret）
    if webhook_secret == "********":
        webhook_secret = str(settings.get("email_webhook_secret") or "").strip()
    try:
        result = reg.deploy_cf_email_worker(
            settings,
            worker_name=worker_name,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            force=bool(force),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=result.get("message") or "部署失败")
    # 成功后把 worker 名 / 公网 URL 写回配置
    try:
        cfg = reg.load_config()
        changed = False
        name = result.get("worker_name") or worker_name
        if name and str(cfg.get("cf_email_worker_name") or "") != str(name):
            cfg["cf_email_worker_name"] = name
            changed = True
        used_url = str(result.get("webhook_url") or webhook_url or "").strip().rstrip("/")
        if used_url and str(cfg.get("email_webhook_public_url") or "").rstrip("/") != used_url:
            cfg["email_webhook_public_url"] = used_url
            changed = True
        if changed:
            reg.config = reg.validate_registration_config(cfg)
            reg.save_config()
    except Exception:
        pass
    return result


@app.post("/api/cloudflare/global/setup-catch-all")
def cf_global_setup_catch_all(payload: dict):
    """把 mail_domains 的 Email Routing catch-all 指到 Worker。"""
    settings = merge_sensitive_values(payload or {})
    body = dict(payload or {})
    domains = body.get("domains") or settings.get("mail_domains") or settings.get("defaultDomains") or ""
    worker_name = body.get("worker_name") or settings.get("cf_email_worker_name")
    try:
        result = reg.setup_cf_email_catch_all(
            domains=domains, settings=settings, worker_name=worker_name
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return result


@app.post("/api/webhook/email")
async def webhook_email(request: Request):
    """兼容 openai-cpa-email Worker 推送。

    Header: X-Webhook-Secret
    Body: {message_id, to_addr, raw_content}
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    headers = request.headers

    settings = reg.load_config()
    secret_cfg = str(settings.get("email_webhook_secret") or "").strip()
    if not secret_cfg:
        raise HTTPException(status_code=503, detail="email_webhook_secret 未配置")

    header_secret = str(
        headers.get("x-webhook-secret")
        or headers.get("X-Webhook-Secret")
        or ""
    ).strip()
    body_secret = str((payload or {}).get("secret") or "").strip()
    if header_secret != secret_cfg and body_secret != secret_cfg:
        raise HTTPException(status_code=401, detail="invalid webhook secret")

    to_addr = str((payload or {}).get("to_addr") or (payload or {}).get("to") or "").strip()
    raw_content = str((payload or {}).get("raw_content") or (payload or {}).get("raw") or "")
    message_id = str((payload or {}).get("message_id") or (payload or {}).get("id") or "").strip()
    if not to_addr or not raw_content:
        raise HTTPException(status_code=400, detail="to_addr and raw_content required")

    try:
        import webhook_mail_store as wms

        result = wms.store_webhook_mail(
            to_addr=to_addr,
            raw_content=raw_content,
            message_id=message_id,
        )
        return {"ok": True, **result, "stats": wms.stats()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/webhook/email/stats")
def webhook_email_stats():
    try:
        import webhook_mail_store as wms

        return {"ok": True, "stats": wms.stats()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/webhook/email/panel")
def webhook_email_panel(request: Request):
    """openai-cpa-email 联调面板：配置状态 + 收件池 + 推荐 Worker 变量。"""
    import webhook_mail_store as wms

    settings = reg.load_config()
    secret = str(settings.get("email_webhook_secret") or "").strip()
    provider = str(settings.get("email_provider") or "").strip()
    enabled = bool(settings.get("email_webhook_enabled")) or provider in {
        "openai_cpa_email",
        "cpa_email",
    }
    mail_domains = str(settings.get("mail_domains") or settings.get("defaultDomains") or "").strip()
    # 优先用户配置的公网 URL；否则用当前请求 Host 推导（内网时会警告）
    configured_public = str(settings.get("email_webhook_public_url") or "").strip().rstrip("/")
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "127.0.0.1:8787"
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").split(",")[0].strip()
    detected = f"{proto}://{host}".rstrip("/")
    base = configured_public or detected
    path = "/api/webhook/email"
    full_url = f"{base.rstrip('/')}{path}"
    private = reg.is_private_or_local_webhook_url(base)
    sample_domain = ""
    if mail_domains:
        sample_domain = mail_domains.split(",")[0].strip()
    sample_to = f"probe@{sample_domain}" if sample_domain else "probe@your-domain.com"
    worker_name = str(settings.get("cf_email_worker_name") or "openai-cpa-email").strip()

    checks = []
    checks.append(
        {
            "key": "secret",
            "ok": bool(secret),
            "label": "Webhook Secret",
            "detail": "已配置" if secret else "未配置 email_webhook_secret",
        }
    )
    checks.append(
        {
            "key": "public_url",
            "ok": bool(base) and not private,
            "label": "公网 Webhook URL",
            "detail": (
                f"内网/本机不可用: {base}（Worker 访问不到，请改 email_webhook_public_url 为公网域名/IP）"
                if private
                else (base or "未配置")
            ),
        }
    )
    checks.append(
        {
            "key": "provider",
            "ok": provider in {"openai_cpa_email", "cpa_email"} or enabled,
            "label": "收件模式",
            "detail": (
                f"provider={provider or '—'}; webhook={'on' if enabled else 'off'}"
            ),
        }
    )
    checks.append(
        {
            "key": "domains",
            "ok": bool(mail_domains),
            "label": "mail_domains",
            "detail": mail_domains or "未填写主域池",
        }
    )
    stats = wms.stats()
    return {
        "ok": True,
        "enabled": enabled,
        "provider": provider,
        "secret_configured": bool(secret),
        "mail_domains": mail_domains,
        "worker_name": worker_name,
        "public_url_configured": bool(configured_public),
        "public_url_is_private": private,
        "detected_base": detected,
        "webhook": {
            "path": path,
            "suggested_base": base,
            "suggested_full_url": full_url,
            "header": "X-Webhook-Secret",
            "body_example": {
                "message_id": "test-001",
                "to_addr": sample_to,
                "raw_content": "SpaceXAI confirmation code: ABC-DEF",
            },
        },
        "worker_env": {
            "EMAIL_WEBHOOK_URL": base,
            "EMAIL_WEBHOOK_SECRET": "(与配置页 Webhook Secret 相同)",
        },
        "warning": (
            "当前 Webhook URL 是内网地址，Cloudflare Worker 无法回推邮件。"
            "请在下方填写公网域名/IP（或 frp/cloudflared 隧道地址），保存后勾选「强制覆盖」重新部署 Worker。"
            if private
            else ""
        ),
        "checks": checks,
        "stats": stats,
        "ready": all(c.get("ok") for c in checks),
    }


@app.post("/api/webhook/email/self-test")
def webhook_email_self_test(payload: dict = None):
    """本机模拟 Worker 推送一封测试邮件，验证 secret + 内存池 + 验码提取。"""
    import uuid

    import webhook_mail_store as wms

    settings = reg.load_config()
    secret_cfg = str(settings.get("email_webhook_secret") or "").strip()
    if not secret_cfg:
        raise HTTPException(status_code=400, detail="请先配置并保存 email_webhook_secret")

    body = dict(payload or {})
    # 允许用配置里的 secret 自测；也允许省略（用已保存 secret）
    provided = str(body.get("secret") or "").strip()
    if provided and provided != secret_cfg and provided != "********":
        raise HTTPException(status_code=401, detail="secret 与配置不一致")

    mail_domains = str(settings.get("mail_domains") or settings.get("defaultDomains") or "").strip()
    domain = mail_domains.split(",")[0].strip() if mail_domains else "example.com"
    to_addr = str(body.get("to_addr") or f"selftest@{domain}").strip()
    code = str(body.get("code") or "AB1-CD2").strip().upper()
    raw = str(
        body.get("raw_content")
        or f"From: noreply@x.ai\nTo: {to_addr}\nSubject: SpaceXAI confirmation code: {code}\n\nYour code is {code}\n"
    )
    message_id = str(body.get("message_id") or f"selftest-{uuid.uuid4().hex[:12]}")

    stored = wms.store_webhook_mail(to_addr=to_addr, raw_content=raw, message_id=message_id)
    peeked = wms.peek_code_for_email(to_addr)
    return {
        "ok": True,
        "stored": stored,
        "to_addr": to_addr,
        "message_id": message_id,
        "expected_code": code,
        "extracted_code": peeked,
        "extract_ok": bool(peeked)
        and str(peeked).replace("-", "").upper() == code.replace("-", "").upper(),
        "stats": wms.stats(),
        "hint": "Worker 侧请用相同 secret 向 /api/webhook/email 推送；注册时会按 to_addr 取码。",
    }


@app.post("/api/webhook/email/clear")
def webhook_email_clear():
    try:
        import webhook_mail_store as wms

        wms.clear()
        return {"ok": True, "stats": wms.stats()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# 账号列表接口不需要这些大字段（探测失败详情、远端原始响应等）
_ACCOUNT_LIST_DROP_KEYS = (
    "sso",
    "refresh_token",
    "sub2api_response",
    "grok2api_response",
    "cpa_response",
    "health_response",
    "sub2api_error",
    "grok2api_error",
    "cpa_error",
    "health_error",
    "sub2api_probe_error",
)


def public_account(account, *, compact=False):
    item = dict(account)
    item.pop("sso", None)
    item.pop("refresh_token", None)
    if compact:
        for key in _ACCOUNT_LIST_DROP_KEYS:
            item.pop(key, None)
    return item


# 作战室 inventory 短缓存（账号列表已有 mtime 缓存，这里再缓存摘要结果）
_inventory_cache = {"signature": None, "status_mtime": None, "payload": None, "at": 0.0}
_INVENTORY_CACHE_TTL_SEC = 3.0
_war_room_light_cache = {"payload": None, "at": 0.0, "key": None}
_WAR_ROOM_LIGHT_TTL_SEC = 2.0


def _classify_fail_line(line: str) -> str:
    text = str(line or "")
    if not text:
        return "other"
    if re.search(r"\[\+\]|注册成功", text):
        return ""
    lower = text.lower()
    is_failish = bool(
        re.search(r"\[-\]|\[!\]|注册失败|触发熔断|停止剩余|失败", text)
        or "error" in lower
        or "exception" in lower
    )
    if not is_failish:
        return ""
    for reason, needles in _FAIL_REASON_RULES:
        for needle in needles:
            if needle.lower() in lower or needle in text:
                return reason
    if re.search(r"\[-\]|注册失败", text):
        return "other"
    return ""


_LOG_TIME_RE = re.compile(r"\[(\d{2}:\d{2}:\d{2})\]")


def _extract_log_time(line: str) -> str:
    match = _LOG_TIME_RE.search(str(line or ""))
    return match.group(1) if match else ""


def _fail_bucket_key(event, index: int) -> str:
    t = str((event or {}).get("t") or "")
    if len(t) >= 5:
        return t[:5]
    return f"#{max(1, (index // 3) + 1)}"


def _build_chart_series(lines):
    events = []
    for raw in lines or []:
        line = str(raw or "")
        t = _extract_log_time(line) or ""
        if re.search(r"\[\+\].*注册成功|注册成功:", line):
            events.append({"t": t, "kind": "success", "reason": ""})
            continue
        reason = _classify_fail_line(line)
        if reason:
            events.append({"t": t, "kind": "fail", "reason": reason})

    timeline = []
    cum_success = 0
    cum_fail = 0
    for idx, ev in enumerate(events, start=1):
        if ev["kind"] == "success":
            cum_success += 1
        else:
            cum_fail += 1
        done = cum_success + cum_fail
        timeline.append(
            {
                "i": idx,
                "t": ev["t"] or f"#{idx}",
                "kind": ev["kind"],
                "reason": ev["reason"],
                "cum_success": cum_success,
                "cum_fail": cum_fail,
                "success_rate": round((cum_success / done) * 100, 1) if done else 0,
            }
        )

    stack_map = {}
    reason_keys = set()
    ordered_buckets = []
    seen_buckets = set()
    for idx, ev in enumerate(events):
        if ev["kind"] != "fail":
            continue
        bucket = _fail_bucket_key(ev, idx)
        if bucket not in stack_map:
            stack_map[bucket] = Counter()
        stack_map[bucket][ev["reason"]] += 1
        reason_keys.add(ev["reason"])
        if bucket not in seen_buckets:
            seen_buckets.add(bucket)
            ordered_buckets.append(bucket)

    fail_stack = []
    for bucket in ordered_buckets:
        counts = stack_map.get(bucket) or Counter()
        row = {"bucket": bucket, "total": int(sum(counts.values()))}
        for key in sorted(reason_keys):
            row[key] = int(counts.get(key) or 0)
        fail_stack.append(row)

    return {
        "timeline": timeline[-80:],
        "fail_stack": fail_stack[-24:],
        "reason_keys": sorted(reason_keys),
        "event_count": len(events),
    }


def _parse_job_log_signals(lines):
    reasons = Counter()
    success_hits = 0
    fail_hits = 0
    recent_fails = []
    for raw in lines or []:
        line = str(raw or "")
        if re.search(r"\[\+\].*注册成功|注册成功:", line):
            success_hits += 1
        reason = _classify_fail_line(line)
        if reason:
            reasons[reason] += 1
            fail_hits += 1
            recent_fails.append({"line": line[-220:], "reason": reason})
    recent_fails = recent_fails[-12:]
    total_reasons = sum(reasons.values()) or 0
    breakdown = [
        {
            "reason": key,
            "count": count,
            "percent": round((count / total_reasons) * 100, 1) if total_reasons else 0,
        }
        for key, count in reasons.most_common()
    ]
    charts = _build_chart_series(lines)
    return {
        "success_hits": success_hits,
        "fail_hits": fail_hits,
        "reasons": breakdown,
        "recent_fails": recent_fails,
        "charts": charts,
    }


def _account_inventory_summary(accounts):
    total = len(accounts or [])
    refresh = 0
    healthy = 0
    unhealthy = 0
    incomplete = 0
    grok2api = 0
    sub2api = 0
    cpa = 0
    need_action = 0
    sources = Counter()
    for acc in accounts or []:
        if acc.get("has_refresh_token"):
            refresh += 1
        health = str(acc.get("health_status") or "")
        health_text = str(acc.get("health_status_text") or "")
        if health == "healthy" or health_text == "可用":
            healthy += 1
        elif health == "unhealthy" or health_text == "失效":
            unhealthy += 1
        elif health == "incomplete" or health_text == "资料不完整":
            incomplete += 1
        if acc.get("grok2api_status") == "pushed" or acc.get("grok2api_status_text") == "已推送":
            grok2api += 1
        if acc.get("sub2api_status") == "pushed" or acc.get("sub2api_status_text") == "已推送":
            sub2api += 1
        if acc.get("cpa_status") == "pushed" or acc.get("cpa_status_text") == "已推送":
            cpa += 1
        failed_push = any(
            str(acc.get(f"{k}_status") or "") == "failed"
            or str(acc.get(f"{k}_status_text") or "").startswith("失败")
            for k in ("grok2api", "sub2api", "cpa")
        )
        if (
            not acc.get("has_refresh_token")
            or health in {"unhealthy", "incomplete"}
            or health_text in {"失效", "资料不完整"}
            or failed_push
        ):
            need_action += 1
        sources[str(acc.get("source_file") or "未知来源")] += 1
    untested = max(0, total - healthy - unhealthy - incomplete)
    top_sources = [
        {"source": name, "count": count}
        for name, count in sources.most_common(6)
    ]
    return {
        "total": total,
        "refresh": refresh,
        "healthy": healthy,
        "unhealthy": unhealthy,
        "incomplete": incomplete,
        "untested": untested,
        "grok2api": grok2api,
        "sub2api": sub2api,
        "cpa": cpa,
        "need_action": need_action,
        "sources": top_sources,
    }


def _inventory_snapshot_cached():
    """作战室用：带短 TTL 的库存摘要，避免每次轮询重算。"""
    now = time.time()
    try:
        data_dir = reg.get_data_dir()
        signature = reg._accounts_files_signature(data_dir)
        status_mtime = reg._file_mtime_ns(reg.get_account_status_file())
    except Exception:
        signature = None
        status_mtime = None
    cached = _inventory_cache
    if (
        cached.get("payload") is not None
        and cached.get("signature") == signature
        and cached.get("status_mtime") == status_mtime
        and now - float(cached.get("at") or 0) < _INVENTORY_CACHE_TTL_SEC
    ):
        return dict(cached["payload"])
    try:
        accounts = reg.list_registered_accounts(include_sso=False)
    except Exception:
        accounts = []
    payload = _account_inventory_summary(accounts)
    _inventory_cache["signature"] = signature
    _inventory_cache["status_mtime"] = status_mtime
    _inventory_cache["payload"] = payload
    _inventory_cache["at"] = now
    return dict(payload)


def _current_job_payload():
    with _job_lock:
        job_id = _active_job_id
        job = _jobs.get(job_id) if job_id else None
        if job is not None:
            st = job.status()
            alive = False
            try:
                alive = bool(job.thread and job.thread.is_alive())
            except Exception:
                alive = st.get("status") in _ACTIVE_JOB_STATUSES
            running = st.get("status") in _ACTIVE_JOB_STATUSES and alive
            if st.get("status") in _ACTIVE_JOB_STATUSES and not alive:
                try:
                    job.status_value = "interrupted"
                    job.finished_at = job.finished_at or __import__(
                        "datetime"
                    ).datetime.now().isoformat(timespec="seconds")
                    job._persist_status()
                except Exception:
                    pass
                st = job.status()
                running = False
                try:
                    import notify_hub

                    notify_hub.emit(
                        "job.interrupted",
                        title="任务异常中断",
                        body=f"成功 {st.get('success_count', 0)} / 失败 {st.get('fail_count', 0)}（进程可能已重启）",
                        level="danger",
                        job_id=job.id,
                        dedupe_key=f"job.interrupted|{job.id}",
                        settings=reg.load_config(),
                    )
                except Exception:
                    pass
            payload = {
                "job_id": job.id,
                "has_job": True,
                **st,
            }
            payload["running"] = running
            return payload

        meta = reg.load_current_job_meta()
        if not meta:
            return {"has_job": False, "job_id": None, "status": "idle", "running": False}
        job_id = str(meta.get("job_id") or "").strip()
        snapshot = reg.load_job_snapshot(job_id) if job_id else None
        if not snapshot:
            return {
                "has_job": False,
                "job_id": job_id or None,
                "status": "idle",
                "running": False,
            }
        st = dict(snapshot) if isinstance(snapshot, dict) else {}
        disk_status = str(st.get("status") or meta.get("status") or "finished")
        if disk_status in _ACTIVE_JOB_STATUSES:
            disk_status = "interrupted"
            try:
                import notify_hub

                notify_hub.emit(
                    "job.interrupted",
                    title="任务异常中断",
                    body=f"成功 {st.get('success_count') or meta.get('success_count') or 0} / 失败 {st.get('fail_count') or meta.get('fail_count') or 0}",
                    level="danger",
                    job_id=job_id,
                    dedupe_key=f"job.interrupted|{job_id}",
                    settings=reg.load_config(),
                )
            except Exception:
                pass
        return {
            "job_id": job_id,
            "has_job": True,
            "running": False,
            "from_disk": True,
            "status": disk_status,
            "success_count": int(st.get("success_count") or meta.get("success_count") or 0),
            "fail_count": int(st.get("fail_count") or meta.get("fail_count") or 0),
            "register_count": st.get("register_count"),
            "register_threads": st.get("register_threads"),
            "consecutive_blocks": st.get("consecutive_blocks"),
            "block_stop_triggered": st.get("block_stop_triggered"),
            "output_file": st.get("output_file"),
            "created_at": st.get("created_at"),
            "started_at": st.get("started_at"),
            "finished_at": st.get("finished_at"),
        }


# 作战室会周期性拉 /war-room；Solver 健康检查单独缓存，避免每 2–3s 打一次 /health
_SOLVER_STATUS_CACHE_TTL_SEC = 20.0
_solver_status_cache = {
    "at": 0.0,
    "url": "",
    "enabled": None,
    "payload": None,
}


def _solver_status_snapshot(settings, force: bool = False):
    enabled = bool(settings.get("turnstile_solver_enabled", True))
    url = ""
    try:
        url = reg.normalize_turnstile_solver_url(
            settings.get("turnstile_solver_url")
        )
    except Exception:
        url = str(settings.get("turnstile_solver_url") or "http://127.0.0.1:5072")

    now = time.time()
    cached = _solver_status_cache
    if (
        not force
        and cached.get("payload") is not None
        and cached.get("url") == url
        and cached.get("enabled") is enabled
        and now - float(cached.get("at") or 0) < _SOLVER_STATUS_CACHE_TTL_SEC
    ):
        payload = dict(cached["payload"])
        payload["cached"] = True
        payload["cache_age_ms"] = int((now - float(cached.get("at") or now)) * 1000)
        return payload

    reachable = False
    latency_ms = None
    error = ""
    if enabled:
        t0 = time.time()
        try:
            old = dict(reg.config or {})
            try:
                reg.config = {**old, **dict(settings or {})}
                # 复用 probe 缓存（默认 30s）；作战室不再 force 打爆 solver
                reachable = bool(reg.probe_local_turnstile_solver(force=False, timeout=1.5))
            finally:
                reg.config = old
            latency_ms = int((time.time() - t0) * 1000)
        except Exception as exc:
            error = str(exc)[:160]
            latency_ms = int((time.time() - t0) * 1000)
    payload = {
        "enabled": enabled,
        "url": url,
        "reachable": reachable,
        "latency_ms": latency_ms,
        "fallback_click": bool(settings.get("turnstile_solver_fallback_click", True)),
        "use_proxy": bool(settings.get("turnstile_solver_use_proxy", True)),
        "error": error,
        "cached": False,
        "cache_age_ms": 0,
    }
    _solver_status_cache["at"] = now
    _solver_status_cache["url"] = url
    _solver_status_cache["enabled"] = enabled
    _solver_status_cache["payload"] = dict(payload)
    return payload


def _mail_domain_snapshot(settings):
    try:
        import mail_domain_pool as mdp

        pool_settings = mdp.settings_from_config(settings or {})
        summary = mdp.runtime_summary(pool_settings)
        domains = list(summary.get("domains") or [])
        domains_sorted = sorted(
            domains,
            key=lambda d: (
                0 if d.get("is_available") else 1,
                -int(d.get("success_count") or 0),
                int(d.get("fail_count") or 0),
                str(d.get("domain") or ""),
            ),
        )
        return {
            "ok": True,
            "total_count": summary.get("total_count", 0),
            "available_count": summary.get("available_count", 0),
            "cooldown_count": summary.get("cooldown_count", 0),
            "disabled_count": summary.get("disabled_count", 0),
            "pinpoint_domain": summary.get("pinpoint_domain") or "",
            "grouping": bool(summary.get("grouping")),
            "domains": domains_sorted[:24],
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "domains": []}


def _throughput_estimate(job, signals):
    success = int((job or {}).get("success_count") or 0)
    fail = int((job or {}).get("fail_count") or 0)
    target = int((job or {}).get("register_count") or 0)
    started = str((job or {}).get("started_at") or "").strip()
    finished = str((job or {}).get("finished_at") or "").strip()
    status = str((job or {}).get("status") or "").strip().lower()
    running = bool((job or {}).get("running"))
    terminal = (not running) and status in {
        "completed",
        "stopped",
        "failed",
        "interrupted",
        "idle",
    }
    elapsed_sec = None
    if started:
        try:
            from datetime import datetime

            started_dt = datetime.fromisoformat(started)
            end_dt = None
            if finished:
                try:
                    end_dt = datetime.fromisoformat(finished)
                except Exception:
                    end_dt = None
            if end_dt is None and not terminal:
                end_dt = datetime.now()
            elif end_dt is None and terminal:
                end_dt = started_dt
            elapsed_sec = max(0, int((end_dt - started_dt).total_seconds()))
            if success > 0 and elapsed_sec <= 0:
                elapsed_sec = 1
        except Exception:
            elapsed_sec = None
    rate_per_min = None
    eta_sec = None
    remain = max(0, target - success)
    if elapsed_sec and success > 0:
        rate_per_min = round((success / elapsed_sec) * 60.0, 2)
        if (not terminal) and rate_per_min > 0 and remain > 0:
            eta_sec = int((remain / rate_per_min) * 60)
    done = success + fail
    success_rate = round((success / done) * 100, 1) if done else None
    return {
        "elapsed_sec": elapsed_sec,
        "rate_per_min": rate_per_min,
        "eta_sec": eta_sec,
        "success_rate": success_rate,
        "terminal": terminal,
        "log_success_hits": int((signals or {}).get("success_hits") or 0),
        "log_fail_hits": int((signals or {}).get("fail_hits") or 0),
    }


TASK_PRESETS = {
    "safe_first": {
        "id": "safe_first",
        "name": "稳妥首跑",
        "blurb": "1 线程 / browser / 大间隔，验证链路",
        "patch": {
            "register_count": 1,
            "register_threads": 1,
            "signup_mode": "browser",
            "thread_start_interval": 3.0,
            "account_interval_seconds": 20,
            "account_interval_jitter_seconds": 10,
            "stop_on_consecutive_blocks": 2,
            "turnstile_solver_enabled": True,
            "turnstile_solver_fallback_click": True,
            "enable_mail_domain_runtime_control": True,
            "mail_domain_prefer_low_failure": True,
            "mail_domain_pinpoint_burst": False,
            "enable_mail_domain_grouping": False,
            "mail_domain_fail_threshold": 2,
            "mail_domain_fail_cooldown_sec": 900,
        },
    },
    "docker_burst": {
        "id": "docker_burst",
        "name": "Docker 冲量",
        "blurb": "http 纯协议 + 多线程，适合 NAS",
        "patch": {
            "register_count": 50,
            "register_threads": 3,
            "signup_mode": "http",
            "thread_start_interval": 2.0,
            "account_interval_seconds": 12,
            "account_interval_jitter_seconds": 8,
            "stop_on_consecutive_blocks": 3,
            "turnstile_solver_enabled": True,
            "turnstile_solver_fallback_click": False,
            "enable_mail_domain_runtime_control": True,
            "mail_domain_prefer_low_failure": True,
            "mail_domain_pinpoint_burst": False,
            "enable_mail_domain_grouping": False,
            "mail_domain_fail_threshold": 3,
            "mail_domain_fail_cooldown_sec": 600,
        },
    },
    "gold_rush": {
        "id": "gold_rush",
        "name": "淘金模式",
        "blurb": "pinpoint 粘住稳域，短冷却",
        "patch": {
            "register_count": 30,
            "register_threads": 2,
            "signup_mode": "http",
            "thread_start_interval": 2.0,
            "account_interval_seconds": 10,
            "account_interval_jitter_seconds": 6,
            "stop_on_consecutive_blocks": 3,
            "turnstile_solver_enabled": True,
            "enable_mail_domain_runtime_control": True,
            "mail_domain_pinpoint_burst": True,
            "mail_domain_prefer_low_failure": False,
            "enable_mail_domain_grouping": False,
            "mail_domain_fail_threshold": 2,
            "mail_domain_fail_cooldown_sec": 300,
        },
    },
    "multi_vendor": {
        "id": "multi_vendor",
        "name": "多供应商隔离",
        "blurb": "域名分组 exhaust，风险隔离",
        "patch": {
            "register_count": 40,
            "register_threads": 2,
            "signup_mode": "http",
            "thread_start_interval": 2.0,
            "account_interval_seconds": 12,
            "account_interval_jitter_seconds": 8,
            "stop_on_consecutive_blocks": 3,
            "turnstile_solver_enabled": True,
            "enable_mail_domain_runtime_control": True,
            "mail_domain_prefer_low_failure": True,
            "mail_domain_pinpoint_burst": False,
            "enable_mail_domain_grouping": True,
            "mail_domain_group_mode": "auto",
            "mail_domain_group_count": 2,
            "mail_domain_group_strategy": "exhaust_then_next",
            "mail_domain_fail_threshold": 3,
            "mail_domain_fail_cooldown_sec": 600,
        },
    },
}

_autopilot_state = {
    "enabled": False,
    "last_eval_at": None,
    "last_actions": [],
    "history": [],
}
_autopilot_lock = Lock()


def _list_task_presets():
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "blurb": p["blurb"],
            "keys": sorted(p["patch"].keys()),
        }
        for p in TASK_PRESETS.values()
    ]


def _apply_task_preset(preset_id: str, base_settings=None):
    preset = TASK_PRESETS.get(str(preset_id or "").strip())
    if not preset:
        raise ValueError(f"未知菜谱: {preset_id}")
    current = dict(base_settings if base_settings is not None else reg.load_config())
    merged = {**current, **preset["patch"]}
    validated = reg.validate_registration_config(merged)
    return validated, preset


def _economics_snapshot(job, throughput, signals, settings=None):
    success = int((job or {}).get("success_count") or 0)
    fail = int((job or {}).get("fail_count") or 0)
    target = int((job or {}).get("register_count") or 0)
    done = success + fail
    elapsed = (throughput or {}).get("elapsed_sec")
    terminal = bool((throughput or {}).get("terminal"))
    sec_per_success = None
    if success > 0 and elapsed:
        sec_per_success = round(float(elapsed) / success, 1)
    attempts_per_success = round(done / success, 2) if success > 0 else None
    mail_est = done
    fail_hits = int((signals or {}).get("fail_hits") or fail)
    reasons = {r.get("reason"): int(r.get("count") or 0) for r in ((signals or {}).get("reasons") or [])}
    turnstile_fails = int(reasons.get("turnstile") or 0)
    remain = max(0, target - success)
    eta_more = None if terminal else (throughput or {}).get("eta_sec")
    est_more_attempts = None
    est_more_mail = None
    if (not terminal) and remain > 0 and attempts_per_success:
        est_more_attempts = int(round(remain * attempts_per_success))
        est_more_mail = est_more_attempts
    elif (not terminal) and remain > 0:
        est_more_attempts = remain
        est_more_mail = remain
    threads = int((settings or {}).get("register_threads") or (job or {}).get("register_threads") or 1)
    return {
        "success": success,
        "fail": fail,
        "done": done,
        "target": target,
        "remain": 0 if terminal else remain,
        "sec_per_success": sec_per_success,
        "attempts_per_success": attempts_per_success,
        "mail_spent_est": mail_est,
        "solver_fail_hits": turnstile_fails,
        "fail_signal_hits": fail_hits,
        "eta_more_sec": eta_more,
        "est_more_attempts": est_more_attempts,
        "est_more_mail": est_more_mail,
        "threads": threads,
        "terminal": terminal,
        "rate_per_min": (throughput or {}).get("rate_per_min"),
        "success_rate": (throughput or {}).get("success_rate"),
        "blurb": _economics_blurb(
            success=success,
            remain=0 if terminal else remain,
            sec_per_success=sec_per_success,
            est_more_mail=est_more_mail,
            eta_more=eta_more,
            success_rate=(throughput or {}).get("success_rate"),
            terminal=terminal,
            shortfall=remain if terminal else 0,
        ),
    }


def _economics_blurb(
    *,
    success,
    remain,
    sec_per_success,
    est_more_mail,
    eta_more,
    success_rate,
    terminal=False,
    shortfall=0,
):
    parts = []
    if sec_per_success is not None:
        parts.append(f"约 {sec_per_success}s/成功号")
    if success_rate is not None:
        parts.append(f"成功率 {success_rate}%")
    if terminal:
        if shortfall > 0:
            parts.append(f"任务已结束（差 {shortfall} 个）")
        else:
            parts.append("任务已结束")
    else:
        if remain > 0 and eta_more is not None:
            m = max(1, int(round(eta_more / 60)))
            parts.append(f"再要 {remain} 个约 {m} 分钟")
        if remain > 0 and est_more_mail is not None:
            parts.append(f"预计再耗邮箱 ~{est_more_mail}")
    if not parts:
        if success <= 0:
            return "尚无成功样本，跑起来后估算产能与邮箱消耗"
        return "产能数据收集中"
    return " · ".join(parts)


def _reason_count(signals, reason: str) -> int:
    for row in (signals or {}).get("reasons") or []:
        if row.get("reason") == reason:
            return int(row.get("count") or 0)
    return 0


def _evaluate_autopilot(job, domains, solver, signals, settings):
    actions = []
    suggestions = []
    running = bool((job or {}).get("running"))
    fail = int((job or {}).get("fail_count") or 0)
    success = int((job or {}).get("success_count") or 0)
    done = success + fail
    threads = int((settings or {}).get("register_threads") or 1)
    threshold = int((settings or {}).get("mail_domain_fail_threshold") or 3)
    cooldown = int((settings or {}).get("mail_domain_fail_cooldown_sec") or 600)
    pinpoint = bool((settings or {}).get("mail_domain_pinpoint_burst"))
    low_fail = bool((settings or {}).get("mail_domain_prefer_low_failure", True))

    domain_rej = _reason_count(signals, "domain_rejected")
    turnstile = _reason_count(signals, "turnstile")
    blocked = _reason_count(signals, "blocked")
    otp = _reason_count(signals, "otp_missing")
    create_code = _reason_count(signals, "create_code")

    avail = int((domains or {}).get("available_count") or 0)
    total_dom = int((domains or {}).get("total_count") or 0)
    cool = int((domains or {}).get("cooldown_count") or 0)

    if (job or {}).get("block_stop_triggered") or blocked >= 3:
        suggestions.append(
            {
                "id": "circuit_block",
                "level": "danger",
                "text": "封禁信号偏多：建议停任务并更换代理/出口",
            }
        )
        if running and threads > 1:
            actions.append(
                {
                    "id": "drop_threads_block",
                    "type": "set",
                    "key": "register_threads",
                    "value": 1,
                    "reason": "连续封禁风险，降并发至 1",
                }
            )

    if domain_rej >= 2 or (done >= 5 and domain_rej / max(1, done) >= 0.3):
        if threshold > 1:
            actions.append(
                {
                    "id": "domain_threshold",
                    "type": "set",
                    "key": "mail_domain_fail_threshold",
                    "value": 1,
                    "reason": "域名拒收偏多，失败 1 次即冷却",
                }
            )
        if cooldown < 1200:
            actions.append(
                {
                    "id": "domain_cooldown",
                    "type": "set",
                    "key": "mail_domain_fail_cooldown_sec",
                    "value": min(1800, max(900, cooldown * 2)),
                    "reason": "拉长域名冷却，减少反复撞拒",
                }
            )
        if pinpoint:
            actions.append(
                {
                    "id": "disable_pinpoint",
                    "type": "set",
                    "key": "mail_domain_pinpoint_burst",
                    "value": False,
                    "reason": "拒收多时关闭黄金矿工",
                }
            )
            actions.append(
                {
                    "id": "enable_low_fail",
                    "type": "set",
                    "key": "mail_domain_prefer_low_failure",
                    "value": True,
                    "reason": "改低失败优先轮换域名",
                }
            )
        elif not low_fail:
            actions.append(
                {
                    "id": "enable_low_fail2",
                    "type": "set",
                    "key": "mail_domain_prefer_low_failure",
                    "value": True,
                    "reason": "开启低失败优先",
                }
            )

    if turnstile >= 2 or (solver.get("enabled") and not solver.get("reachable")):
        if threads > 2:
            actions.append(
                {
                    "id": "drop_threads_ts",
                    "type": "set",
                    "key": "register_threads",
                    "value": max(1, threads - 1),
                    "reason": "Turnstile/Solver 压力大，降并发",
                }
            )
        timeout = float((settings or {}).get("turnstile_solver_timeout") or 120)
        if timeout < 180:
            actions.append(
                {
                    "id": "solver_timeout",
                    "type": "set",
                    "key": "turnstile_solver_timeout",
                    "value": 180,
                    "reason": "提高 Solver 超时到 180s",
                }
            )
        if not bool((settings or {}).get("turnstile_solver_fallback_click", True)):
            mode = str((settings or {}).get("signup_mode") or "")
            if mode in {"browser", "api", "auto"}:
                actions.append(
                    {
                        "id": "fallback_click",
                        "type": "set",
                        "key": "turnstile_solver_fallback_click",
                        "value": True,
                        "reason": "开启 Turnstile 点选回退",
                    }
                )
        if solver.get("enabled") and not solver.get("reachable"):
            suggestions.append(
                {
                    "id": "solver_down",
                    "level": "warn",
                    "text": f"Solver 不可达: {solver.get('url') or '—'}",
                }
            )

    if (otp + create_code) >= 3 and threads > 2:
        actions.append(
            {
                "id": "drop_threads_mail",
                "type": "set",
                "key": "register_threads",
                "value": max(1, min(2, threads - 1)),
                "reason": "验证码/发码失败多，略降并发",
            }
        )

    if total_dom > 0 and avail == 0:
        suggestions.append(
            {
                "id": "domains_exhausted",
                "level": "danger",
                "text": "邮件主域全部不可用，建议重置冷却或补充域名",
            }
        )
        actions.append(
            {
                "id": "reset_domain_pool",
                "type": "reset_domain_pool",
                "reason": "域名全冷却，尝试重置运行时池",
            }
        )
    elif total_dom > 0 and cool / total_dom >= 0.5:
        suggestions.append(
            {
                "id": "domains_half_cool",
                "level": "warn",
                "text": f"过半域名冷却中（{cool}/{total_dom}）",
            }
        )

    if success >= 8 and fail <= 1 and not pinpoint and avail >= 1:
        actions.append(
            {
                "id": "enable_pinpoint_hot",
                "type": "set",
                "key": "mail_domain_pinpoint_burst",
                "value": True,
                "reason": "近期很稳，开启黄金矿工吃满稳域",
            }
        )
        actions.append(
            {
                "id": "disable_low_fail_hot",
                "type": "set",
                "key": "mail_domain_prefer_low_failure",
                "value": False,
                "reason": "与黄金矿工互斥，关闭低失败优先",
            }
        )

    seen_keys = set()
    deduped = []
    for act in reversed(actions):
        if act.get("type") == "set":
            k = act.get("key")
            if k in seen_keys:
                continue
            seen_keys.add(k)
        deduped.append(act)
    deduped.reverse()

    return {
        "actions": deduped,
        "suggestions": suggestions,
        "signals": {
            "domain_rejected": domain_rej,
            "turnstile": turnstile,
            "blocked": blocked,
            "otp_missing": otp,
            "create_code": create_code,
            "domain_available": avail,
            "domain_cooldown": cool,
        },
    }


def _apply_autopilot_actions(actions, settings=None):
    applied = []
    skipped = []
    current = dict(settings if settings is not None else reg.load_config())
    patch = {}
    reset_pool = False
    for act in actions or []:
        if act.get("type") == "reset_domain_pool":
            reset_pool = True
            applied.append(act)
            continue
        if act.get("type") != "set":
            skipped.append({**act, "skip": "unsupported"})
            continue
        key = act.get("key")
        value = act.get("value")
        if key is None:
            skipped.append({**act, "skip": "no_key"})
            continue
        if current.get(key) == value:
            skipped.append({**act, "skip": "unchanged"})
            continue
        patch[key] = value
        applied.append(act)

    if reset_pool:
        try:
            import mail_domain_pool as mdp

            mdp.reset_runtime()
        except Exception as exc:
            skipped.append({"id": "reset_domain_pool", "skip": str(exc)[:120]})

    new_settings = current
    if patch:
        merged = {**current, **patch}
        new_settings = reg.validate_registration_config(merged)
        reg.config = new_settings
        reg.save_config()
        with _job_lock:
            job_id = _active_job_id
            job = _jobs.get(job_id) if job_id else None
            if job is not None and hasattr(job, "settings"):
                try:
                    job.settings = {**dict(job.settings or {}), **patch}
                except Exception:
                    pass

    return {
        "applied": applied,
        "skipped": skipped,
        "settings": mask_config(new_settings),
        "patch": patch,
    }


@app.get("/api/ops/war-room")
def ops_war_room(
    log_tail: int = Query(120, ge=20, le=800),
    light: int = Query(1, ge=0, le=1),
):
    """作战室快照。

    light=1（默认）：更短日志尾、库存摘要缓存、无任务时整体短缓存。
    light=0：完整 tail，强制刷新库存。
    """
    settings = reg.load_config()
    job = _current_job_payload()
    job_id = str(job.get("job_id") or "").strip()
    running = bool(job.get("running") or job.get("status") in _ACTIVE_JOB_STATUSES)
    light_mode = bool(int(light or 0))
    effective_tail = int(log_tail)
    if light_mode and effective_tail > 160:
        effective_tail = 160

    # 无活跃任务时，作战室数据变化慢，做 2s 整包缓存
    cache_key = f"{job_id}|{job.get('status')}|{job.get('success_count')}|{job.get('fail_count')}|{effective_tail}|{int(light_mode)}"
    now = time.time()
    if (
        light_mode
        and not running
        and _war_room_light_cache.get("payload") is not None
        and _war_room_light_cache.get("key") == cache_key
        and now - float(_war_room_light_cache.get("at") or 0) < _WAR_ROOM_LIGHT_TTL_SEC
    ):
        cached = dict(_war_room_light_cache["payload"])
        cached["cached"] = True
        return cached

    log_lines = []
    if job_id:
        try:
            # 只读尾部，避免大日志整文件读入
            log_lines = reg.read_job_log_lines(job_id, offset=0, tail=effective_tail) or []
        except Exception:
            log_lines = []
    signals = _parse_job_log_signals(log_lines)
    # 作战室只需要库存摘要，不必每次拿完整账号数组
    if light_mode:
        inventory = _inventory_snapshot_cached()
    else:
        try:
            accounts = reg.list_registered_accounts(include_sso=False)
        except Exception:
            accounts = []
        inventory = _account_inventory_summary(accounts)
    domains = _mail_domain_snapshot(settings)
    solver = _solver_status_snapshot(settings)
    throughput = _throughput_estimate(job, signals)
    economics = _economics_snapshot(job, throughput, signals, settings)
    plan = _evaluate_autopilot(job, domains, solver, signals, settings)

    alerts = []
    if job.get("running"):
        alerts.append({"level": "info", "text": "注册任务运行中"})
    if job.get("block_stop_triggered"):
        alerts.append({"level": "danger", "text": "已触发连续封禁熔断"})
    if job.get("status") == "interrupted":
        alerts.append({"level": "warn", "text": "任务异常中断（进程可能已重启）"})
    if domains.get("ok") and int(domains.get("available_count") or 0) == 0 and int(
        domains.get("total_count") or 0
    ) > 0:
        alerts.append({"level": "danger", "text": "邮件主域全部不可用（冷却/禁用）"})
    elif domains.get("ok") and int(domains.get("cooldown_count") or 0) > 0:
        cool = int(domains.get("cooldown_count") or 0)
        total = int(domains.get("total_count") or 0)
        if total and cool / total >= 0.5:
            alerts.append({"level": "warn", "text": f"超过半数域名冷却中（{cool}/{total}）"})
    if solver.get("enabled") and not solver.get("reachable"):
        alerts.append({"level": "warn", "text": f"Turnstile Solver 不可达: {solver.get('url')}"})
    if int(inventory.get("need_action") or 0) > 0:
        alerts.append(
            {
                "level": "info",
                "text": f"{inventory['need_action']} 个账号需要处理（缺 Refresh / 失效 / 推送失败）",
            }
        )
    for sug in plan.get("suggestions") or []:
        alerts.append({"level": sug.get("level") or "info", "text": sug.get("text") or ""})

    with _autopilot_lock:
        ap_enabled = bool(_autopilot_state.get("enabled"))
        ap_history = list(_autopilot_state.get("history") or [])[-8:]
        ap_last = list(_autopilot_state.get("last_actions") or [])

    if ap_enabled and job.get("running") and plan.get("actions"):
        result = _apply_autopilot_actions(plan["actions"], settings)
        stamp = __import__("datetime").datetime.now().isoformat(timespec="seconds")
        with _autopilot_lock:
            _autopilot_state["last_eval_at"] = stamp
            _autopilot_state["last_actions"] = result.get("applied") or []
            if result.get("applied"):
                _autopilot_state["history"] = (
                    list(_autopilot_state.get("history") or [])
                    + [
                        {
                            "at": stamp,
                            "applied": result.get("applied"),
                            "patch": result.get("patch"),
                        }
                    ]
                )[-20:]
            ap_history = list(_autopilot_state.get("history") or [])[-8:]
            ap_last = list(_autopilot_state.get("last_actions") or [])
        if result.get("applied"):
            alerts.append(
                {
                    "level": "info",
                    "text": f"Auto Pilot 已执行 {len(result['applied'])} 项调整",
                }
            )
            settings = reg.load_config()
            try:
                import notify_hub

                lines = [
                    f"{a.get('key')} → {a.get('value')}"
                    if a.get("type") == "set"
                    else str(a.get("type") or "action")
                    for a in (result.get("applied") or [])[:6]
                ]
                notify_hub.emit(
                    "autopilot.applied",
                    title=f"Auto Pilot 调整 {len(result['applied'])} 项",
                    body="\n".join(lines),
                    level="info",
                    dedupe_key=f"autopilot|{stamp}",
                    settings=settings,
                )
            except Exception:
                pass

    try:
        import notify_hub

        notify_hub.observe_runtime_edges(
            solver_reachable=bool(solver.get("reachable")) if solver.get("enabled") else None,
            domain_available=domains.get("available_count"),
            domain_total=domains.get("total_count"),
            domain_cooldown=domains.get("cooldown_count"),
            settings=settings,
        )
    except Exception:
        pass

    mode = "auto"
    try:
        old = dict(reg.config or {})
        try:
            reg.config = {**old, **dict(settings or {})}
            mode = reg.resolve_signup_mode()
        finally:
            reg.config = old
    except Exception:
        mode = str(settings.get("signup_mode") or "auto")

    payload = {
        "ok": True,
        "generated_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "job": job,
        "throughput": throughput,
        "economics": economics,
        "failures": signals,
        "charts": (signals or {}).get("charts")
        or {"timeline": [], "fail_stack": [], "reason_keys": [], "event_count": 0},
        "recent_logs": log_lines[-30:] if light_mode else log_lines[-40:],
        "domains": domains,
        "solver": solver,
        "inventory": inventory,
        "alerts": alerts,
        "presets": _list_task_presets(),
        "autopilot": {
            "enabled": ap_enabled,
            "pending_actions": plan.get("actions") or [],
            "suggestions": plan.get("suggestions") or [],
            "signals": plan.get("signals") or {},
            "last_actions": ap_last,
            "history": ap_history,
        },
        "runtime": {
            "signup_mode": mode,
            "email_provider": settings.get("email_provider") or "",
            "register_count": settings.get("register_count"),
            "register_threads": settings.get("register_threads"),
            "proxy_configured": bool(str(settings.get("proxy") or "").strip()),
            "turnstile_solver_enabled": bool(settings.get("turnstile_solver_enabled", True)),
            "mail_domain_pinpoint_burst": bool(settings.get("mail_domain_pinpoint_burst")),
            "mail_domain_prefer_low_failure": bool(
                settings.get("mail_domain_prefer_low_failure", True)
            ),
            "mail_domain_fail_threshold": settings.get("mail_domain_fail_threshold"),
        },
        "cached": False,
        "light": light_mode,
    }
    if light_mode and not running:
        _war_room_light_cache["payload"] = payload
        _war_room_light_cache["at"] = time.time()
        _war_room_light_cache["key"] = cache_key
    return payload


@app.get("/api/ops/presets")
def list_ops_presets():
    return {"ok": True, "presets": _list_task_presets()}


@app.post("/api/ops/presets/{preset_id}/apply")
def apply_ops_preset(preset_id: str):
    try:
        validated, preset = _apply_task_preset(preset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    reg.config = validated
    reg.save_config()
    return {
        "ok": True,
        "preset": {"id": preset["id"], "name": preset["name"], "blurb": preset["blurb"]},
        "config": mask_config(validated),
        "patch": preset["patch"],
    }


@app.get("/api/notify/status")
def notify_status():
    try:
        import notify_hub

        settings = reg.load_config()
        return {"ok": True, **notify_hub.status(settings)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/notify/history")
def notify_history(limit: int = Query(30, ge=1, le=100)):
    try:
        import notify_hub

        return {"ok": True, "items": notify_hub.history(limit)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/notify/test")
def notify_test():
    try:
        import notify_hub

        settings = reg.load_config()
        result = notify_hub.emit_test(settings)
        if not result.get("ok"):
            raise HTTPException(
                status_code=400,
                detail=result.get("error") or result.get("skipped") or "发送失败",
            )
        return {"ok": True, **result}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/ops/autopilot")
def get_autopilot():
    with _autopilot_lock:
        return {
            "ok": True,
            "enabled": bool(_autopilot_state.get("enabled")),
            "last_eval_at": _autopilot_state.get("last_eval_at"),
            "last_actions": list(_autopilot_state.get("last_actions") or []),
            "history": list(_autopilot_state.get("history") or [])[-12:],
        }


@app.post("/api/ops/autopilot")
def set_autopilot(payload: dict):
    enabled = bool((payload or {}).get("enabled"))
    with _autopilot_lock:
        _autopilot_state["enabled"] = enabled
        if not enabled:
            _autopilot_state["last_actions"] = []
    return {"ok": True, "enabled": enabled}


@app.post("/api/ops/autopilot/evaluate")
def evaluate_autopilot(payload: dict = None):
    apply_now = bool((payload or {}).get("apply"))
    settings = reg.load_config()
    job = _current_job_payload()
    job_id = str(job.get("job_id") or "").strip()
    log_lines = []
    if job_id:
        try:
            log_lines = reg.read_job_log_lines(job_id, offset=0, tail=400) or []
        except Exception:
            log_lines = []
    signals = _parse_job_log_signals(log_lines)
    domains = _mail_domain_snapshot(settings)
    solver = _solver_status_snapshot(settings)
    plan = _evaluate_autopilot(job, domains, solver, signals, settings)
    result = None
    if apply_now and plan.get("actions"):
        result = _apply_autopilot_actions(plan["actions"], settings)
        stamp = __import__("datetime").datetime.now().isoformat(timespec="seconds")
        with _autopilot_lock:
            _autopilot_state["last_eval_at"] = stamp
            _autopilot_state["last_actions"] = (result or {}).get("applied") or []
            if (result or {}).get("applied"):
                _autopilot_state["history"] = (
                    list(_autopilot_state.get("history") or [])
                    + [
                        {
                            "at": stamp,
                            "applied": result.get("applied"),
                            "patch": result.get("patch"),
                        }
                    ]
                )[-20:]
    return {
        "ok": True,
        "plan": plan,
        "applied": result,
        "enabled": bool(_autopilot_state.get("enabled")),
    }


@app.get("/api/accounts")
def list_accounts():
    accounts = reg.list_registered_accounts(include_sso=False)
    # 列表页不需要 response/error 大字段，显著减小 JSON
    compact = [public_account(acc, compact=True) for acc in accounts]
    return {"total": len(compact), "accounts": compact}


@app.delete("/api/accounts")
def delete_accounts(payload: dict):
    try:
        result = reg.delete_registered_accounts(payload.get("account_ids") or [])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"删除账号失败: {exc}")
    if not result["deleted"]:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    accounts = reg.list_registered_accounts(include_sso=False)
    return {
        **result,
        "status": "deleted",
        "message": f"已删除 {result['deleted']} 个账号",
        "accounts": [public_account(account) for account in accounts],
    }


@app.post("/api/accounts/import/sub2api")
def import_accounts_to_sub2api(payload: dict):
    settings = merge_sensitive_values(payload)
    account_ids = payload.get("account_ids") or []
    accounts = reg.find_registered_accounts(account_ids)
    if not accounts:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    try:
        result = reg.import_accounts_to_sub2api(accounts, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"导入 sub2api 失败: {exc}")
    reg.persist_sub2api_push_status(accounts, result)
    accounts = reg.find_registered_accounts(account_ids)
    total = int(result.get("total") or len(accounts))
    failed = int(result.get("failed") or 0)
    probe_failed = int(result.get("probe_failed") or 0)
    status = "partial_failed" if failed or probe_failed else "pushed"
    message = f"已推送到 sub2api：{total} 个账号"
    if failed or probe_failed:
        message = (
            f"sub2api 推送完成：入库 {total} 个，推送失败 {failed} 个"
            + (f"，探测失败 {probe_failed} 个" if probe_failed else "")
        )
    return {
        **result,
        "status": status,
        "message": message,
        "accounts": [public_account(account) for account in accounts],
    }


@app.post("/api/accounts/sub2api/probe")
def probe_accounts_on_sub2api(payload: dict):
    """对已入库账号重新探测（不重复创建）。"""
    settings = merge_sensitive_values(payload)
    account_ids = payload.get("account_ids") or []
    accounts = reg.find_registered_accounts(account_ids)
    if not accounts:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    try:
        result = reg.probe_accounts_on_sub2api(accounts, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"sub2api 探测失败: {exc}")
    reg.persist_sub2api_push_status(accounts, result)
    accounts = reg.find_registered_accounts(account_ids)
    total = int(result.get("total") or 0)
    failed = int(result.get("failed") or 0)
    return {
        **result,
        "status": "partial_failed" if failed else "probed",
        "message": f"sub2api 重新探测：通过 {total} 个，失败 {failed} 个",
        "accounts": [public_account(account) for account in accounts],
    }


@app.post("/api/accounts/sub2api/delete-remote")
def delete_accounts_from_sub2api(payload: dict):
    """删除 sub2api 远端账号，本地标记为未推送。"""
    settings = merge_sensitive_values(payload)
    account_ids = payload.get("account_ids") or []
    accounts = reg.find_registered_accounts(account_ids)
    if not accounts:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    try:
        result = reg.delete_accounts_from_sub2api(accounts, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"删除 sub2api 远端失败: {exc}")
    reg.persist_sub2api_push_status(accounts, result)
    accounts = reg.find_registered_accounts(account_ids)
    total = int(result.get("total") or 0)
    failed = int(result.get("failed") or 0)
    return {
        **result,
        "status": "partial_failed" if failed else "deleted_remote",
        "message": f"已删除 sub2api 远端：成功 {total} 个，失败 {failed} 个",
        "accounts": [public_account(account) for account in accounts],
    }


@app.post("/api/accounts/import/grok2api")
def import_accounts_to_grok2api(payload: dict):
    settings = merge_sensitive_values(payload)
    account_ids = payload.get("account_ids") or []
    accounts = reg.find_registered_accounts(account_ids)
    if not accounts:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    try:
        result = reg.import_accounts_to_grok2api(accounts, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"导入 grok2api 失败: {exc}")
    reg.persist_grok2api_push_status(accounts, result)
    accounts = reg.find_registered_accounts(account_ids)
    total = int(result.get("total") or len(accounts))
    failed = int(result.get("failed") or 0)
    status = "partial_failed" if failed else "pushed"
    message = f"已推送到 grok2api：{total} 个账号"
    if failed:
        message = f"grok2api 推送完成：成功 {total} 个，失败 {failed} 个"
    return {
        **result,
        "status": status,
        "message": message,
        "accounts": [public_account(account) for account in accounts],
    }


@app.post("/api/accounts/import/cpa")
def import_accounts_to_cpa(payload: dict):
    settings = merge_sensitive_values(payload)
    account_ids = payload.get("account_ids") or []
    accounts = reg.find_registered_accounts(account_ids)
    if not accounts:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    try:
        result = reg.import_accounts_to_cpa(accounts, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"推送 CPA 失败: {exc}")
    reg.persist_cpa_push_status(accounts, result)
    accounts = reg.find_registered_accounts(account_ids)
    total = int(result.get("total") or 0)
    failed = int(result.get("failed") or 0)
    status = "partial_failed" if failed else "pushed"
    message = f"已推送到 CPA：{total} 个账号"
    if failed:
        message = f"CPA 推送完成：成功 {total} 个，失败 {failed} 个"
    return {
        **result,
        "status": status,
        "message": message,
        "accounts": [public_account(account) for account in accounts],
    }


@app.post("/api/accounts/check-health")
def check_accounts_health(payload: dict):
    settings = merge_sensitive_values(payload)
    account_ids = payload.get("account_ids") or []
    accounts = reg.find_registered_accounts(account_ids)
    if not accounts:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    try:
        result = reg.check_registered_accounts_health(accounts, settings)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"健康检查失败: {exc}")
    reg.persist_account_health_status(accounts, result)
    accounts = reg.find_registered_accounts(account_ids)
    healthy = int(result.get("healthy") or 0)
    failed = int(result.get("failed") or 0)
    status = "partial_failed" if failed else "healthy"
    return {
        **result,
        "status": status,
        "message": f"健康检查完成：可用 {healthy} 个，异常 {failed} 个",
        "accounts": [public_account(account) for account in accounts],
    }


@app.post("/api/accounts/export")
def export_accounts(payload: dict):
    """导出选中账号。formats 多选：native/grok2api/sub2api/cpa，每种格式一个 zip。"""
    settings = merge_sensitive_values(payload)
    account_ids = payload.get("account_ids") or []
    formats = payload.get("formats") or []
    accounts = reg.find_registered_accounts(account_ids)
    if not accounts:
        raise HTTPException(status_code=404, detail="未找到选中的账号")
    try:
        result = reg.export_accounts_zip(accounts, formats, settings=settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"导出失败: {exc}")
    content = result.get("content") or b""
    filename = str(result.get("filename") or "export_accounts.zip")
    return Response(
        content=content,
        media_type=str(result.get("content_type") or "application/zip"),
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Formats": ",".join(result.get("formats") or []),
        },
    )


def _resolve_job(job_id: str):
    """内存中的 job，或从落盘恢复的只读快照。"""
    job = _jobs.get(job_id)
    if job is not None:
        return job, False
    snapshot = reg.load_job_snapshot(job_id)
    if snapshot is None:
        return None, False
    return snapshot, True


@app.get("/api/jobs/current")
def get_current_job():
    """页面刷新后恢复：优先返回运行中任务；落盘 running 若进程已无则标为中断。"""
    with _job_lock:
        job_id = _active_job_id
        job = _jobs.get(job_id) if job_id else None
        if job is not None:
            st = job.status()
            alive = False
            try:
                alive = bool(job.thread and job.thread.is_alive())
            except Exception:
                alive = st.get("status") in _ACTIVE_JOB_STATUSES
            running = st.get("status") in _ACTIVE_JOB_STATUSES and alive
            # 线程已死但状态还是 running/stopping：纠正
            if st.get("status") in _ACTIVE_JOB_STATUSES and not alive:
                try:
                    job.status_value = "interrupted"
                    job.finished_at = job.finished_at or __import__("datetime").datetime.now().isoformat(timespec="seconds")
                    job._persist_status()
                except Exception:
                    pass
                st = job.status()
                running = False
            payload = {
                "job_id": job.id,
                "has_job": True,
                **st,
            }
            payload["running"] = running
            return payload

        # 内存没有：读落盘 current（只读历史，不能当 running）
        meta = reg.load_current_job_meta()
        if not meta:
            return {"has_job": False, "job_id": None, "status": "idle", "running": False}
        job_id = str(meta.get("job_id") or "").strip()
        snapshot = reg.load_job_snapshot(job_id) if job_id else None
        if not snapshot:
            return {"has_job": False, "job_id": job_id or None, "status": "idle", "running": False}
        st = dict(snapshot) if isinstance(snapshot, dict) else {}
        disk_status = str(st.get("status") or meta.get("status") or "finished")
        # 进程重启后磁盘上的 running/stopping 是僵尸状态
        if disk_status in _ACTIVE_JOB_STATUSES:
            disk_status = "interrupted"
            try:
                st["status"] = "interrupted"
                reg.save_job_snapshot(job_id, st)
                reg.save_current_job_meta(
                    {
                        "job_id": job_id,
                        "status": "interrupted",
                        "success_count": st.get("success_count"),
                        "fail_count": st.get("fail_count"),
                    }
                )
            except Exception:
                pass
        return {
            "job_id": job_id,
            "has_job": True,
            "running": False,
            "from_disk": True,
            "status": disk_status,
            "success_count": int(st.get("success_count") or meta.get("success_count") or 0),
            "fail_count": int(st.get("fail_count") or meta.get("fail_count") or 0),
            "register_count": st.get("register_count"),
            "register_threads": st.get("register_threads"),
            "output_file": st.get("output_file"),
            "created_at": st.get("created_at"),
            "started_at": st.get("started_at"),
            "finished_at": st.get("finished_at"),
        }


@app.post("/api/jobs/start")
def start_job(payload: dict):
    global _active_job_id
    settings = merge_sensitive_values(payload)
    try:
        validated = reg.validate_registration_config(settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    with _job_lock:
        if active_job_running():
            job = _jobs.get(_active_job_id)
            if job is not None:
                return {
                    "job_id": job.id,
                    "already_running": True,
                    **job.status(),
                }
            raise HTTPException(status_code=409, detail="已有任务正在运行")
        reg.config = validated
        reg.save_config()
        job = reg.RegistrationJob(validated)
        _jobs[job.id] = job
        _active_job_id = job.id
        job.start()
        return {"job_id": job.id, **job.status()}


def _do_stop_job(job_id: str = None):
    """停止任务：优先指定 id，否则停当前 active；找不到则清理僵尸状态。

    协作式停止：立即返回 status=stopping / stop_requested=true。
    工作线程需等到当前可取消点才会真正退出。
    """
    global _active_job_id
    with _job_lock:
        target_id = str(job_id or "").strip() or str(_active_job_id or "").strip()
        job = _jobs.get(target_id) if target_id else None
        if job is None and _active_job_id and _active_job_id != target_id:
            job = _jobs.get(_active_job_id)
            if job is not None:
                target_id = _active_job_id
        if job is not None:
            job.stop()
            st = dict(job.status())
            # 线程仍存活时明确返回 stopping，避免前端误以为已停完
            try:
                alive = bool(job.thread and job.thread.is_alive())
            except Exception:
                alive = st.get("status") in _ACTIVE_JOB_STATUSES
            if alive and st.get("status") not in {"stopped", "failed", "completed", "interrupted"}:
                st["status"] = "stopping"
                st["running"] = True
                st["stop_requested"] = True
                st["message"] = "已请求停止，等待当前步骤结束"
            return {"ok": True, "job_id": target_id, **st}

        meta = reg.load_current_job_meta() or {}
        disk_id = str(meta.get("job_id") or target_id or "").strip()
        snapshot = reg.load_job_snapshot(disk_id) if disk_id else None
        if isinstance(snapshot, dict):
            snapshot["status"] = "stopped"
            snapshot["stop_requested"] = True
            try:
                reg.save_job_snapshot(disk_id, snapshot)
            except Exception:
                pass
        if disk_id:
            try:
                reg.save_current_job_meta(
                    {
                        "job_id": disk_id,
                        "status": "stopped",
                        "success_count": (snapshot or {}).get("success_count")
                        or meta.get("success_count"),
                        "fail_count": (snapshot or {}).get("fail_count")
                        or meta.get("fail_count"),
                    }
                )
            except Exception:
                pass
        _active_job_id = None
        return {
            "ok": True,
            "job_id": disk_id or target_id or None,
            "status": "stopped",
            "message": "无运行中任务，已清理状态",
            "from_disk": True,
            "success_count": int((snapshot or {}).get("success_count") or meta.get("success_count") or 0),
            "fail_count": int((snapshot or {}).get("fail_count") or meta.get("fail_count") or 0),
        }


@app.post("/api/jobs/stop")
def stop_current_job():
    return _do_stop_job(None)


@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str):
    return _do_stop_job(job_id)


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job, from_disk = _resolve_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if from_disk:
        st = dict(job) if isinstance(job, dict) else {}
        st.setdefault("id", job_id)
        st["from_disk"] = True
        # 磁盘上的 running/stopping 不可信
        if str(st.get("status") or "") in _ACTIVE_JOB_STATUSES:
            st["status"] = "interrupted"
            st["running"] = False
        return st
    st = dict(job.status())
    try:
        alive = bool(job.thread and job.thread.is_alive())
    except Exception:
        alive = st.get("status") in _ACTIVE_JOB_STATUSES
    if st.get("status") in _ACTIVE_JOB_STATUSES and not alive:
        st["status"] = "interrupted"
        st["running"] = False
    else:
        st["running"] = bool(alive and st.get("status") in _ACTIVE_JOB_STATUSES)
    return st


@app.get("/api/jobs/{job_id}/logs")
def get_job_logs(job_id: str, offset: int = Query(0, ge=0)):
    job, from_disk = _resolve_job(job_id)
    if job is None:
        # 仅日志文件
        lines = reg.read_job_log_lines(job_id, offset=offset)
        return {"offset": offset, "next_offset": offset + len(lines), "lines": lines, "from_disk": True}
    if from_disk:
        lines = reg.read_job_log_lines(job_id, offset=offset)
        return {"offset": offset, "next_offset": offset + len(lines), "lines": lines, "from_disk": True}
    lines = job.logs(offset=offset)
    return {"offset": offset, "next_offset": offset + len(lines), "lines": lines}
