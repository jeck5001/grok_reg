"""Shared configuration defaults, load/save, and validation.

``config`` is a single mutable dict shared across the process. Always mutate it
via ``replace_config`` (or ``load_config``) so ``import grok_register_ttk as reg``
callers keep a stable ``reg.config`` object identity.
"""

from __future__ import annotations

import json
import os

from core.paths import get_config_file


DEFAULT_CONFIG = {
    "duckmail_api_key": "",
    "cloudflare_api_base": "",
    "cloudflare_api_key": "",
    "cloudflare_auth_mode": "bearer",
    "cloudflare_path_domains": "/domains",
    "cloudflare_path_accounts": "/accounts",
    "cloudflare_path_token": "/token",
    "cloudflare_path_messages": "/messages",
    # Cloudflare 官方全局身份鉴权（X-Auth-Email + Global API Key）
    # 用于域名托管 / Email Routing DNS 等官方 API；与上面 temp-email Worker 鉴权分开。
    "cf_api_email": "",
    "cf_api_key": "",
    "proxy": "http://127.0.0.1:7890",
    # 注册成功后立刻改 NSFW/生日等特征，容易被当成机器号；默认关闭，需要时再开。
    "enable_nsfw": False,
    "register_count": 1,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "grok2api_auto_add_local": True,
    "grok2api_local_token_file": "",
    "grok2api_pool_name": "ssoBasic",
    "grok2api_auto_add_remote": False,
    "grok2api_remote_base": "",
    "grok2api_remote_app_key": "",
    "sub2api_auto_import_remote": False,
    "sub2api_base": "",
    "sub2api_auth_mode": "x-api-key",
    "sub2api_admin_token": "",
    "sub2api_account_name": "Grok Auto",
    "sub2api_group_ids": "",
    "sub2api_concurrency": 3,
    "sub2api_priority": 50,
    # 推送后是否自动探测（遇 xAI 429 时可关掉，只 refresh）
    "sub2api_auto_probe": True,
    "sub2api_init_gap_seconds": 8,
    "sub2api_test_model": "grok-4.5",
    "cpa_auth_dir": "cpa_auths",
    "cpa_auto_push_remote": False,
    "cpa_management_base": "",
    "cpa_management_key": "",
    "cpa_push_workers": 3,
    "register_threads": 1,
    # 线程启动错开，避免同一秒内多开浏览器打到同一出口。
    "thread_start_interval": 2.0,
    # 同线程相邻账号间隔 + 抖动，降低“工厂流水线”节奏。
    "account_interval_seconds": 12,
    "account_interval_jitter_seconds": 8,
    # 连续检测到账号封禁时熔断，避免同 IP/代理继续批量送死。
    "stop_on_consecutive_blocks": 3,
    # Docker 下默认不要补丁 window.turnstile：手动能过时，API 补丁反而会干扰 flexible 模式。
    "turnstile_patch_api": False,
    # 默认不强制 execute；先完全交给 Cloudflare 被动评分。
    "turnstile_force_execute": False,
    # 资料页等 token 的最长时间（秒）
    "turnstile_wait_seconds": 120,
    # 方案 A：优先走本地/远端 Turnstile Solver（YesCaptcha 协议，参考 grokcli-2api/turnstile-solver）。
    # 默认开启；solver 不可达时自动回退 shadow/CDP 点选。
    "turnstile_solver_enabled": True,
    "turnstile_solver_url": "http://127.0.0.1:5072",
    "turnstile_solver_client_key": "local",
    "turnstile_solver_timeout": 120,
    "turnstile_solver_fallback_click": True,
    # 把 config.proxy 透传给 solver（任务级 task.proxy），保证与注册浏览器同出口 IP
    "turnstile_solver_use_proxy": True,
    # accounts.x.ai 公开 sitekey（页面刮不到时回退；非密钥）
    "turnstile_sitekey": "0x4AAAAAAAhr9JGVDZbrZOo0",
    # 注册最终建号方式：auto|api|browser
    # auto：Docker 默认走 API create_account（与 grokcli-2api 同路径）；本机默认 browser
    # auto|http|api|browser — docker 默认 http 纯协议；api=浏览器OTP+HTTP建号；browser=全浏览器
    "signup_mode": "auto",
    # 并发时 Device Flow 最小间隔（秒），防 xAI rate_limited
    "device_flow_gap_seconds": 2.0,
    # 邮件域名池（对齐 openai-cpa 内存池精简版）
    "mail_domains": "",  # 与 defaultDomains 二选一；非空优先
    "enable_sub_domains": False,
    "sub_domain_level": 1,
    "random_sub_domain_level": False,
    "enable_mail_domain_runtime_control": True,
    "mail_domain_pinpoint_burst": False,  # 黄金矿工/定点爆破
    "mail_domain_prefer_low_failure": True,
    "mail_domain_fail_threshold": 3,
    "mail_domain_fail_cooldown_sec": 600,
    "enable_mail_domain_grouping": False,
    "mail_domain_group_count": 2,
    "mail_domain_group_mode": "auto",  # auto|manual
    "mail_domain_group_strategy": "round_robin",  # round_robin|exhaust_then_next
    "mail_domain_groups": [],  # 手动分组时每组逗号域名
    "disabled_mail_domains": "",  # 手动禁用主域
    "mail_domain_failure_types": ["discarded_email", "cloudflare_temp_email_network", "capacity_exceeded"],
    # openai-cpa-email Worker webhook 收件（本地内存池）
    "email_webhook_enabled": False,
    "email_webhook_secret": "",
    # openai-cpa-email Worker 名称（CF Workers 脚本名；catch-all 要指向它）
    "cf_email_worker_name": "openai-cpa-email",
    # Worker 回推 grok_reg 的公网基址（EMAIL_WEBHOOK_URL）。必须公网可达，不能是 127.0.0.1 / 192.168.x.x
    "email_webhook_public_url": "",
    # 是否允许覆盖已存在的 Worker 脚本（默认 false：已存在则只更新 bindings 需 force）
    "cf_email_worker_force": False,
    # Web 访问密码（公网务必修改）。环境变量 GROK_REG_WEB_PASSWORD 优先；空字符串=关闭鉴权。
    "web_password": "admin",
    "notify_enabled": False,
    "notify_min_level": "warn",
    "notify_cooldown_sec": 180,
    "notify_telegram_bot_token": "",
    "notify_telegram_chat_id": "",
    "notify_milestone_success": [10, 50, 100, 200, 500],
    "notify_events": {
        "job.started": True,
        "job.completed": True,
        "job.stopped": True,
        "job.failed": True,
        "job.interrupted": True,
        "job.circuit_break": True,
        "milestone.success_n": True,
        "domain.pool_exhausted": True,
        "domain.half_cooling": True,
        "solver.down": True,
        "solver.recovered": True,
        "autopilot.applied": False,
    },
    "show_tutorial_on_start": True,
    "cloudmail_url": "",
    "cloudmail_admin_email": "",
    "cloudmail_password": "",
}

config = DEFAULT_CONFIG.copy()


def replace_config(settings):
    """In-place replace of the shared ``config`` dict (keeps object identity).

    Callers (and tests) that hold a reference via ``import grok_register_ttk as reg``
    and then ``monkeypatch.setitem(reg.config, ...)`` must not see the binding
    swapped out. Prefer this over ``reg.config = {...}``.
    """
    new = dict(settings or {})
    config.clear()
    config.update(new)
    return config


def load_config():
    config_file = get_config_file()
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            new = {**DEFAULT_CONFIG, **loaded}
        except Exception:
            new = DEFAULT_CONFIG.copy()
    else:
        new = DEFAULT_CONFIG.copy()
    return replace_config(new)


def save_config():
    try:
        with open(get_config_file(), "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"保存配置失败: {e}")


def _parse_positive_int(value, default, minimum=1, maximum=None):
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _normalize_path(value):
    raw = str(value or "").strip()
    if not raw:
        return raw
    return raw if raw.startswith("/") else f"/{raw}"


_EMAIL_PROVIDERS = (
    "duckmail",
    "yyds",
    "cloudflare",
    "cloudmail",
    "openai_cpa_email",
    "cpa_email",
)


def validate_registration_config(settings):
    normalized = {**DEFAULT_CONFIG, **dict(settings or {})}
    provider = str(normalized.get("email_provider") or "duckmail").strip().lower() or "duckmail"
    # 兼容大小写 / 空格；未知值不要静默回落 duckmail（会误打 DuckMail API 出一串 401）
    if provider not in _EMAIL_PROVIDERS:
        raise ValueError(
            f"未知邮箱服务商: {provider!r}（可选: {', '.join(_EMAIL_PROVIDERS)}）"
        )
    normalized["email_provider"] = provider
    normalized["register_count"] = _parse_positive_int(
        normalized.get("register_count"), 1, minimum=1, maximum=1000
    )
    normalized["register_threads"] = _parse_positive_int(
        normalized.get("register_threads"), 1, minimum=1, maximum=10
    )
    try:
        start_interval = float(normalized.get("thread_start_interval", 2.0))
    except Exception:
        start_interval = 2.0
    normalized["thread_start_interval"] = max(0.0, min(start_interval, 60.0))
    try:
        account_interval = float(normalized.get("account_interval_seconds", 12))
    except Exception:
        account_interval = 12.0
    normalized["account_interval_seconds"] = max(0.0, min(account_interval, 600.0))
    try:
        account_jitter = float(normalized.get("account_interval_jitter_seconds", 8))
    except Exception:
        account_jitter = 8.0
    normalized["account_interval_jitter_seconds"] = max(0.0, min(account_jitter, 300.0))
    normalized["stop_on_consecutive_blocks"] = _parse_positive_int(
        normalized.get("stop_on_consecutive_blocks"), 3, minimum=0, maximum=50
    )
    for bool_key in (
        "turnstile_patch_api",
        "turnstile_force_execute",
        "turnstile_solver_enabled",
        "turnstile_solver_fallback_click",
        "turnstile_solver_use_proxy",
        "enable_sub_domains",
        "random_sub_domain_level",
        "enable_mail_domain_runtime_control",
        "mail_domain_pinpoint_burst",
        "mail_domain_prefer_low_failure",
        "enable_mail_domain_grouping",
        "email_webhook_enabled",
        "notify_enabled",
    ):
        raw_bool = normalized.get(bool_key)
        if isinstance(raw_bool, str):
            normalized[bool_key] = raw_bool.strip().lower() in {"1", "true", "yes", "on"}
        else:
            normalized[bool_key] = bool(raw_bool)
    normalized["email_webhook_secret"] = str(normalized.get("email_webhook_secret") or "").strip()
    try:
        import notify_hub as _notify_hub

        normalized.update(_notify_hub.normalize_notify_settings(normalized))
    except Exception:
        normalized["notify_telegram_bot_token"] = str(
            normalized.get("notify_telegram_bot_token") or ""
        ).strip()
        normalized["notify_telegram_chat_id"] = str(
            normalized.get("notify_telegram_chat_id") or ""
        ).strip()
        level = str(normalized.get("notify_min_level") or "warn").strip().lower()
        if level not in {"info", "warn", "danger"}:
            level = "warn"
        normalized["notify_min_level"] = level
    signup_mode = str(normalized.get("signup_mode") or "auto").strip().lower()
    if signup_mode not in {"auto", "http", "api", "browser"}:
        signup_mode = "auto"
    env_mode = str(os.environ.get("GROK_REG_SIGNUP_MODE") or "").strip().lower()
    if env_mode in {"auto", "http", "api", "browser"}:
        signup_mode = env_mode
    normalized["signup_mode"] = signup_mode
    try:
        normalized["sub_domain_level"] = max(1, min(7, int(normalized.get("sub_domain_level") or 1)))
    except Exception:
        normalized["sub_domain_level"] = 1
    try:
        normalized["mail_domain_fail_threshold"] = max(
            0, min(50, int(normalized.get("mail_domain_fail_threshold") or 3))
        )
    except Exception:
        normalized["mail_domain_fail_threshold"] = 3
    try:
        normalized["mail_domain_fail_cooldown_sec"] = max(
            0, min(86400, int(normalized.get("mail_domain_fail_cooldown_sec") or 600))
        )
    except Exception:
        normalized["mail_domain_fail_cooldown_sec"] = 600
    try:
        normalized["mail_domain_group_count"] = max(
            1, min(10, int(normalized.get("mail_domain_group_count") or 2))
        )
    except Exception:
        normalized["mail_domain_group_count"] = 2
    gmode = str(normalized.get("mail_domain_group_mode") or "auto").strip().lower()
    normalized["mail_domain_group_mode"] = gmode if gmode in {"auto", "manual"} else "auto"
    gstrat = str(normalized.get("mail_domain_group_strategy") or "round_robin").strip().lower()
    normalized["mail_domain_group_strategy"] = (
        gstrat if gstrat in {"round_robin", "exhaust_then_next"} else "round_robin"
    )
    # 互斥：分组 > 黄金矿工 > 低失败（与 cpa 一致）
    if normalized.get("enable_mail_domain_grouping"):
        normalized["mail_domain_pinpoint_burst"] = False
    if normalized.get("mail_domain_pinpoint_burst") and normalized.get("mail_domain_prefer_low_failure"):
        normalized["mail_domain_prefer_low_failure"] = False
    # groups
    raw_groups = normalized.get("mail_domain_groups") or []
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    if not isinstance(raw_groups, list):
        raw_groups = []
    groups = [str(x or "").strip() for x in raw_groups]
    while len(groups) < normalized["mail_domain_group_count"]:
        groups.append("")
    normalized["mail_domain_groups"] = groups[: normalized["mail_domain_group_count"]]
    # failure types
    raw_ft = normalized.get("mail_domain_failure_types") or "discarded_email"
    if isinstance(raw_ft, str):
        ftypes = [x.strip() for x in raw_ft.replace("，", ",").split(",") if x.strip()]
    else:
        ftypes = [str(x).strip() for x in (raw_ft or []) if str(x).strip()]
    allowed_ft = {"discarded_email", "cloudflare_temp_email_network", "capacity_exceeded"}
    ftypes = [x for x in ftypes if x in allowed_ft] or ["discarded_email"]
    normalized["mail_domain_failure_types"] = ftypes
    # disabled
    if isinstance(normalized.get("disabled_mail_domains"), list):
        normalized["disabled_mail_domains"] = ",".join(
            str(x).strip() for x in normalized["disabled_mail_domains"] if str(x).strip()
        )
    else:
        normalized["disabled_mail_domains"] = str(normalized.get("disabled_mail_domains") or "").strip()
    mail_domains = str(normalized.get("mail_domains") or "").strip()
    default_domains = str(normalized.get("defaultDomains") or "").strip()
    if not mail_domains and default_domains:
        mail_domains = default_domains
    normalized["mail_domains"] = mail_domains
    try:
        wait_seconds = float(normalized.get("turnstile_wait_seconds", 120) or 120)
    except Exception:
        wait_seconds = 120.0
    normalized["turnstile_wait_seconds"] = max(45.0, min(wait_seconds, 300.0))
    solver_url = str(normalized.get("turnstile_solver_url") or "").strip() or "http://127.0.0.1:5072"
    normalized["turnstile_solver_url"] = solver_url.rstrip("/")
    normalized["turnstile_solver_client_key"] = str(
        normalized.get("turnstile_solver_client_key") or "local"
    ).strip() or "local"
    try:
        solver_timeout = float(normalized.get("turnstile_solver_timeout", 120) or 120)
    except Exception:
        solver_timeout = 120.0
    normalized["turnstile_solver_timeout"] = max(30.0, min(solver_timeout, 300.0))
    sitekey = str(normalized.get("turnstile_sitekey") or "").strip()
    if not sitekey:
        sitekey = DEFAULT_CONFIG.get("turnstile_sitekey") or "0x4AAAAAAAhr9JGVDZbrZOo0"
    normalized["turnstile_sitekey"] = sitekey
    normalized["sub2api_concurrency"] = _parse_positive_int(
        normalized.get("sub2api_concurrency"), 3, minimum=0, maximum=1000
    )
    normalized["cpa_push_workers"] = _parse_positive_int(
        normalized.get("cpa_push_workers"), 3, minimum=1, maximum=10
    )
    normalized["sub2api_priority"] = _parse_positive_int(
        normalized.get("sub2api_priority"), 50, minimum=0, maximum=1000
    )
    auth_mode = str(normalized.get("sub2api_auth_mode") or "x-api-key").strip().lower()
    normalized["sub2api_auth_mode"] = "bearer" if auth_mode == "bearer" else "x-api-key"
    if isinstance(normalized.get("enable_nsfw"), str):
        normalized["enable_nsfw"] = normalized["enable_nsfw"].strip().lower() in {"1", "true", "yes", "on"}
    else:
        normalized["enable_nsfw"] = bool(normalized.get("enable_nsfw"))
    normalized["grok2api_auto_add_remote"] = bool(normalized.get("grok2api_auto_add_remote"))
    normalized["sub2api_auto_import_remote"] = bool(normalized.get("sub2api_auto_import_remote"))
    if "sub2api_auto_probe" in normalized:
        raw_probe = normalized.get("sub2api_auto_probe")
        if isinstance(raw_probe, str):
            normalized["sub2api_auto_probe"] = raw_probe.strip().lower() in {"1", "true", "yes", "on"}
        else:
            normalized["sub2api_auto_probe"] = bool(raw_probe)
    else:
        normalized["sub2api_auto_probe"] = True
    try:
        normalized["sub2api_init_gap_seconds"] = max(
            1.0, min(120.0, float(normalized.get("sub2api_init_gap_seconds") or 8))
        )
    except Exception:
        normalized["sub2api_init_gap_seconds"] = 8.0
    normalized["sub2api_test_model"] = str(
        normalized.get("sub2api_test_model") or "grok-4.5"
    ).strip() or "grok-4.5"
    if isinstance(normalized.get("cpa_auto_push_remote"), str):
        normalized["cpa_auto_push_remote"] = normalized["cpa_auto_push_remote"].strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    else:
        normalized["cpa_auto_push_remote"] = bool(normalized.get("cpa_auto_push_remote"))

    raw_paths = normalized.pop("cloudflare_paths", "")
    if raw_paths:
        parts = [x.strip() for x in str(raw_paths).split(",") if x.strip()]
        if len(parts) >= 4:
            normalized["cloudflare_path_domains"] = _normalize_path(parts[0])
            normalized["cloudflare_path_accounts"] = _normalize_path(parts[1])
            normalized["cloudflare_path_token"] = _normalize_path(parts[2])
            normalized["cloudflare_path_messages"] = _normalize_path(parts[3])

    for key in (
        "cloudflare_path_domains",
        "cloudflare_path_accounts",
        "cloudflare_path_token",
        "cloudflare_path_messages",
    ):
        normalized[key] = _normalize_path(normalized.get(key))

    if provider == "cloudflare" and not str(normalized.get("cloudflare_api_base") or "").strip():
        raise ValueError("Cloudflare 模式需要先填写 Cloudflare API Base")
    if provider == "cloudmail":
        if not str(normalized.get("cloudmail_url") or "").strip():
            raise ValueError("CloudMail 模式需要先填写 CloudMail URL")
        if not str(normalized.get("cloudmail_admin_email") or "").strip():
            raise ValueError("CloudMail 模式需要先填写 CloudMail 管理员邮箱")
        if not str(normalized.get("cloudmail_password") or "").strip():
            raise ValueError("CloudMail 模式需要先填写 CloudMail 管理员密码")
    if provider in {"openai_cpa_email", "cpa_email"}:
        mail_domains = str(
            normalized.get("mail_domains") or normalized.get("defaultDomains") or ""
        ).strip()
        if not mail_domains:
            raise ValueError("openai_cpa_email 模式需要填写 mail_domains / defaultDomains")
        # webhook 模式默认开启收件池（仅该 provider 依赖）
        normalized["email_webhook_enabled"] = True
        if not str(normalized.get("email_webhook_secret") or "").strip():
            raise ValueError(
                "openai_cpa_email 模式需要填写 email_webhook_secret（与 CF Worker EMAIL_WEBHOOK_SECRET 一致）"
            )
    # 说明：email_webhook_enabled 仅表示「允许接收 Worker 推送」。
    # yyds/duckmail/cloudflare/cloudmail 的收信路径不再受该开关影响。
    if normalized["cpa_auto_push_remote"]:
        if not str(normalized.get("cpa_management_base") or "").strip():
            raise ValueError("CPA 自动推送需要先填写 CPA 管理地址")
        if not str(normalized.get("cpa_management_key") or "").strip():
            raise ValueError("CPA 自动推送需要先填写 CPA 管理密钥")
    return normalized

