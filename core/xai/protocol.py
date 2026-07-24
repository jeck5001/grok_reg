"""xAI accounts protocol: next-action, gRPC, pure HTTP / API signup."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import sys
import threading
import time
import uuid

from core.cancel import raise_if_cancelled as _raise_if_cancelled_impl
from core.cancel import sleep_with_cancel as _sleep_with_cancel_impl
from core.config import DEFAULT_CONFIG, config
from core.exceptions import (
    EmailDomainRejected,
    EmailProviderUnavailable,
    ProfileSessionLost,
    RegistrationCancelled,
    StaleNextActionError,
)
from core.http_client import get_proxies, http_get, http_post
from core.paths import get_data_dir
from core.runtime import _env_truthy, normalize_proxy_for_runtime
from core.turnstile.solver import (
    normalize_turnstile_solver_url,
    probe_local_turnstile_solver,
    solve_turnstile_via_local_solver,
)

try:
    from curl_cffi import requests
except ModuleNotFoundError:
    requests = None


def _facade():
    return sys.modules.get("grok_register_ttk")


def _resolve(name, default):
    fac = _facade()
    if fac is not None and hasattr(fac, name):
        return getattr(fac, name)
    return default


def sleep_with_cancel(seconds, cancel_callback=None):
    return _resolve("sleep_with_cancel", _sleep_with_cancel_impl)(seconds, cancel_callback)


def raise_if_cancelled(cancel_callback=None):
    return _resolve("raise_if_cancelled", _raise_if_cancelled_impl)(cancel_callback)


def _now():
    fac = _facade()
    if fac is not None:
        tmod = getattr(fac, "time", None)
        if tmod is not None and hasattr(tmod, "time"):
            return tmod.time()
    return time.time()



def get_user_agent():
    fac = _facade()
    if fac is not None and hasattr(fac, "get_user_agent"):
        return fac.get_user_agent()
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def build_profile():
    return _resolve("build_profile", lambda: ("Neo", "Lin", "Ntest!a7#x"))()


def get_email_and_token(*args, **kwargs):
    fn = _resolve("get_email_and_token", None)
    if fn is None:
        from core.email.providers import get_email_and_token as fn
    return fn(*args, **kwargs)


def get_oai_code(*args, **kwargs):
    fn = _resolve("get_oai_code", None)
    if fn is None:
        from core.email.providers import get_oai_code as fn
    return fn(*args, **kwargs)


def remember_rejected_email_domain(*args, **kwargs):
    fn = _resolve("remember_rejected_email_domain", None)
    if fn is None:
        from core.email.providers import remember_rejected_email_domain as fn
    return fn(*args, **kwargs)


def scrape_turnstile_context_from_page(page):
    return _resolve(
        "scrape_turnstile_context_from_page",
        lambda p: {"url": "", "sitekey": config.get("turnstile_sitekey") or "", "action": "", "cdata": "", "source": ""},
    )(page)


def _get_page():
    return _resolve("_get_page", lambda: None)()

def _read_turnstile_token_from_page(page):
    return _resolve("_read_turnstile_token_from_page", lambda p: "")(page)


def inject_turnstile_token_to_page(page, token):
    return _resolve("inject_turnstile_token_to_page", lambda p, t: 0)(page, token)


def getTurnstileToken(*args, **kwargs):
    fn = _resolve("getTurnstileToken", None)
    if fn is None:
        from core.turnstile.solver import getTurnstileToken as fn
    return fn(*args, **kwargs)

SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
_RSC_PUSH_RE = re.compile(r'self\.__next_f\.push\(\[1,"((?:[^"\\]|\\.)*)"\]\)')
_NEXT_ACTION_CHUNK_HINTS = (
    "createUserAndSessionRequest",
    "emailValidationCode",
    "turnstileToken",
)


def resolve_signup_mode():
    """auto: Docker 默认 http 纯协议；本机默认 browser。"""
    mode = str(config.get("signup_mode") or "auto").strip().lower()
    if mode in {"http", "api", "browser"}:
        return mode
    env_mode = str(os.environ.get("GROK_REG_SIGNUP_MODE") or "").strip().lower()
    if env_mode in {"http", "api", "browser"}:
        return env_mode
    if _env_truthy("GROK_REG_IN_DOCKER"):
        return "http"
    return "browser"


def export_browser_cookies(page, domain_hint="x.ai"):
    """导出浏览器 cookie，供 curl_cffi Session 复用 cf_clearance 等。"""
    cookies = []
    if not page:
        return cookies
    try:
        raw = page.cookies(all_domains=True, all_info=True) or []
    except Exception:
        try:
            raw = page.cookies() or []
        except Exception:
            raw = []
    for item in raw:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            value = str(item.get("value") or "").strip()
            domain = str(item.get("domain") or item.get("host") or "").strip()
            path = str(item.get("path") or "/").strip() or "/"
        else:
            name = str(getattr(item, "name", "") or "").strip()
            value = str(getattr(item, "value", "") or "").strip()
            domain = str(getattr(item, "domain", "") or "").strip()
            path = str(getattr(item, "path", "/") or "/").strip() or "/"
        if not name:
            continue
        if domain_hint and domain and domain_hint not in domain:
            continue
        cookies.append(
            {
                "name": name,
                "value": value,
                "domain": domain or ".x.ai",
                "path": path,
            }
        )
    return cookies


def _cookie_header_from_list(cookies):
    pairs = []
    for c in cookies or []:
        name = str(c.get("name") or "").strip()
        value = str(c.get("value") or "")
        if name:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


_NEXT_ACTION_CACHE = {
    "action": "",
    "router": "",
    "chunk_path": "",
    "at": 0.0,
    "html_sig": "",
}
# xAI 部署会换 next-action；缓存过长会 404 Server action not found
_NEXT_ACTION_CACHE_TTL = 2 * 3600  # 2h
_NEXT_ACTION_CACHE_LOCK = threading.Lock()


def _next_action_cache_path():
    return os.path.join(get_data_dir(), "next_action_cache.json")


def _load_next_action_disk_cache():
    path = _next_action_cache_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return
        with _NEXT_ACTION_CACHE_LOCK:
            _NEXT_ACTION_CACHE.update(
                {
                    "action": str(data.get("action") or ""),
                    "router": str(data.get("router") or ""),
                    "chunk_path": str(data.get("chunk_path") or ""),
                    "at": float(data.get("at") or 0),
                    "html_sig": str(data.get("html_sig") or ""),
                }
            )
    except Exception:
        pass


def _save_next_action_disk_cache():
    path = _next_action_cache_path()
    try:
        with _NEXT_ACTION_CACHE_LOCK:
            payload = dict(_NEXT_ACTION_CACHE)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
    except Exception:
        pass


def invalidate_next_action_cache(log_callback=None):
    """next-action 过期（Server action not found）时清缓存。"""
    with _NEXT_ACTION_CACHE_LOCK:
        _NEXT_ACTION_CACHE["action"] = ""
        _NEXT_ACTION_CACHE["router"] = ""
        _NEXT_ACTION_CACHE["chunk_path"] = ""
        _NEXT_ACTION_CACHE["at"] = 0.0
        _NEXT_ACTION_CACHE["html_sig"] = ""
    path = _next_action_cache_path()
    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass
    if log_callback:
        log_callback("[*] 已清除 next-action 缓存（将强制重扫）")


def _html_action_signature(html):
    """用页面引用的 chunk 文件名做指纹，部署变更时自动失效缓存。"""
    names = re.findall(r"/_next/static/chunks/([^\"']+\.js)", str(html or ""))
    names = sorted(set(names))[:30]
    return hashlib.sha1("|".join(names).encode("utf-8")).hexdigest()[:16]


def _default_router_state_tree_header():
    router_tree = json.dumps(
        [
            "",
            {
                "children": [
                    "(app)",
                    {
                        "children": [
                            "(auth)",
                            {
                                "children": [
                                    "sign-up",
                                    {
                                        "children": [
                                            '__PAGE__?{"redirect":"grok-com"}',
                                            {},
                                        ]
                                    },
                                ]
                            },
                        ]
                    },
                ]
            },
            "$undefined",
            "$undefined",
            16,
        ],
        separators=(",", ":"),
    )
    return urllib.parse.quote(router_tree, safe="")


def scrape_signup_next_headers(
    html,
    log_callback=None,
    proxies=None,
    force_refresh=False,
    browser_cookies=None,
    page=None,
):
    """从 accounts.x.ai sign-up HTML/JS 提取 next-action 与 router-state-tree。

    逻辑对齐 grokcli-2api/xconsole_client；带内存+磁盘缓存，避免每次扫 40+ chunk。
    chunk 下载必须带浏览器 cookie（cf_clearance），否则代理下常被 CF 空响应。
    """
    html = str(html or "")
    if not html:
        raise RuntimeError("sign-up 页面 HTML 为空，无法提取 next-action")

    sig = _html_action_signature(html)
    now = _now()
    if not force_refresh:
        _load_next_action_disk_cache()
        with _NEXT_ACTION_CACHE_LOCK:
            cached_action = str(_NEXT_ACTION_CACHE.get("action") or "")
            cached_router = str(_NEXT_ACTION_CACHE.get("router") or "")
            cached_at = float(_NEXT_ACTION_CACHE.get("at") or 0)
            cached_sig = str(_NEXT_ACTION_CACHE.get("html_sig") or "")
        # 只要 action 有效且未过期就用（html_sig 仅作参考，部署变了再靠失败重扫）
        if cached_action and len(cached_action) >= 40 and now - cached_at < _NEXT_ACTION_CACHE_TTL:
            if log_callback:
                age = int(now - cached_at)
                log_callback(
                    f"[*] next-action 缓存命中 {cached_action[:16]}... (age={age}s)"
                )
            return {
                "next_action": cached_action,
                "router_state_tree": cached_router or _default_router_state_tree_header(),
            }

    # ---- router state tree ----
    router_tree = None
    rsc_segments = _RSC_PUSH_RE.findall(html)
    for seg in rsc_segments:
        unescaped = seg.replace('\\"', '"')
        m = re.search(r'"f":\[(\[.*?\])', unescaped)
        if not m:
            continue
        flight_seg = m.group(1)
        if not flight_seg.startswith('[["",{"children"'):
            continue
        depth = 0
        tree_end = 0
        for i, ch in enumerate(flight_seg):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    tree_end = i + 1
                    break
        if tree_end <= 0:
            continue
        try:
            parsed = json.loads(flight_seg[:tree_end])
            if isinstance(parsed, list) and parsed:
                router_tree = json.dumps(parsed[0], separators=(",", ":"))
                break
        except Exception:
            continue
    if router_tree:
        router_header = urllib.parse.quote(router_tree, safe="")
    else:
        router_header = _default_router_state_tree_header()
        if log_callback:
            log_callback("[Debug] next-router-state-tree 使用 grok-com 兜底结构")

    # ---- next-action from JS chunks ----
    # 1) 先从 HTML/RSC 正文抠 42 位 hex（部分部署会内联）
    # 2) 再用「浏览器 cookie」下载 chunk（无 cookie 时代理下常被 CF 空响应）
    js_paths = list(set(re.findall(r'src="(/_next/static/chunks/[^"]+\.js)"', html)))
    if log_callback:
        log_callback(f"[Debug] 扫描 JS chunk 查找 next-action（共 {len(js_paths)}）...")

    signup_hash = None
    fallback_hash = None
    scanned = 0
    hit_ok = 0
    hit_empty = 0

    # HTML 内联候选
    inline_hashes = re.findall(r'["\']([a-f0-9]{42})["\']', html)
    for h in inline_hashes:
        # 带 7f 前缀的更像 server action metadata
        if h.startswith("7f") and not fallback_hash:
            fallback_hash = h

    cookie_header = _cookie_header_from_list(browser_cookies or [])
    session = None
    if requests is not None:
        sk = {"impersonate": "chrome131", "timeout": 15}
        if proxies:
            sk["proxies"] = proxies
        try:
            session = requests.Session(**sk)
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
        except Exception:
            session = None

    def _fetch_chunk(path):
        url = f"https://accounts.x.ai{path}"
        text = ""
        # 优先浏览器 fetch（同源 cookie/TLS 最稳；CDP awaitPromise 真正等待）
        if page is not None:
            try:
                expr = (
                    "(async()=>{try{const r=await fetch(%s,{credentials:'include',cache:'force-cache'});"
                    "return r.ok?await r.text():'';}catch(e){return '';}})()"
                ) % json.dumps(url)
                cdp = page.run_cdp(
                    "Runtime.evaluate",
                    expression=expr,
                    awaitPromise=True,
                    returnByValue=True,
                ) or {}
                text = str(((cdp.get("result") or {}).get("value")) or "")
            except Exception:
                text = ""
        if (not text or len(text) < 50) and session is not None:
            try:
                headers = {
                    "accept": "*/*",
                    "user-agent": get_user_agent(),
                    "referer": SIGNUP_URL,
                }
                if cookie_header:
                    headers["cookie"] = cookie_header
                resp = session.get(url, headers=headers, timeout=15)
                text = resp.text or ""
            except Exception:
                text = ""
        if not text or len(text) < 50:
            return None, False
        hashes = re.findall(r'"([a-f0-9]{42})"', text)
        if not hashes:
            # 无引号形态
            hashes = re.findall(r'(?<![a-f0-9])([a-f0-9]{42})(?![a-f0-9])', text)
        if not hashes:
            return None, False
        is_signup = any(h in text for h in _NEXT_ACTION_CHUNK_HINTS)
        # signup chunk 里优先 7f 开头
        preferred = next((x for x in hashes if x.startswith("7f")), hashes[0])
        return preferred, is_signup

    with _NEXT_ACTION_CACHE_LOCK:
        preferred_path = str(_NEXT_ACTION_CACHE.get("chunk_path") or "")
    ordered = sorted(
        js_paths,
        key=lambda p: (
            0 if preferred_path and p == preferred_path else 1,
            0
            if any(
                x in p
                for x in (
                    "06rq",
                    "create",
                    "sign",
                    "auth",
                    "action",
                    "0rq",
                    "csyr",
                    "user",
                )
            )
            else 1,
            p,
        ),
    )
    # 命中 signup 关键字立即停；最多扫 12 个优先 chunk（避免 40 次空请求）
    hit_path = ""
    for path in ordered[:12]:
        scanned += 1
        h, is_signup = _fetch_chunk(path)
        if not h:
            hit_empty += 1
            continue
        hit_ok += 1
        if is_signup:
            signup_hash = h
            hit_path = path
            break
        if fallback_hash is None or (h.startswith("7f") and not str(fallback_hash).startswith("7f")):
            fallback_hash = h
            if not hit_path:
                hit_path = path
    # 前 12 没命中 signup，再扩扫剩余（仍命中即停）
    if not signup_hash:
        for path in ordered[12:]:
            scanned += 1
            h, is_signup = _fetch_chunk(path)
            if not h:
                hit_empty += 1
                continue
            hit_ok += 1
            if is_signup:
                signup_hash = h
                hit_path = path
                break
            if fallback_hash is None or (h.startswith("7f") and not str(fallback_hash).startswith("7f")):
                fallback_hash = h
                if not hit_path:
                    hit_path = path

    try:
        if session is not None:
            session.close()
    except Exception:
        pass

    action_id = signup_hash or fallback_hash

    # 扫描失败：放宽用任意缓存（忽略 html_sig，最长 14 天）
    if not action_id or len(str(action_id)) < 40:
        _load_next_action_disk_cache()
        with _NEXT_ACTION_CACHE_LOCK:
            stale_action = str(_NEXT_ACTION_CACHE.get("action") or "")
            stale_router = str(_NEXT_ACTION_CACHE.get("router") or "")
            stale_at = float(_NEXT_ACTION_CACHE.get("at") or 0)
        if stale_action and len(stale_action) >= 40 and _now() - stale_at < 14 * 86400:
            if log_callback:
                log_callback(
                    f"[!] next-action 扫描失败（ok={hit_ok}/empty={hit_empty}/total={scanned}），"
                    f"回退缓存 {stale_action[:16]}... age={int(_now() - stale_at)}s"
                )
            return {
                "next_action": stale_action,
                "router_state_tree": stale_router or router_header,
            }
        raise RuntimeError(
            f"未能从 JS chunk 提取 next-action（ok={hit_ok}/empty={hit_empty}/total={scanned}）。"
            "请确认代理可访问 accounts.x.ai 静态资源，或检查浏览器 cookie 是否带 cf_clearance"
        )

    if log_callback:
        log_callback(
            f"[*] next-action={action_id[:16]}... ({len(action_id)} chars, "
            f"{'signup' if signup_hash else 'fallback'}, scanned={scanned})"
        )

    with _NEXT_ACTION_CACHE_LOCK:
        _NEXT_ACTION_CACHE["action"] = action_id
        _NEXT_ACTION_CACHE["router"] = router_header
        _NEXT_ACTION_CACHE["chunk_path"] = hit_path or preferred_path
        _NEXT_ACTION_CACHE["at"] = _now()
        _NEXT_ACTION_CACHE["html_sig"] = sig
    _save_next_action_disk_cache()
    return {"next_action": action_id, "router_state_tree": router_header}


def _normalize_rsc_text(rsc_body):
    text = str(rsc_body or "")
    for _ in range(3):
        nxt = (
            text.replace("\\u0026", "&")
            .replace("\\u003d", "=")
            .replace("\\u003f", "?")
            .replace("\\u002F", "/")
            .replace("\\u002f", "/")
            .replace("\\/", "/")
            .replace("&amp;", "&")
        )
        if nxt == text:
            break
        text = nxt
    return text


def _parse_jwt_payload(token):
    try:
        parts = str(token or "").split(".")
        if len(parts) < 2:
            return None
        raw = parts[1]
        raw += "=" * ((4 - len(raw) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
    except Exception:
        return None


def _looks_like_sso_session_jwt(token):
    """sso cookie JWT 通常带 session_id；过滤 RSC 里的其它 JWT 误匹配。"""
    token = str(token or "").strip()
    if not token.startswith("eyJ") or token.count(".") < 2:
        return False
    payload = _parse_jwt_payload(token) or {}
    if not isinstance(payload, dict):
        return False
    # 真实 sso 常见字段
    if payload.get("session_id") or payload.get("sid") or payload.get("sub"):
        return True
    # 过短 payload 多半不是会话 cookie
    return len(token) >= 80 and bool(payload)


def extract_sso_from_http_result(set_cookies=None, body="", cookie_jar=None):
    """从 Set-Cookie / RSC body / session jar 提取 sso（仅接受会话 JWT）。"""
    patterns = [
        re.compile(
            r"(?:^|,\s*)sso=(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
            re.I,
        ),
    ]
    for raw in set_cookies or []:
        text = str(raw or "")
        for pat in patterns:
            m = pat.search(text)
            if m and _looks_like_sso_session_jwt(m.group(1)):
                return m.group(1).strip()
    body_text = _normalize_rsc_text(body)
    m = re.search(
        r'(?:^|[;,\s\'"\\])sso=(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
        body_text,
        flags=re.I | re.M,
    )
    if m and _looks_like_sso_session_jwt(m.group(1)):
        return m.group(1).strip()
    if cookie_jar is not None:
        try:
            if hasattr(cookie_jar, "get"):
                for domain in (".x.ai", "accounts.x.ai", ".grok.com", "auth.x.ai", None):
                    try:
                        val = (
                            cookie_jar.get("sso", domain=domain)
                            if domain is not None
                            else cookie_jar.get("sso")
                        )
                        if val and _looks_like_sso_session_jwt(val):
                            return str(val).strip()
                    except Exception:
                        pass
        except Exception:
            pass
    return ""


def _normalize_set_cookie_hop_url(raw):
    """规范化 RSC 里抠出的 set-cookie hop URL，避免 accounts.x.ai//auth.xxx 坏链。"""
    url = str(raw or "").strip().strip("\\\"'")
    if not url:
        return ""
    url = url.replace("\\/", "/")
    if url.startswith("//"):
        url = "https:" + url
    # 错误形态：/auth.grokipedia.com/set-cookie?...
    if re.match(r"^/auth\.[^/]+/", url):
        # /auth.grokipedia.com/... → https://auth.grokipedia.com/...
        url = "https://" + url.lstrip("/")
    if url.startswith("/") and "set-cookie" in url:
        url = "https://accounts.x.ai" + url
    # 修双重斜杠 accounts.x.ai//host
    url = re.sub(r"https://accounts\.x\.ai//+", "https://", url)
    if not url.startswith("http"):
        return ""
    return url


def _collect_set_cookie_hop_urls(rsc_body):
    text = _normalize_rsc_text(rsc_body)
    hops = []

    def _add(u):
        u = _normalize_set_cookie_hop_url(u)
        if u and u not in hops:
            hops.append(u)

    for m in re.finditer(
        r'https?://[^\s"\'<>\\]+set-cookie/?\?q='
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        text,
        flags=re.I,
    ):
        _add(m.group(0))
    for m in re.finditer(
        r'//[^\s"\'<>\\]+set-cookie/?\?q='
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        text,
        flags=re.I,
    ):
        _add(m.group(0))
    for m in re.finditer(
        r'(?:https?:)?//auth\.(?:x\.ai|grokusercontent\.com|grokipedia\.com)/set-cookie/?\?q='
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        text,
        flags=re.I,
    ):
        _add(m.group(0) if m.group(0).startswith("http") else "https:" + m.group(0).lstrip(":"))

    # 相对 path
    for m in re.finditer(
        r'(?<![a-zA-Z0-9:])/set-cookie/?\?q='
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        text,
        flags=re.I,
    ):
        _add("https://accounts.x.ai" + m.group(0))

    # JWT near set-cookie → 优先 grokusercontent / auth.x.ai；跳过 grokipedia（几乎总是 400）
    if not hops:
        m = re.search(
            r"set-cookie[^e]{0,120}(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
            text,
            flags=re.I,
        )
        if m:
            jwt = m.group(1)
            _add(f"https://auth.grokusercontent.com/set-cookie?q={jwt}")
            _add(f"https://auth.x.ai/set-cookie?q={jwt}")

    # expand success_url（过滤 grokipedia）
    expanded = []
    for hop in hops:
        if "grokipedia.com" in hop:
            continue
        if hop not in expanded:
            expanded.append(hop)
    for hop in list(expanded):
        m = re.search(r"q=(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", hop)
        if not m:
            continue
        payload = _parse_jwt_payload(m.group(1)) or {}
        for key in ("success_url", "successUrl", "redirect_url", "redirectUrl"):
            success = str(payload.get(key) or "").strip()
            if not success or "grokipedia.com" in success:
                continue
            u = _normalize_set_cookie_hop_url(success)
            if u and u not in expanded and "grokipedia.com" not in u:
                expanded.append(u)
    # 固定兜底 hop（2api fetch_sso_token）— 不再默认扫 grok.com（慢且无 sso）
    for fixed in (
        "https://auth.grokusercontent.com/set-cookie",
        "https://auth.x.ai/set-cookie",
        "https://accounts.x.ai/",
    ):
        if fixed not in expanded:
            expanded.append(fixed)
    return expanded


def _extract_any_sso_from_set_cookies(set_cookies):
    """hop 响应里放宽解析：先严格会话 JWT，再退回任意 sso=eyJ。"""
    token = extract_sso_from_http_result(set_cookies, "", None)
    if token:
        return token
    for raw in set_cookies or []:
        m = re.search(
            r"(?:^|,\s*)sso=(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
            str(raw or ""),
            flags=re.I,
        )
        if m:
            return m.group(1).strip()
    return ""


def extract_sso_via_set_cookie_chain(rsc_body, session=None, proxies=None, log_callback=None):
    """对齐 grokcli-2api：跟随 RSC set-cookie JWT 链路拿真实 sso。"""
    text = _normalize_rsc_text(rsc_body)
    direct = extract_sso_from_http_result([], text, None)
    if direct:
        if log_callback:
            payload = _parse_jwt_payload(direct) or {}
            log_callback(
                f"[Debug] RSC 直接含 sso JWT len={len(direct)} "
                f"session_id={str(payload.get('session_id') or payload.get('sid') or '')[:24]}"
            )
        return direct

    hop_urls = _collect_set_cookie_hop_urls(rsc_body)
    if log_callback:
        log_callback(f"[Debug] SSO set-cookie 链路候选: {len(hop_urls)}")
        for u in hop_urls[:5]:
            log_callback(f"[Debug]   hop: {u[:100]}")

    if not hop_urls:
        return ""

    own_session = session is None
    if own_session:
        if requests is None:
            return ""
        sk = {"impersonate": "chrome131", "timeout": 30}
        if proxies:
            sk["proxies"] = proxies
        session = requests.Session(**sk)

    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "user-agent": get_user_agent(),
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "referer": "https://accounts.x.ai/",
    }
    token = ""
    try:
        for hop in hop_urls[:12]:
            try:
                resp = session.get(hop, headers=headers, allow_redirects=True)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] SSO hop 失败: {str(exc)[:120]}")
                continue
            set_cookies = []
            try:
                if hasattr(resp.headers, "get_list"):
                    set_cookies = resp.headers.get_list("set-cookie") or []
                else:
                    raw_sc = resp.headers.get("set-cookie")
                    if raw_sc:
                        set_cookies = [raw_sc] if isinstance(raw_sc, str) else list(raw_sc)
            except Exception:
                set_cookies = []
            # 有些 hop 即使 HTTP 400 也会带 Set-Cookie
            token = (
                _extract_any_sso_from_set_cookies(set_cookies)
                or extract_sso_from_http_result([], resp.text or "", session.cookies)
            )
            if log_callback:
                sc_preview = ""
                if set_cookies:
                    sc_preview = str(set_cookies[0])[:80]
                log_callback(
                    f"[Debug] SSO hop HTTP {resp.status_code} "
                    f"set_cookies={len(set_cookies)} sso={'yes' if token else 'no'} "
                    f"url={hop[:90]} sc={sc_preview!r}"
                )
            if token:
                break
            loc = ""
            try:
                loc = str(resp.headers.get("location") or resp.headers.get("Location") or "")
            except Exception:
                loc = ""
            loc = _normalize_set_cookie_hop_url(loc)
            if loc and loc not in hop_urls:
                hop_urls.append(loc)
    finally:
        if own_session:
            try:
                session.close()
            except Exception:
                pass
    return token


def _grpc_encode_varint(value):
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _grpc_encode_string(field_no, text):
    raw = str(text or "").encode("utf-8")
    tag = _grpc_encode_varint((field_no << 3) | 2)
    return tag + _grpc_encode_varint(len(raw)) + raw


def _grpc_encode_bytes(field_no, raw):
    raw = bytes(raw or b"")
    tag = _grpc_encode_varint((field_no << 3) | 2)
    return tag + _grpc_encode_varint(len(raw)) + raw


def _grpc_frame_request(message):
    msg = bytes(message or b"")
    return b"\x00" + struct.pack(">I", len(msg)) + msg


def _grpc_decode_fields(data):
    """Best-effort protobuf decode for CreateSession response strings."""
    fields = []
    i = 0
    data = bytes(data or b"")
    n = len(data)
    while i < n:
        # varint tag
        result = 0
        shift = 0
        while i < n:
            b = data[i]
            i += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        field_no = result >> 3
        wt = result & 0x07
        if wt == 2:  # length-delimited
            ln = 0
            shift = 0
            while i < n:
                b = data[i]
                i += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            chunk = data[i : i + ln]
            i += ln
            try:
                text = chunk.decode("utf-8")
                if text.isprintable() or text.startswith("eyJ"):
                    fields.append({"field": field_no, "type": "string", "value": text})
                else:
                    fields.append({"field": field_no, "type": "bytes", "value": chunk})
            except Exception:
                fields.append({"field": field_no, "type": "bytes", "value": chunk})
        elif wt == 0:  # varint
            val = 0
            shift = 0
            while i < n:
                b = data[i]
                i += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            fields.append({"field": field_no, "type": "varint", "value": val})
        else:
            break
    return fields


def _grpc_parse_response(raw):
    """Parse grpc-web frames → messages + trailers."""
    raw = bytes(raw or b"")
    messages = []
    trailers = {}
    i = 0
    while i + 5 <= len(raw):
        flag = raw[i]
        length = struct.unpack(">I", raw[i + 1 : i + 5])[0]
        i += 5
        payload = raw[i : i + length]
        i += length
        if flag == 0x00:
            messages.append(_grpc_decode_fields(payload))
        elif flag == 0x80:
            try:
                text = payload.decode("utf-8", "replace")
                for line in text.split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        trailers[k.strip().lower()] = v.strip()
            except Exception:
                pass
    grpc_status = trailers.get("grpc-status")
    try:
        grpc_status = int(grpc_status) if grpc_status is not None else None
    except Exception:
        pass
    return {"messages": messages, "trailers": trailers, "grpc_status": grpc_status}


def encode_create_session_request(email, password, turnstile_token, castle_request_token=""):
    """CreateSessionRequest protobuf — 对齐 grokcli-2api oauth_protocol。"""
    email_pw = _grpc_encode_string(1, email) + _grpc_encode_string(2, password)
    credentials = _grpc_encode_bytes(1, email_pw)
    req = _grpc_encode_bytes(1, credentials)
    anti = _grpc_encode_string(1, turnstile_token) + _grpc_encode_string(
        2, castle_request_token or ""
    )
    req += _grpc_encode_bytes(4, anti)
    return req


def obtain_sso_via_create_session(
    email,
    password,
    turnstile_token,
    *,
    browser_cookies=None,
    proxies=None,
    log_callback=None,
    cancel_callback=None,
    retries=3,
):
    """对齐 2api：create_account 无 sso 链路时，用密码 CreateSession 拿会话 JWT。"""
    if requests is None:
        return ""
    email = str(email or "").strip()
    password = str(password or "")
    turnstile_token = str(turnstile_token or "").strip()
    if not email or not password or len(turnstile_token) < 80:
        return ""

    proxies = proxies if proxies is not None else get_proxies()
    sk = {"impersonate": "chrome131", "timeout": 30}
    if proxies:
        sk["proxies"] = proxies
    signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"
    rpc = "https://accounts.x.ai/auth_mgmt.AuthManagement/CreateSession"

    with requests.Session(**sk) as session:
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
        for attempt in range(1, max(1, int(retries)) + 1):
            raise_if_cancelled(cancel_callback)
            body = encode_create_session_request(email, password, turnstile_token)
            framed = _grpc_frame_request(body)
            headers = {
                "content-type": "application/grpc-web+proto",
                "x-grpc-web": "1",
                "x-user-agent": "connect-es/2.1.1",
                "accept": "*/*",
                "origin": "https://accounts.x.ai",
                "referer": signin_url,
                "user-agent": get_user_agent(),
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
            }
            try:
                resp = session.post(rpc, data=framed, headers=headers, timeout=30)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[!] CreateSession 网络错误: {exc}")
                sleep_with_cancel(0.6 * attempt, cancel_callback)
                continue
            set_cookies = []
            try:
                if hasattr(resp.headers, "get_list"):
                    set_cookies = resp.headers.get_list("set-cookie") or []
                else:
                    raw_sc = resp.headers.get("set-cookie")
                    if raw_sc:
                        set_cookies = [raw_sc] if isinstance(raw_sc, str) else list(raw_sc)
            except Exception:
                set_cookies = []
            token = (
                _extract_any_sso_from_set_cookies(set_cookies)
                or extract_sso_from_http_result([], "", session.cookies)
            )
            session_jwt = None
            grpc_status = None
            try:
                parsed = _grpc_parse_response(resp.content or b"")
                for msg in parsed.get("messages") or []:
                    for f in msg:
                        if f.get("type") == "string":
                            val = str(f.get("value") or "")
                            if val.startswith("eyJ") and val.count(".") >= 2:
                                session_jwt = val
                                break
                    if session_jwt:
                        break
                grpc_status = parsed.get("grpc_status")
            except Exception:
                pass
            if log_callback:
                log_callback(
                    f"[*] CreateSession HTTP {resp.status_code} grpc={grpc_status} "
                    f"jwt={'yes' if (token or session_jwt) else 'no'}"
                )
            sso = token or (
                session_jwt
                if session_jwt and session_jwt.startswith("eyJ") and session_jwt.count(".") >= 2
                else ""
            )
            if sso:
                # CreateSession 的 JWT 只是 accounts 会话；要走 OAuth Device Flow / consent，
                # 还需要 CreateCookieSetterLink 把 sso 种到 auth.x.ai / grokusercontent 等域。
                try:
                    promo = promote_sso_session_cookies(
                        sso,
                        session=session,
                        proxies=proxies,
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                    )
                    if isinstance(promo, dict) and promo.get("ok"):
                        # 导出推广后 jar，供后续 Device Flow 复用（勿另开空 session）
                        promo["cookies"] = promo.get("cookies") or _export_session_cookie_list(
                            session
                        )
                        promote_sso_session_cookies._last_promo = promo
                        # 关键：在同一 CreateSession session 上立刻换 RT
                        # （另开 Session 再塞 cookie 常出现 approve 成功但 token Access denied）
                        try:
                            from core.push.integrations import (
                                exchange_sso_to_refresh_token_via_device_flow,
                            )

                            if log_callback:
                                log_callback(
                                    "[*] CreateSession 同会话立即 Device Flow 换 Refresh Token..."
                                )
                            rt = exchange_sso_to_refresh_token_via_device_flow(
                                sso,
                                log_callback=log_callback,
                                cancel_callback=cancel_callback,
                                browser_cookies=promo.get("cookies"),
                                session=session,
                            )
                            if rt:
                                promote_sso_session_cookies._last_refresh_token = rt
                                if log_callback:
                                    log_callback(
                                        f"[*] CreateSession 同会话 Device Flow 成功，"
                                        f"refresh_token 长度={len(rt)}"
                                    )
                        except Exception as rt_exc:
                            if log_callback:
                                log_callback(
                                    f"[Debug] CreateSession 同会话 Device Flow 失败"
                                    f"（将在后续步骤重试）: {rt_exc}"
                                )
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] CookieSetter 推广会话失败（仍返回 sso）: {exc}")
                return sso
            sleep_with_cancel(0.5 * attempt, cancel_callback)
    return ""


def _set_sso_cookie_on_session(session, jwt_token):
    """把 session JWT 挂到多个相关域，供 AuthManagement / OIDC 读取。"""
    if not session or not jwt_token:
        return
    domains = (
        "accounts.x.ai",
        ".x.ai",
        "auth.x.ai",
        ".grok.com",
        "grok.com",
        "auth.grokusercontent.com",
    )
    for domain in domains:
        try:
            session.cookies.set("sso", jwt_token, domain=domain)
        except Exception:
            continue
    try:
        session.cookies.set("sso", jwt_token)
    except Exception:
        pass
    for domain in ("accounts.x.ai", ".x.ai", ".grok.com"):
        try:
            session.cookies.set("sso-rw", jwt_token, domain=domain)
        except Exception:
            continue


def create_cookie_setter_link(
    success_url,
    *,
    error_url="https://accounts.x.ai/sign-in",
    referer="https://accounts.x.ai/sign-in",
    session=None,
    proxies=None,
    log_callback=None,
):
    """AuthManagement/CreateCookieSetterLink → 多域 set-cookie 跳转 URL。"""
    if requests is None:
        return {"ok": False, "error": "curl_cffi 未安装", "cookie_setter_url": ""}
    success_url = str(success_url or "").strip()
    if not success_url:
        return {"ok": False, "error": "success_url 为空", "cookie_setter_url": ""}
    proxies = proxies if proxies is not None else get_proxies()
    own = session is None
    if own:
        sk = {"impersonate": "chrome131", "timeout": 30}
        if proxies:
            sk["proxies"] = proxies
        session = requests.Session(**sk)
    try:
        msg = _grpc_encode_string(1, success_url) + _grpc_encode_string(2, error_url)
        headers = {
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-user-agent": "connect-es/2.1.1",
            "accept": "*/*",
            "origin": "https://accounts.x.ai",
            "referer": referer,
            "user-agent": get_user_agent(),
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
        resp = session.post(
            "https://accounts.x.ai/auth_mgmt.AuthManagement/CreateCookieSetterLink",
            data=_grpc_frame_request(msg),
            headers=headers,
            timeout=30,
        )
        try:
            parsed = _grpc_parse_response(resp.content or b"")
        except Exception:
            parsed = {"messages": [], "trailers": {}, "grpc_status": None}
        grpc_status = parsed.get("grpc_status")
        try:
            grpc_status = int(grpc_status) if grpc_status is not None else None
        except Exception:
            pass
        urls = []
        for msg_fields in parsed.get("messages") or []:
            for f in msg_fields or []:
                if f.get("type") != "string":
                    continue
                val = str(f.get("value") or "")
                if "http://" in val or "https://" in val or "set-cookie" in val:
                    urls.append(val)
        cookie_setter = next((u for u in urls if "set-cookie" in u), None) or (
            urls[0] if urls else ""
        )
        ok = grpc_status in (None, 0) and bool(cookie_setter)
        if log_callback:
            log_callback(
                f"[*] CreateCookieSetterLink HTTP {resp.status_code} "
                f"grpc={grpc_status} setter={'yes' if cookie_setter else 'no'}"
            )
        return {
            "ok": ok,
            "error": None if ok else "CreateCookieSetterLink failed",
            "grpc_status": grpc_status,
            "cookie_setter_url": cookie_setter,
            "raw_urls": urls,
        }
    finally:
        if own:
            try:
                session.close()
            except Exception:
                pass


def _export_session_cookie_list(session):
    """导出 curl_cffi/requests cookie jar 为 [{name,value,domain,path}, ...]。"""
    out = []
    if not session:
        return out
    try:
        jar = session.cookies
        if hasattr(jar, "jar"):
            for c in jar.jar:
                out.append(
                    {
                        "name": getattr(c, "name", "") or "",
                        "value": getattr(c, "value", "") or "",
                        "domain": getattr(c, "domain", "") or ".x.ai",
                        "path": getattr(c, "path", "/") or "/",
                    }
                )
        elif hasattr(jar, "items"):
            for name, value in jar.items():
                out.append(
                    {"name": name, "value": value, "domain": ".x.ai", "path": "/"}
                )
    except Exception:
        pass
    return [c for c in out if c.get("name") and c.get("value") is not None]


def promote_sso_session_cookies(
    sso,
    *,
    session=None,
    proxies=None,
    success_url=None,
    log_callback=None,
    cancel_callback=None,
):
    """CreateSession 后把 session JWT 推广到 OAuth 相关域（CreateCookieSetterLink + 跳转）。

    返回 dict: {ok, cookie_setter_url, cookies, final_url}
    Device Flow 应复用 cookies，不要另开空 session 只塞 JWT。
    """
    sso = str(sso or "").strip()
    empty = {"ok": False, "cookie_setter_url": "", "cookies": [], "final_url": ""}
    if not sso or requests is None:
        return empty
    proxies = proxies if proxies is not None else get_proxies()
    own = session is None
    if own:
        sk = {"impersonate": "chrome131", "timeout": 30}
        if proxies:
            sk["proxies"] = proxies
        session = requests.Session(**sk)
    try:
        _set_sso_cookie_on_session(session, sso)
        success_url = (
            str(success_url or "").strip()
            or "https://accounts.x.ai/account"
        )
        raise_if_cancelled(cancel_callback)
        csl = create_cookie_setter_link(
            success_url,
            session=session,
            proxies=proxies,
            log_callback=log_callback,
        )
        setter = str(csl.get("cookie_setter_url") or "").strip()
        if not setter:
            return {
                "ok": False,
                "cookie_setter_url": "",
                "cookies": _export_session_cookie_list(session),
                "final_url": "",
            }
        # 关键：必须 allow_redirects=True，让 jar 真正吸收各 hop 的 Set-Cookie
        # （手动 302 链容易只拿到终页 HTML，auth 域 cookie 仍为空 → Device Flow Access denied）
        raise_if_cancelled(cancel_callback)
        try:
            resp = session.get(
                setter,
                headers={
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "user-agent": get_user_agent(),
                    "upgrade-insecure-requests": "1",
                },
                allow_redirects=True,
                timeout=45,
            )
            final_url = str(getattr(resp, "url", "") or setter)
            status = int(getattr(resp, "status_code", 0) or 0)
            if log_callback:
                log_callback(
                    f"[*] CookieSetter 完成 HTTP {status} "
                    f"url={final_url[:120]} cookies={len(_export_session_cookie_list(session))}"
                )
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] CookieSetter 跟随跳转失败: {exc}")
            final_url = setter
        cookies = _export_session_cookie_list(session)
        return {
            "ok": True,
            "cookie_setter_url": setter,
            "cookies": cookies,
            "final_url": final_url,
        }
    finally:
        if own:
            try:
                session.close()
            except Exception:
                pass

def extract_signup_hard_error(rsc_body):
    text = str(rsc_body or "")
    if not text:
        return None
    text_l = text.lower()
    m = re.search(r"(?m)^(\d+):E\{([^}]{0,400})", text)
    if m:
        return f"next_action_error:{m.group(2)[:160]}"
    for pat in (
        r"\b(turnstile_failed)\b",
        r"\b(account_signup_error)\b",
        r"\b(rate_limited)\b",
        r"\b(invalid_verification_code)\b",
        r"\b(email_already_in_use)\b",
        r"\b(user_already_exists)\b",
        r"\b(account_email_domain_rejected)\b",
        r"\b(form_invalid_disposable_email)\b",
    ):
        m = re.search(pat, text_l)
        if m:
            return m.group(1)
    m = re.search(r"wke\s*=\s*([a-z0-9_.:/-]+)", text_l)
    if m:
        return f"wke={m.group(1)}"
    return None


def create_xai_account_via_http(
    email,
    given_name,
    family_name,
    password,
    email_code,
    turnstile_token,
    *,
    next_action,
    router_state_tree,
    browser_cookies=None,
    signup_url=None,
    log_callback=None,
    cancel_callback=None,
    allow_create_session_fallback=True,
    signin_turnstile_token=None,
):
    """对齐 grokcli-2api：POST accounts.x.ai/sign-up Next.js server action 建号。

    signin_turnstile_token: 若已并行解好 sign-in token，CreateSession 直接用，不再串行等 Solver。
    """
    if requests is None:
        raise RuntimeError("curl_cffi 未安装，无法 API 建号")
    raise_if_cancelled(cancel_callback)
    signup_url = (signup_url or SIGNUP_URL).strip()
    email_code = str(email_code or "").strip().upper().replace(" ", "").replace("-", "")
    turnstile_token = str(turnstile_token or "").strip()
    if len(email_code) != 6:
        raise ValueError(f"验证码格式异常: {email_code!r}")
    if len(turnstile_token) < 80:
        raise ValueError(f"turnstile token 过短: len={len(turnstile_token)}")

    create_req = {
        "email": email,
        "givenName": given_name,
        "familyName": family_name,
        "clearTextPassword": password,
        "tosAcceptedVersion": "$undefined",
    }
    args = [
        {
            "emailValidationCode": email_code,
            "createUserAndSessionRequest": create_req,
            "turnstileToken": turnstile_token,
            "conversionId": str(uuid.uuid4()),
            "castleRequestToken": "",
        },
        {"client": "$T", "meta": "$undefined", "mutationKey": "$undefined"},
    ]
    body = json.dumps(args, separators=(",", ":"))
    ua = get_user_agent()
    proxies = get_proxies()
    headers = {
        "accept": "text/x-component",
        "content-type": "text/plain;charset=UTF-8",
        "next-action": next_action,
        "next-router-state-tree": router_state_tree,
        "origin": "https://accounts.x.ai",
        "referer": signup_url,
        "user-agent": ua,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
    }
    cookie_header = _cookie_header_from_list(browser_cookies)
    if cookie_header:
        headers["cookie"] = cookie_header

    if log_callback:
        log_callback(
            f"[*] API create_account: email={email} action={str(next_action)[:16]}... "
            f"tokenLen={len(turnstile_token)} cookies={len(browser_cookies or [])}"
        )

    session_kwargs = {"impersonate": "chrome131", "timeout": 45}
    if proxies:
        session_kwargs["proxies"] = proxies
    with requests.Session(**session_kwargs) as session:
        # 注入浏览器 cookie（cf_clearance 等）
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
        resp = session.post(signup_url, data=body.encode("utf-8"), headers=headers)
        set_cookies = []
        try:
            # curl_cffi may expose headers differently
            if hasattr(resp.headers, "get_list"):
                set_cookies = resp.headers.get_list("set-cookie") or []
            else:
                raw_sc = resp.headers.get("set-cookie")
                if raw_sc:
                    set_cookies = [raw_sc] if isinstance(raw_sc, str) else list(raw_sc)
        except Exception:
            set_cookies = []
        rsc_body = resp.text or ""
        hard_err = extract_signup_hard_error(rsc_body)
        sso = extract_sso_from_http_result(set_cookies, rsc_body, session.cookies)
        if log_callback:
            log_callback(
                f"[*] create_account HTTP {resp.status_code} hard_error={hard_err!r} "
                f"direct_sso={'yes' if sso else 'no'} body_len={len(rsc_body)} "
                f"preview={rsc_body[:180]!r}"
            )
        if hard_err:
            raise RuntimeError(f"create_account 被拒绝: {hard_err}")
        if resp.status_code != 200:
            body_l = (rsc_body or "").lower()
            if resp.status_code == 404 and "server action not found" in body_l:
                invalidate_next_action_cache(log_callback=log_callback)
                raise StaleNextActionError(
                    f"create_account HTTP 404: Server action not found "
                    f"(next-action 已失效，请重扫): {(next_action or '')[:20]}"
                )
            raise RuntimeError(
                f"create_account HTTP {resp.status_code}: {rsc_body[:300]}"
            )
        # 优先走 RSC set-cookie JWT 链路（真实浏览器种 cookie 路径）；
        # 只有链路上没有 sso 时才 CreateSession 密码登录兜底。
        if not sso:
            try:
                sso = extract_sso_via_set_cookie_chain(
                    rsc_body,
                    session=session,
                    proxies=proxies,
                    log_callback=log_callback,
                )
                if sso and log_callback:
                    log_callback(f"[*] RSC set-cookie 链路拿到 sso len={len(sso)}")
            except Exception as hop_exc:
                if log_callback:
                    log_callback(f"[Debug] RSC set-cookie 链路失败: {hop_exc}")
        # 账号刚创建时 CreateSession 偶发不可见，给一点传播时间
        if (not sso) and allow_create_session_fallback:
            sleep_with_cancel(2.0, cancel_callback)
        # create_account → CreateSession（优先用预解的 sign-in token，避免再等一轮 Solver）
        if (not sso) and allow_create_session_fallback:
            sitekey = str(config.get("turnstile_sitekey") or "0x4AAAAAAAhr9JGVDZbrZOo0")
            signin_token = str(signin_turnstile_token or "").strip()
            if len(signin_token) < 80:
                if log_callback:
                    log_callback("[*] 解 sign-in Turnstile 供 CreateSession...")
                try:
                    signin_token = solve_turnstile_via_local_solver(
                        website_url="https://accounts.x.ai/sign-in?redirect=grok-com",
                        website_key=sitekey,
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                    )
                except Exception as ts_exc:
                    if log_callback:
                        log_callback(f"[!] sign-in Turnstile 失败: {ts_exc}")
                    signin_token = turnstile_token
            elif log_callback:
                log_callback("[*] CreateSession 使用预解 sign-in token")
            sso = obtain_sso_via_create_session(
                email,
                password,
                signin_token,
                browser_cookies=browser_cookies,
                proxies=proxies,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
                retries=1,
            )
            if not sso:
                if log_callback:
                    log_callback("[*] CreateSession 重试：刷新 Turnstile...")
                try:
                    fresh = solve_turnstile_via_local_solver(
                        website_url="https://accounts.x.ai/sign-in?redirect=grok-com",
                        website_key=sitekey,
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                    )
                    sso = obtain_sso_via_create_session(
                        email,
                        password,
                        fresh,
                        browser_cookies=browser_cookies,
                        proxies=proxies,
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                        retries=1,
                    )
                except Exception as cs_exc:
                    if log_callback:
                        log_callback(f"[!] CreateSession 重试失败: {cs_exc}")
        if not sso:
            raise RuntimeError(
                "create_account 成功但未拿到 sso（CreateSession 失败）；"
                f"set_cookies={len(set_cookies)} preview={rsc_body[:200]!r}"
            )
        if log_callback:
            payload = _parse_jwt_payload(sso) or {}
            log_callback(
                f"[*] 会话就绪 JWT len={len(sso)} "
                f"sid={str(payload.get('session_id') or payload.get('sid') or payload.get('sub') or '')[:32]}"
            )
        return sso


def _solve_turnstile_quiet(website_url, website_key, label, log_callback=None, cancel_callback=None):
    """Solver 调用：只打开始/结束，去掉处理中刷屏。"""
    def _log(msg):
        if not log_callback:
            return
        # 过滤轮询噪音
        if "处理中" in msg or "任务已创建" in msg:
            return
        if msg.startswith("[*] 请求 Turnstile"):
            log_callback(f"[*] {label} Turnstile...")
            return
        if "成功" in msg and "token长度" in msg:
            log_callback(msg.replace("Turnstile Solver 成功", f"{label} Turnstile 成功"))
            return
        if msg.startswith("[Debug]"):
            return
        log_callback(msg)

    return solve_turnstile_via_local_solver(
        website_url=website_url,
        website_key=website_key,
        log_callback=_log,
        cancel_callback=cancel_callback,
    )


def register_via_api_after_otp(
    email,
    email_code,
    log_callback=None,
    cancel_callback=None,
):
    """OTP 已在浏览器验证后：并行 Solver + HTTP create_account / CreateSession。"""
    page = _get_page()
    if page is None:
        raise RuntimeError("页面未就绪，无法 API 建号")

    given_name, family_name, password = build_profile()
    if log_callback:
        log_callback(f"[*] API 建号：{given_name} {family_name}")

    try:
        html = page.html or ""
    except Exception:
        html = ""
    if len(html) < 500:
        try:
            page.get(SIGNUP_URL)
            sleep_with_cancel(1.2, cancel_callback)
            html = page.html or ""
        except Exception as exc:
            if log_callback:
                log_callback(f"[!] 页面 HTML 不足: {exc}")
    browser_cookies = export_browser_cookies(page)

    headers_meta = scrape_signup_next_headers(
        html,
        log_callback=log_callback,
        proxies=get_proxies(),
        browser_cookies=browser_cookies,
        page=page,
    )

    ctx = scrape_turnstile_context_from_page(page)
    website_url = ctx.get("url") or SIGNUP_URL
    website_key = ctx.get("sitekey") or str(
        config.get("turnstile_sitekey") or "0x4AAAAAAAhr9JGVDZbrZOo0"
    )
    signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"
    if not probe_local_turnstile_solver():
        raise RuntimeError(
            f"Turnstile Solver 不可达: {normalize_turnstile_solver_url()}"
        )

    # 并行解 signup + sign-in 两个 token（省掉串行第二轮 ~12s）
    if log_callback:
        log_callback("[*] 并行求解 signup/sign-in Turnstile...")
    signup_token = {"value": "", "error": None}
    signin_token = {"value": "", "error": None}

    def _job_signup():
        try:
            signup_token["value"] = _solve_turnstile_quiet(
                website_url,
                website_key,
                "signup",
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )
        except Exception as exc:
            signup_token["error"] = exc

    def _job_signin():
        try:
            signin_token["value"] = _solve_turnstile_quiet(
                signin_url,
                website_key,
                "sign-in",
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )
        except Exception as exc:
            signin_token["error"] = exc

    t1 = threading.Thread(target=_job_signup, name="ts-signup", daemon=True)
    t2 = threading.Thread(target=_job_signin, name="ts-signin", daemon=True)
    t1.start()
    t2.start()
    while t1.is_alive() or t2.is_alive():
        raise_if_cancelled(cancel_callback)
        t1.join(timeout=0.4)
        t2.join(timeout=0.4)
    if signup_token["error"] or len(str(signup_token["value"] or "")) < 80:
        raise RuntimeError(f"signup Turnstile 失败: {signup_token['error'] or 'empty'}")
    if signin_token["error"] or len(str(signin_token["value"] or "")) < 80:
        # sign-in 失败仍可继续，create_account 后再补
        if log_callback:
            log_callback(f"[!] sign-in Turnstile 并行失败，将串行补解: {signin_token['error']}")
        signin_token["value"] = ""

    try:
        sso = create_xai_account_via_http(
            email=email,
            given_name=given_name,
            family_name=family_name,
            password=password,
            email_code=email_code,
            turnstile_token=signup_token["value"],
            next_action=headers_meta["next_action"],
            router_state_tree=headers_meta["router_state_tree"],
            browser_cookies=browser_cookies,
            signup_url=SIGNUP_URL,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            signin_turnstile_token=signin_token["value"],
        )
    except StaleNextActionError as stale_exc:
        if log_callback:
            log_callback(f"[!] {stale_exc}；强制重扫 next-action 后重试一次")
        try:
            html2 = page.html or html
        except Exception:
            html2 = html
        headers_meta = scrape_signup_next_headers(
            html2,
            log_callback=log_callback,
            proxies=get_proxies(),
            browser_cookies=browser_cookies,
            page=page,
            force_refresh=True,
        )
        sso = create_xai_account_via_http(
            email=email,
            given_name=given_name,
            family_name=family_name,
            password=password,
            email_code=email_code,
            turnstile_token=signup_token["value"],
            next_action=headers_meta["next_action"],
            router_state_tree=headers_meta["router_state_tree"],
            browser_cookies=browser_cookies,
            signup_url=SIGNUP_URL,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            signin_turnstile_token=signin_token["value"],
        )
    return sso, {
        "given_name": given_name,
        "family_name": family_name,
        "password": password,
    }


def _xai_http_session():
    if requests is None:
        raise RuntimeError("curl_cffi 未安装")
    proxies = get_proxies()
    sk = {"impersonate": "chrome131", "timeout": 30}
    if proxies:
        sk["proxies"] = proxies
    return requests.Session(**sk)


def _xai_grpc_call(session, url, fields, referer=SIGNUP_URL, log_callback=None):
    """gRPC-web AuthManagement 调用。fields: [(field_no, string), ...]."""
    msg = b""
    for field_no, value in fields:
        msg += _grpc_encode_string(int(field_no), str(value))
    body = _grpc_frame_request(msg)
    headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "accept": "*/*",
        "origin": "https://accounts.x.ai",
        "referer": referer,
        "user-agent": get_user_agent(),
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
    }
    resp = session.post(url, data=body, headers=headers, timeout=30)
    raw = resp.content or b""
    parsed = _grpc_parse_response(raw)
    ok = int(getattr(resp, "status_code", 0) or 0) == 200 and parsed.get("grpc_status") == 0
    if log_callback:
        log_callback(
            f"[*] gRPC {url.rsplit('/', 1)[-1]} HTTP {resp.status_code} "
            f"grpc={parsed.get('grpc_status')} ok={ok} body_len={len(raw)}"
        )
    return {
        "ok": ok,
        "http_status": int(getattr(resp, "status_code", 0) or 0),
        "grpc_status": parsed.get("grpc_status"),
        "trailers": parsed.get("trailers") or {},
        "raw": raw,
    }


def register_via_pure_http(log_callback=None, cancel_callback=None):
    """纯 HTTP 注册（无浏览器），对齐 grokcli-2api：

    1) 创建临时邮箱
    2) GET sign-up 取 cookie + next-action
    3) CreateEmailValidationCode（失败则直接换号，不占 Solver）
    4) 并行解 signup/sign-in Turnstile（与等邮件重叠）
    5) 收码 → 立刻 VerifyEmailValidationCode（不等 Turnstile，验证码时效短）
    6) 等 Turnstile → create_account + CreateSession + 返回 sso
    """
    raise_if_cancelled(cancel_callback)
    given_name, family_name, password = build_profile()
    sitekey = str(config.get("turnstile_sitekey") or "0x4AAAAAAAhr9JGVDZbrZOo0")
    signup_url = SIGNUP_URL
    signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"
    create_code_url = "https://accounts.x.ai/auth_mgmt.AuthManagement/CreateEmailValidationCode"
    verify_code_url = "https://accounts.x.ai/auth_mgmt.AuthManagement/VerifyEmailValidationCode"

    if log_callback:
        log_callback(f"[*] 纯 HTTP 建号：{given_name} {family_name}")

    # 1) 邮箱
    email, dev_token = get_email_and_token(log_callback=log_callback)
    if log_callback:
        log_callback(f"[*] 邮箱: {email}")
    try:
        with open(os.path.join(get_data_dir(), "mail_credentials.txt"), "a", encoding="utf-8") as f:
            f.write(f"{email}\t{dev_token}\n")
    except Exception:
        pass

    if not probe_local_turnstile_solver():
        raise RuntimeError(f"Turnstile Solver 不可达: {normalize_turnstile_solver_url()}")

    session = _xai_http_session()
    try:
        # 2) 打开 sign-up（拿 CF cookie）
        raise_if_cancelled(cancel_callback)
        page_headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "user-agent": get_user_agent(),
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "upgrade-insecure-requests": "1",
        }
        resp = session.get(signup_url, headers=page_headers, timeout=30)
        html = resp.text or ""
        if log_callback:
            log_callback(f"[*] GET sign-up HTTP {resp.status_code} html_len={len(html)}")
        if resp.status_code >= 400 or len(html) < 200:
            raise RuntimeError(f"加载 sign-up 失败 HTTP {resp.status_code}")

        # session cookies → list for later CreateSession
        browser_cookies = []
        try:
            jar = session.cookies
            # curl_cffi Cookies may support jar iteration
            if hasattr(jar, "jar"):
                for c in jar.jar:
                    browser_cookies.append(
                        {
                            "name": getattr(c, "name", ""),
                            "value": getattr(c, "value", ""),
                            "domain": getattr(c, "domain", "") or ".x.ai",
                            "path": getattr(c, "path", "/") or "/",
                        }
                    )
            elif hasattr(jar, "items"):
                for name, value in jar.items():
                    browser_cookies.append(
                        {"name": name, "value": value, "domain": ".x.ai", "path": "/"}
                    )
        except Exception:
            pass

        headers_meta = scrape_signup_next_headers(
            html,
            log_callback=log_callback,
            proxies=get_proxies(),
            browser_cookies=browser_cookies,
            page=None,
        )

        # 3) 先发验证码：失败直接换号，避免无用 Turnstile 占满 Semaphore(2)
        raise_if_cancelled(cancel_callback)
        send_res = _xai_grpc_call(
            session,
            create_code_url,
            [(1, email)],
            referer=signup_url,
            log_callback=log_callback,
        )
        if not send_res.get("ok"):
            trailers = send_res.get("trailers") or {}
            msg = str(trailers.get("grpc-message") or "")
            raw = send_res.get("raw") or b""
            if "reject" in msg.lower() or "domain" in msg.lower():
                domain = email.split("@")[-1] if "@" in email else ""
                if domain:
                    remember_rejected_email_domain(domain, log_callback=log_callback)
                raise EmailDomainRejected(domain or email)
            raise RuntimeError(
                f"CreateEmailValidationCode 失败 http={send_res.get('http_status')} "
                f"grpc={send_res.get('grpc_status')} msg={msg!r} raw={(raw[:120])!r}"
            )

        # 4) 发码成功后再解 Turnstile（与等邮件重叠）
        if log_callback:
            log_callback("[*] 并行求解 signup/sign-in Turnstile...")
        signup_token = {"value": "", "error": None}
        signin_token = {"value": "", "error": None}
        # 本轮失败/取消时置位，后台线程尽快退出，不再写日志
        ts_abort = {"v": False}

        def _ts_cancelled():
            if ts_abort["v"]:
                return True
            if cancel_callback:
                try:
                    return bool(cancel_callback())
                except Exception:
                    return False
            return False

        def _job_signup():
            try:
                signup_token["value"] = _solve_turnstile_quiet(
                    signup_url, sitekey, "signup",
                    log_callback=log_callback, cancel_callback=_ts_cancelled,
                )
            except Exception as exc:
                signup_token["error"] = exc

        def _job_signin():
            try:
                signin_token["value"] = _solve_turnstile_quiet(
                    signin_url, sitekey, "sign-in",
                    log_callback=log_callback, cancel_callback=_ts_cancelled,
                )
            except Exception as exc:
                signin_token["error"] = exc

        t1 = threading.Thread(target=_job_signup, name="http-ts-signup", daemon=True)
        t2 = threading.Thread(target=_job_signin, name="http-ts-signin", daemon=True)
        t1.start()
        t2.start()

        def _abort_turnstile_threads():
            """换号/失败时中止本轮 Solver，释放并发槽位。"""
            ts_abort["v"] = True
            # 不无限 join：cancel 后 solver 应在下一次 poll 退出
            t1.join(timeout=0.2)
            t2.join(timeout=0.2)

        # 5) 收验证码
        if log_callback:
            log_callback("[*] 等待邮箱验证码...")
        try:
            code = get_oai_code(
                dev_token,
                email,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )
        except Exception:
            _abort_turnstile_threads()
            raise
        if not code:
            _abort_turnstile_threads()
            raise Exception("获取验证码失败")
        clean_code = str(code).replace("-", "").replace(" ", "").strip().upper()
        if log_callback:
            log_callback(f"[*] 验证码: {clean_code}")

        # 6) 立刻 verify（验证码时效短；不先等 Turnstile）
        raise_if_cancelled(cancel_callback)
        vres = _xai_grpc_call(
            session,
            verify_code_url,
            [(1, email), (2, clean_code)],
            referer=signup_url,
            log_callback=log_callback,
        )
        if not vres.get("ok") and log_callback:
            log_callback(
                f"[!] VerifyEmail 非 ok（仍尝试 create_account） "
                f"grpc={vres.get('grpc_status')}"
            )

        # 7) 等 Turnstile 完成后再 create_account
        while t1.is_alive() or t2.is_alive():
            raise_if_cancelled(cancel_callback)
            t1.join(timeout=0.4)
            t2.join(timeout=0.4)
        if signup_token["error"] or len(str(signup_token["value"] or "")) < 80:
            raise RuntimeError(f"signup Turnstile 失败: {signup_token['error'] or 'empty'}")
        if signin_token["error"] or len(str(signin_token["value"] or "")) < 80:
            if log_callback:
                log_callback(f"[!] sign-in Turnstile 失败，CreateSession 将串行补解: {signin_token['error']}")
            signin_token["value"] = ""

        # 8) create_account + CreateSession
        # 从 session 刷新 cookie 列表
        try:
            if hasattr(session.cookies, "jar"):
                browser_cookies = []
                for c in session.cookies.jar:
                    browser_cookies.append(
                        {
                            "name": getattr(c, "name", ""),
                            "value": getattr(c, "value", ""),
                            "domain": getattr(c, "domain", "") or ".x.ai",
                            "path": getattr(c, "path", "/") or "/",
                        }
                    )
        except Exception:
            pass

        try:
            sso = create_xai_account_via_http(
                email=email,
                given_name=given_name,
                family_name=family_name,
                password=password,
                email_code=clean_code,
                turnstile_token=signup_token["value"],
                next_action=headers_meta["next_action"],
                router_state_tree=headers_meta["router_state_tree"],
                browser_cookies=browser_cookies,
                signup_url=signup_url,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
                signin_turnstile_token=signin_token["value"],
            )
        except StaleNextActionError as stale_exc:
            if log_callback:
                log_callback(f"[!] {stale_exc}；强制重扫 next-action 后重试一次")
            # 重新 GET 页面再扫（部署可能已换 action）
            try:
                resp2 = session.get(signup_url, headers=page_headers, timeout=30)
                html2 = resp2.text or html
            except Exception:
                html2 = html
            headers_meta = scrape_signup_next_headers(
                html2,
                log_callback=log_callback,
                proxies=get_proxies(),
                browser_cookies=browser_cookies,
                page=None,
                force_refresh=True,
            )
            sso = create_xai_account_via_http(
                email=email,
                given_name=given_name,
                family_name=family_name,
                password=password,
                email_code=clean_code,
                turnstile_token=signup_token["value"],
                next_action=headers_meta["next_action"],
                router_state_tree=headers_meta["router_state_tree"],
                browser_cookies=browser_cookies,
                signup_url=signup_url,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
                signin_turnstile_token=signin_token["value"],
            )
        return sso, {
            "given_name": given_name,
            "family_name": family_name,
            "password": password,
            "email": email,
            "signup_mode": "http",
            "sso": sso,
        }
    finally:
        try:
            session.close()
        except Exception:
            pass


