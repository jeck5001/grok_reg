"""Turnstile solver client (YesCaptcha protocol) and page token helpers."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time

from core.cancel import raise_if_cancelled as _raise_if_cancelled_impl
from core.cancel import sleep_with_cancel as _sleep_with_cancel_impl
from core.config import DEFAULT_CONFIG, config
from core.runtime import normalize_proxy_for_runtime

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


def _fail_until_get():
    fac = _facade()
    if fac is not None and hasattr(fac, "_turnstile_solver_fail_until"):
        try:
            return float(getattr(fac, "_turnstile_solver_fail_until") or 0)
        except Exception:
            return 0.0
    try:
        return float(_turnstile_solver_fail_until or 0)
    except Exception:
        return 0.0


def _fail_until_set(value):
    global _turnstile_solver_fail_until
    v = float(value or 0)
    _turnstile_solver_fail_until = v
    fac = _facade()
    if fac is not None:
        try:
            setattr(fac, "_turnstile_solver_fail_until", v)
        except Exception:
            pass


def normalize_turnstile_solver_url(url=None):
    """Docker 内把 loopback solver 地址映射到宿主机。"""
    raw = str(url if url is not None else config.get("turnstile_solver_url") or "").strip()
    if not raw:
        raw = "http://127.0.0.1:5072"
    env_url = str(os.environ.get("GROK_REG_TURNSTILE_SOLVER_URL") or "").strip()
    if env_url:
        raw = env_url
    return normalize_proxy_for_runtime(raw).rstrip("/")


# 本地 Turnstile Solver 探测缓存 / 串行锁（Camoufox 池并发有限）
_turnstile_solver_probe_cache = {"ok": None, "at": 0.0, "url": ""}
_fail_until_set(0.0)
# 允许最多 2 路并行打 Solver（与 TURNSTILE_THREAD 对齐，signup+sign-in 可同时解）
_turnstile_solver_sem = threading.Semaphore(2)
_TURNSTILE_SITEKEY_RE = re.compile(r"0x4[0-9A-Za-z_-]{10,}")


def scrape_turnstile_sitekey_text(text):
    """从 HTML/JS 文本中提取 Turnstile sitekey。"""
    raw = str(text or "")
    patterns = (
        r'sitekey["\']\s*[:=]\s*["\'](0x4[0-9A-Za-z_-]{10,})["\']',
        r'data-sitekey=["\'](0x4[0-9A-Za-z_-]{10,})["\']',
        r'Turnstile[^"\']{0,80}["\'](0x4[0-9A-Za-z_-]{10,})["\']',
        r'(0x4AAAAA[0-9A-Za-z_-]{8,})',
    )
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.I)
        if match:
            key = str(match.group(1) or "").strip()
            if _TURNSTILE_SITEKEY_RE.fullmatch(key):
                return key
    match = _TURNSTILE_SITEKEY_RE.search(raw)
    return match.group(0) if match else ""


def scrape_turnstile_context_from_page(page):
    """从当前资料页读取 websiteURL / sitekey / action / cdata。"""
    fallback_key = str(config.get("turnstile_sitekey") or DEFAULT_CONFIG.get("turnstile_sitekey") or "").strip()
    detail = {
        "url": "",
        "sitekey": "",
        "action": "",
        "cdata": "",
        "source": "",
    }
    if not page:
        detail["sitekey"] = fallback_key
        detail["source"] = "fallback-config"
        return detail
    try:
        raw = page.run_js(
            r"""
const out = {
  url: String(location.href || ''),
  sitekey: '',
  action: '',
  cdata: '',
  source: '',
};
try {
  const hook = window.__grokTurnstile || {};
  const widgets = Array.isArray(hook.widgets) ? hook.widgets : [];
  for (let i = widgets.length - 1; i >= 0; i--) {
    const w = widgets[i] || {};
    const key = String(w.sitekey || '').trim();
    if (key) {
      out.sitekey = key;
      out.action = String(w.action || '');
      out.cdata = String(w.cData || w.cdata || '');
      out.source = 'hook-widget';
      break;
    }
  }
} catch (e) {}
if (!out.sitekey) {
  const nodes = Array.from(document.querySelectorAll('[data-sitekey], div.cf-turnstile, .cf-turnstile'));
  for (const node of nodes) {
    const key = String(node.getAttribute('data-sitekey') || '').trim();
    if (key) {
      out.sitekey = key;
      out.action = String(node.getAttribute('data-action') || '');
      out.cdata = String(node.getAttribute('data-cdata') || '');
      out.source = 'dom-sitekey';
      break;
    }
  }
}
if (!out.sitekey) {
  try {
    const html = String(document.documentElement && document.documentElement.outerHTML || '').slice(0, 250000);
    const patterns = [
      /sitekey["']\s*[:=]\s*["'](0x4[0-9A-Za-z_-]{10,})["']/i,
      /data-sitekey=["'](0x4[0-9A-Za-z_-]{10,})["']/i,
      /(0x4AAAAA[0-9A-Za-z_-]{8,})/,
    ];
    for (const re of patterns) {
      const m = html.match(re);
      if (m && m[1]) { out.sitekey = m[1]; out.source = 'html-scan'; break; }
    }
  } catch (e) {}
}
return out;
            """
        )
        if isinstance(raw, dict):
            detail.update({k: raw.get(k) or detail.get(k) for k in detail})
            detail["url"] = str(raw.get("url") or detail["url"] or "")
            detail["sitekey"] = str(raw.get("sitekey") or "").strip()
            detail["action"] = str(raw.get("action") or "").strip()
            detail["cdata"] = str(raw.get("cdata") or "").strip()
            detail["source"] = str(raw.get("source") or "").strip()
    except Exception as exc:
        detail["source"] = f"js-error:{str(exc)[:80]}"
    if not detail["sitekey"]:
        try:
            html = page.html or ""
        except Exception:
            html = ""
        scraped = scrape_turnstile_sitekey_text(html)
        if scraped:
            detail["sitekey"] = scraped
            detail["source"] = detail["source"] or "page-html"
    if not detail["sitekey"] and fallback_key:
        detail["sitekey"] = fallback_key
        detail["source"] = detail["source"] or "fallback-config"
    if not detail["url"]:
        try:
            detail["url"] = str(getattr(page, "url", "") or "")
        except Exception:
            detail["url"] = ""
    if not detail["url"]:
        detail["url"] = "https://accounts.x.ai/sign-up"
    return detail


def inject_turnstile_token_to_page(page, token):
    """把外部 solver 拿到的 token 写回页面 hidden input，并尽量暴露给 getResponse。"""
    token = str(token or "").strip()
    if not page or len(token) < 80:
        return 0
    try:
        value = page.run_js(
            r"""
const token = String(arguments[0] || '').trim();
if (!token) return 0;
let wrote = 0;
const inputs = Array.from(document.querySelectorAll(
  'input[name="cf-turnstile-response"], input[name*="turnstile"], textarea[name="cf-turnstile-response"]'
));
if (!inputs.length) {
  const input = document.createElement('input');
  input.type = 'hidden';
  input.name = 'cf-turnstile-response';
  document.body.appendChild(input);
  inputs.push(input);
}
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
for (const input of inputs) {
  try {
    if (nativeSetter) nativeSetter.call(input, token);
    else input.value = token;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    wrote = Math.max(wrote, String(input.value || '').trim().length);
  } catch (e) {}
}
try {
  window.__grokTurnstile = window.__grokTurnstile || {};
  window.__grokTurnstile.lastToken = token;
  window.__grokTurnstile.callbackCount = (window.__grokTurnstile.callbackCount || 0) + 1;
  window.__grokTurnstile.externalInjected = true;
} catch (e) {}
try {
  if (window.turnstile) {
    try {
      window.turnstile.getResponse = function () { return token; };
    } catch (e) {}
  }
} catch (e) {}
return wrote;
            """,
            token,
        )
        return int(value or 0)
    except Exception:
        return 0


def _is_transient_solver_transport_error(exc) -> bool:
    """curl (52) Empty reply / 连接重置 / 超时等瞬时传输错误。"""
    text = str(exc or "")
    low = text.lower()
    needles = (
        "empty reply",
        "curl: (52)",
        "curl: (56)",
        "curl: (28)",
        "curl: (7)",
        "connection reset",
        "connection refused",
        "broken pipe",
        "timed out",
        "timeout",
        "temporarily unavailable",
        "server closed",
        "recv failure",
        "failed to perform",
    )
    return any(n in low for n in needles)


def _solver_http_json(method, path, payload=None, timeout=20.0, retries=3):
    """直连 solver（不走业务代理），返回 JSON dict。

    对 Empty reply / 连接重置等瞬时错误自动短退避重试，减轻并行 signup+sign-in 时
    solver 偶发掐连接导致的「sign-in Turnstile 失败」。
    """
    if requests is None:
        raise RuntimeError("curl_cffi 未安装，无法请求 Turnstile Solver")
    base = normalize_turnstile_solver_url()
    url = f"{base}{path if str(path).startswith('/') else '/' + str(path)}"
    kwargs = {
        "timeout": timeout,
        "proxies": {},
        "headers": {"Content-Type": "application/json", "Accept": "application/json"},
    }
    try:
        attempts = max(1, int(retries or 1))
    except Exception:
        attempts = 3
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            if method.upper() == "GET":
                resp = requests.get(url, **kwargs)
            else:
                resp = requests.post(url, json=payload or {}, **kwargs)
            # 部分 solver 过载会直接掐连接，status 可能异常；仍解析 body
            try:
                data = resp.json()
            except Exception:
                # 空 body / 非 JSON：若像瞬时故障则重试
                body = (getattr(resp, "text", None) or "")[:200]
                status = int(getattr(resp, "status_code", 0) or 0)
                if attempt < attempts and (not body or status in {0, 502, 503, 504}):
                    time.sleep(min(1.5, 0.25 * attempt))
                    continue
                raise RuntimeError(
                    f"Turnstile Solver 非 JSON 响应 HTTP {status}: {body}"
                )
            if not isinstance(data, dict):
                raise RuntimeError(f"Turnstile Solver 返回非对象: {data!r}")
            return data, resp.status_code
        except Exception as exc:
            last_exc = exc
            if attempt >= attempts or not _is_transient_solver_transport_error(exc):
                raise
            time.sleep(min(1.5, 0.25 * attempt))
    if last_exc:
        raise last_exc
    raise RuntimeError("Turnstile Solver 请求失败")


def probe_local_turnstile_solver(force=False, timeout=2.0, cache_ttl=30.0):
    """探测本地/远端 YesCaptcha 协议 solver 是否可用。

    默认缓存 30s，避免看板轮询把 solver /health 打成高频探测。
    """
    if not bool(config.get("turnstile_solver_enabled", True)):
        return False
    url = normalize_turnstile_solver_url()
    now = _now()
    cache = _turnstile_solver_probe_cache
    try:
        ttl = max(1.0, float(cache_ttl or 30.0))
    except Exception:
        ttl = 30.0
    if (
        not force
        and cache.get("url") == url
        and cache.get("ok") is not None
        and now - float(cache.get("at") or 0) < ttl
    ):
        return bool(cache["ok"])
    ok = False
    try:
        data, status = _resolve("_solver_http_json", _solver_http_json)("GET", "/health", timeout=timeout)
        ok = status == 200 and (data.get("ok") is True or data.get("status") in {"ok", "ready", True})
    except Exception:
        ok = False
    if not ok:
        # 兼容未暴露 /health 的 solver：用 createTask 空校验不合适，只记失败
        ok = False
    cache["ok"] = ok
    cache["at"] = now
    cache["url"] = url
    return ok


def _proxy_for_turnstile_solver():
    """业务代理透传给 solver 的 createTask.task.proxy。

    注意：这里传的是「solver 进程自己去连的上游代理」，不是 grok_reg 容器内
    访问代理的地址。必须原样透传配置值（如 http://192.168.5.35:7890），
    不要用 normalize_proxy_for_runtime 把 127.0.0.1 改成 host.docker.internal——
    那是给「当前容器访问代理」用的；solver 若在另一台机/另一容器，会连错甚至失败。

    可用 turnstile_solver_use_proxy=false 关闭透传。
    """
    if not bool(config.get("turnstile_solver_use_proxy", True)):
        return ""
    return str(config.get("proxy") or "").strip()


def _redact_proxy_for_log(proxy):
    raw = str(proxy or "").strip()
    if not raw:
        return ""
    try:
        if "@" in raw and "://" in raw:
            scheme, rest = raw.split("://", 1)
            _auth, hostpart = rest.rsplit("@", 1)
            return f"{scheme}://***:***@{hostpart}"
    except Exception:
        pass
    return raw


def solve_turnstile_via_local_solver(
    website_url,
    website_key,
    action="",
    cdata="",
    proxy=None,
    log_callback=None,
    cancel_callback=None,
    timeout=None,
):
    """YesCaptcha 协议：POST /createTask + 轮询 /getTaskResult，返回 token。

    兼容本地 turnstile-solver（Camoufox，支持 task.proxy）以及远端 YesCaptcha。
    """
    website_url = str(website_url or "").strip()
    website_key = str(website_key or "").strip()
    if not website_url or not website_key:
        raise ValueError("website_url 与 website_key 不能为空")
    try:
        timeout = float(timeout if timeout is not None else config.get("turnstile_solver_timeout", 120) or 120)
    except Exception:
        timeout = 120.0
    timeout = max(30.0, min(timeout, 300.0))
    client_key = str(config.get("turnstile_solver_client_key") or "local").strip() or "local"
    base = normalize_turnstile_solver_url()
    if proxy is None:
        proxy = _resolve("_proxy_for_turnstile_solver", _proxy_for_turnstile_solver)()
    else:
        proxy = str(proxy or "").strip()
    task = {
        "type": "TurnstileTaskProxyless",
        "websiteURL": website_url,
        "websiteKey": website_key,
    }
    if action:
        task["action"] = str(action)
    if cdata:
        task["cdata"] = str(cdata)
    if proxy:
        # 本地 solver 已支持任务级 proxy；云端 YesCaptcha 会忽略未知字段
        task["proxy"] = proxy

    if log_callback:
        log_callback(
            f"[*] 请求 Turnstile Solver: {base} key={website_key[:14]}... "
            f"url={website_url[:80]} proxy={_redact_proxy_for_log(proxy) or '直连'}"
        )

    # 本地 Camoufox 池有限，串行化避免打爆
    with _turnstile_solver_sem:
        raise_if_cancelled(cancel_callback)
        create_body = {"clientKey": client_key, "task": task}
        data, _status = _resolve("_solver_http_json", _solver_http_json)("POST", "/createTask", create_body, timeout=45)
        if int(data.get("errorId") or 0) != 0:
            raise RuntimeError(
                f"createTask 失败: {data.get('errorCode')}: {data.get('errorDescription')}"
            )
        task_id = str(data.get("taskId") or "").strip()
        if not task_id:
            raise RuntimeError(f"createTask 未返回 taskId: {data}")
        if log_callback:
            log_callback(f"[*] Turnstile Solver 任务已创建: {task_id[:18]}...")

        started = _now()
        deadline = started + timeout
        poll_interval = 2.0
        while _now() < deadline:
            raise_if_cancelled(cancel_callback)
            result, _ = _resolve("_solver_http_json", _solver_http_json)(
                "POST",
                "/getTaskResult",
                {"clientKey": client_key, "taskId": task_id},
                timeout=45,
            )
            if int(result.get("errorId") or 0) != 0:
                raise RuntimeError(
                    f"getTaskResult 失败: {result.get('errorCode')}: {result.get('errorDescription')}"
                )
            status = str(result.get("status") or "").lower()
            if status == "ready":
                solution = result.get("solution") or {}
                token = (
                    solution.get("token")
                    or solution.get("gRecaptchaResponse")
                    or solution.get("cf_clearance")
                    or ""
                )
                token = str(token or "").strip()
                if len(token) < 80:
                    raise RuntimeError(f"Solver 返回 token 过短: len={len(token)}")
                if log_callback:
                    log_callback(
                        f"[*] Turnstile Solver 成功，耗时 {int(_now() - started)}s，token长度={len(token)}"
                    )
                return token
            if status in {"", "processing", "idle", "captcha_not_ready"}:
                elapsed = int(_now() - started)
                if log_callback and elapsed > 0 and elapsed % 8 < poll_interval:
                    log_callback(f"[*] Turnstile Solver 处理中... {elapsed}s/{int(timeout)}s")
                sleep_with_cancel(poll_interval, cancel_callback)
                continue
            # 兼容本地 solver 直接把 value 塞在顶层的情况
            direct = result.get("value") or result.get("token")
            if direct and len(str(direct)) >= 80 and str(direct) not in {"CAPTCHA_FAIL", "CAPTCHA_NOT_READY"}:
                if log_callback:
                    log_callback(f"[*] Turnstile Solver 成功(直接value)，token长度={len(str(direct))}")
                return str(direct).strip()
            raise RuntimeError(f"Solver 未知状态: status={status} body={str(result)[:240]}")

        raise TimeoutError(f"Turnstile Solver 超时 {int(timeout)}s (task={task_id[:18]}..., endpoint={base})")


def getTurnstileToken(log_callback=None, cancel_callback=None, attempts=15):
    """优先本地/远端 Turnstile Solver 出 token，失败再 shadow_root/CDP 点选。"""
    _get_page = _resolve("_get_page", lambda: None)
    _read_turnstile_token_from_page = _resolve(
        "_read_turnstile_token_from_page", lambda _p: ""
    )
    _click_turnstile_via_shadow_dom = _resolve(
        "_click_turnstile_via_shadow_dom", lambda _p, log_callback=None: {"ok": False}
    )
    _click_turnstile_challenge_if_visible = _resolve(
        "_click_turnstile_challenge_if_visible", lambda _p: {"ok": False}
    )
    probe_local_turnstile_solver = _resolve(
        "probe_local_turnstile_solver", globals().get("probe_local_turnstile_solver")
    )
    scrape_turnstile_context_from_page = _resolve(
        "scrape_turnstile_context_from_page",
        globals().get("scrape_turnstile_context_from_page"),
    )
    solve_turnstile_via_local_solver = _resolve(
        "solve_turnstile_via_local_solver",
        globals().get("solve_turnstile_via_local_solver"),
    )
    inject_turnstile_token_to_page = _resolve(
        "inject_turnstile_token_to_page",
        globals().get("inject_turnstile_token_to_page"),
    )
    normalize_turnstile_solver_url = _resolve(
        "normalize_turnstile_solver_url",
        globals().get("normalize_turnstile_solver_url"),
    )
    page = _get_page()
    if page is None:
        raise Exception("页面未就绪，无法执行 Turnstile")

    token = _read_turnstile_token_from_page(page)
    if len(token) >= 80:
        if log_callback:
            log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
        return token

    solver_enabled = bool(config.get("turnstile_solver_enabled", True))
    fallback_click = bool(config.get("turnstile_solver_fallback_click", True))
    solver_cooled = _now() < _fail_until_get()
    if solver_enabled and not solver_cooled:
        try:
            if probe_local_turnstile_solver():
                ctx = scrape_turnstile_context_from_page(page)
                if log_callback:
                    log_callback(
                        f"[*] 使用 Turnstile Solver 过盾 "
                        f"(sitekey来源={ctx.get('source') or '?'}, key={(ctx.get('sitekey') or '')[:14]}...)"
                    )
                solver_token = solve_turnstile_via_local_solver(
                    website_url=ctx.get("url") or "https://accounts.x.ai/sign-up",
                    website_key=ctx.get("sitekey") or "",
                    action=ctx.get("action") or "",
                    cdata=ctx.get("cdata") or "",
                    log_callback=log_callback,
                    cancel_callback=cancel_callback,
                )
                synced = inject_turnstile_token_to_page(page, solver_token)
                # 再读一次确认
                back = _read_turnstile_token_from_page(page)
                if len(back) >= 80:
                    _fail_until_set(0.0)
                    if log_callback:
                        log_callback(f"[*] Turnstile Solver token 已回填，长度={len(back)} (inject={synced})")
                    return back
                if len(solver_token) >= 80:
                    _fail_until_set(0.0)
                    if log_callback:
                        log_callback(
                            f"[*] 页面回填长度异常 inject={synced}，直接使用 solver token 长度={len(solver_token)}"
                        )
                    return solver_token
            elif log_callback:
                log_callback(
                    f"[Debug] Turnstile Solver 不可达: {normalize_turnstile_solver_url()}，"
                    f"{'回退 shadow/CDP 点选' if fallback_click else '且已关闭点选回退'}"
                )
        except Exception as solver_exc:
            # 失败后冷却，避免资料页每 2s 重入再堵满 timeout
            _fail_until_set(_now() + 60.0)
            if log_callback:
                log_callback(f"[Debug] Turnstile Solver 失败（60s 内不再重试）: {solver_exc}")
            if not fallback_click:
                raise Exception(f"Turnstile Solver 失败且已关闭点选回退: {solver_exc}") from solver_exc
    elif solver_enabled and solver_cooled and log_callback:
        remain = max(0, int(_fail_until_get() - _now()))
        if remain and remain % 15 == 0:
            log_callback(f"[Debug] Turnstile Solver 冷却中，{remain}s 后可再试")

    if not fallback_click and solver_enabled:
        raise Exception("Turnstile Solver 未出 token，且 turnstile_solver_fallback_click=false")

    for i in range(max(1, int(attempts))):
        raise_if_cancelled(cancel_callback)
        token = _read_turnstile_token_from_page(page)
        if len(token) >= 80:
            if log_callback:
                log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
            return token

        click_info = _click_turnstile_via_shadow_dom(page, log_callback=log_callback)
        if log_callback:
            log_callback(
                f"[*] Turnstile shadow 点击尝试 #{i+1}: "
                + json.dumps(click_info, ensure_ascii=False)[:500]
            )

        # 点完多等一会：Docker 里 CF 出 token 更慢
        sleep_with_cancel(1.2 if i == 0 else 1.0, cancel_callback)
        token = _read_turnstile_token_from_page(page)
        if len(token) >= 80:
            if log_callback:
                log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
            return token

        # 若“点成功”但 token 仍空，再强制 CDP 全局点一次
        if isinstance(click_info, dict) and click_info.get("ok") and not token:
            try:
                cdp_info = _click_turnstile_challenge_if_visible(page)
                if log_callback:
                    log_callback(
                        "[*] 点击后 token 仍为空，CDP 再点: "
                        + json.dumps(cdp_info if isinstance(cdp_info, dict) else {"raw": str(cdp_info)}, ensure_ascii=False)[:300]
                    )
                sleep_with_cancel(1.0, cancel_callback)
                token = _read_turnstile_token_from_page(page)
                if len(token) >= 80:
                    if log_callback:
                        log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
                    return token
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] CDP 再点失败: {exc}")

    raise Exception("Turnstile 获取 token 失败")


