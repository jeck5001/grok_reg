"""Browser lifecycle, stealth options, and page automation helpers."""

from __future__ import annotations

import json
import os
import random
import re
import secrets
import subprocess
import sys
import threading
import time

from core.cancel import raise_if_cancelled as _raise_if_cancelled_impl
from core.cancel import sleep_with_cancel as _sleep_with_cancel_impl
from core.config import DEFAULT_CONFIG, config
from core.exceptions import (
    EmailDomainRejected,
    ProfileSessionLost,
    RegistrationCancelled,
    StaleNextActionError,
)
from core.paths import APP_DIR, get_data_dir
from core.runtime import (
    _env_truthy,
    normalize_proxy_for_runtime,
    should_apply_container_chrome_flags,
    should_run_headless,
)

try:
    from DrissionPage import Chromium, ChromiumOptions
    from DrissionPage.errors import PageDisconnectedError
except ModuleNotFoundError:
    Chromium = None
    ChromiumOptions = None

    class PageDisconnectedError(Exception):
        pass


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


from core.email.providers import (
    get_email_and_token as _email_get_email_and_token,
    get_oai_code as _email_get_oai_code,
)
from core.turnstile.solver import (
    getTurnstileToken as _solver_getTurnstileToken,
    inject_turnstile_token_to_page as _solver_inject_turnstile_token_to_page,
)
from core.xai.protocol import (
    register_via_api_after_otp as _xai_register_via_api_after_otp,
    resolve_signup_mode as _xai_resolve_signup_mode,
    scrape_signup_next_headers as _xai_scrape_signup_next_headers,
)


def get_oai_code(*args, **kwargs):
    fn = _resolve("get_oai_code", _email_get_oai_code)
    # avoid recursion if fac points back here
    if getattr(fn, "__module__", "") == __name__:
        fn = _email_get_oai_code
    return fn(*args, **kwargs)


def get_email_and_token(*args, **kwargs):
    fn = _resolve("get_email_and_token", _email_get_email_and_token)
    if getattr(fn, "__module__", "") == __name__:
        fn = _email_get_email_and_token
    return fn(*args, **kwargs)


def getTurnstileToken(*args, **kwargs):
    fn = _resolve("getTurnstileToken", _solver_getTurnstileToken)
    if getattr(fn, "__module__", "") == __name__:
        fn = _solver_getTurnstileToken
    return fn(*args, **kwargs)


def inject_turnstile_token_to_page(page, token):
    fn = _resolve("inject_turnstile_token_to_page", _solver_inject_turnstile_token_to_page)
    if getattr(fn, "__module__", "") == __name__:
        fn = _solver_inject_turnstile_token_to_page
    return fn(page, token)


def resolve_signup_mode():
    fn = _resolve("resolve_signup_mode", _xai_resolve_signup_mode)
    if getattr(fn, "__module__", "") == __name__:
        fn = _xai_resolve_signup_mode
    return fn()


def register_via_api_after_otp(*args, **kwargs):
    fn = _resolve("register_via_api_after_otp", _xai_register_via_api_after_otp)
    if getattr(fn, "__module__", "") == __name__:
        fn = _xai_register_via_api_after_otp
    return fn(*args, **kwargs)


def scrape_signup_next_headers(*args, **kwargs):
    fn = _resolve("scrape_signup_next_headers", _xai_scrape_signup_next_headers)
    if getattr(fn, "__module__", "") == __name__:
        fn = _xai_scrape_signup_next_headers
    return fn(*args, **kwargs)



def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def extract_rejected_email_domain(*args, **kwargs):
    fac = _facade()
    if fac is not None and hasattr(fac, "extract_rejected_email_domain"):
        fn = fac.extract_rejected_email_domain
        if getattr(fn, "__module__", "") != __name__:
            return fn(*args, **kwargs)
    return ""


def wait_for_email_verification_step(*args, **kwargs):
    fac = _facade()
    if fac is not None and hasattr(fac, "wait_for_email_verification_step"):
        fn = fac.wait_for_email_verification_step
        if getattr(fn, "__module__", "") != __name__:
            return fn(*args, **kwargs)
    return "otp"


def wait_for_post_code_transition(*args, **kwargs):
    fac = _facade()
    if fac is not None and hasattr(fac, "wait_for_post_code_transition"):
        fn = fac.wait_for_post_code_transition
        if getattr(fn, "__module__", "") != __name__:
            return fn(*args, **kwargs)
    return "profile-form"


def build_email_form_script(action):
    fac = _facade()
    if fac is not None and hasattr(fac, "build_email_form_script"):
        fn = fac.build_email_form_script
        if getattr(fn, "__module__", "") != __name__:
            return fn(action)
    return "return true;"


def build_email_submission_state_script():
    fac = _facade()
    if fac is not None and hasattr(fac, "build_email_submission_state_script"):
        fn = fac.build_email_submission_state_script
        if getattr(fn, "__module__", "") != __name__:
            return fn()
    return "return {};"


def build_otp_native_target_script():
    fac = _facade()
    if fac is not None and hasattr(fac, "build_otp_native_target_script"):
        fn = fac.build_otp_native_target_script
        if getattr(fn, "__module__", "") != __name__:
            return fn()
    return "return {};"


def build_otp_submit_target_script():
    fac = _facade()
    if fac is not None and hasattr(fac, "build_otp_submit_target_script"):
        fn = fac.build_otp_submit_target_script
        if getattr(fn, "__module__", "") != __name__:
            return fn()
    return "return {};"


def build_profile_submit_script(action):
    fac = _facade()
    if fac is not None and hasattr(fac, "build_profile_submit_script"):
        fn = fac.build_profile_submit_script
        if getattr(fn, "__module__", "") != __name__:
            return fn(action)
    return "return true;"


def detect_cloudflare_block_page(page_html):
    fac = _facade()
    if fac is not None and hasattr(fac, "detect_cloudflare_block_page"):
        fn = fac.detect_cloudflare_block_page
        if getattr(fn, "__module__", "") != __name__:
            return fn(page_html)
    return False


def should_log_cloudflare_wait(state, scope, token_len, interval=5.0):
    fac = _facade()
    if fac is not None and hasattr(fac, "should_log_cloudflare_wait"):
        fn = fac.should_log_cloudflare_wait
        if getattr(fn, "__module__", "") != __name__:
            return fn(state, scope, token_len, interval=interval)
    return True

EXTENSION_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "turnstilePatch")
)
TURNSTILE_PAGE_HOOK_PATH = os.path.join(EXTENSION_PATH, "pageHook.js")
_turnstile_page_hook_source_cache = None




def ensure_virtual_display(log_callback=None):
    global _xvfb_process
    if should_run_headless():
        return False
    if not should_apply_container_chrome_flags():
        return False
    if os.environ.get("DISPLAY"):
        return False

    with _xvfb_lock:
        if _xvfb_process is not None and _xvfb_process.poll() is None:
            os.environ["DISPLAY"] = os.environ.get("GROK_REG_DISPLAY", ":99")
            return False

        display = os.environ.get("GROK_REG_DISPLAY", ":99")
        # 与浏览器窗口一致，避免虚拟屏过小触发异常布局/指纹。
        cmd = ["Xvfb", display, "-screen", "0", "1920x1080x24", "-nolisten", "tcp"]
        _xvfb_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.environ["DISPLAY"] = display
        if log_callback:
            log_callback(f"[Debug] 已自动启动 Xvfb: DISPLAY={display} (1920x1080)")
        time.sleep(0.5)
        return True


def _active_config():
    """Prefer facade ``reg.config`` so tests that rebind the attribute still work."""
    return _resolve("config", config)


def create_browser_options():
    options_cls = _resolve("ChromiumOptions", ChromiumOptions)
    if options_cls is None:
        raise RuntimeError("DrissionPage 未安装，无法启动浏览器自动化")
    options = options_cls()
    options.auto_port()
    options.set_timeouts(base=1)
    browser_path = os.environ.get("CHROME_BIN", "").strip()
    if browser_path:
        options.set_browser_path(browser_path)
    cfg = _active_config()
    proxy = normalize_proxy_for_runtime(cfg.get("proxy", ""))
    if proxy:
        options.set_argument("--proxy-server", proxy)

    # 关键：手动浏览器能过、脚本不过时，优先消掉明显的自动化开关。
    # 不要强行覆盖成“Chrome/138”这类可能与容器真实 Chromium 版本不一致的 UA，
    # 版本漂移本身就是 Turnstile 常见扣分项；仅在配置显式给出时才设置。
    configured_ua = str(cfg.get("user_agent") or "").strip()
    default_ua = str(DEFAULT_CONFIG.get("user_agent") or "").strip()
    if configured_ua and configured_ua != default_ua:
        try:
            options.set_user_agent(configured_ua)
        except Exception:
            options.set_argument(f"--user-agent={configured_ua}")
    # 隐藏 automation controlled / enable-automation 横幅类特征。
    options.set_argument("--disable-blink-features=AutomationControlled")
    options.set_argument("--disable-infobars")
    options.set_argument("--no-first-run")
    options.set_argument("--no-default-browser-check")
    options.set_argument("--password-store=basic")
    try:
        # DrissionPage/Chromium 参数写法兼容两种形式。
        options.set_argument("--exclude-switches", "enable-automation")
    except Exception:
        options.set_argument("--exclude-switches=enable-automation")
    try:
        options.set_pref("credentials_enable_service", False)
        options.set_pref("profile.password_manager_enabled", False)
    except Exception:
        pass

    # turnstilePatch 扩展负责 document_start 隐藏 webdriver / 自动点选。
    # Docker 中跳过扩展加载：--load-extension / --enable-unsafe-extension-debugging 是已知自动化检测向量，
    # stealth 功能已由 CDP Page.addScriptToEvaluateOnNewDocument 完全覆盖。
    # Tests monkeypatch should_apply_container_chrome_flags / EXTENSION_PATH / os.path.isdir on facade.
    apply_container = _resolve(
        "should_apply_container_chrome_flags", should_apply_container_chrome_flags
    )()
    in_docker_env = _env_truthy("GROK_REG_IN_DOCKER")
    ext_path_root = _resolve("EXTENSION_PATH", EXTENSION_PATH)
    isdir = os.path.isdir
    fac = _facade()
    if fac is not None and hasattr(fac, "os"):
        try:
            isdir = fac.os.path.isdir
        except Exception:
            pass
    if not in_docker_env and isdir(ext_path_root):
        ext_path = os.path.abspath(ext_path_root)
        try:
            if hasattr(options, "add_extension"):
                options.add_extension(ext_path)
        except Exception:
            pass
        try:
            options.set_argument(f"--load-extension={ext_path}")
            options.set_argument(f"--disable-extensions-except={ext_path}")
        except Exception:
            pass

    if apply_container:
        options.set_argument("--no-sandbox")
        options.set_argument("--disable-dev-shm-usage")
        # 注意：不要 --disable-gpu，Turnstile 需要 WebGL。
        # 不指定 --use-angle=swiftshader-webgl：该参数可被 Turnstile 检测到。
        # Chrome 在无 GPU 时会自动回退到 SwiftShader，无需显式指定。
        options.set_argument("--use-gl=angle")
        options.set_argument("--enable-webgl")
        options.set_argument("--enable-webgl2-compute-context")
        options.set_argument("--ignore-gpu-blocklist")
        # 不要 --enable-features=NetworkService,NetworkServiceInProcess —— 这是 Electron/自动化常用参数
        # 更接近常见桌面分辨率，避免 1365x900 这种少见尺寸成为指纹。
        options.set_argument("--window-size", "1920,1080")
        options.set_argument("--window-position", "0,0")
        options.set_argument("--lang", "en-US")
        options.set_argument("--accept-lang", "en-US,en")        # 不要 --disable-background-timer-throttling / --disable-renderer-backgrounding —— 自动化常用参数
    if _resolve("should_run_headless", should_run_headless)():
        options.headless(True)
    return options


def probe_browser_stealth(page, log_callback=None):
    """启动后采样自动化指纹，方便对照“手动能过/脚本不过”。"""
    if not page:
        return {}
    try:
        detail = page.run_js(
            r"""
return {
  webdriver: navigator.webdriver,
  languages: navigator.languages,
  platform: navigator.platform,
  userAgent: navigator.userAgent,
  hardwareConcurrency: navigator.hardwareConcurrency,
  deviceMemory: navigator.deviceMemory || null,
  chrome: !!(window.chrome && window.chrome.runtime),
  plugins: navigator.plugins ? navigator.plugins.length : 0,
  hasOwnPlatform: navigator.hasOwnProperty('platform'),
  hasOwnUA: navigator.hasOwnProperty('userAgent'),
  hasOwnWebdriver: navigator.hasOwnProperty('webdriver'),
  toStringCheck: (function() {
    try {
      const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent');
      if (!desc || !desc.get) return 'no-getter';
      const s = desc.get.toString();
      return s.indexOf('[native code]') >= 0 ? 'native' : 'HOOKED:' + s.slice(0, 60);
    } catch(e) { return 'error:' + String(e).slice(0, 40); }
  })(),
  userAgentData: navigator.userAgentData ? {
    platform: navigator.userAgentData.platform,
    brands: navigator.userAgentData.brands,
  } : null,
  maxTouchPoints: navigator.maxTouchPoints,
  connection: navigator.connection ? navigator.connection.effectiveType : null,
  webgl: (function () {
    try {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return {ok:false};
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        ok: true,
        vendor: gl.getParameter(ext ? ext.UNMASKED_VENDOR_WEBGL : gl.VENDOR),
        renderer: gl.getParameter(ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER),
        extCount: (gl.getSupportedExtensions() || []).length,
      };
    } catch (e) {
      return {ok:false, error: String(e && e.message || e).slice(0, 120)};
    }
  })(),
};
            """
        )
    except Exception as exc:
        detail = {"error": str(exc)[:200]}
    if log_callback:
        try:
            log_callback(f"[Debug] 浏览器指纹采样: {json.dumps(detail, ensure_ascii=False)[:500]}")
        except Exception:
            log_callback(f"[Debug] 浏览器指纹采样: {detail}")
    return detail if isinstance(detail, dict) else {"raw": detail}


def humanize_page_activity(page, log_callback=None, cancel_callback=None):
    """在 Turnstile 评分窗口内模拟轻微鼠标/滚动，避免“纯脚本填表零交互”。"""
    if not page:
        return
    try:
        viewport = page.run_js(
            """
return {
  w: Math.max(320, window.innerWidth || 1365),
  h: Math.max(320, window.innerHeight || 900),
};
            """
        ) or {"w": 1365, "h": 900}
        width = int(viewport.get("w") or 1365)
        height = int(viewport.get("h") or 900)
        points = [
            (int(width * 0.22), int(height * 0.28)),
            (int(width * 0.48), int(height * 0.42)),
            (int(width * 0.63), int(height * 0.57)),
            (int(width * 0.40), int(height * 0.70)),
        ]
        for x, y in points:
            raise_if_cancelled(cancel_callback)
            try:
                page.run_cdp(
                    "Input.dispatchMouseEvent",
                    type="mouseMoved",
                    x=x,
                    y=y,
                    modifiers=0,
                )
            except Exception:
                pass
            sleep_with_cancel(random.uniform(0.05, 0.16), cancel_callback)
        try:
            page.run_js(
                """
window.scrollBy(0, Math.floor(40 + Math.random() * 120));
setTimeout(() => window.scrollBy(0, -Math.floor(20 + Math.random() * 60)), 120);
                """
            )
        except Exception:
            pass
        if log_callback:
            log_callback("[Debug] 已注入轻微鼠标/滚动交互，等待 Turnstile 被动评分")
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 人机交互模拟失败: {str(exc)[:160]}")


def turnstile_page_hook_source():
    global _turnstile_page_hook_source_cache
    # Tests monkeypatch reg.turnstile_page_hook_source; prefer facade only when it is not us.
    fac = _facade()
    if fac is not None:
        fn = getattr(fac, "turnstile_page_hook_source", None)
        if callable(fn) and getattr(fn, "__module__", "") != __name__:
            return fn()
    if _turnstile_page_hook_source_cache is not None:
        return _turnstile_page_hook_source_cache
    hook_path = _resolve("TURNSTILE_PAGE_HOOK_PATH", TURNSTILE_PAGE_HOOK_PATH)
    try:
        with open(hook_path, "r", encoding="utf-8") as handle:
            _turnstile_page_hook_source_cache = handle.read()
    except Exception:
        _turnstile_page_hook_source_cache = ""
    return _turnstile_page_hook_source_cache

def install_light_stealth_script(page, log_callback=None):
    """增强 stealth：WebGL/Canvas/Audio 反指纹 + 插件/WebRTC 伪装，绝不补丁 window.turnstile。"""
    if not page:
        return False
    source = r"""
(() => {
  // ====== 0. Function.prototype.toString 保护 ======
  // 核心防线：Cloudflare 通过 fn.toString() 检查函数是否为原生代码。
  // 原生 getter: "function get userAgent() { [native code] }"
  // 我们替换的: "function () { return fakeUa; }" ← 一行代码即可检测。
  // 解决方法：劫持 toString，对所有被替换的函数返回正确的 [native code] 字符串。
  const _origToString = Function.prototype.toString;
  const _nativeStrMap = new WeakMap();

  const _initToString = function() {
    const outStr = _nativeStrMap.has(this) ? _nativeStrMap.get(this) : _origToString.call(this);
    return outStr;
  };
  // 把 toString 自身也伪装为 native
  _nativeStrMap.set(_initToString, 'function toString() { [native code] }');
  Function.prototype.toString = _initToString;

  // 工具函数：在原型上覆盖 getter，并注册 native toString
  function _hookGetter(obj, prop, getterFn, nativeStr) {
    try {
      _nativeStrMap.set(getterFn, nativeStr || ('function get ' + prop + '() { [native code] }'));
      Object.defineProperty(obj, prop, { get: getterFn, configurable: true, enumerable: true });
    } catch (e) {}
  }
  // 工具函数：在原型上覆盖 value，并注册 native toString
  function _hookValue(obj, prop, valueFn, nativeStr) {
    try {
      _nativeStrMap.set(valueFn, nativeStr || ('function ' + prop + '() { [native code] }'));
      Object.defineProperty(obj, prop, { value: valueFn, configurable: true, writable: true });
    } catch (e) {}
  }

  const isTop = (window.top === window.self);

  // ====== 1. navigator.webdriver ======
  try {
    const wd = navigator.webdriver;
    if (wd === true || wd === undefined) {
      _hookGetter(Navigator.prototype, 'webdriver', function() { return false; });
    }
  } catch (e) {}

  // ====== 2. chrome 对象 —— 仅顶层 frame ======
  try {
    if (isTop) {
      if (!window.chrome) window.chrome = {};
      if (!window.chrome.runtime) window.chrome.runtime = {};
      if (!window.chrome.app) {
        window.chrome.app = {
          getDetails: function() { return null; },
          getIsInstalled: function() { return false; },
          runningState: function() { return 'cannot_run'; },
          installState: function() { return 'disabled'; },
          isInstalled: false,
        };
        _nativeStrMap.set(window.chrome.app.getDetails, 'function getDetails() { [native code] }');
        _nativeStrMap.set(window.chrome.app.getIsInstalled, 'function getIsInstalled() { [native code] }');
        _nativeStrMap.set(window.chrome.app.runningState, 'function runningState() { [native code] }');
        _nativeStrMap.set(window.chrome.app.installState, 'function installState() { [native code] }');
      }
      if (!window.chrome.csi) {
        const _csi = function() {
          const _t = performance.timing || {};
          return { startE: _t.navigationStart || Date.now() - 2000, onloadT: _t.loadEventEnd || Date.now() - 500, pageT: 2000, tran: 15 };
        };
        _nativeStrMap.set(_csi, 'function csi() { [native code] }');
        window.chrome.csi = _csi;
      }
      if (!window.chrome.loadTimes) {
        const _lt = function() {
          const _t = performance.timing || {};
          const base = (_t.navigationStart || Date.now()) / 1000;
          return {
            commitLoadTime: base + 0.5, connectionInfo: 'h2',
            finishDocumentLoadTime: base + 1.5, finishLoadTime: base + 2,
            firstPaintAfterLoadTime: 0, firstPaintTime: base + 1,
            navigationType: 'Other', npnNegotiatedProtocol: 'h2',
            requestTime: base - 0.5, startLoadTime: base,
            wasAlternateProtocolAvailable: false, wasFetchedViaSPDY: true,
            wasNpnNegotiated: true
          };
        };
        _nativeStrMap.set(_lt, 'function loadTimes() { [native code] }');
        window.chrome.loadTimes = _lt;
      }
    }
  } catch (e) {}

  // ====== 3. permissions.query ======
  try {
    if (window.navigator.permissions && window.navigator.permissions.query) {
      const origQuery = Permissions.prototype.query;
      _hookValue(Permissions.prototype, 'query', function(parameters) {
        if (parameters && parameters.name === 'notifications') {
          return Promise.resolve({ state: Notification.permission });
        }
        return origQuery.call(this, parameters);
      }, 'function query() { [native code] }');
    }
  } catch (e) {}

  // ====== 4. languages ======
  _hookGetter(Navigator.prototype, 'languages', function() { return ['en-US', 'en']; });

  // ====== 5. platform + userAgent + appVersion ======
  try {
    const ua = navigator.userAgent || '';
    let p = 'Linux x86_64';
    let fakeUa = ua;
    if (/Windows/.test(ua)) { p = 'Win32'; }
    else if (/Macintosh/.test(ua)) { p = 'MacIntel'; }
    else if (/Linux/.test(ua)) { p = 'Win32'; fakeUa = ua.replace('X11; Linux x86_64', 'Windows NT 10.0; Win64; x64'); }
    _hookGetter(Navigator.prototype, 'platform', function() { return p; });
    if (fakeUa !== ua) {
      _hookGetter(Navigator.prototype, 'userAgent', function() { return fakeUa; });
    }
    const effectiveUa = fakeUa !== ua ? fakeUa : ua;
    _hookGetter(Navigator.prototype, 'appVersion', function() { return effectiveUa.replace('Mozilla/', ''); });
  } catch (e) {}

  // ====== 6. maxTouchPoints ======
  _hookGetter(Navigator.prototype, 'maxTouchPoints', function() { return 0; });

  // ====== 7. navigator.connection ======
  try {
    if (!navigator.connection) {
      _hookGetter(Navigator.prototype, 'connection', function() {
        return { effectiveType: '4g', rtt: 50, downlink: 10, saveData: false };
      });
    }
  } catch (e) {}

  // ====== 8. navigator.userAgentData ======
  try {
    if (navigator.userAgentData) {
      const ua = navigator.userAgent || '';
      const cm = ua.match(/Chrome\/(\d+)/);
      const cv = cm ? cm[1] : '150';
      const isWin = /Windows/.test(ua);
      const fakeUAD = {
        brands: [
          { brand: 'Google Chrome', version: cv },
          { brand: 'Chromium', version: cv },
          { brand: 'Not_A Brand', version: '24' },
        ],
        mobile: false,
        platform: isWin ? 'Windows' : 'macOS',
      };
      const _hev = function(hints) {
        return Promise.resolve({
          brands: fakeUAD.brands, mobile: false,
          platform: isWin ? 'Windows' : 'macOS',
          platformVersion: isWin ? '10.0.0' : '13.6.0',
          architecture: 'x86', bitness: '64', model: '',
          uaFullVersion: cv + '.0.0.0',
          fullVersionList: [
            { brand: 'Google Chrome', version: cv + '.0.0.0' },
            { brand: 'Chromium', version: cv + '.0.0.0' },
            { brand: 'Not_A Brand', version: '24.0.0.0' },
          ],
        });
      };
      _nativeStrMap.set(_hev, 'function getHighEntropyValues() { [native code] }');
      fakeUAD.getHighEntropyValues = _hev;
      const _toJSON = function() { return { brands: fakeUAD.brands, mobile: false, platform: fakeUAD.platform }; };
      _nativeStrMap.set(_toJSON, 'function toJSON() { [native code] }');
      fakeUAD.toJSON = _toJSON;
      _hookGetter(Navigator.prototype, 'userAgentData', function() { return fakeUAD; });
    }
  } catch (e) {}

  // ====== 9. WebGL vendor/renderer/extensions ======
  try {
    const FAKE_WGL_VENDOR = 'Google Inc. (Intel)';
    const FAKE_WGL_RENDERER = 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)';
    const SW_RE = /swiftshader|llvmpipe|softpipe|software[\s_-]*rasterizer|mesa[\s_-]*swrast/i;
    const FAKE_WGL1_EXTS = [
      'ANGLE_instanced_arrays','EXT_blend_minmax','EXT_color_buffer_half_float',
      'EXT_disjoint_timer_query','EXT_float_blend','EXT_frag_depth',
      'EXT_shader_texture_lod','EXT_texture_compression_bptc',
      'EXT_texture_compression_rgtc','EXT_texture_filter_anisotropic',
      'EXT_sRGB','OES_element_index_uint','OES_fbo_render_mipmap',
      'OES_standard_derivatives','OES_texture_float','OES_texture_float_linear',
      'OES_texture_half_float','OES_texture_half_float_linear','OES_vertex_array_object',
      'WEBGL_color_buffer_float','WEBGL_compressed_texture_s3tc',
      'WEBGL_compressed_texture_s3tc_srgb','WEBGL_debug_renderer_info',
      'WEBGL_debug_shaders','WEBGL_depth_texture','WEBGL_draw_buffers',
      'WEBGL_lose_context','WEBGL_multi_draw'
    ];
    const FAKE_WGL2_EXTS = [
      'EXT_color_buffer_float','EXT_color_buffer_half_float','EXT_disjoint_timer_query_webgl2',
      'EXT_float_blend','EXT_texture_compression_bptc','EXT_texture_compression_rgtc',
      'EXT_texture_filter_anisotropic','EXT_texture_norm16','KHR_parallel_shader_compile',
      'OES_draw_buffers_indexed','OES_texture_float_linear','OVR_multiview2',
      'WEBGL_compressed_texture_s3tc','WEBGL_compressed_texture_s3tc_srgb',
      'WEBGL_debug_renderer_info','WEBGL_debug_shaders','WEBGL_lose_context',
      'WEBGL_multi_draw','WEBGL_provoking_vertex'
    ];

    const hookWebGL = (proto, fakeExts) => {
      if (!proto || !proto.getParameter) return;
      const origGetParam = proto.getParameter;
      const origGetExts = proto.getSupportedExtensions;
      const isSW = (gl) => { try { return SW_RE.test(String(origGetParam.call(gl, 37446))); } catch(e) { return false; } };

      const _getParam = function(param) {
        const result = origGetParam.call(this, param);
        if (param === 37446 && SW_RE.test(String(result))) return FAKE_WGL_RENDERER;
        if (param === 37445 && isSW(this)) return FAKE_WGL_VENDOR;
        return result;
      };
      _nativeStrMap.set(_getParam, 'function getParameter() { [native code] }');
      proto.getParameter = _getParam;

      if (origGetExts) {
        const _getExts = function() {
          if (isSW(this)) return fakeExts;
          return origGetExts.call(this);
        };
        _nativeStrMap.set(_getExts, 'function getSupportedExtensions() { [native code] }');
        proto.getSupportedExtensions = _getExts;
      }
    };
    try { hookWebGL(WebGLRenderingContext.prototype, FAKE_WGL1_EXTS); } catch (e) {}
    try { hookWebGL(WebGL2RenderingContext.prototype, FAKE_WGL2_EXTS); } catch (e) {}
  } catch (e) {}

  // ====== 10. Canvas 指纹噪声 ======
  try {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    const _noiseOff = ((window.location.hostname || '').length * 7 + 3) % 5 + 1;

    function _canvasInjectNoise(canvas) {
      try {
        const ctx = canvas.getContext('2d');
        if (!ctx || canvas.width < 1 || canvas.height < 1) return;
        const img = ctx.getImageData(0, 0, 1, 1);
        img.data[3] = (img.data[3] + _noiseOff) & 0xFF;
        ctx.putImageData(img, 0, 0);
      } catch (e) {}
    }

    const _toDataURL = function() { _canvasInjectNoise(this); return origToDataURL.apply(this, arguments); };
    _nativeStrMap.set(_toDataURL, 'function toDataURL() { [native code] }');
    HTMLCanvasElement.prototype.toDataURL = _toDataURL;

    if (origToBlob) {
      const _toBlob = function() { _canvasInjectNoise(this); return origToBlob.apply(this, arguments); };
      _nativeStrMap.set(_toBlob, 'function toBlob() { [native code] }');
      HTMLCanvasElement.prototype.toBlob = _toBlob;
    }
  } catch (e) {}

  // ====== 11. AudioContext 指纹噪声 ======
  try {
    const origGetChannelData = AudioBuffer.prototype.getChannelData;
    const _gcd = function(channel) {
      const data = origGetChannelData.call(this, channel);
      if (data && data.length > 0) {
        const off = ((this.length || 0) * 3 + 1) % 7 / 100000;
        data[0] = data[0] + off;
      }
      return data;
    };
    _nativeStrMap.set(_gcd, 'function getChannelData() { [native code] }');
    AudioBuffer.prototype.getChannelData = _gcd;
  } catch (e) {}

  // ====== 12. WebRTC + enumerateDevices ======
  try {
    if (window.RTCPeerConnection || window.webkitRTCPeerConnection) {
      const _RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
      const _origSetConfig = _RTC.prototype.setConfiguration;
      if (_origSetConfig) {
        const _setConfig = function(config) {
          if (config && config.iceTransportPolicy === undefined) { config.iceTransportPolicy = 'relay'; }
          return _origSetConfig.call(this, config);
        };
        _nativeStrMap.set(_setConfig, 'function setConfiguration() { [native code] }');
        _RTC.prototype.setConfiguration = _setConfig;
      }
    }
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const _origEnum = MediaDevices.prototype.enumerateDevices;
      const _enum = function() { return _origEnum.call(this).then(d => d.filter(x => x.kind !== 'videoinput')); };
      _nativeStrMap.set(_enum, 'function enumerateDevices() { [native code] }');
      MediaDevices.prototype.enumerateDevices = _enum;
    }
  } catch (e) {}

  // ====== 13. iframe contentWindow.chrome 检测修复 ======
  // 真实 Chrome 中，主页面创建的 iframe 的 contentWindow 也有 chrome 对象（同源），
  // 但跨域 iframe 的 chrome 为 undefined。之前的修复跳过了所有 iframe 的 chrome 注入，
  // 但同源 iframe 仍需要 chrome 对象，否则也是一种检测方式。
  // 此处不额外处理：跨域 iframe 不注入 chrome 已经正确，同源 iframe 会从原型继承。
})();
"""
    ok = False
    try:
        page.run_cdp("Page.addScriptToEvaluateOnNewDocument", source=source)
        ok = True
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 增强 stealth 预注入失败: {str(exc)[:160]}")
    try:
        page.run_cdp("Runtime.evaluate", expression=source)
        ok = True
    except Exception:
        pass
    if ok and log_callback:
        log_callback("[Debug] 已安装增强 stealth（toString保护+原型级覆盖+帧隔离+userAgentData+WebGL扩展）")
    return ok


def read_turnstile_token_len(page):
    if not page:
        return 0
    try:
        value = page.run_js(
            r"""
const input = document.querySelector('input[name="cf-turnstile-response"]');
const direct = String((input && input.value) || '').trim();
if (direct) return direct.length;
try {
  if (window.turnstile && typeof window.turnstile.getResponse === 'function') {
    const resp = String(window.turnstile.getResponse() || '').trim();
    if (resp) return resp.length;
  }
} catch (e) {}
return 0;
            """
        )
        return int(value or 0)
    except Exception:
        return 0


def install_turnstile_page_hook(page, log_callback=None):
    source_fn = _resolve("turnstile_page_hook_source", turnstile_page_hook_source)
    if getattr(source_fn, "__module__", "") == __name__:
        source = turnstile_page_hook_source()
    else:
        source = source_fn()
    if not page or not source:
        return False
    installed = False
    try:
        page.run_cdp("Page.addScriptToEvaluateOnNewDocument", source=source)
        installed = True
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] Turnstile CDP 预注入失败: {str(exc)[:180]}")
    try:
        page.run_cdp("Runtime.evaluate", expression=source)
        installed = True
    except Exception:
        pass
    return installed

def _dispatch_cdp_click(page, x, y, include_keyboard=True):
    page.run_cdp("Input.dispatchMouseEvent", type="mouseMoved", x=x, y=y)
    page.run_cdp(
        "Input.dispatchMouseEvent",
        type="mousePressed",
        x=x,
        y=y,
        button="left",
        clickCount=1,
    )
    page.run_cdp(
        "Input.dispatchMouseEvent",
        type="mouseReleased",
        x=x,
        y=y,
        button="left",
        clickCount=1,
    )
    if include_keyboard:
        try:
            page.run_cdp("Input.dispatchKeyEvent", type="keyDown", key="Enter", code="Enter", windowsVirtualKeyCode=13)
            page.run_cdp("Input.dispatchKeyEvent", type="keyUp", key="Enter", code="Enter", windowsVirtualKeyCode=13)
            page.run_cdp("Input.dispatchKeyEvent", type="keyDown", key=" ", code="Space", windowsVirtualKeyCode=32)
            page.run_cdp("Input.dispatchKeyEvent", type="keyUp", key=" ", code="Space", windowsVirtualKeyCode=32)
        except Exception:
            pass


def _dispatch_cdp_text(page, text):
    page.run_cdp("Input.insertText", text=str(text or ""))


def _click_point_on_page(page, x, y):
    x, y = int(x), int(y)
    try:
        page.run_cdp("Input.dispatchMouseEvent", type="mouseMoved", x=x, y=y, modifiers=0)
    except Exception:
        pass
    _dispatch_cdp_click(page, x, y, include_keyboard=False)
    return {"x": x, "y": y, "nativeClicked": True}


def _locate_turnstile_target_via_js(page):
    """主文档 JS 定位（含 open shadow）。跨域 iframe 内文案看不到，但 iframe 元素本身应能看到。"""
    try:
        return page.run_js(
            r"""
function visible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity || '1') > 0;
}
function centerLeft(node) {
  const rect = node.getBoundingClientRect();
  return {
    x: Math.round(rect.left + Math.min(Math.max(16, rect.width * 0.1), 34)),
    y: Math.round(rect.top + rect.height / 2),
    width: Math.round(rect.width),
    height: Math.round(rect.height),
  };
}
const frames = [];
const widgets = [];
const allIframes = [];
function visit(root, depth) {
  if (!root || !root.querySelectorAll || depth > 8) return;
  let nodes;
  try { nodes = Array.from(root.querySelectorAll('*')); } catch (e) { return; }
  for (const node of nodes) {
    try { if (node.shadowRoot) visit(node.shadowRoot, depth + 1); } catch (e) {}
    const tag = String(node.tagName || '').toLowerCase();
    if (tag === 'iframe' && visible(node)) {
      const src = String(node.getAttribute('src') || '');
      const title = String(node.getAttribute('title') || '');
      const name = String(node.getAttribute('name') || '');
      const marker = (src + ' ' + title + ' ' + name + ' ' + (node.className || '') + ' ' + (node.id || '')).toLowerCase();
      allIframes.push({src: src.slice(0, 120), title: title.slice(0, 60), w: Math.round(node.getBoundingClientRect().width), h: Math.round(node.getBoundingClientRect().height)});
      if (
        marker.includes('challenge') || marker.includes('turnstile') ||
        marker.includes('cloudflare') || marker.includes('cf-chl') ||
        title.includes('小部件') || title.toLowerCase().includes('widget') ||
        // 无 src 标记时，尺寸像 turnstile checkbox 条（常见 ~300x65）
        (node.getBoundingClientRect().width >= 200 && node.getBoundingClientRect().width <= 420 &&
         node.getBoundingClientRect().height >= 40 && node.getBoundingClientRect().height <= 100)
      ) {
        frames.push(node);
      }
    }
    const sitekey = node.getAttribute && node.getAttribute('data-sitekey');
    const cls = String(node.className || '').toLowerCase();
    if (visible(node) && (sitekey || cls.includes('cf-turnstile') || cls.includes('cf-chl'))) {
      widgets.push(node);
    }
  }
}
visit(document, 0);
if (frames.length) {
  return { state: 'turnstile-challenge-target', via: 'js-iframe', count: frames.length, allIframes, ...centerLeft(frames[0]), src: String(frames[0].getAttribute('src')||'').slice(0,160) };
}
if (widgets.length) {
  return { state: 'turnstile-challenge-target', via: 'js-widget', count: widgets.length, allIframes, ...centerLeft(widgets[0]) };
}
// 兜底：任意“像 checkbox 条”的可见 iframe
const sized = allIframes.filter((f) => f.w >= 200 && f.w <= 420 && f.h >= 40 && f.h <= 100);
return { state: 'turnstile-challenge-not-found', via: 'js', frameCount: frames.length, widgetCount: widgets.length, allIframes: allIframes.slice(0, 8), sizedCount: sized.length };
            """
        )
    except Exception as exc:
        return {"state": "turnstile-js-error", "error": str(exc)[:200]}


def _locate_turnstile_target_via_cdp(page):
    """用 CDP DOM/FrameTree/AX 找跨域 turnstile iframe 并算页面坐标。"""
    diagnostics = {"via": "cdp"}
    # 1) FrameTree：子 frame URL 含 cloudflare/turnstile
    try:
        tree = page.run_cdp("Page.getFrameTree") or {}
        frames = []

        def walk(node, depth=0):
            if not isinstance(node, dict) or depth > 10:
                return
            frame = node.get("frame") or {}
            url = str(frame.get("url") or "")
            frames.append({"id": frame.get("id"), "url": url[:180], "name": frame.get("name")})
            for child in node.get("childFrames") or []:
                walk(child, depth + 1)

        root_frame_id = None
        frame_tree = tree.get("frameTree") or tree
        if isinstance(frame_tree, dict) and isinstance(frame_tree.get("frame"), dict):
            root_frame_id = frame_tree.get("frame", {}).get("id")
        walk(frame_tree)
        diagnostics["frames"] = frames[:12]
        cloud_frames = [
            f for f in frames
            if any(k in str(f.get("url") or "").lower() for k in ("cloudflare", "turnstile", "cf-chl", "challenges."))
        ]
        # Turnstile 在本地经常是 about:blank 子 frame（srcdoc/blob），URL 不含 cloudflare。
        blank_frames = [
            f for f in frames
            if f.get("id") and f.get("id") != root_frame_id
            and (
                not str(f.get("url") or "").strip()
                or str(f.get("url") or "").startswith("about:blank")
                or str(f.get("url") or "").startswith("blob:")
            )
        ]
        diagnostics["cloudFrameCount"] = len(cloud_frames)
        diagnostics["blankFrameCount"] = len(blank_frames)
        candidate_frames = cloud_frames + blank_frames
    except Exception as exc:
        diagnostics["frameTreeError"] = str(exc)[:160]
        cloud_frames = []
        blank_frames = []
        candidate_frames = []
        root_frame_id = None

    # 2) pierce DOM 找 iframe 节点 box
    try:
        doc = page.run_cdp("DOM.getDocument", depth=-1, pierce=True) or {}
        root_id = (doc.get("root") or {}).get("nodeId")
        if root_id:
            search = page.run_cdp("DOM.querySelectorAll", nodeId=root_id, selector="iframe") or {}
            node_ids = search.get("nodeIds") or []
            diagnostics["iframeNodeCount"] = len(node_ids)
            for node_id in node_ids[:20]:
                try:
                    attrs_resp = page.run_cdp("DOM.getAttributes", nodeId=node_id) or {}
                    attrs_list = attrs_resp.get("attributes") or []
                    attrs = {}
                    for i in range(0, len(attrs_list) - 1, 2):
                        attrs[str(attrs_list[i]).lower()] = str(attrs_list[i + 1])
                    src = attrs.get("src", "")
                    title = attrs.get("title", "")
                    marker = f"{src} {title}".lower()
                    box = page.run_cdp("DOM.getBoxModel", nodeId=node_id) or {}
                    model = box.get("model") or {}
                    content = model.get("content") or model.get("border") or []
                    if len(content) < 8:
                        continue
                    xs = content[0::2]
                    ys = content[1::2]
                    left, right = min(xs), max(xs)
                    top, bottom = min(ys), max(ys)
                    width, height = right - left, bottom - top
                    if width <= 1 or height <= 1:
                        continue
                    looks_like = (
                        any(k in marker for k in ("cloudflare", "turnstile", "challenge", "cf-chl"))
                        or (200 <= width <= 420 and 40 <= height <= 100)
                    )
                    if not looks_like:
                        continue
                    return {
                        "state": "turnstile-challenge-target",
                        "via": "cdp-iframe",
                        "x": int(left + min(max(16, width * 0.1), 34)),
                        "y": int(top + height / 2),
                        "width": int(width),
                        "height": int(height),
                        "src": src[:160],
                        "title": title[:80],
                        "diagnostics": diagnostics,
                    }
                except Exception:
                    continue
    except Exception as exc:
        diagnostics["domError"] = str(exc)[:160]

    # 3) Accessibility 树：可见 checkbox / 请验证您是真人
    try:
        page.run_cdp("Accessibility.enable")
        ax = page.run_cdp("Accessibility.getFullAXTree") or {}
        nodes = ax.get("nodes") or []
        diagnostics["axNodeCount"] = len(nodes)
        for node in nodes:
            if not isinstance(node, dict):
                continue
            name = str(node.get("name", {}).get("value") if isinstance(node.get("name"), dict) else node.get("name") or "")
            role = str(node.get("role", {}).get("value") if isinstance(node.get("role"), dict) else node.get("role") or "")
            compact = name.replace(" ", "")
            interesting = (
                "请验证您是真人" in name
                or "确认您是真人" in name
                or "Verify you are human" in name
                or "verify you are human" in name.lower()
                or (role.lower() == "checkbox" and ("真人" in name or "human" in name.lower() or "cloudflare" in name.lower()))
            )
            if not interesting:
                continue
            backend_id = node.get("backendDOMNodeId")
            if not backend_id:
                continue
            try:
                resolved = page.run_cdp("DOM.resolveNode", backendNodeId=backend_id) or {}
                obj_id = (resolved.get("object") or {}).get("objectId")
                if not obj_id:
                    continue
                desc = page.run_cdp("DOM.describeNode", objectId=obj_id, pierce=True, depth=1) or {}
                node_id = (desc.get("node") or {}).get("nodeId")
                if not node_id:
                    # 尝试 backendDOMNodeId 直接 box
                    box = page.run_cdp("DOM.getBoxModel", backendNodeId=backend_id) or {}
                else:
                    box = page.run_cdp("DOM.getBoxModel", nodeId=node_id) or {}
                model = box.get("model") or {}
                content = model.get("content") or model.get("border") or []
                if len(content) < 8:
                    continue
                xs = content[0::2]
                ys = content[1::2]
                left, right = min(xs), max(xs)
                top, bottom = min(ys), max(ys)
                width, height = right - left, bottom - top
                return {
                    "state": "turnstile-challenge-target",
                    "via": "cdp-ax",
                    "x": int(left + min(max(16, width * 0.1), 34)),
                    "y": int(top + height / 2),
                    "width": int(width),
                    "height": int(height),
                    "name": name[:80],
                    "role": role[:40],
                    "diagnostics": diagnostics,
                }
            except Exception:
                continue
    except Exception as exc:
        diagnostics["axError"] = str(exc)[:160]

    # 4) 对 cloudflare / about:blank 子 frame，用 DOM.getFrameOwner 拿宿主 iframe 的 box 并点击左侧
    for frame in (candidate_frames or cloud_frames)[:12]:
        frame_id = frame.get("id")
        if not frame_id or frame_id == root_frame_id:
            continue
        try:
            owner = page.run_cdp("DOM.getFrameOwner", frameId=frame_id) or {}
            backend_id = owner.get("backendNodeId")
            node_id = owner.get("nodeId")
            if node_id:
                box = page.run_cdp("DOM.getBoxModel", nodeId=node_id) or {}
            elif backend_id:
                box = page.run_cdp("DOM.getBoxModel", backendNodeId=backend_id) or {}
            else:
                continue
            model = box.get("model") or {}
            content = model.get("content") or model.get("border") or []
            if len(content) < 8:
                continue
            xs = content[0::2]
            ys = content[1::2]
            left, right = min(xs), max(xs)
            top, bottom = min(ys), max(ys)
            width, height = right - left, bottom - top
            if width <= 1 or height <= 1:
                continue
            url = str(frame.get("url") or "")
            is_cf_url = any(k in url.lower() for k in ("cloudflare", "turnstile", "cf-chl", "challenges."))
            # about:blank 宿主框常见尺寸：宽 240~520，高 50~90
            checkbox_like = (180 <= width <= 560 and 36 <= height <= 120)
            if not is_cf_url and not checkbox_like:
                diagnostics.setdefault("skippedBlankOwners", []).append(
                    {"url": url[:80], "w": int(width), "h": int(height)}
                )
                continue
            return {
                "state": "turnstile-challenge-target",
                "via": "cdp-frame-owner",
                "x": int(left + min(max(16, width * 0.1), 34)),
                "y": int(top + height / 2),
                "width": int(width),
                "height": int(height),
                "src": url[:160],
                "diagnostics": diagnostics,
            }
        except Exception:
            continue

    return {"state": "turnstile-challenge-not-found", "diagnostics": diagnostics}


def _click_turnstile_challenge_if_visible(page):
    """点击可见的 Cloudflare 复选框/挑战框。

    本地桌面 Chrome 常渲染成可见的「请验证您是真人」复选框（在跨域 iframe 内）。
    仅靠主文档 querySelector 经常找不到，需要 CDP FrameTree/AX 兜底。
    """
    attempts = []
    target = _locate_turnstile_target_via_js(page)
    attempts.append({"method": "js", "state": (target or {}).get("state") if isinstance(target, dict) else type(target).__name__})
    if not (isinstance(target, dict) and target.get("state") == "turnstile-challenge-target"):
        cdp_target = _locate_turnstile_target_via_cdp(page)
        attempts.append({"method": "cdp", "state": (cdp_target or {}).get("state") if isinstance(cdp_target, dict) else type(cdp_target).__name__})
        if isinstance(cdp_target, dict) and cdp_target.get("state") == "turnstile-challenge-target":
            target = cdp_target
        elif isinstance(target, dict):
            # 合并诊断信息
            diag = {}
            if isinstance(target.get("allIframes"), list):
                diag["jsIframes"] = target.get("allIframes")
            if isinstance(cdp_target, dict):
                diag.update(cdp_target.get("diagnostics") or {})
                diag["cdpState"] = cdp_target.get("state")
            target = {
                "state": "turnstile-challenge-not-found",
                "attempts": attempts,
                "diagnostics": diag,
            }
        else:
            target = {"state": "turnstile-challenge-not-found", "attempts": attempts}

    if not isinstance(target, dict) or target.get("state") != "turnstile-challenge-target":
        return target
    if target.get("x") is None or target.get("y") is None:
        return {"state": "turnstile-challenge-missing-center", **target}

    click_meta = _click_point_on_page(page, target.get("x"), target.get("y"))
    # 有些实现要点两次才勾选
    sleep_with_cancel(0.15)
    try:
        _click_point_on_page(page, int(target.get("x")), int(target.get("y")))
    except Exception:
        pass
    return {**target, **click_meta, "attempts": attempts}


def _dispatch_cdp_keypress(page, ch):
    """派发真实按键事件（keyDown 带 text + keyUp），驱动 input-otp 等依赖
    keydown/onChange 的受控组件；insertText 会绕过这些处理器导致值不同步。"""
    ch = str(ch or "")
    if not ch:
        return
    vk = ord(ch.upper())
    page.run_cdp(
        "Input.dispatchKeyEvent",
        type="keyDown",
        text=ch,
        key=ch,
        windowsVirtualKeyCode=vk,
        nativeVirtualKeyCode=vk,
    )
    page.run_cdp(
        "Input.dispatchKeyEvent",
        type="keyUp",
        key=ch,
        windowsVirtualKeyCode=vk,
        nativeVirtualKeyCode=vk,
    )


def _fill_otp_code_native(page, clean_code, cancel_callback=None):
    target = page.run_js(build_otp_native_target_script(), len(clean_code))
    if not isinstance(target, dict) or target.get("state") != "otp-target":
        return target
    if target.get("centerX") is None or target.get("centerY") is None:
        return {"state": "otp-target-missing-center", **target}
    _dispatch_cdp_click(
        page,
        int(target.get("centerX")),
        int(target.get("centerY")),
        include_keyboard=False,
    )
    inserted = 0
    for ch in str(clean_code or ""):
        _dispatch_cdp_keypress(page, ch)
        inserted += 1
        sleep_with_cancel(0.08, cancel_callback)
    # 填后回读实际值长度，确认按键事件真的驱动了受控组件
    filled_len = None
    try:
        filled_len = page.run_js(
            r"""
try {
  const el = document.activeElement;
  const v = (el && typeof el.value === 'string') ? el.value : '';
  const otp = document.querySelector('input[data-input-otp="true"], input[name="code"], input[autocomplete="one-time-code"]');
  const ov = otp ? String(otp.value || '') : '';
  return Math.max(String(v).replace(/\s+/g, '').length, ov.replace(/\s+/g, '').length);
} catch (e) { return -1; }
            """
        )
    except Exception:
        filled_len = None
    return {**target, "nativeInput": True, "insertedChars": inserted, "filledLen": filled_len}


def _click_otp_submit_native(page):
    target = page.run_js(build_otp_submit_target_script())
    if not isinstance(target, dict) or target.get("state") != "otp-submit-target":
        return target
    if target.get("centerX") is None or target.get("centerY") is None:
        return {"state": "otp-submit-missing-center", **target}
    _dispatch_cdp_click(
        page,
        int(target.get("centerX")),
        int(target.get("centerY")),
        include_keyboard=False,
    )
    return {**target, "nativeClicked": True}


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




def _click_xai_oauth_consent_if_present(page):
    try:
        script_fn = _resolve("build_xai_oauth_consent_click_script", build_xai_oauth_consent_click_script)
        result = page.run_js(script_fn())
        if isinstance(result, dict) and result.get("centerX") is not None and result.get("centerY") is not None:
            x = int(result.get("centerX"))
            y = int(result.get("centerY"))
            try:
                _dispatch_cdp_click(page, x, y)
                result["nativeClicked"] = True
            except Exception as exc:
                result["nativeClickError"] = str(exc)[:160]
        return result
    except Exception:
        return False


_thread_ctx = threading.local()
_browser_launch_semaphore = threading.Semaphore(2)
_xvfb_process = None
_xvfb_lock = threading.Lock()


def _get_browser():
    fac = _facade()
    if fac is not None:
        fn = getattr(fac, "_get_browser", None)
        # Only use facade override when tests monkeypatch a different function.
        if callable(fn) and getattr(fn, "__module__", "") != __name__:
            return fn()
    return getattr(_thread_ctx, "browser", None)


def _set_browser(value):
    fac = _facade()
    if fac is not None:
        fn = getattr(fac, "_set_browser", None)
        if callable(fn) and getattr(fn, "__module__", "") != __name__:
            return fn(value)
    _thread_ctx.browser = value


def _get_page():
    fac = _facade()
    if fac is not None:
        fn = getattr(fac, "_get_page", None)
        if callable(fn) and getattr(fn, "__module__", "") != __name__:
            return fn()
    return getattr(_thread_ctx, "page", None)


def _set_page(value):
    fac = _facade()
    if fac is not None:
        fn = getattr(fac, "_set_page", None)
        if callable(fn) and getattr(fn, "__module__", "") != __name__:
            return fn(value)
    _thread_ctx.page = value


def override_user_agent_for_docker(page, log_callback=None):
    """Docker 中将 Linux UA 覆盖为 Windows UA（保持 Chrome 版本一致），同时覆盖 HTTP 头、JS 层和 userAgentData。"""
    if not page or not _env_truthy("GROK_REG_IN_DOCKER"):
        return
    try:
        actual_ua = page.run_js("return navigator.userAgent;") or ""
        if not actual_ua:
            return
        # 仅替换平台部分，保持 Chrome 版本号一致
        windows_ua = actual_ua.replace("X11; Linux x86_64", "Windows NT 10.0; Win64; x64")
        if windows_ua == actual_ua:
            return  # 不是 Linux UA，无需修改
        # 提取 Chrome 版本号用于 userAgentMetadata
        import re
        chrome_match = re.search(r'Chrome/(\d+)', windows_ua)
        chrome_ver = chrome_match.group(1) if chrome_match else "150"
        # CDP 覆盖 HTTP 头中的 UA + userAgentData（platform 改为 Windows）
        page.run_cdp("Network.setUserAgentOverride", userAgent=windows_ua, platform="Windows",
                      userAgentMetadata={
                          "brands": [
                              {"brand": "Google Chrome", "version": chrome_ver},
                              {"brand": "Chromium", "version": chrome_ver},
                              {"brand": "Not_A Brand", "version": "24"},
                          ],
                          "fullVersionList": [
                              {"brand": "Google Chrome", "version": chrome_ver + ".0.0.0"},
                              {"brand": "Chromium", "version": chrome_ver + ".0.0.0"},
                              {"brand": "Not_A Brand", "version": "24.0.0.0"},
                          ],
                          "fullVersion": chrome_ver + ".0.0.0",
                          "platform": "Windows",
                          "platformVersion": "10.0.0",
                          "architecture": "x86",
                          "bitness": "64",
                          "model": "",
                          "mobile": False,
                          "wow64": False,
                      })
        if log_callback and resolve_signup_mode() != "api":
            log_callback(f"[Debug] UA+userAgentData 已覆盖为 Windows: {windows_ua}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] UA 覆盖失败: {str(exc)[:160]}")


def start_browser(log_callback=None):
    last_exc = None
    for attempt in range(1, 5):
        try:
            # 高并发下限制同时启动浏览器数量，降低 auto_port/user_data 竞争
            with _browser_launch_semaphore:
                ensure_virtual_display(log_callback=log_callback)
                browser = Chromium(create_browser_options())
                tabs = browser.get_tabs()
                page = tabs[-1] if tabs else browser.new_tab()
            _set_browser(browser)
            _set_page(page)
            # Docker 中先覆盖 UA（HTTP 头 + JS 层），再装 stealth
            try:
                override_user_agent_for_docker(page, log_callback=log_callback)
            except Exception:
                pass
            # 启动时只装轻量 stealth，绝不补丁 turnstile API。
            # pageHook（补丁 window.turnstile）默认关闭，手动能过时补丁反而容易干扰 flexible 模式。
            api_mode = resolve_signup_mode() == "api"
            try:
                install_light_stealth_script(
                    page, log_callback=None if api_mode else log_callback
                )
            except Exception:
                pass
            if log_callback and not api_mode and getattr(browser, "user_data_path", None):
                log_callback(f"[Debug] 当前浏览器资料目录: {browser.user_data_path}")
            if log_callback:
                proxy = normalize_proxy_for_runtime(config.get("proxy", ""))
                if api_mode:
                    log_callback(f"[*] 浏览器已启动（API建号） 代理={proxy or '直连'}")
                else:
                    mode = "headless" if should_run_headless() else "visible"
                    extension_loaded = os.path.isdir(EXTENSION_PATH)
                    solver_on = bool(config.get("turnstile_solver_enabled", True))
                    log_callback(
                        f"[Debug] 浏览器模式: {mode}，代理: {proxy or '直连'}，"
                        f"Turnstile扩展路径: {'存在' if extension_loaded else '未找到'}，"
                        f"API补丁: {'开' if config.get('turnstile_patch_api') else '关'}，"
                        f"强制execute: {'开' if config.get('turnstile_force_execute') else '关'}，"
                        f"Solver: {'开 ' + normalize_turnstile_solver_url() if solver_on else '关'}"
                    )
            # API 建号路径不依赖浏览器指纹对抗，跳过采样噪音
            if not api_mode:
                probe_browser_stealth(page, log_callback=log_callback)
            if log_callback and attempt > 1:
                log_callback(f"[*] 浏览器第 {attempt} 次启动成功")
            return browser, page
        except Exception as exc:
            last_exc = exc
            if log_callback:
                log_callback(f"[Debug] 浏览器启动失败(第{attempt}/4次): {exc}")
                log_callback(
                    "[Debug] 浏览器启动环境: "
                    f"DISPLAY={os.environ.get('DISPLAY', '') or '(empty)'}，"
                    f"CHROME_BIN={os.environ.get('CHROME_BIN', '') or '(empty)'}，"
                    f"模式={'headless' if should_run_headless() else 'visible'}，"
                    f"代理={normalize_proxy_for_runtime(config.get('proxy', '')) or '直连'}"
                )
            try:
                current = _get_browser()
                if current is not None:
                    current.quit(del_data=True)
            except Exception:
                pass
            _set_browser(None)
            _set_page(None)
            # 短睡切片，避免 stop 后仍卡在启动重试的整段 sleep
            sleep_with_cancel(min(1.5 * attempt, 4))
    raise Exception(f"浏览器启动失败，已重试4次: {last_exc}")


def stop_browser():
    browser = _get_browser()
    if browser is not None:
        try:
            browser.quit(del_data=True)
        except Exception:
            pass
    _set_browser(None)
    _set_page(None)


def restart_browser(log_callback=None):
    stop_browser()
    return start_browser(log_callback=log_callback)


def refresh_active_page():
    browser = _get_browser()
    if browser is None:
        browser, _ = restart_browser()
    try:
        tabs = browser.get_tabs()
        if tabs:
            page = tabs[-1]
        else:
            page = browser.new_tab()
        _set_page(page)
    except Exception:
        _, page = restart_browser()
    return _get_page()


def click_email_signup_button(timeout=10, log_callback=None, cancel_callback=None):
    page = _get_page()
    deadline = time.time() + timeout
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if log_callback:
            log_callback("[Debug] 尝试查找“使用邮箱注册”按钮...")

        clicked = page.run_js(r"""
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = candidates.find((node) => {
    const text = (node.innerText || node.textContent || '').replace(/\s+/g, '');
    const lower = text.toLowerCase();
    return (
        text.includes('使用邮箱注册') ||
        lower.includes('signupwithemail') ||
        lower.includes('continuewithemail') ||
        lower.includes('email')
    );
});
if (!target) {
    return false;
}
target.click();
return true;
        """)

        if clicked:
            if log_callback:
                log_callback("[*] 已点击「使用邮箱注册」按钮")
            sleep_with_cancel(2, cancel_callback)
            return True

        if log_callback:
            current_url = page.url if page else "none"
            log_callback(f"[Debug] 当前URL: {current_url}")

        sleep_with_cancel(1, cancel_callback)

    page_html = page.html[:500] if page else "no page"
    if log_callback:
        log_callback(f"[Debug] 页面内容片段: {page_html}")
    if detect_cloudflare_block_page(page_html):
        raise Exception("Cloudflare 已拦截当前浏览器环境，请使用 Xvfb 非 headless 模式或更换出口 IP")

    raise Exception("未找到「使用邮箱注册」按钮")


def open_signup_page(log_callback=None, cancel_callback=None):
    browser = _get_browser()
    page = _get_page()
    raise_if_cancelled(cancel_callback)
    if browser is None:
        browser, page = start_browser()
        if log_callback:
            log_callback("[*] 浏览器已启动")
    try:
        page = browser.get_tab(0)
        _set_page(page)
        page.get(SIGNUP_URL)
    except Exception as e:
        if log_callback:
            log_callback(f"[Debug] 打开URL异常: {e}")
        try:
            page = browser.new_tab()
            _set_page(page)
            page.get(SIGNUP_URL)
        except Exception as e2:
            if log_callback:
                log_callback(f"[Debug] 创建新标签页异常: {e2}")
            browser, _ = restart_browser()
            page = browser.new_tab()
            _set_page(page)
            page.get(SIGNUP_URL)
    page.wait.doc_loaded()
    sleep_with_cancel(2, cancel_callback)
    if log_callback:
        log_callback(f"[*] 当前URL: {page.url}")
    click_email_signup_button(
        log_callback=log_callback, cancel_callback=cancel_callback
    )


def has_profile_form(log_callback=None):
    page = refresh_active_page()
    try:
        return bool(
            page.run_js(
                """
const givenInput = document.querySelector('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"]');
const familyInput = document.querySelector('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"]');
const passwordInput = document.querySelector('input[data-testid="password"], input[name="password"], input[type="password"]');
return !!(givenInput && familyInput && passwordInput);
            """
            )
        )
    except Exception:
        return False


def fill_email_and_submit(timeout=30, log_callback=None, cancel_callback=None):
    page = _get_page()
    raise_if_cancelled(cancel_callback)
    email, dev_token = get_email_and_token(log_callback=log_callback)
    if not email or not dev_token:
        raise Exception("获取邮箱失败")
    if log_callback:
        log_callback(f"[*] 已创建邮箱: {email}")
    deadline = time.time() + timeout
    last_state = "not-started"
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        filled = page.run_js(
            build_email_form_script("fill"),
            email,
        )
        last_state = str(filled)
        if filled == "not-ready":
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if filled != "filled":
            if log_callback:
                log_callback(f"[Debug] 邮箱输入框已出现，但写入失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        sleep_with_cancel(0.8, cancel_callback)
        clicked = page.run_js(
            build_email_form_script("submit"),
            email,
        )
        last_state = str(clicked)
        if clicked is True:
            wait_for_email_verification_step(
                page,
                email,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )
            if log_callback:
                log_callback(f"[*] 已填写邮箱并点击注册: {email}")
            return email, dev_token
        sleep_with_cancel(0.5, cancel_callback)
    if log_callback:
        try:
            diag = page.run_js(build_email_form_script("diagnose"), email)
        except Exception as diag_exc:
            diag = f"诊断失败: {diag_exc}"
        log_callback(f"[Debug] 邮箱表单诊断: last_state={last_state}; {diag}")
    raise Exception("未找到邮箱输入框或注册按钮")


def fill_code_and_submit(email, dev_token, timeout=180, log_callback=None, cancel_callback=None):
    page = _get_page()
    def _resend_code():
        page.run_js(
            r"""
const nodes = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = nodes.find((node) => {
  const t = (node.innerText || node.textContent || '').replace(/\s+/g, '').toLowerCase();
  return t.includes('重新发送') || t.includes('resend') || t.includes('再次发送');
});
if (target && !target.disabled) { target.click(); return true; }
return false;
            """
        )

    code = get_oai_code(
        dev_token,
        email,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=_resend_code,
    )
    if not code:
        raise Exception("获取验证码失败")
    clean_code = str(code).replace("-", "").strip()
    deadline = time.time() + timeout

    # 不要在 OTP 页安装 Turnstile pageHook。
    # 验证码接口 200 后 xAI 前端路由对脚本注入很敏感，过早 hook 会导致
    # 持续停在 "An error occurred" 过渡/错误页，无法进入资料页。
    # Turnstile 仅存在于资料页，延后到 fill_profile_and_submit 再注入。

    # 在填充/提交前启动 CDP 网络监听，无论请求经由 fetch/XHR/worker 发出，
    # 都能截获 VerifyEmailValidationCode 的响应体，定位服务端拒绝原因。
    listen_started = False
    try:
        page.listen.start("VerifyEmailValidationCode", method="POST")
        listen_started = True
    except Exception as listen_exc:
        if log_callback:
            log_callback(f"[Debug] 启动 verify-email 网络监听失败: {str(listen_exc)[:160]}")

    def _log_verify_packet():
        if not listen_started or not log_callback:
            return
        try:
            packet = page.listen.wait(count=1, timeout=1.5, fit_count=False)
        except Exception:
            packet = None
        if not packet:
            return
        packets = packet if isinstance(packet, (list, tuple)) else [packet]
        for pkt in packets:
            try:
                resp = getattr(pkt, "response", None)
                req = getattr(pkt, "request", None)
                body = getattr(resp, "body", "") if resp else ""
                status = getattr(resp, "status", "") if resp else ""
                post = getattr(req, "postData", "") if req else ""
                log_callback(
                    "[Debug] verify-email CDP 抓包: "
                    + json.dumps(
                        {
                            "status": status,
                            "reqBody": str(post)[:400],
                            "respBody": str(body)[:600],
                        },
                        ensure_ascii=False,
                    )[:1200]
                )
            except Exception as pkt_exc:
                log_callback(f"[Debug] verify-email 抓包解析失败: {str(pkt_exc)[:160]}")

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        # 上游验证码填充（JS + _valueTracker 同步）为主路径：已验证能正确驱动
        # input-otp 受控组件的 onComplete；CDP 原生输入仅作兜底，避免其绕过
        # React 状态导致自动提交携带无效值被 verify-email 拒绝。
        filled = page.run_js(
            """
const code = String(arguments[0] || '').trim();
if (!code) return 'empty-code';

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function setInputValue(input, value) {
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

const aggregate = Array.from(document.querySelectorAll(
  'input[data-input-otp=\"true\"], input[name=\"code\"], input[autocomplete=\"one-time-code\"], input[inputmode=\"numeric\"], input[inputmode=\"text\"]'
)).find((node) => isVisible(node) && !node.disabled && !node.readOnly && Number(node.maxLength || 6) > 1);

if (aggregate) {
    aggregate.focus();
    aggregate.click();
    setInputValue(aggregate, code);
    return String(aggregate.value || '').replace(/\\s+/g, '') ? 'filled-aggregate' : 'aggregate-failed';
}

const otpBoxes = Array.from(document.querySelectorAll('input')).filter((node) => {
    if (!isVisible(node) || node.disabled || node.readOnly) return false;
    const maxLength = Number(node.maxLength || 0);
    const ac = String(node.autocomplete || '').toLowerCase();
    return maxLength === 1 || ac === 'one-time-code';
});

if (otpBoxes.length >= code.length) {
    for (let i = 0; i < code.length; i += 1) {
        const ch = code[i] || '';
        const box = otpBoxes[i];
        box.focus();
        box.click();
        setInputValue(box, ch);
        box.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: ch }));
        box.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: ch }));
    }
    const merged = otpBoxes.slice(0, code.length).map((x) => String(x.value || '').trim()).join('');
    return merged.length ? 'filled-boxes' : 'boxes-failed';
}

return 'not-ready';
            """,
            clean_code,
        )

        # JS 主路径未成功时，回退到 CDP 原生按键输入
        if filled == "not-ready" or "failed" in str(filled):
            native_state = _fill_otp_code_native(page, clean_code, cancel_callback=cancel_callback)
            if isinstance(native_state, dict) and native_state.get("nativeInput"):
                filled = "filled-native"
                if log_callback:
                    log_callback(
                        "[Debug] 验证码 JS 填充未就绪，回退 CDP 原生输入: "
                        + json.dumps(native_state, ensure_ascii=False)[:500]
                    )

        if filled == "not-ready":
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if "failed" in str(filled):
            if log_callback:
                log_callback(f"[Debug] 验证码填写失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if log_callback:
            log_callback("[Debug] 验证码已填入，等待前端状态同步...")
        sleep_with_cancel(0.6, cancel_callback)

        native_submit = _click_otp_submit_native(page)
        if isinstance(native_submit, dict) and native_submit.get("nativeClicked"):
            clicked = "clicked"
            if log_callback:
                log_callback(
                    "[Debug] 验证码提交按钮已通过 CDP 原生点击: "
                    + json.dumps(native_submit, ensure_ascii=False)[:500]
                )
        else:
            clicked = page.run_js(
                r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const buttons = Array.from(document.querySelectorAll('button[type=\"submit\"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});

const btn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return (
        t.includes('确认邮箱') ||
        t.includes('继续') ||
        t.includes('下一步') ||
        t.includes('confirm') ||
        t.includes('continue') ||
        t.includes('next')
    );
});

if (!btn) return 'no-button';
btn.focus();
btn.click();
return 'clicked';
            """
            )

        if clicked == "clicked":
            if log_callback:
                log_callback(f"[*] 已填写验证码并提交: {code}")
            _log_verify_packet()
            if listen_started:
                try: page.listen.stop()
                except Exception: pass
            wait_for_post_code_transition(
                page,
                email,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )
            return code
        if clicked == "no-button":
            if log_callback:
                log_callback("[Debug] 验证码提交按钮未出现，等待前端自动提交结果...")
            _log_verify_packet()
            if listen_started:
                try: page.listen.stop()
                except Exception: pass
            wait_for_post_code_transition(
                page,
                email,
                log_callback=log_callback,
                cancel_callback=cancel_callback,
            )
            return code

        sleep_with_cancel(0.5, cancel_callback)

    if listen_started:
        try: page.listen.stop()
        except Exception: pass
    raise Exception("验证码已获取，但自动填写/提交失败")


def _read_turnstile_token_from_page(page):
    try:
        token = page.run_js(
            """
try {
  const byInput = String((document.querySelector('input[name="cf-turnstile-response"]') || {}).value || '').trim();
  if (byInput) return byInput;
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    return String(turnstile.getResponse() || '').trim();
  }
  return '';
} catch(e) { return ''; }
            """
        )
        return str(token or "").strip()
    except Exception:
        return ""


def _parse_element_rect(box):
    """兼容 DrissionPage rect 的多种返回形态：对象 / dict / (x,y,w,h) tuple。"""
    if box is None:
        return None
    try:
        # 对象形态：.location / .size 或 .x/.y/.width/.height
        loc = getattr(box, "location", None)
        size = getattr(box, "size", None)
        if isinstance(loc, dict) or isinstance(size, dict):
            x = float((loc or {}).get("x") or getattr(box, "x", 0) or 0)
            y = float((loc or {}).get("y") or getattr(box, "y", 0) or 0)
            w = float((size or {}).get("width") or getattr(box, "width", 0) or 0)
            h = float((size or {}).get("height") or getattr(box, "height", 0) or 0)
            return {"x": x, "y": y, "width": w, "height": h}
        if all(hasattr(box, attr) for attr in ("x", "y", "width", "height")):
            return {
                "x": float(box.x or 0),
                "y": float(box.y or 0),
                "width": float(box.width or 0),
                "height": float(box.height or 0),
            }
    except Exception:
        pass
    # tuple/list: (x, y, w, h) 或 (x1,y1,x2,y2)
    if isinstance(box, (tuple, list)):
        nums = [float(v) for v in box[:4]]
        if len(nums) >= 4:
            # JS getBoundingClientRect 导出为 [left, top, width, height]
            return {"x": nums[0], "y": nums[1], "width": nums[2], "height": nums[3]}
    if isinstance(box, dict):
        if "location" in box or "size" in box:
            loc = box.get("location") or {}
            size = box.get("size") or {}
            return {
                "x": float(loc.get("x") or box.get("x") or 0),
                "y": float(loc.get("y") or box.get("y") or 0),
                "width": float(size.get("width") or box.get("width") or 0),
                "height": float(size.get("height") or box.get("height") or 0),
            }
        return {
            "x": float(box.get("x") or 0),
            "y": float(box.get("y") or 0),
            "width": float(box.get("width") or box.get("w") or 0),
            "height": float(box.get("height") or box.get("h") or 0),
        }
    return None


def _safe_element_click(el, actions=None, label="element"):
    """兼容 ChromiumElement / ChromiumFrame 的点击。"""
    actions = actions if actions is not None else []
    if el is None:
        return False
    # 1) 标准 click
    for kwargs in ({"by_js": False}, {}, {"by_js": True}):
        try:
            if kwargs:
                el.click(**kwargs)
            else:
                el.click()
            actions.append(f"clicked-{label}")
            return True
        except TypeError:
            try:
                el.click()
                actions.append(f"clicked-{label}")
                return True
            except Exception:
                continue
        except Exception as exc:
            actions.append(f"click-{label}-fail:{type(el).__name__}:{exc}")
            break
    # 2) 某些 Frame 只有 .click.left
    try:
        click_obj = getattr(el, "click", None)
        if click_obj is not None and hasattr(click_obj, "left"):
            click_obj.left()
            actions.append(f"clicked-{label}-left")
            return True
    except Exception as exc:
        actions.append(f"click-{label}-left-fail:{exc}")
    return False


def _is_page_absolute_turnstile_rect(rect):
    """过滤 iframe 内部相对坐标（Docker 里常见 x=25,y=32 这种误点）。"""
    if not rect:
        return False
    x = float(rect.get("x") or 0)
    y = float(rect.get("y") or 0)
    w = float(rect.get("width") or 0)
    h = float(rect.get("height") or 0)
    if w < 80 or h < 20:
        return False
    # 页面中部/下方的 checkbox 条，不太可能贴在 (0,0) 附近
    if x < 40 and y < 40 and w < 120:
        return False
    # 明显在可视区域内
    if x > 2500 or y > 2500:
        return False
    return True


def _locate_turnstile_box_on_page(page):
    """在主文档坐标系下找 Turnstile 可见区域（页面绝对坐标）。"""
    try:
        raw = page.run_js(
            r"""
function boxOf(node) {
  if (!node || !node.getBoundingClientRect) return null;
  const r = node.getBoundingClientRect();
  if (r.width < 40 || r.height < 16) return null;
  return [r.left, r.top, r.width, r.height];
}
// 1) 从 hidden input 向上找合适容器
const input = document.querySelector('input[name="cf-turnstile-response"]');
if (input) {
  let n = input;
  for (let i = 0; i < 10 && n; i++) {
    const b = boxOf(n);
    if (b && b[2] >= 180 && b[2] <= 560 && b[3] >= 36 && b[3] <= 120) return {via:'input-parent', box:b};
    n = n.parentElement;
  }
}
// 2) 标准 host
const hosts = Array.from(document.querySelectorAll('div.cf-turnstile, [data-sitekey], iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"], iframe[title*="Cloudflare"], iframe[title*="小部件"]'));
for (const h of hosts) {
  const b = boxOf(h);
  if (b) return {via:'host', box:b, tag:h.tagName};
}
// 3) 开放 shadow 里的 iframe
function walk(root, depth) {
  if (!root || depth > 6) return null;
  let nodes;
  try { nodes = root.querySelectorAll('*'); } catch (e) { return null; }
  for (const node of nodes) {
    try {
      if (node.shadowRoot) {
        const hit = walk(node.shadowRoot, depth + 1);
        if (hit) return hit;
      }
    } catch (e) {}
    if (String(node.tagName||'').toLowerCase() === 'iframe') {
      const b = boxOf(node);
      if (b && b[2] >= 180 && b[2] <= 560 && b[3] >= 36 && b[3] <= 120) {
        return {via:'open-shadow-iframe', box:b};
      }
    }
  }
  return null;
}
const shadowHit = walk(document, 0);
if (shadowHit) return shadowHit;
// 4) 任意“checkbox 条”尺寸元素（靠近密码框下方优先）
const password = document.querySelector('input[type="password"], input[name="password"]');
const py = password ? password.getBoundingClientRect().bottom : 0;
let best = null;
for (const node of Array.from(document.querySelectorAll('div,iframe,section'))) {
  const b = boxOf(node);
  if (!b || b[2] < 200 || b[2] > 520 || b[3] < 40 || b[3] > 90) continue;
  const score = Math.abs((b[1] + b[3]/2) - (py || b[1]));
  if (!best || score < best.score) best = {via:'sized', box:b, score};
}
return best;
            """
        )
    except Exception as exc:
        return {"error": str(exc)[:160]}
    if not isinstance(raw, dict):
        return None
    box = _parse_element_rect(raw.get("box"))
    if not _is_page_absolute_turnstile_rect(box):
        return {"raw": raw, "rejected_box": box}
    return {"via": raw.get("via"), "box": box}


def _cdp_click_page_box_left(page, box, actions=None, label="page-box"):
    actions = actions if actions is not None else []
    if not _is_page_absolute_turnstile_rect(box):
        actions.append(f"skip-bad-box-{label}:{box}")
        return False
    x = int(box["x"] + min(max(16, box["width"] * 0.12), 36))
    y = int(box["y"] + max(box["height"] / 2, 12))
    # 再保险：拒绝贴边误点
    if x < 30 and y < 30:
        actions.append(f"skip-corner-{label}:{x},{y}")
        return False
    try:
        _click_point_on_page(page, x, y)
        actions.append(f"cdp-click-{label}:{x},{y}")
        sleep_with_cancel(0.15)
        _click_point_on_page(page, x + 2, y)
        actions.append(f"cdp-click2-{label}:{x+2},{y}")
        return True
    except Exception as exc:
        actions.append(f"cdp-click-{label}-fail:{exc}")
        return False


def _cdp_click_element_left(page, el, actions=None, label="element"):
    """仅在能拿到页面绝对坐标时 CDP 点击；拒绝 iframe 内相对坐标。"""
    actions = actions if actions is not None else []
    if el is None:
        return False
    rect = None
    for getter in (
        lambda: getattr(el, "rect", None),
        lambda: el.run_js(
            "const r=this.getBoundingClientRect();"
            "return [r.left + (window.scrollX||0), r.top + (window.scrollY||0), r.width, r.height];"
        )
        if hasattr(el, "run_js")
        else None,
    ):
        try:
            raw = getter()
            rect = _parse_element_rect(raw)
            if rect and rect.get("width", 0) > 1:
                break
        except Exception as exc:
            actions.append(f"rect-{label}-fail:{exc}")
            rect = None
    if not _is_page_absolute_turnstile_rect(rect):
        # 元素坐标不可信（常见于 iframe 内 shadow input），改用主文档定位
        actions.append(f"untrusted-rect-{label}:{rect}")
        located = _locate_turnstile_box_on_page(page)
        if isinstance(located, dict) and located.get("box"):
            return _cdp_click_page_box_left(page, located["box"], actions, f"{label}-via-page")
        actions.append(f"no-page-box-{label}:{located}")
        return False
    return _cdp_click_page_box_left(page, rect, actions, label)


def _click_turnstile_via_shadow_dom(page, log_callback=None):
    """参考 grok-auto-register：通过 DrissionPage shadow_root 点 Cloudflare 复选框。

    Docker 中 element.click() 常“假成功”不出 token，因此 shadow 点选后
    必须再补一次 CDP 坐标点击。
    """
    actions = []
    try:
        challenge_input = None
        for locator in (
            "@name=cf-turnstile-response",
            'css:input[name="cf-turnstile-response"]',
            "css:input[name*=turnstile]",
        ):
            try:
                challenge_input = page.ele(locator, timeout=0.3)
            except Exception:
                challenge_input = None
            if challenge_input:
                actions.append(f"found-input:{locator}")
                break

        iframe = None
        btn = None

        if challenge_input:
            wrapper = challenge_input
            for depth in range(0, 6):
                try:
                    if hasattr(wrapper, "shadow_root") and wrapper.shadow_root:
                        try:
                            iframe = wrapper.shadow_root.ele("tag:iframe", timeout=0.3)
                        except Exception:
                            iframe = None
                        if iframe:
                            actions.append(f"iframe-via-shadow-depth:{depth}")
                            break
                except Exception:
                    pass
                try:
                    parent = wrapper.parent()
                except Exception:
                    parent = None
                if not parent:
                    break
                wrapper = parent

        if not iframe:
            for locator in (
                "tag:iframe@src():turnstile",
                "tag:iframe@src():challenges.cloudflare.com",
                "css:iframe[src*='turnstile']",
                "css:iframe[src*='challenges.cloudflare.com']",
                "css:iframe[title*='Cloudflare']",
                "css:iframe[title*='小部件']",
                "css:div.cf-turnstile iframe",
                "css:[data-sitekey] iframe",
            ):
                try:
                    iframe = page.ele(locator, timeout=0.25)
                except Exception:
                    iframe = None
                if iframe:
                    actions.append(f"iframe-via:{locator}")
                    break

        if not iframe:
            try:
                frames = page.eles("tag:iframe") or []
                for fr in frames[:16]:
                    try:
                        rect = _parse_element_rect(getattr(fr, "rect", None))
                        w = float((rect or {}).get("width") or 0)
                        h = float((rect or {}).get("height") or 0)
                    except Exception:
                        w = h = 0
                    if 180 <= w <= 560 and 36 <= h <= 120:
                        iframe = fr
                        actions.append(f"iframe-via-size:{int(w)}x{int(h)}")
                        break
            except Exception as exc:
                actions.append(f"iframe-scan-fail:{exc}")

        if not iframe and not challenge_input:
            return {"ok": False, "actions": actions or ["no-cf-input"]}

        # 参考项目：伪造 screenX/screenY
        if iframe is not None:
            try:
                iframe.run_js(
                    """
window.dtp = 1;
function getRandomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
let sx = getRandomInt(800, 1200);
let sy = getRandomInt(400, 700);
try {
  Object.defineProperty(MouseEvent.prototype, 'screenX', { get: function(){ return sx; } });
  Object.defineProperty(MouseEvent.prototype, 'screenY', { get: function(){ return sy; } });
} catch (e) {}
                    """
                )
                actions.append("patched-mouse-screen")
            except Exception as exc:
                actions.append(f"patch-mouse-fail:{exc}")

        clicked = False
        # 1) iframe body shadow_root 内 checkbox（本地桌面最有效）
        if iframe is not None:
            try:
                body = iframe.ele("tag:body", timeout=0.8)
                body_sr = getattr(body, "shadow_root", None) if body else None
                if body_sr:
                    for sel in (
                        "tag:input",
                        "css:input[type=checkbox]",
                        "css:input",
                        "css:.cb-lb",
                        "css:label",
                        "css:[role=checkbox]",
                    ):
                        try:
                            btn = body_sr.ele(sel, timeout=0.25)
                        except Exception:
                            btn = None
                        if btn:
                            actions.append(f"btn:{sel}")
                            break
                if btn is not None:
                    if _safe_element_click(btn, actions, "shadow-input"):
                        clicked = True
            except Exception as exc:
                actions.append(f"shadow-click-fail:{exc}")

        # 2) 主文档坐标系下定位 widget 后 CDP 点左侧
        # 关键：禁止使用 iframe 内相对坐标（Docker 曾误点 25,32 把页面点飞）
        located = _locate_turnstile_box_on_page(page)
        if isinstance(located, dict) and located.get("box"):
            actions.append(f"page-box:{located.get('via')}:{located.get('box')}")
            if _cdp_click_page_box_left(page, located["box"], actions, "page-widget"):
                clicked = True
        else:
            actions.append(f"page-box-miss:{located}")

        # 3) 仅当元素 rect 是页面绝对坐标时，才对 host 再点
        if challenge_input is not None:
            try:
                host = challenge_input.parent()
            except Exception:
                host = challenge_input
            if _cdp_click_element_left(page, host, actions, "host"):
                clicked = True

        # 4) 不要对 ChromiumFrame 调 .click()；坐标不可信时跳过
        # 5) 全局 CDP frame-owner 兜底（about:blank）
        if not clicked:
            try:
                cdp_info = _click_turnstile_challenge_if_visible(page)
                actions.append(
                    "cdp-global:"
                    + json.dumps(cdp_info if isinstance(cdp_info, dict) else {"raw": str(cdp_info)}, ensure_ascii=False)[:180]
                )
                if isinstance(cdp_info, dict) and cdp_info.get("nativeClicked"):
                    # 若坐标看起来像左上角误点，视为失败
                    cx = int(cdp_info.get("x") or 0)
                    cy = int(cdp_info.get("y") or 0)
                    if cx < 40 and cy < 40:
                        actions.append(f"cdp-global-rejected-corner:{cx},{cy}")
                    else:
                        clicked = True
            except Exception as exc:
                actions.append(f"cdp-global-fail:{exc}")

        return {"ok": clicked, "actions": actions}
    except Exception as exc:
        return {"ok": False, "actions": actions + [f"fatal:{exc}"]}

def build_profile():
    given_name_pool = [
        "Neo", "Ethan", "Liam", "Noah", "Lucas", "Mason", "Ryan", "Leo",
        "Owen", "Aiden", "Elio", "Aron", "Ivan", "Nolan", "Evan", "Kai",
        "Caleb", "Adam", "Ezra", "Miles", "Logan", "Carter", "Hunter", "Jason",
        "Brian", "Dylan", "Alex", "Colin", "Blake", "Gavin", "Henry", "Julian",
        "Kevin", "Louis", "Marcus", "Nathan", "Oscar", "Peter", "Quinn", "Robin",
        "Simon", "Tristan", "Victor", "Wesley", "Xavier", "Yuri", "Zane", "Felix",
        "Aaron", "Damian",
    ]
    family_name_pool = [
        "Lin", "Wang", "Zhao", "Liu", "Chen", "Zhang", "Xu", "Sun",
        "Guo", "He", "Yang", "Wu", "Zhou", "Tang", "Qin", "Shi",
        "Fang", "Peng", "Cao", "Deng", "Fan", "Fu", "Gao", "Han",
        "Hu", "Jiang", "Kong", "Lu", "Ma", "Nie", "Pan", "Qiao",
        "Ren", "Shao", "Tian", "Xie", "Yan", "Yao", "Yu", "Zeng",
        "Bai", "Duan", "Hou", "Jin", "Kang", "Luo", "Mao", "Song",
        "Wei", "Xiong",
    ]
    given_name = random.choice(given_name_pool)
    family_name = random.choice(family_name_pool)
    password = "N" + secrets.token_hex(4) + "!a7#" + secrets.token_urlsafe(6)
    return given_name, family_name, password


def fill_profile_and_submit(timeout=120, log_callback=None, cancel_callback=None):
    page = _get_page()
    profile_fn = _resolve("build_profile", build_profile)
    if getattr(profile_fn, "__module__", "") == __name__ and _facade() is not None:
        # if facade re-exports us, use local; tests monkeypatch fac.build_profile to lambda
        fac = _facade()
        patched = getattr(fac, "build_profile", None)
        if callable(patched) and getattr(patched, "__module__", "") != __name__:
            profile_fn = patched
    given_name, family_name, password = profile_fn()
    patch_api = bool(config.get("turnstile_patch_api"))
    force_execute = bool(config.get("turnstile_force_execute"))
    try:
        wait_limit = float(config.get("turnstile_wait_seconds", 120) or 120)
    except Exception:
        wait_limit = 120.0
    wait_limit = max(45.0, min(wait_limit, 300.0))
    # 默认不补丁 turnstile API。手动浏览器能过时，API hook 往往是负优化。
    if patch_api:
        install_turnstile_page_hook(page, log_callback=log_callback)
        if log_callback:
            log_callback("[Debug] 已按配置安装 turnstile API pageHook")
    else:
        install_light_stealth_script(page, log_callback=log_callback)
    # 预热 Turnstile：完全交给 Cloudflare 被动评分，不要一上来 execute。
    if log_callback:
        log_callback(
            f"[*] 预热 Turnstile（被动评分，API补丁={'开' if patch_api else '关'}，"
            f"强制execute={'开' if force_execute else '关'}，最长等待 {wait_limit:.0f}s）..."
        )
    humanize_page_activity(page, log_callback=log_callback, cancel_callback=cancel_callback)
    sleep_with_cancel(5, cancel_callback)
    # 预热后先采集一次 Turnstile 结构，便于判断是 IP 信誉还是自动化指纹问题
    if log_callback:
        try:
            warm_diag = page.run_js(build_profile_submit_script("diagnose"))
            warm_obj = json.loads(warm_diag) if isinstance(warm_diag, str) else warm_diag
            token_now = read_turnstile_token_len(page)
            log_callback(
                f"[Debug] 预热后 Turnstile 状态: {json.dumps(warm_obj.get('turnstile', {}), ensure_ascii=False)} "
                f"tokenLen={token_now}"
            )
        except Exception as warm_exc:
            log_callback(f"[Debug] 预热诊断失败: {warm_exc}")
    deadline = time.time() + max(timeout, wait_limit + 30)
    form_filled_once = False
    wait_cf_since = None
    last_cf_retry_at = 0.0
    last_humanize_at = 0.0
    cf_wait_log_state = {}
    error_page_retries = 0
    max_error_page_retries = 4
    last_error_page_retry_at = 0.0
    entry_page_retries = 0
    max_entry_page_retries = 2
    last_entry_page_retry_at = 0.0

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        now = time.time()
        if now - last_error_page_retry_at >= 2.0:
            try:
                error_state = page.run_js(build_profile_submit_script("retry_error"))
            except Exception as error_retry_exc:
                error_state = f"profile-error-check-failed:{error_retry_exc}"

            if isinstance(error_state, dict) and str(error_state.get("state") or "") in {
                "profile-error-retry-target",
                "profile-error-page-no-retry",
            }:
                if error_state.get("state") == "profile-error-retry-target":
                    error_page_retries += 1
                    if error_page_retries > max_error_page_retries:
                        raise Exception(
                            f"xAI 最终注册页连续返回错误页，已重试 {max_error_page_retries} 次仍未恢复"
                        )
                    if error_state.get("centerX") is not None and error_state.get("centerY") is not None:
                        try:
                            _dispatch_cdp_click(
                                page,
                                int(error_state.get("centerX")),
                                int(error_state.get("centerY")),
                                include_keyboard=False,
                            )
                            error_state["nativeClicked"] = True
                        except Exception as native_exc:
                            error_state["nativeClickError"] = str(native_exc)[:160]
                    if log_callback:
                        log_callback(
                            f"[*] 最终注册页错误页，点击 Retry 重试 ({error_page_retries}/{max_error_page_retries})"
                        )
                        log_callback(f"[Debug] 最终注册页错误页状态: {json.dumps(error_state, ensure_ascii=False)}")
                    last_error_page_retry_at = now
                    sleep_with_cancel(2, cancel_callback)
                    try:
                        refresh_active_page()
                        page = _get_page()
                    except Exception:
                        pass
                    continue
                if error_state.get("state") == "profile-error-page-no-retry":
                    raise Exception(f"xAI 最终注册页错误页且未找到 Retry 按钮: {error_state.get('bodySnippet', '')}")

        now = time.time()
        if now - last_entry_page_retry_at >= 2.0:
            try:
                entry_state = page.run_js(build_profile_submit_script("recover_entry"))
            except Exception as entry_retry_exc:
                entry_state = f"profile-entry-check-failed:{entry_retry_exc}"

            if isinstance(entry_state, dict) and str(entry_state.get("state") or "") in {
                "profile-entry-email-target",
                "profile-entry-page-no-email",
            }:
                if entry_state.get("state") == "profile-entry-email-target":
                    entry_page_retries += 1
                    if entry_page_retries > max_entry_page_retries:
                        raise ProfileSessionLost(
                            f"xAI 最终注册页反复退回注册入口，已尝试恢复 {max_entry_page_retries} 次仍未进入资料页"
                        )
                    if entry_state.get("centerX") is not None and entry_state.get("centerY") is not None:
                        try:
                            _dispatch_cdp_click(
                                page,
                                int(entry_state.get("centerX")),
                                int(entry_state.get("centerY")),
                                include_keyboard=False,
                            )
                            entry_state["nativeClicked"] = True
                        except Exception as native_exc:
                            entry_state["nativeClickError"] = str(native_exc)[:160]
                    if log_callback:
                        log_callback(
                            f"[*] 最终注册页退回注册入口，点击邮箱注册恢复 ({entry_page_retries}/{max_entry_page_retries})"
                        )
                        log_callback(f"[Debug] 最终注册页入口恢复状态: {json.dumps(entry_state, ensure_ascii=False)}")
                    last_entry_page_retry_at = now
                    sleep_with_cancel(2, cancel_callback)
                    try:
                        refresh_active_page()
                        page = _get_page()
                    except Exception:
                        pass
                    continue
                if entry_state.get("state") == "profile-entry-page-no-email":
                    raise ProfileSessionLost(f"xAI 最终注册页退回注册入口且未找到邮箱注册按钮: {entry_state.get('bodySnippet', '')}")

        # 资料已填过，且表单已从页面消失 => 提交已被隐形 Turnstile 驱动成功，页面已推进
        if form_filled_once:
            try:
                progressed = page.run_js(
                    """
try {
  const pwd = document.querySelector('input[name="password"], input[type="password"]');
  const given = document.querySelector('input[name="givenName"], input[autocomplete="given-name"]');
  return (!pwd && !given) ? 'gone' : 'present';
} catch (e) { return 'present'; }
                    """
                )
            except Exception:
                progressed = "present"
            if progressed == "gone":
                if log_callback:
                    log_callback(f"[*] 注册资料已提交，页面已跳转: {given_name} {family_name}")
                return {"given_name": given_name, "family_name": family_name, "password": password}
        if not form_filled_once:
            filled = page.run_js(
                """
const givenName = arguments[0];
const familyName = arguments[1];
const password = arguments[2];

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function pickInput(selector) {
    return Array.from(document.querySelectorAll(selector)).find((node) => {
        return isVisible(node) && !node.disabled && !node.readOnly;
    }) || null;
}

function setInputValue(input, value) {
    if (!input) return false;
    input.focus();
    input.click();
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.blur();
    return String(input.value || '').trim() === String(value || '').trim();
}

const givenInput = pickInput('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"], input[aria-label*="名"]');
const familyInput = pickInput('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"], input[aria-label*="姓"]');
const passwordInput = pickInput('input[data-testid="password"], input[name="password"], input[type="password"], input[autocomplete="new-password"]');

if (!givenInput || !familyInput || !passwordInput) {
    const emailInput = pickInput('input[type="email"], input[name="email"], input[autocomplete="email"]');
    if (emailInput) return 'email-step';
    return 'not-ready';
}

const ok1 = setInputValue(givenInput, givenName);
const ok2 = setInputValue(familyInput, familyName);
const ok3 = setInputValue(passwordInput, password);

if (!ok1 || !ok2 || !ok3) return 'fill-failed';

// 必须等待 Cloudflare 校验通过后再提交
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

return 'profile-filled';
            """,
                given_name,
                family_name,
                password,
            )

            if isinstance(filled, str) and filled.startswith("wait-cloudflare"):
                form_filled_once = True
                token_len = str(read_turnstile_token_len(page) or (filled.split(":", 1)[1] if ":" in filled else "0"))
                if log_callback and should_log_cloudflare_wait(cf_wait_log_state, "profile-fill", token_len):
                    log_callback(f"[*] 资料已填写，等待 Cloudflare 人机验证通过... 当前token长度={token_len}")
                now = time.time()
                if wait_cf_since is None:
                    wait_cf_since = now
                if int(float(token_len or 0)) >= 80:
                    # token 已到，下一轮走提交
                    sleep_with_cancel(0.3, cancel_callback)
                    continue
                if now - wait_cf_since >= wait_limit and str(token_len) in {"0", ""}:
                    raise Exception(
                        f"Cloudflare Turnstile {wait_limit:.0f}s 内未签发 token（token长度=0）。"
                        "已尝试本地 Solver（若开启）与 shadow_root 点选；"
                        "请确认 turnstile-solver 已启动（默认 http://127.0.0.1:5072）或检查代理/出口 IP"
                    )
                # 参考 grok-auto-register：token 为空时短暂停顿 + shadow DOM 点选复用
                if str(token_len) in {"0", ""}:
                    pause_seconds = random.uniform(1.0, 2.5)
                    if log_callback and should_log_cloudflare_wait(cf_wait_log_state, "profile-pause", "0"):
                        log_callback(f"[*] Cloudflare token 为空，暂停 {pause_seconds:.1f}s 后 shadow 点选")
                    sleep_with_cancel(pause_seconds, cancel_callback)
                if now - last_humanize_at >= 5:
                    humanize_page_activity(page, log_callback=None, cancel_callback=cancel_callback)
                    last_humanize_at = now
                if now - last_cf_retry_at >= 2.0:
                    try:
                        # 关键：用参考项目同款 shadow_root 点击，而不是无效的主文档 CDP 搜索
                        token = getTurnstileToken(
                            log_callback=log_callback,
                            cancel_callback=cancel_callback,
                            attempts=4,
                        )
                        if token:
                            synced = page.run_js(
                                """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return 0;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                                """,
                                token,
                            )
                            if log_callback:
                                log_callback(f"[*] Turnstile 复用完成，回填长度={synced}")
                    except Exception as cf_exc:
                        if log_callback:
                            log_callback(f"[Debug] Turnstile shadow 复用未完成: {cf_exc}")
                    if force_execute:
                        try:
                            trig = page.run_js(build_profile_submit_script("trigger"))
                            if log_callback:
                                log_callback(f"[Debug] Turnstile 主动触发结果: {trig}")
                        except Exception as cf_exc:
                            if log_callback:
                                log_callback(f"[Debug] Turnstile 主动触发失败: {cf_exc}")
                    last_cf_retry_at = now
                sleep_with_cancel(0.8, cancel_callback)
                continue

            if filled in ("profile-filled", "ready-to-submit", "filled-no-submit"):
                form_filled_once = True
            elif filled == "fill-failed" and log_callback:
                log_callback("[Debug] 资料输入失败，重试中...")
                sleep_with_cancel(0.5, cancel_callback)
                continue
            elif filled == "not-ready":
                sleep_with_cancel(0.5, cancel_callback)
                continue
            elif filled == "email-step":
                raise ProfileSessionLost("xAI 最终注册页退回邮箱输入页，验证码会话已失效")

        submit_state = page.run_js(build_profile_submit_script("submit"))

        if isinstance(submit_state, str) and submit_state.startswith("wait-cloudflare"):
            token_len = str(read_turnstile_token_len(page) or (submit_state.split(":", 1)[1] if ":" in submit_state else "0"))
            if log_callback and should_log_cloudflare_wait(cf_wait_log_state, "profile-submit", token_len):
                log_callback(f"[*] 等待 Cloudflare 人机验证通过后再提交... 当前token长度={token_len}")
            now = time.time()
            if wait_cf_since is None:
                wait_cf_since = now
            if int(float(token_len or 0)) >= 80:
                sleep_with_cancel(0.3, cancel_callback)
                continue
            if now - wait_cf_since >= wait_limit and str(token_len) in {"0", ""}:
                raise Exception(
                    f"Cloudflare Turnstile {wait_limit:.0f}s 内未签发 token（token长度=0）。"
                    "已尝试本地 Solver（若开启）与 shadow_root 点选"
                )
            if now - last_humanize_at >= 5:
                humanize_page_activity(page, log_callback=None, cancel_callback=cancel_callback)
                last_humanize_at = now
            if now - last_cf_retry_at >= 2.0:
                try:
                    token = getTurnstileToken(
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                        attempts=4,
                    )
                    if token:
                        synced = page.run_js(
                            """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return 0;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
                            """,
                            token,
                        )
                        if log_callback:
                            log_callback(f"[*] 提交前 Turnstile 复用完成，回填长度={synced}")
                except Exception as click_exc:
                    if log_callback:
                        log_callback(f"[Debug] 提交前 Turnstile shadow 复用未完成: {click_exc}")
                if force_execute:
                    try:
                        trig = page.run_js(build_profile_submit_script("trigger"))
                        if log_callback:
                            log_callback(f"[Debug] Turnstile 主动触发结果: {trig}")
                    except Exception as cf_exc:
                        if log_callback:
                            log_callback(f"[Debug] Turnstile 主动触发失败: {cf_exc}")
                last_cf_retry_at = now
            sleep_with_cancel(0.8, cancel_callback)
            continue

        if submit_state == "submitted":
            if log_callback:
                log_callback(f"[*] 已填写注册资料并提交: {given_name} {family_name}")
            return {"given_name": given_name, "family_name": family_name, "password": password}
        if submit_state == "submitted-no-challenge":
            # 兼容旧脚本返回值：无 CF 痕迹才允许；有空 token 时继续等。
            if log_callback:
                log_callback("[Debug] 收到 submitted-no-challenge，复查 Cloudflare 状态...")
            try:
                recheck = page.run_js(build_profile_submit_script("check"))
            except Exception:
                recheck = "unknown"
            if isinstance(recheck, str) and recheck.startswith("wait-cloudflare"):
                sleep_with_cancel(0.8, cancel_callback)
                continue
            if log_callback:
                log_callback(f"[*] 已填写注册资料并提交: {given_name} {family_name}")
            return {"given_name": given_name, "family_name": family_name, "password": password}
        if submit_state == "wait-password-validation":
            if log_callback and should_log_cloudflare_wait(cf_wait_log_state, "password-validation", "0"):
                log_callback("[*] 等待 xAI 密码校验完成后再提交...")
            sleep_with_cancel(0.8, cancel_callback)
            continue
        wait_cf_since = None
        if submit_state == "no-submit-button" and log_callback:
            log_callback("[Debug] 未找到提交按钮，继续等待页面稳定...")

        sleep_with_cancel(0.5, cancel_callback)

    if log_callback:
        try:
            diag = page.run_js(build_profile_submit_script("diagnose"))
        except Exception as diag_exc:
            diag = f"诊断失败: {diag_exc}"
        log_callback(f"[Debug] 最终注册页诊断: {diag}")
    raise Exception("最终注册页资料填写失败")


def wait_for_sso_cookie(timeout=120, log_callback=None, cancel_callback=None):
    deadline = time.time() + timeout
    last_seen_names = set()
    last_submit_retry = 0.0
    last_cf_retry_at = 0.0
    last_final_retry_state = ""
    wait_cf_zero_since = None

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            refresh_active_page()
            page = _get_page()
            if page is None:
                sleep_with_cancel(1, cancel_callback)
                continue

            # 仍停留在最终注册页时，若 Cloudflare 已通过，周期性重试点击提交。
            # xAI 页面会按区域显示中文或英文，不能只用中文标题判断。
            now = time.time()
            if now - last_submit_retry >= 2.5:
                retried = page.run_js(
                    r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function compactText(node) {
    return String(node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '')
        .replace(/\s+/g, '')
        .toLowerCase();
}
const titleHit = !!Array.from(document.querySelectorAll('h1,h2,div,span')).find((el) => {
    const t = compactText(el);
    return t.includes('完成注册') || t.includes('completeyoursignup') || t.includes('completesignup') || t.includes('createyourgrokaccount');
});
const formHit = !!document.querySelector('input[name="givenName"], input[autocomplete="given-name"]')
    && !!document.querySelector('input[name="password"], input[type="password"]');
const urlHit = location.href.includes('/sign-up');
if (!titleHit && !(formHit && urlHit)) return 'not-final-page:' + compactText(document.body).slice(0, 80);

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
const rawHook = window.__grokTurnstile || {};
const capturedWidgets = Array.isArray(rawHook.widgets) ? rawHook.widgets : [];
const executedWidgetIds = Array.isArray(rawHook.executedWidgetIds) ? rawHook.executedWidgetIds : [];
if (!Array.isArray(rawHook.executedWidgetIds)) rawHook.executedWidgetIds = executedWidgetIds;
const executedWidgets = [];
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solved = token.length >= 80;
    // managed/flexible 模式经常没有可见 iframe，只要 token 未签发就必须等待，禁止空 token 提交。
    if (!solved) {
        try {
            if (window.turnstile && typeof window.turnstile.execute === 'function') {
                // token 仍为空时允许重复 execute，避免“只执行一次后永久卡住”。
                if (token.length === 0 && executedWidgetIds.length > 8) {
                    rawHook.executedWidgetIds = [];
                    executedWidgetIds.length = 0;
                }
                for (const widget of capturedWidgets) {
                    const id = widget && widget.id;
                    const idText = String(id || '');
                    if (!idText) continue;
                    if (token.length > 0 && executedWidgetIds.includes(idText)) continue;
                    try {
                        window.turnstile.execute(id);
                        if (!executedWidgetIds.includes(idText)) executedWidgetIds.push(idText);
                        executedWidgets.push(idText);
                    } catch (e) {}
                }
                if (!executedWidgets.length) {
                    try { window.turnstile.execute(); executedWidgets.push('anonymous'); } catch (e) {}
                }
            }
        } catch (e) {}
        return {
            state: 'final-page-wait-cf',
            tokenLen: token.length,
            executedWidgets,
            captured: {
                executeCount: rawHook.executeCount || 0,
                callbackCount: rawHook.callbackCount || 0,
                executedWidgetIds: executedWidgetIds.slice(-5),
                errors: Array.isArray(rawHook.errors) ? rawHook.errors.slice(-5) : [],
            },
        };
    }
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = compactText(node);
    return t.includes('完成注册') || t.includes('创建账户') || t.includes('completesignup') || t.includes('signup') || t.includes('createaccount');
});
if (!submitBtn) return 'final-page-no-submit';
submitBtn.focus();
const rect = submitBtn.getBoundingClientRect();
try { submitBtn.click(); } catch (e) {}
return {
    state: 'final-page-submit-target',
    centerX: Math.round(rect.left + rect.width / 2),
    centerY: Math.round(rect.top + rect.height / 2),
    text: compactText(submitBtn).slice(0, 80),
    tokenLen: String((cfInput && cfInput.value) || '').trim().length,
    captured: (() => {
        try {
            const raw = window.__grokTurnstile || {};
            return {
                hookInstalled: !!window.__grokTurnstileHookInstalled,
                renderCount: raw.renderCount || 0,
                executeCount: raw.executeCount || 0,
                callbackCount: raw.callbackCount || 0,
                lastTokenLen: String(raw.lastToken || '').trim().length,
                executedWidgets,
                widgets: Array.isArray(raw.widgets) ? raw.widgets.slice(-5) : [],
                errors: Array.isArray(raw.errors) ? raw.errors.slice(-5) : [],
            };
        } catch (e) {
            return { error: String(e && e.message || e).slice(0, 160), executedWidgets };
        }
    })(),
};
                    """
                )
                last_submit_retry = now
                token_len_now = None
                if isinstance(retried, str):
                    last_final_retry_state = retried
                    if retried.startswith("final-page-wait-cf"):
                        token_len_now = retried.split(":", 1)[1] if ":" in retried else "0"
                if isinstance(retried, dict):
                    last_final_retry_state = str(retried.get("state") or "final-page-dict")
                    if last_final_retry_state == "final-page-wait-cf":
                        token_len_now = str(retried.get("tokenLen", "0"))
                        if retried.get("executedWidgets"):
                            try:
                                retried["challengeClick"] = _click_turnstile_challenge_if_visible(page)
                            except Exception as challenge_exc:
                                retried["challengeClickError"] = str(challenge_exc)[:160]
                    # 只有 CF 已通过/无 CF 时才原生点击提交，避免空 token 连点。
                    if (
                        last_final_retry_state == "final-page-submit-target"
                        and retried.get("centerX") is not None
                        and retried.get("centerY") is not None
                        and int(retried.get("tokenLen") or 0) >= 80
                    ):
                        try:
                            x = int(retried.get("centerX"))
                            y = int(retried.get("centerY"))
                            _dispatch_cdp_click(page, x, y, include_keyboard=False)
                            retried["nativeClicked"] = True
                            last_final_retry_state = f"{last_final_retry_state}:native-click:{x},{y}"
                        except Exception as native_exc:
                            retried["nativeClickError"] = str(native_exc)[:160]
                            last_final_retry_state = f"{last_final_retry_state}:native-failed"
                    if log_callback:
                        log_callback(f"[Debug] 最终页状态: {json.dumps(retried, ensure_ascii=False)}")
                if token_len_now is not None:
                    if str(token_len_now) in {"0", ""}:
                        if wait_cf_zero_since is None:
                            wait_cf_zero_since = now
                        elif now - wait_cf_zero_since >= 45:
                            raise Exception(
                                "最终页 Cloudflare Turnstile 45s 内未签发 token（token长度=0）。"
                                "常见原因是代理/出口 IP 信誉差或被 Cloudflare 静默拒绝，请更换代理后重试"
                            )
                    else:
                        wait_cf_zero_since = None
                    if log_callback:
                        log_callback(f"[Debug] 最终页状态: final-page-wait-cf, token长度={token_len_now}")
                    if now - last_cf_retry_at >= 10:
                        if log_callback:
                            log_callback("[*] 最终页 Cloudflare 卡住，尝试 Solver/触发 Turnstile（暂不空 token 提交）...")
                        try:
                            # 优先走本地 solver 回填 token（与资料页同一路径）
                            try:
                                final_token = getTurnstileToken(
                                    log_callback=log_callback,
                                    cancel_callback=cancel_callback,
                                    attempts=3,
                                )
                                if final_token:
                                    inject_turnstile_token_to_page(page, final_token)
                            except Exception as solver_final_exc:
                                if log_callback:
                                    log_callback(f"[Debug] 最终页 Solver/点选: {solver_final_exc}")
                            trig = page.run_js(
                                r"""
let executed = false;
try {
    if (window.turnstile && typeof window.turnstile.execute === 'function') {
        try { window.turnstile.execute(); executed = true; } catch (e) {}
    }
} catch (e) {}
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const tokenLen = String((cfInput && cfInput.value) || '').trim().length;
return 'final-trigger:' + (executed ? '1' : '0') + ':token=' + tokenLen;
                                """
                            )
                            if log_callback:
                                log_callback(f"[Debug] 最终页 Turnstile 主动触发结果: {trig}")
                            _click_turnstile_challenge_if_visible(page)
                        except Exception as cf_exc:
                            if log_callback:
                                log_callback(f"[Debug] 最终页 Turnstile 主动触发失败: {cf_exc}")
                        last_cf_retry_at = now
                if log_callback and retried in ("final-page-no-submit", "final-page-clicked-submit"):
                    log_callback(f"[Debug] 最终页状态: {retried}")

            cookies = page.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    value = str(item.get("value", "")).strip()
                else:
                    name = str(getattr(item, "name", "")).strip()
                    value = str(getattr(item, "value", "")).strip()

                if name:
                    last_seen_names.add(name)

                if name == "sso" and value:
                    if log_callback:
                        log_callback("[*] 已获取到 sso cookie")
                    return value
        except PageDisconnectedError:
            refresh_active_page()
        except Exception:
            pass

        sleep_with_cancel(1, cancel_callback)

    raise Exception(
        f"等待超时：未获取到 sso cookie。最后最终页状态: {last_final_retry_state or 'unknown'}。已看到 cookies: {sorted(last_seen_names)}"
    )


