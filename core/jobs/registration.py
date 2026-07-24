"""Registration job orchestration and on-disk job state."""

from __future__ import annotations

import datetime
import json
import os
import queue
import random
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.cancel import raise_if_cancelled as _raise_if_cancelled_impl
from core.cancel import sleep_with_cancel as _sleep_with_cancel_impl
from core.config import DEFAULT_CONFIG, config, load_config, replace_config, validate_registration_config
from core.exceptions import (
    EmailDomainRejected,
    EmailProviderUnavailable,
    ProfileSessionLost,
    RegistrationCancelled,
)
from core.paths import get_data_dir

try:
    from core.accounts.store import (
        is_account_blocked_error,
        persist_cpa_push_status,
        persist_grok2api_push_status,
        persist_account_created_at,
        _account_id,
        _normalize_sso_token,
        invalidate_account_list_cache,
    )
except Exception:
    pass


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


def sleep_with_cancel(seconds, cancel_callback=None):
    return _resolve("sleep_with_cancel", _sleep_with_cancel_impl)(seconds, cancel_callback)


def raise_if_cancelled(cancel_callback=None):
    return _resolve("raise_if_cancelled", _raise_if_cancelled_impl)(cancel_callback)


def _active_config():
    return _resolve("config", config)


def register_via_pure_http(*a, **k):
    return _resolve("register_via_pure_http", None)(*a, **k)


def register_via_api_after_otp(*a, **k):
    return _resolve("register_via_api_after_otp", None)(*a, **k)


def start_browser(*a, **k):
    return _resolve("start_browser", None)(*a, **k)


def stop_browser(*a, **k):
    fn = _resolve("stop_browser", None)
    return fn(*a, **k) if fn else None


def restart_browser(*a, **k):
    return _resolve("restart_browser", None)(*a, **k)


def open_signup_page(*a, **k):
    return _resolve("open_signup_page", None)(*a, **k)


def fill_email_and_submit(*a, **k):
    return _resolve("fill_email_and_submit", None)(*a, **k)


def fill_code_and_submit(*a, **k):
    return _resolve("fill_code_and_submit", None)(*a, **k)


def fill_profile_and_submit(*a, **k):
    return _resolve("fill_profile_and_submit", None)(*a, **k)


def wait_for_sso_cookie(*a, **k):
    return _resolve("wait_for_sso_cookie", None)(*a, **k)


def auto_push_registered_account(*a, **k):
    return _resolve("auto_push_registered_account", None)(*a, **k)


def enable_nsfw_for_token(*a, **k):
    return _resolve("enable_nsfw_for_token", None)(*a, **k)


def add_token_to_grok2api_pools(*a, **k):
    return _resolve("add_token_to_grok2api_pools", None)(*a, **k)


def resolve_signup_mode(*a, **k):
    return _resolve("resolve_signup_mode", lambda: "browser")(*a, **k)


def get_email_and_token(*a, **k):
    return _resolve("get_email_and_token", None)(*a, **k)


def remember_rejected_email_domain(*a, **k):
    return _resolve("remember_rejected_email_domain", None)(*a, **k)


def note_mail_domain_outcome(*a, **k):
    return _resolve("note_mail_domain_outcome", None)(*a, **k)


def persist_cpa_push_status(*a, **k):
    return _resolve("persist_cpa_push_status", None)(*a, **k)


def persist_grok2api_push_status(*a, **k):
    return _resolve("persist_grok2api_push_status", None)(*a, **k)


def persist_account_created_at(*a, **k):
    return _resolve("persist_account_created_at", None)(*a, **k)


def _account_id(*a, **k):
    return _resolve("_account_id", None)(*a, **k)


def _normalize_sso_token(*a, **k):
    return _resolve("_normalize_sso_token", lambda x: x)(*a, **k)


def is_account_blocked_error(*a, **k):
    return _resolve("is_account_blocked_error", lambda x: False)(*a, **k)


def invalidate_account_list_cache(*a, **k):
    fn = _resolve("invalidate_account_list_cache", None)
    return fn(*a, **k) if fn else None


def fetch_xai_oauth_refresh_token(*a, **k):
    return _resolve("fetch_xai_oauth_refresh_token", None)(*a, **k)


def export_and_push_cpa_credential(*a, **k):
    return _resolve("export_and_push_cpa_credential", None)(*a, **k)


def parse_registered_account_line(*a, **k):
    return _resolve("parse_registered_account_line", None)(*a, **k)


def add_token_to_grok2api_local_pool(*a, **k):
    return _resolve("add_token_to_grok2api_local_pool", None)(*a, **k)


def add_token_to_grok2api_remote_pool(*a, **k):
    return _resolve("add_token_to_grok2api_remote_pool", None)(*a, **k)


def get_email_provider(*a, **k):
    return _resolve("get_email_provider", lambda: "duckmail")(*a, **k)


def build_profile(*a, **k):
    return _resolve("build_profile", lambda: ("A", "B", "pass"))(*a, **k)



def _registered_accounts_lock_proxy():
    return _resolve("_registered_accounts_lock", None)


# thread-safe account file write uses module-level lock from accounts store
from core.accounts.store import _registered_accounts_lock  # noqa: E402


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
        refresh_token = ""
        try:
            refresh_token = (
                fetch_xai_oauth_refresh_token(
                    sso, log_callback=logf, cancel_callback=self.should_stop
                )
                or ""
            )
            refresh_token = str(refresh_token).strip()
        except Exception as rt_exc:
            # 号已建好（有 sso）时：RT 失败不应整单作废。xAI 对新号/部分出口
            # Device Flow + 浏览器 OAuth 都会 Access denied，需后置换 RT。
            logf(f"[!] 获取 Refresh Token 失败，仍保存 SSO 账号: {rt_exc}")
            refresh_token = ""
        if not refresh_token:
            logf("[!] 本账号无 refresh_token（仅 SSO）；CPA/部分推送将跳过")
        cpa_push_item = None
        if self.settings.get("cpa_auto_push_remote") and refresh_token:
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
        elif self.settings.get("cpa_auto_push_remote") and not refresh_token:
            logf("[!] 跳过 CPA 推送：缺少 refresh_token")
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
            # 第四段可为空：仅 SSO 账号；后置批量换 RT 时再补全
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
        if refresh_token:
            logf(f"[+] 注册成功: {email}")
        else:
            logf(f"[+] 注册成功(仅 SSO，待补 Refresh Token): {email}")
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
        provider = str(self.settings.get("email_provider") or _active_config().get("email_provider") or "").strip()
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


