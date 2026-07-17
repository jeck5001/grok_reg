# -*- coding: utf-8 -*-
"""Telegram-only notification hub for grok_reg.

emit() never raises into callers. Delivery is async via daemon threads.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

LEVEL_RANK = {"info": 10, "warn": 20, "danger": 30}

DEFAULT_EVENTS = {
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
}

MIN_LEVEL_BYPASS_EVENTS = {
    "milestone.success_n",
    "job.started",
    "job.completed",
    "solver.recovered",
}

_LOCK = threading.RLock()
_HISTORY: List[Dict[str, Any]] = []
_COOLDOWN: Dict[str, float] = {}
_MILESTONE_SEEN: Dict[str, set] = {}
_EDGE: Dict[str, Any] = {
    "solver_down": None,
    "domain_exhausted": False,
    "domain_half_cool": False,
}
_MAX_HISTORY = 80


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    if v is None:
        return default
    return bool(v)


def _int(v: Any, default: int, lo: int = 0, hi: int = 10**9) -> int:
    try:
        n = int(v)
    except Exception:
        n = default
    return max(lo, min(hi, n))


def _parse_milestones(raw: Any) -> List[int]:
    if raw is None or raw == "":
        return [10, 50, 100, 200, 500]
    if isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        text = str(raw).replace("，", ",").replace(" ", ",")
        items = [x for x in text.split(",") if x.strip()]
    out = []
    seen = set()
    for item in items:
        try:
            n = int(item)
        except Exception:
            continue
        if n > 0 and n not in seen:
            seen.add(n)
            out.append(n)
    return sorted(out) or [10, 50, 100, 200, 500]


def normalize_notify_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    s = dict(settings or {})
    s["notify_enabled"] = _bool(s.get("notify_enabled"), False)
    level = str(s.get("notify_min_level") or "warn").strip().lower()
    if level not in LEVEL_RANK:
        level = "warn"
    s["notify_min_level"] = level
    s["notify_cooldown_sec"] = _int(s.get("notify_cooldown_sec"), 180, 30, 86400)
    s["notify_telegram_bot_token"] = str(s.get("notify_telegram_bot_token") or "").strip()
    s["notify_telegram_chat_id"] = str(s.get("notify_telegram_chat_id") or "").strip()
    s["notify_milestone_success"] = _parse_milestones(s.get("notify_milestone_success"))

    events = dict(DEFAULT_EVENTS)
    raw_events = s.get("notify_events")
    if isinstance(raw_events, dict):
        for key, val in raw_events.items():
            k = str(key or "").strip()
            if k in events:
                events[k] = _bool(val, events[k])
    elif isinstance(raw_events, str) and raw_events.strip():
        try:
            parsed = json.loads(raw_events)
            if isinstance(parsed, dict):
                for key, val in parsed.items():
                    k = str(key or "").strip()
                    if k in events:
                        events[k] = _bool(val, events[k])
        except Exception:
            pass
    s["notify_events"] = events
    return s


def settings_from_config(config: Dict[str, Any]) -> Dict[str, Any]:
    return normalize_notify_settings(config or {})


def telegram_configured(settings: Dict[str, Any]) -> bool:
    s = normalize_notify_settings(settings)
    return bool(s["notify_telegram_bot_token"] and s["notify_telegram_chat_id"])


def _level_ok(level: str, min_level: str) -> bool:
    return LEVEL_RANK.get(level, 10) >= LEVEL_RANK.get(min_level, 20)


def _event_enabled(settings: Dict[str, Any], event_type: str) -> bool:
    events = settings.get("notify_events") or DEFAULT_EVENTS
    if event_type not in events:
        return True
    return bool(events.get(event_type))


def _cooldown_hit(dedupe_key: str, cooldown_sec: int) -> bool:
    if not dedupe_key or cooldown_sec <= 0:
        return False
    now = time.time()
    with _LOCK:
        expired = [k for k, until in _COOLDOWN.items() if until <= now]
        for k in expired:
            _COOLDOWN.pop(k, None)
        until = float(_COOLDOWN.get(dedupe_key) or 0)
        if until > now:
            return True
        _COOLDOWN[dedupe_key] = now + cooldown_sec
    return False


def _push_history(item: Dict[str, Any]) -> None:
    with _LOCK:
        _HISTORY.append(item)
        if len(_HISTORY) > _MAX_HISTORY:
            del _HISTORY[: len(_HISTORY) - _MAX_HISTORY]


def history(limit: int = 30) -> List[Dict[str, Any]]:
    n = max(1, min(100, int(limit or 30)))
    with _LOCK:
        return list(_HISTORY[-n:])


def status(settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    s = normalize_notify_settings(settings or {})
    with _LOCK:
        hist = list(_HISTORY[-10:])
    return {
        "enabled": bool(s.get("notify_enabled")),
        "configured": telegram_configured(s),
        "min_level": s.get("notify_min_level"),
        "cooldown_sec": s.get("notify_cooldown_sec"),
        "milestones": s.get("notify_milestone_success"),
        "events": s.get("notify_events"),
        "chat_id_set": bool(s.get("notify_telegram_chat_id")),
        "token_set": bool(s.get("notify_telegram_bot_token")),
        "recent": hist,
    }


def format_telegram_html(event: Dict[str, Any]) -> str:
    level = str(event.get("level") or "info").upper()
    title = _escape_html(str(event.get("title") or event.get("type") or "通知"))
    body = _escape_html(str(event.get("body") or "")).strip()
    at = _escape_html(str(event.get("at") or ""))
    job_id = str(event.get("job_id") or "").strip()
    lines = [f"<b>[{level}] {title}</b>"]
    if body:
        lines.append(body)
    meta = []
    if job_id:
        meta.append(f"job <code>{_escape_html(job_id[:12])}</code>")
    if at:
        meta.append(at)
    if meta:
        lines.append(" · ".join(meta))
    return "\n".join(lines)


def _escape_html(text: str) -> str:
    return (
        str(text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def send_telegram(
    bot_token: str,
    chat_id: str,
    text: str,
    *,
    timeout: float = 8.0,
) -> Dict[str, Any]:
    token = str(bot_token or "").strip()
    chat = str(chat_id or "").strip()
    if not token or not chat:
        return {"ok": False, "error": "bot_token 或 chat_id 未配置"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode(
        {
            "chat_id": chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw else {}
            ok = bool(data.get("ok"))
            return {
                "ok": ok,
                "latency_ms": int((time.time() - t0) * 1000),
                "error": "" if ok else str(data.get("description") or raw)[:200],
                "response": data if ok else None,
            }
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            detail = str(exc)
        return {
            "ok": False,
            "latency_ms": int((time.time() - t0) * 1000),
            "error": f"HTTP {exc.code}: {detail}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "latency_ms": int((time.time() - t0) * 1000),
            "error": str(exc)[:200],
        }


def _deliver(settings: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    text = format_telegram_html(event)
    result = send_telegram(
        settings.get("notify_telegram_bot_token") or "",
        settings.get("notify_telegram_chat_id") or "",
        text,
    )
    record = {
        "id": event.get("id"),
        "type": event.get("type"),
        "level": event.get("level"),
        "title": event.get("title"),
        "body": event.get("body"),
        "at": event.get("at"),
        "job_id": event.get("job_id"),
        "ok": bool(result.get("ok")),
        "error": result.get("error") or "",
        "latency_ms": result.get("latency_ms"),
        "channel": "telegram",
    }
    _push_history(record)
    return result


def emit(
    event_type: str,
    *,
    title: str,
    body: str = "",
    level: str = "info",
    job_id: str = "",
    dedupe_key: str = "",
    settings: Optional[Dict[str, Any]] = None,
    force: bool = False,
    sync: bool = False,
) -> Dict[str, Any]:
    """Queue a Telegram notification. Never raises."""
    try:
        s = normalize_notify_settings(settings or {})
        if not force and not s.get("notify_enabled"):
            return {"ok": False, "skipped": "disabled"}
        if not force and not _event_enabled(s, event_type):
            return {"ok": False, "skipped": "event_off"}
        lvl = str(level or "info").strip().lower()
        if lvl not in LEVEL_RANK:
            lvl = "info"
        event_name = str(event_type or "custom")
        if (
            not force
            and event_name not in MIN_LEVEL_BYPASS_EVENTS
            and not _level_ok(lvl, str(s.get("notify_min_level") or "warn"))
        ):
            return {"ok": False, "skipped": "level"}
        if not telegram_configured(s):
            return {"ok": False, "skipped": "not_configured"}
        key = dedupe_key or f"{event_type}|{job_id}|{title}"
        if not force and _cooldown_hit(key, int(s.get("notify_cooldown_sec") or 180)):
            return {"ok": False, "skipped": "cooldown"}

        event = {
            "id": uuid.uuid4().hex,
            "type": str(event_type or "custom"),
            "level": lvl,
            "title": str(title or event_type or "通知")[:120],
            "body": str(body or "")[:800],
            "at": _now_iso(),
            "job_id": str(job_id or "")[:64],
            "dedupe_key": key,
        }

        if sync:
            return _deliver(s, event)

        def _run():
            try:
                _deliver(s, event)
            except Exception:
                pass

        threading.Thread(target=_run, name="notify-tg", daemon=True).start()
        return {"ok": True, "queued": True, "id": event["id"]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160]}


def emit_test(settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return emit(
        "notify.test",
        title="测试通知",
        body="Grok Register Telegram 通知通道正常。",
        level="info",
        dedupe_key=f"test|{time.time()}",
        settings=settings,
        force=True,
        sync=True,
    )


def maybe_milestone(job_id: str, success_count: int, settings: Optional[Dict[str, Any]] = None) -> None:
    s = normalize_notify_settings(settings or {})
    # 任务启动时的 settings 可能缺 notify 字段；尽量补全 token/开关
    try:
        import grok_register_ttk as reg

        live = normalize_notify_settings(reg.load_config() or {})
        for key in (
            "notify_enabled",
            "notify_min_level",
            "notify_cooldown_sec",
            "notify_telegram_bot_token",
            "notify_telegram_chat_id",
            "notify_milestone_success",
            "notify_events",
        ):
            if key.startswith("notify_telegram_") and s.get(key):
                continue
            if live.get(key) not in (None, "", [], {}):
                s[key] = live.get(key)
        s = normalize_notify_settings(s)
    except Exception:
        pass

    marks = list(s.get("notify_milestone_success") or [])
    jid = str(job_id or "job")
    count = int(success_count or 0)
    hits: List[int] = []
    with _LOCK:
        seen = _MILESTONE_SEEN.setdefault(jid, set())
        for m in marks:
            if count >= int(m) and int(m) not in seen:
                seen.add(int(m))
                hits.append(int(m))
    for hit in hits:
        emit(
            "milestone.success_n",
            title=f"成功达到 {hit}",
            body=f"任务累计成功 {count} 个账号。",
            level="info",
            job_id=jid,
            dedupe_key=f"milestone|{jid}|{hit}",
            settings=s,
        )


def observe_runtime_edges(
    *,
    solver_reachable: Optional[bool],
    domain_available: Optional[int],
    domain_total: Optional[int],
    domain_cooldown: Optional[int],
    settings: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Edge-triggered domain/solver notifications. Returns fired types."""
    s = normalize_notify_settings(settings or {})
    fired: List[str] = []
    with _LOCK:
        prev_solver = _EDGE.get("solver_down")
        if solver_reachable is not None:
            down = not bool(solver_reachable)
            if prev_solver is None:
                _EDGE["solver_down"] = down
            elif down and not prev_solver:
                _EDGE["solver_down"] = True
                fired.append("solver.down")
            elif (not down) and prev_solver:
                _EDGE["solver_down"] = False
                fired.append("solver.recovered")

        avail = int(domain_available) if domain_available is not None else None
        total = int(domain_total) if domain_total is not None else 0
        cool = int(domain_cooldown) if domain_cooldown is not None else 0
        if avail is not None and total > 0:
            exhausted = avail <= 0
            half = (cool / total) >= 0.5 if total else False
            if exhausted and not _EDGE.get("domain_exhausted"):
                _EDGE["domain_exhausted"] = True
                fired.append("domain.pool_exhausted")
            elif not exhausted:
                _EDGE["domain_exhausted"] = False
            if half and not _EDGE.get("domain_half_cool"):
                _EDGE["domain_half_cool"] = True
                fired.append("domain.half_cooling")
            elif not half:
                _EDGE["domain_half_cool"] = False

    for t in fired:
        if t == "solver.down":
            emit(
                t,
                title="Turnstile Solver 不可达",
                body="健康检查失败，注册可能受阻。",
                level="warn",
                dedupe_key="solver.down",
                settings=s,
            )
        elif t == "solver.recovered":
            emit(
                t,
                title="Turnstile Solver 已恢复",
                body="健康检查恢复正常。",
                level="info",
                dedupe_key="solver.recovered",
                settings=s,
            )
        elif t == "domain.pool_exhausted":
            emit(
                t,
                title="邮件域名池耗尽",
                body="可用主域为 0，请补充域名或重置冷却。",
                level="danger",
                dedupe_key="domain.exhausted",
                settings=s,
            )
        elif t == "domain.half_cooling":
            emit(
                t,
                title="过半域名冷却中",
                body=f"冷却 {cool}/{total}，注意库存。",
                level="warn",
                dedupe_key="domain.half_cool",
                settings=s,
            )
    return fired


def reset_runtime_state() -> None:
    with _LOCK:
        _HISTORY.clear()
        _COOLDOWN.clear()
        _MILESTONE_SEEN.clear()
        _EDGE["solver_down"] = None
        _EDGE["domain_exhausted"] = False
        _EDGE["domain_half_cool"] = False
