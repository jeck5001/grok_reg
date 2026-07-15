# -*- coding: utf-8 -*-
"""邮件域名池：多级子域 + 失败冷却 + 黄金矿工（单域爆发）+ 低失败优先。

对齐 openai-cpa 内存池思路，精简版接入 grok_reg：
- enable_sub_domains: 在主域前随机嵌套子域，降低 CF 按「主域+地址」的日配额触发
- mail_domain_pinpoint_burst: 黄金矿工，尽量打满当前最优主域再换
- mail_domain_prefer_low_failure: 优先失败少的主域
- fail_threshold + cooldown: 连续失败后冷却主域
"""

from __future__ import annotations

import random
import string
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set


_LOCK = threading.Lock()
_STATE: Dict[str, Dict[str, Any]] = {}
_SESSION = {
    "cursor": 0,
    "pinpoint_domain": "",
    "pinpoint_picks": 0,
}


def _norm_domain(domain: str) -> str:
    text = str(domain or "").strip().lower().strip(".")
    if not text:
        return ""
    if "@" in text:
        text = text.rsplit("@", 1)[-1].strip().strip(".")
    return text


def parse_domain_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        items = [p for p in str(raw).replace("，", ",").replace(" ", ",").split(",") if p.strip()]
    seen = set()
    out = []
    for item in items:
        d = _norm_domain(item)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _state_of(domain: str) -> Dict[str, Any]:
    d = _norm_domain(domain)
    st = _STATE.setdefault(
        d,
        {
            "fail_count": 0,
            "success_count": 0,
            "pick_count": 0,
            "cooldown_until": 0.0,
            "last_failure_reason": "",
            "last_used_at": 0.0,
        },
    )
    return st


def _prune_cooldown(now: Optional[float] = None) -> None:
    now = now if now is not None else time.time()
    expired = [d for d, st in _STATE.items() if float(st.get("cooldown_until") or 0) and float(st["cooldown_until"]) <= now]
    for d in expired:
        st = _STATE.get(d) or {}
        st["cooldown_until"] = 0.0
        st["fail_count"] = 0


def is_domain_cooling(domain: str, now: Optional[float] = None) -> bool:
    now = now if now is not None else time.time()
    d = _norm_domain(domain)
    if not d:
        return False
    with _LOCK:
        st = _state_of(d)
        until = float(st.get("cooldown_until") or 0)
        return until > now


def available_main_domains(
    main_domains: Sequence[str],
    *,
    rejected: Optional[Set[str]] = None,
    now: Optional[float] = None,
) -> List[str]:
    now = now if now is not None else time.time()
    rejected = rejected or set()
    out = []
    with _LOCK:
        _prune_cooldown(now)
        for d in main_domains:
            nd = _norm_domain(d)
            if not nd:
                continue
            if nd in rejected or any(nd.endswith("." + r) for r in rejected if r):
                continue
            st = _state_of(nd)
            if float(st.get("cooldown_until") or 0) > now:
                continue
            out.append(nd)
    return out


def _pick_low_failure(candidates: List[str]) -> str:
    best = None
    best_key = None
    for d in candidates:
        st = _state_of(d)
        key = (int(st.get("fail_count") or 0), int(st.get("pick_count") or 0), float(st.get("last_used_at") or 0))
        if best_key is None or key < best_key:
            best_key = key
            best = d
    return best or candidates[0]


def pick_main_domain(
    main_domains: Sequence[str],
    *,
    rejected: Optional[Set[str]] = None,
    pinpoint_burst: bool = False,
    prefer_low_failure: bool = False,
    now: Optional[float] = None,
) -> str:
    """选一个主域。黄金矿工：粘住当前最优主域连续使用。"""
    now = now if now is not None else time.time()
    cands = available_main_domains(main_domains, rejected=rejected, now=now)
    if not cands:
        # 全冷却时退回未拒收列表
        rejected = rejected or set()
        cands = [
            _norm_domain(d)
            for d in main_domains
            if _norm_domain(d)
            and _norm_domain(d) not in rejected
            and not any(_norm_domain(d).endswith("." + r) for r in rejected if r)
        ]
        cands = [c for c in cands if c]
    if not cands:
        raise RuntimeError("没有可用邮件主域（均被拒收或冷却）")

    with _LOCK:
        _prune_cooldown(now)
        selected = ""
        if pinpoint_burst:
            pin = _norm_domain(_SESSION.get("pinpoint_domain") or "")
            if pin and pin in cands:
                selected = pin
            else:
                selected = _pick_low_failure(cands) if prefer_low_failure else cands[0]
                _SESSION["pinpoint_domain"] = selected
                _SESSION["pinpoint_picks"] = 0
            _SESSION["pinpoint_picks"] = int(_SESSION.get("pinpoint_picks") or 0) + 1
        elif prefer_low_failure:
            selected = _pick_low_failure(cands)
        else:
            cursor = int(_SESSION.get("cursor") or 0)
            # 按配置顺序 round-robin
            ordered = [_norm_domain(d) for d in main_domains if _norm_domain(d) in set(cands)]
            if not ordered:
                ordered = cands
            selected = ordered[cursor % len(ordered)]
            _SESSION["cursor"] = cursor + 1

        st = _state_of(selected)
        st["pick_count"] = int(st.get("pick_count") or 0) + 1
        st["last_used_at"] = now
        return selected


def mark_domain_success(domain: str) -> None:
    d = _norm_domain(domain)
    if not d:
        return
    with _LOCK:
        st = _state_of(d)
        st["success_count"] = int(st.get("success_count") or 0) + 1
        st["fail_count"] = max(0, int(st.get("fail_count") or 0) - 1)
        st["cooldown_until"] = 0.0
        st["last_failure_reason"] = ""


def mark_domain_failure(
    domain: str,
    *,
    reason: str = "discarded_email",
    threshold: int = 3,
    cooldown_sec: int = 600,
) -> Dict[str, Any]:
    """记录主域失败；达阈值进入冷却。返回状态摘要。"""
    d = _norm_domain(domain)
    if not d:
        return {}
    now = time.time()
    with _LOCK:
        st = _state_of(d)
        st["fail_count"] = int(st.get("fail_count") or 0) + 1
        st["last_failure_reason"] = str(reason or "")
        cooled = False
        if threshold > 0 and st["fail_count"] >= threshold:
            st["cooldown_until"] = now + max(0, int(cooldown_sec or 0))
            st["fail_count"] = 0
            cooled = True
            # 黄金矿工换域
            if _norm_domain(_SESSION.get("pinpoint_domain") or "") == d:
                _SESSION["pinpoint_domain"] = ""
                _SESSION["pinpoint_picks"] = 0
        return {
            "domain": d,
            "fail_count": int(st.get("fail_count") or 0),
            "cooled": cooled,
            "cooldown_until": float(st.get("cooldown_until") or 0),
            "reason": reason,
        }


def build_local_part(length: int = 10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(max(4, int(length or 10))))


def build_subdomain_prefix(
    *,
    level: int = 1,
    random_level: bool = False,
    max_level: int = 4,
) -> str:
    """生成多级子域前缀：a.b.c（不含主域）。"""
    if random_level:
        level = random.randint(1, max(1, min(7, int(max_level or 4))))
    else:
        level = max(1, min(7, int(level or 1)))
    parts = []
    for _ in range(level):
        # 4~8 位随机段，避免过长
        n = random.randint(4, 8)
        parts.append(build_local_part(n))
    return ".".join(parts)


def compose_email_address(
    main_domain: str,
    *,
    enable_sub_domains: bool = False,
    sub_domain_level: int = 1,
    random_sub_domain_level: bool = False,
    local_part: Optional[str] = None,
) -> str:
    """生成最终邮箱地址。子域模式：user@rand.main.com。"""
    main = _norm_domain(main_domain)
    if not main:
        raise ValueError("main_domain empty")
    local = (local_part or build_local_part(10)).strip().lower()
    if enable_sub_domains:
        prefix = build_subdomain_prefix(
            level=sub_domain_level,
            random_level=random_sub_domain_level,
        )
        host = f"{prefix}.{main}"
    else:
        host = main
    return f"{local}@{host}"


def main_domain_of(email_or_domain: str, main_domains: Sequence[str]) -> str:
    """从邮箱/完整域解析回配置中的主域根。"""
    text = _norm_domain(email_or_domain)
    if "@" in str(email_or_domain or ""):
        text = _norm_domain(str(email_or_domain).rsplit("@", 1)[-1])
    roots = [_norm_domain(d) for d in main_domains if _norm_domain(d)]
    for root in roots:
        if text == root or text.endswith("." + root):
            return root
    return text


def snapshot(main_domains: Sequence[str] = ()) -> List[Dict[str, Any]]:
    now = time.time()
    with _LOCK:
        _prune_cooldown(now)
        domains = [_norm_domain(d) for d in (main_domains or list(_STATE.keys())) if _norm_domain(d)]
        out = []
        for d in domains:
            st = _state_of(d)
            out.append(
                {
                    "domain": d,
                    "fail_count": int(st.get("fail_count") or 0),
                    "success_count": int(st.get("success_count") or 0),
                    "pick_count": int(st.get("pick_count") or 0),
                    "cooling": float(st.get("cooldown_until") or 0) > now,
                    "cooldown_left": max(0, int(float(st.get("cooldown_until") or 0) - now)),
                    "last_failure_reason": st.get("last_failure_reason") or "",
                }
            )
        return out


def reset_runtime() -> None:
    with _LOCK:
        _STATE.clear()
        _SESSION["cursor"] = 0
        _SESSION["pinpoint_domain"] = ""
        _SESSION["pinpoint_picks"] = 0
