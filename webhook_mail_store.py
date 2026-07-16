# -*- coding: utf-8 -*-
"""openai-cpa-email Worker 推送的邮件内存池。

Worker 协议（https://github.com/wenfxl/openai-cpa-email）：
  POST /api/webhook/email
  Header: X-Webhook-Secret: <secret>
  Body: {
    "message_id": "...",
    "to_addr": "user@sub.main.com",
    "raw_content": "<raw email text>"
  }

本模块只存最近邮件，供注册流程按 to_addr 轮询验证码。
"""

from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict, defaultdict
from typing import Any, Dict, List, Optional, Tuple


_LOCK = threading.RLock()
_MAILS: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
_SEEN_IDS: "OrderedDict[str, bool]" = OrderedDict()
_MAX_IDS = 20000
_MAX_MAILS_PER_ADDR = 30
_MAX_AGE_SEC = 30 * 60


def _norm_email(addr: str) -> str:
    text = str(addr or "").strip().lower()
    # 可能带 <> 或显示名
    m = re.search(r"([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})", text, re.I)
    return (m.group(1) if m else text).strip().lower()


def _remember_id(msg_id: str) -> bool:
    """True if first time."""
    mid = str(msg_id or "").strip()
    if not mid:
        return True
    if mid in _SEEN_IDS:
        return False
    _SEEN_IDS[mid] = True
    while len(_SEEN_IDS) > _MAX_IDS:
        _SEEN_IDS.popitem(last=False)
    return True


def _prune(now: Optional[float] = None) -> None:
    now = now if now is not None else time.time()
    dead = []
    for addr, items in _MAILS.items():
        kept = [m for m in items if now - float(m.get("ts") or 0) < _MAX_AGE_SEC]
        if kept:
            _MAILS[addr] = kept[-_MAX_MAILS_PER_ADDR:]
        else:
            dead.append(addr)
    for addr in dead:
        _MAILS.pop(addr, None)


def store_webhook_mail(
    *,
    to_addr: str,
    raw_content: str,
    message_id: str = "",
) -> Dict[str, Any]:
    to_n = _norm_email(to_addr)
    raw = str(raw_content or "")
    if not to_n:
        return {"ok": False, "error": "missing to_addr"}
    if not raw:
        return {"ok": False, "error": "missing raw_content"}
    with _LOCK:
        _prune()
        if not _remember_id(message_id or f"{to_n}:{hash(raw) & 0xFFFFFFFF}"):
            return {"ok": True, "dedup": True, "to": to_n}
        item = {
            "message_id": str(message_id or ""),
            "to": to_n,
            "raw": raw,
            "ts": time.time(),
        }
        bucket = _MAILS[to_n]
        bucket.append(item)
        if len(bucket) > _MAX_MAILS_PER_ADDR:
            del bucket[: len(bucket) - _MAX_MAILS_PER_ADDR]
        return {"ok": True, "dedup": False, "to": to_n, "count": len(bucket)}


def list_mails(to_addr: str) -> List[Dict[str, Any]]:
    to_n = _norm_email(to_addr)
    with _LOCK:
        _prune()
        return list(_MAILS.get(to_n) or [])


def pop_code_for_email(
    email: str,
    *,
    extract_fn=None,
    ignore_code: str = "",
) -> Optional[str]:
    """从该地址最新邮件里提取验证码；成功则移除该邮件。"""
    to_n = _norm_email(email)
    ignore = str(ignore_code or "").strip().upper().replace("-", "").replace(" ", "")
    with _LOCK:
        _prune()
        items = _MAILS.get(to_n) or []
        if not items:
            return None
        # 从新到旧
        for idx in range(len(items) - 1, -1, -1):
            raw = str(items[idx].get("raw") or "")
            code = ""
            if extract_fn:
                try:
                    code = extract_fn(raw) or ""
                except Exception:
                    code = ""
            if not code:
                code = extract_xai_code_from_raw(raw)
            clean = str(code or "").strip().upper().replace("-", "").replace(" ", "")
            if not clean:
                continue
            if ignore and clean == ignore:
                continue
            # 移除已消费邮件
            items.pop(idx)
            if not items:
                _MAILS.pop(to_n, None)
            return code
        return None


def extract_xai_code_from_raw(raw: str) -> str:
    """从原始邮件提取 xAI / 通用验证码。"""
    text = str(raw or "")
    if not text:
        return ""
    # 去 HTML
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"\s+", " ", text)

    patterns = [
        r"(?:confirmation|verification|security)\s*code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})",
        r"(?:confirmation|verification|security)\s*code[:\s]+([A-Z0-9]{6})",
        r"(?:验证码|确认码)[：:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})",
        r"(?:验证码|确认码)[：:\s]+([A-Z0-9]{6})",
        r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b",
        r"(?<![A-Z0-9])([A-Z0-9]{6})(?![A-Z0-9])",
        r"(?<!\d)(\d{6})(?!\d)",
    ]
    for pat in patterns:
        m = re.search(pat, text, flags=re.I)
        if m:
            return m.group(1).strip()
    return ""


def stats() -> Dict[str, Any]:
    with _LOCK:
        _prune()
        return {
            "addresses": len(_MAILS),
            "mails": sum(len(v) for v in _MAILS.values()),
            "seen_ids": len(_SEEN_IDS),
        }


def clear() -> None:
    with _LOCK:
        _MAILS.clear()
        _SEEN_IDS.clear()
