"""File-backed registered account store and status.

Accounts live in ``accounts_*.txt`` under the data dir; side-car state in
``account_status.json``. Public surface is re-exported from ``grok_register_ttk``.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import tempfile
import threading

from core.paths import get_account_status_file, get_data_dir

_registered_accounts_lock = threading.Lock()
_account_status_lock = threading.Lock()

def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def _mask_token(token, head=6, tail=6):
    value = str(token or "").strip()
    if len(value) <= 8:
        return value
    return f"{value[:head]}...{value[-tail:]}"


def _account_id(source, line_no, email, sso):
    seed = f"{source}:{line_no}:{email}:{_normalize_sso_token(sso)}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


_ACCOUNT_FILE_TS_RE = re.compile(
    r"^accounts_(\d{8})_(\d{6})(?:_[^.]+)?\.txt$"
)


def parse_account_file_created_at(source_name, path=None):
    """从 accounts_YYYYMMDD_HHMMSS_*.txt 解析创建时间；失败则用文件 mtime。"""
    name = str(source_name or "").strip()
    match = _ACCOUNT_FILE_TS_RE.match(name)
    if match:
        try:
            dt = datetime.datetime.strptime(
                f"{match.group(1)}{match.group(2)}", "%Y%m%d%H%M%S"
            )
            return dt.isoformat(timespec="seconds")
        except Exception:
            pass
    if path and os.path.isfile(path):
        try:
            return datetime.datetime.fromtimestamp(os.path.getmtime(path)).isoformat(
                timespec="seconds"
            )
        except Exception:
            pass
    return ""


def parse_registered_account_line(
    line, source="", line_no=0, include_sso=True, created_at=""
):
    parts = str(line or "").rstrip("\n").split("----", 3)
    if len(parts) not in {3, 4}:
        return None
    email, password, sso = [part.strip() for part in parts[:3]]
    refresh_token = parts[3].strip() if len(parts) == 4 else ""
    sso = _normalize_sso_token(sso)
    if not email or not sso:
        return None
    account = {
        "id": _account_id(source, line_no, email, sso),
        "email": email,
        "password": password,
        "sso_preview": _mask_token(sso),
        "refresh_token_preview": _mask_token(refresh_token) if refresh_token else "",
        "has_refresh_token": bool(refresh_token),
        "source_file": source,
        "line_no": line_no,
        "created_at": str(created_at or ""),
    }
    if include_sso:
        account["sso"] = sso
        if refresh_token:
            account["refresh_token"] = refresh_token
    return account


# account_status.json / accounts_*.txt 列表缓存（减少作战室与账号页重复全盘扫描）
_account_status_cache = {"path": "", "mtime": None, "data": None, "by_email": None}
_account_list_cache = {
    "dir": "",
    "signature": None,
    "with_sso": None,
    "without_sso": None,
    "status_mtime": None,
}
_account_list_cache_lock = threading.Lock()


def _file_mtime_ns(path):
    try:
        return os.stat(path).st_mtime_ns
    except Exception:
        return None


def invalidate_account_list_cache():
    """账号文件或状态变更后清列表缓存。"""
    with _account_list_cache_lock:
        _account_list_cache["signature"] = None
        _account_list_cache["with_sso"] = None
        _account_list_cache["without_sso"] = None
        _account_list_cache["status_mtime"] = None
    _account_status_cache["mtime"] = None
    _account_status_cache["data"] = None
    _account_status_cache["by_email"] = None


def load_account_statuses():
    path = get_account_status_file()
    mtime = _file_mtime_ns(path)
    if (
        _account_status_cache.get("path") == path
        and _account_status_cache.get("mtime") == mtime
        and isinstance(_account_status_cache.get("data"), dict)
        and mtime is not None
    ):
        return _account_status_cache["data"]
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    accounts = data.get("accounts") if isinstance(data.get("accounts"), dict) else data
    if not isinstance(accounts, dict):
        accounts = {}
    by_email = {}
    for rec in accounts.values():
        if not isinstance(rec, dict):
            continue
        email_key = str(rec.get("email") or "").strip().lower()
        if email_key and email_key not in by_email:
            by_email[email_key] = rec
    _account_status_cache["path"] = path
    _account_status_cache["mtime"] = mtime
    _account_status_cache["data"] = accounts
    _account_status_cache["by_email"] = by_email
    return accounts


def _account_status_by_email_index(statuses=None):
    """email -> status record 索引（与 load_account_statuses 缓存同步）。"""
    if statuses is None:
        load_account_statuses()
        return _account_status_cache.get("by_email") or {}
    by_email = {}
    if isinstance(statuses, dict):
        for rec in statuses.values():
            if not isinstance(rec, dict):
                continue
            email_key = str(rec.get("email") or "").strip().lower()
            if email_key and email_key not in by_email:
                by_email[email_key] = rec
    return by_email


def save_account_statuses(statuses):
    path = get_account_status_file()
    payload = {
        "updated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "accounts": statuses if isinstance(statuses, dict) else {},
    }
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, path)
    invalidate_account_list_cache()


def update_account_status_records(mutator):
    """线程安全更新账号状态文件。mutator(statuses_dict) -> None"""
    with _account_status_lock:
        statuses = load_account_statuses()
        if not isinstance(statuses, dict):
            statuses = {}
        statuses = dict(statuses)
        mutator(statuses)
        save_account_statuses(statuses)
        return statuses


def account_status_text(status):
    value = str(status or "").strip().lower()
    if value == "pushed":
        return "已推送"
    if value == "probe_failed":
        return "已入库·探测失败"
    if value == "failed":
        return "推送失败"
    if value == "pushing":
        return "推送中"
    return "未推送"


def account_health_status_text(status):
    value = str(status or "").strip().lower()
    if value == "healthy":
        return "可用"
    if value == "unhealthy":
        return "失效"
    if value == "incomplete":
        return "资料不完整"
    if value == "checking":
        return "检查中"
    return "未检查"


def _sub2api_error_text(exc, step=""):
    response = getattr(exc, "response", None)
    status_code = (
        getattr(response, "status_code", None)
        or getattr(exc, "status_code", None)
        or getattr(exc, "code", None)
    )
    text = getattr(response, "text", "") if response is not None else ""
    if not text:
        reader = getattr(exc, "read", None)
        if callable(reader):
            try:
                body = reader()
                text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body or "")
            except Exception:
                text = ""
    message = str(exc)
    if status_code:
        message = f"{step + ' ' if step else ''}HTTP {status_code}: {text or message}"
    elif step:
        message = f"{step}: {message}"
    return message[:1000]


def is_refresh_token_revoked_error(error_text):
    text = str(error_text or "").lower()
    return "invalid_grant" in text or "revoked" in text or "refresh token has been revoked" in text


def is_account_blocked_error(error_text):
    text = str(error_text or "").lower()
    return (
        "user account is blocked" in text
        or "account is blocked" in text
        or "account has been blocked" in text
        or "账号已封禁" in text
        or "账号被封" in text
    )


def is_xai_refresh_token_client_error(exc):
    response = getattr(exc, "response", None)
    status_code = (
        getattr(response, "status_code", None)
        or getattr(exc, "status_code", None)
        or getattr(exc, "code", None)
    )
    text = _sub2api_error_text(exc).lower()
    return str(status_code) == "400" or "http 400" in text or "http error 400" in text or is_refresh_token_revoked_error(text)


def attach_account_status(account, statuses=None, by_email=None):
    if not isinstance(account, dict):
        return account
    statuses = load_account_statuses() if statuses is None else statuses
    account_id = str(account.get("id") or "").strip()
    record = statuses.get(account_id, {}) if account_id else {}
    # 兼容：id 对不上时按 email 回退匹配（自动注册时 line_no 偶发漂移）
    # 使用 email 索引，避免对每个账号 O(n) 扫 statuses
    if not isinstance(record, dict) or not record:
        email_key = str(account.get("email") or "").strip().lower()
        if email_key:
            index = by_email if isinstance(by_email, dict) else _account_status_by_email_index(statuses)
            record = index.get(email_key) or {}
    if not isinstance(record, dict):
        record = {}
    # 优先用账号级 created_at（注册成功时写入）；否则保留文件名/mtime 批次时间
    per_account_created = str(record.get("created_at") or "").strip()
    if per_account_created:
        account["created_at"] = per_account_created
        account["created_at_source"] = "account"
    elif account.get("created_at"):
        account["created_at_source"] = "batch"
    status = str(record.get("sub2api_status") or record.get("status") or "not_pushed").strip() or "not_pushed"
    account["sub2api_status"] = status
    account["sub2api_status_text"] = str(record.get("sub2api_status_text") or account_status_text(status))
    if record.get("sub2api_pushed_at"):
        account["sub2api_pushed_at"] = record.get("sub2api_pushed_at")
    if "sub2api_response" in record:
        account["sub2api_response"] = record.get("sub2api_response")
    if record.get("sub2api_error"):
        account["sub2api_error"] = record.get("sub2api_error")
    remote_id = str(record.get("sub2api_remote_id") or "").strip()
    if remote_id:
        account["sub2api_remote_id"] = remote_id
    if record.get("sub2api_probe_at"):
        account["sub2api_probe_at"] = record.get("sub2api_probe_at")
    if record.get("sub2api_probe_error"):
        account["sub2api_probe_error"] = record.get("sub2api_probe_error")
    grok2api_status = str(record.get("grok2api_status") or "not_pushed").strip() or "not_pushed"
    account["grok2api_status"] = grok2api_status
    account["grok2api_status_text"] = str(record.get("grok2api_status_text") or account_status_text(grok2api_status))
    if record.get("grok2api_pushed_at"):
        account["grok2api_pushed_at"] = record.get("grok2api_pushed_at")
    if "grok2api_response" in record:
        account["grok2api_response"] = record.get("grok2api_response")
    if record.get("grok2api_error"):
        account["grok2api_error"] = record.get("grok2api_error")
    cpa_status = str(record.get("cpa_status") or "not_pushed").strip() or "not_pushed"
    account["cpa_status"] = cpa_status
    account["cpa_status_text"] = str(record.get("cpa_status_text") or account_status_text(cpa_status))
    if record.get("cpa_pushed_at"):
        account["cpa_pushed_at"] = record.get("cpa_pushed_at")
    if "cpa_response" in record:
        account["cpa_response"] = record.get("cpa_response")
    if record.get("cpa_error"):
        account["cpa_error"] = record.get("cpa_error")
    health_status = str(record.get("health_status") or "unknown").strip() or "unknown"
    account["health_status"] = health_status
    account["health_status_text"] = str(record.get("health_status_text") or account_health_status_text(health_status))
    if record.get("health_checked_at"):
        account["health_checked_at"] = record.get("health_checked_at")
    if record.get("health_error"):
        account["health_error"] = record.get("health_error")
    if "health_response" in record:
        account["health_response"] = record.get("health_response")
    return account


def _accounts_files_signature(data_dir):
    """accounts_*.txt 的 (name, mtime_ns, size) 签名，用于列表缓存失效。"""
    items = []
    try:
        names = os.listdir(data_dir)
    except Exception:
        return tuple()
    for name in names:
        if not (name.startswith("accounts_") and name.endswith(".txt")):
            continue
        path = os.path.join(data_dir, name)
        try:
            st = os.stat(path)
            items.append((name, st.st_mtime_ns, st.st_size))
        except Exception:
            continue
    items.sort()
    return tuple(items)


def list_registered_accounts(include_sso=True):
    data_dir = get_data_dir()
    status_path = get_account_status_file()
    status_mtime = _file_mtime_ns(status_path)
    signature = _accounts_files_signature(data_dir)
    cache_key = "with_sso" if include_sso else "without_sso"

    with _account_list_cache_lock:
        if (
            _account_list_cache.get("dir") == data_dir
            and _account_list_cache.get("signature") == signature
            and _account_list_cache.get("status_mtime") == status_mtime
            and _account_list_cache.get(cache_key) is not None
        ):
            # 返回浅拷贝，避免调用方原地改缓存
            return [dict(a) for a in _account_list_cache[cache_key]]

    statuses = load_account_statuses()
    by_email = _account_status_by_email_index(statuses)
    accounts = []
    for name in sorted(os.listdir(data_dir), reverse=True):
        if not (name.startswith("accounts_") and name.endswith(".txt")):
            continue
        path = os.path.join(data_dir, name)
        if not os.path.isfile(path):
            continue
        created_at = parse_account_file_created_at(name, path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, start=1):
                    account = parse_registered_account_line(
                        line,
                        source=name,
                        line_no=line_no,
                        include_sso=include_sso,
                        created_at=created_at,
                    )
                    if account:
                        attach_account_status(account, statuses, by_email=by_email)
                        accounts.append(account)
        except Exception:
            continue

    with _account_list_cache_lock:
        _account_list_cache["dir"] = data_dir
        _account_list_cache["signature"] = signature
        _account_list_cache["status_mtime"] = status_mtime
        _account_list_cache[cache_key] = accounts
        # 另一种 include_sso 视图过期
        other = "without_sso" if include_sso else "with_sso"
        _account_list_cache[other] = None
        return [dict(a) for a in accounts]


def _account_matches_filter(account, filter_name="all"):
    """与前端 accountPushFilter 语义对齐的服务端筛选。"""
    name = str(filter_name or "all").strip().lower() or "all"
    if name in {"", "all"}:
        return True

    def _status(channel):
        return str(account.get(f"{channel}_status") or "").strip().lower()

    def _text(channel):
        return str(account.get(f"{channel}_status_text") or "")

    def _is_pushed(channel):
        st = _status(channel)
        tx = _text(channel)
        if channel == "sub2api" and (st == "probe_failed" or "探测失败" in tx):
            return False
        return st == "pushed" or tx == "已推送"

    def _is_failed(channel):
        st = _status(channel)
        tx = _text(channel)
        if st == "failed":
            return True
        if channel == "sub2api" and (st == "probe_failed" or "探测失败" in tx):
            return True
        return tx.startswith("失败") or tx == "推送失败"

    if name == "any_pushed":
        return any(_is_pushed(c) for c in ("grok2api", "sub2api", "cpa"))
    if name == "none_pushed":
        return all(not _is_pushed(c) for c in ("grok2api", "sub2api", "cpa"))
    if name == "grok2api_pushed":
        return _is_pushed("grok2api")
    if name == "sub2api_pushed":
        return _is_pushed("sub2api")
    if name == "sub2api_probe_failed":
        st = _status("sub2api")
        tx = _text("sub2api")
        return (
            st == "probe_failed"
            or "已入库·探测失败" in tx
            or "探测失败" in tx
            or bool(account.get("sub2api_probe_error"))
        )
    if name == "cpa_pushed":
        return _is_pushed("cpa")
    if name == "failed":
        return any(_is_failed(c) for c in ("grok2api", "sub2api", "cpa"))
    if name == "has_refresh":
        return bool(account.get("has_refresh_token"))
    if name == "no_refresh":
        return not bool(account.get("has_refresh_token"))
    return True


def _account_search_haystack(account):
    parts = [
        account.get("email"),
        account.get("source_file"),
        account.get("created_at"),
        account.get("sso_preview"),
        account.get("grok2api_status_text"),
        account.get("sub2api_status_text"),
        account.get("cpa_status_text"),
        account.get("health_status_text"),
        account.get("sub2api_remote_id"),
    ]
    return " ".join(str(x or "").lower() for x in parts)


def _account_sort_key(account, sort_key="created"):
    key = str(sort_key or "created").strip().lower() or "created"
    if key == "email":
        return str(account.get("email") or "").lower()
    if key == "sso":
        return str(account.get("sso_preview") or "").lower()
    if key == "source":
        return str(account.get("source_file") or "").lower()
    if key == "index":
        try:
            return int(account.get("line_no") or 0)
        except Exception:
            return 0
    if key == "refresh":
        return "1" if account.get("has_refresh_token") else "0"
    if key == "password":
        return "1" if account.get("password") else "0"
    if key == "health":
        return str(account.get("health_status_text") or account.get("health_status") or "").lower()
    if key in {"grok2api", "sub2api", "cpa"}:
        return str(account.get(f"{key}_status_text") or account.get(f"{key}_status") or "").lower()
    # created / default
    return str(account.get("created_at") or "")


def query_registered_accounts(
    *,
    include_sso=False,
    q="",
    filter_name="all",
    sort_key="created",
    sort_dir="desc",
    page=1,
    page_size=20,
):
    """账号列表服务端筛选/排序/分页（7000+ 账号必备）。"""
    accounts = list_registered_accounts(include_sso=include_sso)
    query = str(q or "").strip().lower()
    filtered = []
    for acc in accounts:
        if query and query not in _account_search_haystack(acc):
            continue
        if not _account_matches_filter(acc, filter_name):
            continue
        filtered.append(acc)

    reverse = str(sort_dir or "desc").lower() != "asc"
    sk = str(sort_key or "created")
    # 稳定排序：主 key + created_at + line_no
    try:
        filtered.sort(
            key=lambda a: (
                _account_sort_key(a, sk),
                str(a.get("created_at") or ""),
                int(a.get("line_no") or 0),
            ),
            reverse=reverse,
        )
    except Exception:
        filtered.sort(key=lambda a: _account_sort_key(a, sk), reverse=reverse)

    try:
        page = max(1, int(page or 1))
    except Exception:
        page = 1
    try:
        page_size = max(1, min(200, int(page_size or 20)))
    except Exception:
        page_size = 20
    total = len(filtered)
    pages = max(1, (total + page_size - 1) // page_size)
    if page > pages:
        page = pages
    start = (page - 1) * page_size
    items = filtered[start : start + page_size]
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "accounts": items,
        "filter": str(filter_name or "all"),
        "q": str(q or ""),
        "sort_key": sk,
        "sort_dir": "asc" if not reverse else "desc",
    }


def replace_registered_account_refresh_token(account, refresh_token):
    refresh_token = str(refresh_token or "").strip()
    source = str((account or {}).get("source_file") or "").strip()
    line_no = int((account or {}).get("line_no") or 0)
    if not refresh_token or not source or line_no <= 0:
        return False
    path = os.path.join(get_data_dir(), source)
    if not os.path.isfile(path):
        return False
    try:
        with _registered_accounts_lock:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if line_no > len(lines):
                return False
            parts = lines[line_no - 1].rstrip("\n").split("----", 3)
            if len(parts) < 3:
                return False
            newline = "\n" if lines[line_no - 1].endswith("\n") else ""
            lines[line_no - 1] = f"{parts[0]}----{parts[1]}----{parts[2]}----{refresh_token}{newline}"
            _write_registered_account_lines(path, lines)
        invalidate_account_list_cache()
        account["refresh_token"] = refresh_token
        account["refresh_token_preview"] = _mask_token(refresh_token)
        account["has_refresh_token"] = True
        return True
    except Exception:
        return False


def persist_account_created_at(account, created_at=None):
    """把每个账号的真实注册成功时间写入状态文件（避免整批共用文件名时间）。"""
    if not isinstance(account, dict):
        return None
    account_id = str(account.get("id") or "").strip()
    if not account_id:
        return None
    stamp = str(created_at or account.get("created_at") or "").strip()
    if not stamp:
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
    account["created_at"] = stamp
    account["created_at_source"] = "account"

    def _mutate(statuses):
        record = statuses.get(account_id)
        record = dict(record) if isinstance(record, dict) else {}
        # 已有精确时间不覆盖（防止后续推送状态回写冲掉）
        if not str(record.get("created_at") or "").strip():
            record["created_at"] = stamp
        record["email"] = str(account.get("email") or record.get("email") or "").strip()
        if account.get("source_file"):
            record["source_file"] = account.get("source_file")
        if account.get("line_no"):
            record["line_no"] = account.get("line_no")
        statuses[account_id] = record

    return update_account_status_records(_mutate)


def _extract_sub2api_account_id(created):
    """从创建账号响应里尽量抠出 account id。"""
    if not isinstance(created, dict):
        return ""
    for key in ("id", "account_id", "accountId"):
        val = created.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    data = created.get("data")
    if isinstance(data, dict):
        for key in ("id", "account_id", "accountId"):
            val = data.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
        account = data.get("account")
        if isinstance(account, dict):
            for key in ("id", "account_id", "accountId"):
                val = account.get(key)
                if val is not None and str(val).strip():
                    return str(val).strip()
    return ""


def _extract_sub2api_remote_id_from_item(item):
    """从推送/探测结果里取远端 sub2api account id。"""
    if not isinstance(item, dict):
        return ""
    for key in ("remote_id", "sub2api_remote_id", "account_id"):
        val = str(item.get(key) or "").strip()
        if val:
            return val
    post = item.get("post_actions") if isinstance(item.get("post_actions"), dict) else {}
    val = str(post.get("account_id") or "").strip()
    if val:
        return val
    resp = item.get("response")
    if isinstance(resp, dict):
        extracted = _extract_sub2api_account_id(resp)
        if extracted:
            return extracted
    return ""


def persist_sub2api_push_status(accounts, result):
    items = result.get("items") if isinstance(result, dict) else []
    if not isinstance(items, list):
        items = []
    now = datetime.datetime.now().isoformat(timespec="seconds")

    def _mutate(statuses):
        for index, account in enumerate(accounts or []):
            account_id = str(account.get("id") or "").strip()
            email = str(account.get("email") or "").strip()
            if not account_id and not email:
                continue
            key = account_id or f"email:{email.lower()}"
            record = statuses.get(key)
            if not isinstance(record, dict):
                record = {}
            item = items[index] if index < len(items) and isinstance(items[index], dict) else {}
            if not item and email:
                for it in items:
                    if isinstance(it, dict) and str(it.get("email") or "").strip().lower() == email.lower():
                        item = it
                        break
            item_status = str(item.get("status") or "pushed").strip().lower()
            remote_id = _extract_sub2api_remote_id_from_item(item) or str(
                record.get("sub2api_remote_id") or account.get("sub2api_remote_id") or ""
            ).strip()
            base_meta = {
                "email": email,
                "source_file": account.get("source_file", ""),
                "line_no": account.get("line_no", ""),
            }
            if remote_id:
                base_meta["sub2api_remote_id"] = remote_id

            if item_status == "failed":
                step = str(item.get("step") or "").strip()
                err = str(item.get("error") or "")
                prev_status = str(record.get("sub2api_status") or "").strip().lower()
                # 重新探测找不到远端 id：保留历史「已推送」，不要整批改成推送失败
                if step == "probe" and prev_status in {"pushed", "probe_failed", ""}:
                    record.update(base_meta)
                    record["sub2api_error"] = err[:400]
                    record["sub2api_probe_error"] = err[:400]
                    record["sub2api_probe_at"] = now
                    if prev_status in {"", "not_pushed"}:
                        # 从未成功入库的，仍记失败
                        record["sub2api_status"] = "failed"
                        record["sub2api_status_text"] = f"失败：{err[:220]}"
                        record["sub2api_failed_at"] = now
                        record["sub2api_step"] = step
                    # pushed / probe_failed 保持原状态
                else:
                    record.update(
                        {
                            **base_meta,
                            "sub2api_status": "failed",
                            "sub2api_status_text": f"失败：{err[:220]}",
                            "sub2api_failed_at": now,
                            "sub2api_error": err,
                            "sub2api_step": step,
                        }
                    )
            elif item_status in {"probe_failed", "probed_failed"}:
                probe_err = ""
                post = item.get("post_actions") if isinstance(item.get("post_actions"), dict) else {}
                test = post.get("test") if isinstance(post.get("test"), dict) else {}
                probe_err = str(
                    item.get("probe_error")
                    or item.get("error")
                    or test.get("msg")
                    or ""
                ).strip()
                record.update(
                    {
                        **base_meta,
                        "sub2api_status": "probe_failed",
                        "sub2api_status_text": account_status_text("probe_failed"),
                        "sub2api_pushed_at": record.get("sub2api_pushed_at") or now,
                        "sub2api_probe_at": now,
                        "sub2api_probe_error": probe_err[:400],
                        "sub2api_response": item.get("response", item),
                        "sub2api_error": probe_err[:400],
                    }
                )
            elif item_status in {"deleted_remote", "remote_deleted"}:
                record.update(
                    {
                        **base_meta,
                        "sub2api_status": "not_pushed",
                        "sub2api_status_text": "远端已删除",
                        "sub2api_deleted_at": now,
                    }
                )
                record.pop("sub2api_remote_id", None)
                record.pop("sub2api_error", None)
                record.pop("sub2api_probe_error", None)
                record.pop("sub2api_probe_at", None)
            else:
                # pushed / probed_ok
                record.update(
                    {
                        **base_meta,
                        "sub2api_status": "pushed",
                        "sub2api_status_text": "已推送",
                        "sub2api_pushed_at": now,
                        "sub2api_probe_at": now,
                        "sub2api_response": item.get("response", item),
                    }
                )
                record.pop("sub2api_error", None)
                record.pop("sub2api_probe_error", None)
                record.pop("sub2api_failed_at", None)
                record.pop("sub2api_step", None)
            statuses[key] = record
            if account_id:
                statuses[account_id] = record

    return update_account_status_records(_mutate)


def persist_grok2api_push_status(accounts, result):
    items = result.get("items") if isinstance(result, dict) else []
    if not isinstance(items, list):
        items = []
    now = datetime.datetime.now().isoformat(timespec="seconds")

    def _mutate(statuses):
        for index, account in enumerate(accounts or []):
            account_id = str(account.get("id") or "").strip()
            email = str(account.get("email") or "").strip()
            if not account_id and not email:
                continue
            key = account_id or f"email:{email.lower()}"
            record = statuses.get(key)
            if not isinstance(record, dict):
                record = {}
            item = items[index] if index < len(items) and isinstance(items[index], dict) else {}
            if not item and email:
                for it in items:
                    if isinstance(it, dict) and str(it.get("email") or "").strip().lower() == email.lower():
                        item = it
                        break
            item_status = str(item.get("status") or "pushed").strip().lower()
            if item_status == "failed":
                record.update(
                    {
                        "grok2api_status": "failed",
                        "grok2api_status_text": f"失败：{str(item.get('error') or '')[:220]}",
                        "grok2api_failed_at": now,
                        "grok2api_error": str(item.get("error") or ""),
                        "email": email,
                        "source_file": account.get("source_file", ""),
                        "line_no": account.get("line_no", ""),
                    }
                )
            else:
                record.update(
                    {
                        "grok2api_status": "pushed",
                        "grok2api_status_text": "已推送",
                        "grok2api_pushed_at": now,
                        "grok2api_response": item.get("response", item),
                        "email": email,
                        "source_file": account.get("source_file", ""),
                        "line_no": account.get("line_no", ""),
                    }
                )
                record.pop("grok2api_error", None)
            statuses[key] = record
            if account_id:
                statuses[account_id] = record

    return update_account_status_records(_mutate)


def persist_cpa_push_status(accounts, result):
    items = result.get("items") if isinstance(result, dict) else []
    if not isinstance(items, list):
        items = []
    now = datetime.datetime.now().isoformat(timespec="seconds")

    def _mutate(statuses):
        for index, account in enumerate(accounts or []):
            account_id = str(account.get("id") or "").strip()
            email = str(account.get("email") or "").strip()
            if not account_id and not email:
                continue
            key = account_id or f"email:{email.lower()}"
            record = statuses.get(key)
            if not isinstance(record, dict):
                record = {}
            item = items[index] if index < len(items) and isinstance(items[index], dict) else {}
            if not item and email:
                for it in items:
                    if isinstance(it, dict) and str(it.get("email") or "").strip().lower() == email.lower():
                        item = it
                        break
            item_status = str(item.get("status") or "pushed").strip().lower()
            if item_status in {"failed", "error"}:
                record.pop("cpa_pushed_at", None)
                record.pop("cpa_response", None)
                record.update(
                    {
                        "cpa_status": "failed",
                        "cpa_status_text": f"失败：{str(item.get('error') or item.get('upload_error') or '')[:220]}",
                        "cpa_failed_at": now,
                        "cpa_error": str(item.get("error") or item.get("upload_error") or ""),
                        "cpa_step": str(item.get("step") or ""),
                        "email": email,
                        "source_file": account.get("source_file", ""),
                        "line_no": account.get("line_no", ""),
                    }
                )
            else:
                record.pop("cpa_failed_at", None)
                record.pop("cpa_error", None)
                record.pop("cpa_step", None)
                record.update(
                    {
                        "cpa_status": "pushed",
                        "cpa_status_text": "已推送",
                        "cpa_pushed_at": now,
                        "cpa_response": item.get("response", item),
                        "email": email,
                        "source_file": account.get("source_file", ""),
                        "line_no": account.get("line_no", ""),
                    }
                )
            statuses[key] = record
            if account_id:
                statuses[account_id] = record

    return update_account_status_records(_mutate)


def persist_account_health_status(accounts, result):
    statuses = load_account_statuses()
    items = result.get("items") if isinstance(result, dict) else []
    if not isinstance(items, list):
        items = []
    now = datetime.datetime.now().isoformat(timespec="seconds")
    for index, account in enumerate(accounts or []):
        account_id = str(account.get("id") or "").strip()
        if not account_id:
            continue
        record = statuses.get(account_id)
        if not isinstance(record, dict):
            record = {}
        item = items[index] if index < len(items) and isinstance(items[index], dict) else {}
        health_status = str(item.get("status") or "unknown").strip().lower() or "unknown"
        record.update(
            {
                "health_status": health_status,
                "health_status_text": account_health_status_text(health_status),
                "health_checked_at": now,
                "email": account.get("email", ""),
                "source_file": account.get("source_file", ""),
                "line_no": account.get("line_no", ""),
            }
        )
        if item.get("error"):
            record["health_error"] = str(item.get("error") or "")
        else:
            record.pop("health_error", None)
        if "response" in item:
            record["health_response"] = item.get("response")
        statuses[account_id] = record
    save_account_statuses(statuses)
    return statuses


def find_registered_accounts(account_ids):
    wanted = {str(item) for item in (account_ids or []) if str(item).strip()}
    if not wanted:
        return []
    return [account for account in list_registered_accounts(include_sso=True) if account["id"] in wanted]


def _write_registered_account_lines(path, lines):
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix=".accounts-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.writelines(lines)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def delete_registered_accounts(account_ids):
    wanted = {str(account_id).strip() for account_id in (account_ids or []) if str(account_id).strip()}
    if not wanted:
        raise ValueError("请选择要删除的账号")

    deleted_ids = set()
    statuses = load_account_statuses()
    with _registered_accounts_lock:
        data_dir = get_data_dir()
        for name in sorted(os.listdir(data_dir), reverse=True):
            if not (name.startswith("accounts_") and name.endswith(".txt")):
                continue
            path = os.path.join(data_dir, name)
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as file:
                lines = file.readlines()

            retained_lines = []
            for old_line_no, line in enumerate(lines, start=1):
                account = parse_registered_account_line(
                    line, source=name, line_no=old_line_no, include_sso=True
                )
                if account and account["id"] in wanted:
                    deleted_ids.add(account["id"])
                    statuses.pop(account["id"], None)
                    continue

                retained_lines.append(line)
                if not account:
                    continue
                new_line_no = len(retained_lines)
                new_account_id = _account_id(name, new_line_no, account["email"], account["sso"])
                if new_account_id == account["id"]:
                    continue
                record = statuses.pop(account["id"], None)
                if isinstance(record, dict):
                    record = dict(record)
                    record.update(
                        {
                            "email": account["email"],
                            "source_file": name,
                            "line_no": new_line_no,
                        }
                    )
                    statuses[new_account_id] = record

            if len(retained_lines) != len(lines):
                _write_registered_account_lines(path, retained_lines)

        if deleted_ids:
            save_account_statuses(statuses)
        else:
            # 可能只改了行号映射但未删净时也清缓存
            invalidate_account_list_cache()

    return {"deleted": len(deleted_ids), "missing": len(wanted - deleted_ids)}


