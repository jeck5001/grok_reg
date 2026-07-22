import time

from fastapi.testclient import TestClient

import grok_register_ttk as reg


def wait_for_api_job(client, job_id, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        response.raise_for_status()
        payload = response.json()
        if payload["status"] in {"completed", "failed", "stopped"}:
            return payload
        time.sleep(0.02)
    raise AssertionError("API job did not finish")


def test_healthz():
    from web_app import app

    client = TestClient(app)
    response = client.get("/healthz")

    assert response.status_code == 200
    body = response.json()
    assert body.get("status") == "ok"
    assert "auth_enabled" in body


def test_web_password_login_guards_api(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GROK_REG_WEB_PASSWORD", "unit-pass")
    import web_app
    from web_app import app

    # 清会话，避免污染
    web_app._AUTH_SESSIONS.clear()
    client = TestClient(app)

    blocked = client.get("/api/config")
    assert blocked.status_code == 401

    bad = client.post("/api/auth/login", json={"password": "nope"})
    assert bad.status_code == 401

    ok = client.post("/api/auth/login", json={"password": "unit-pass"})
    assert ok.status_code == 200
    assert ok.json().get("ok") is True

    cfg = client.get("/api/config")
    assert cfg.status_code == 200

    # webhook 仍公开（业务层校验 secret）
    wh = client.post("/api/webhook/email", json={})
    assert wh.status_code in {400, 503}

    out = client.post("/api/auth/logout")
    assert out.status_code == 200
    assert client.get("/api/config").status_code == 401


def test_config_round_trip_masks_sensitive_values(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    from web_app import app

    client = TestClient(app)
    response = client.put(
        "/api/config",
        json={
            "email_provider": "cloudmail",
            "cloudmail_url": "https://mail.example.test",
            "cloudmail_admin_email": "admin@example.test",
            "cloudmail_password": "top-secret",
            "defaultDomains": "example.test",
            "register_count": 2,
            "register_threads": 1,
        },
    )

    assert response.status_code == 200
    assert response.json()["cloudmail_password"] == "********"
    response = client.get("/api/config")
    assert response.status_code == 200
    assert response.json()["cloudmail_password"] == "********"


def test_yyds_config_round_trip_masks_sensitive_values(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    from web_app import app

    client = TestClient(app)
    response = client.put(
        "/api/config",
        json={
            "email_provider": "yyds",
            "yyds_api_key": "api-key-value",
            "yyds_jwt": "jwt-value",
            "register_count": 1,
            "register_threads": 1,
        },
    )

    assert response.status_code == 200
    assert response.json()["yyds_api_key"] == "********"
    assert response.json()["yyds_jwt"] == "********"

    saved = tmp_path.joinpath("config.json").read_text(encoding="utf-8")
    assert "api-key-value" in saved
    assert "jwt-value" in saved


def test_sub2api_config_round_trip_masks_sensitive_values(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    from web_app import app

    client = TestClient(app)
    response = client.put(
        "/api/config",
        json={
            "email_provider": "duckmail",
            "sub2api_base": "https://sub2api.example/api/v1",
            "sub2api_auth_mode": "x-api-key",
            "sub2api_admin_token": "admin-secret",
            "register_count": 1,
            "register_threads": 1,
        },
    )

    assert response.status_code == 200
    assert response.json()["sub2api_admin_token"] == "********"

    saved = tmp_path.joinpath("config.json").read_text(encoding="utf-8")
    assert "admin-secret" in saved


def test_cpa_management_config_round_trip_masks_management_key(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    from web_app import app

    client = TestClient(app)
    response = client.put(
        "/api/config",
        json={
            "email_provider": "duckmail",
            "cpa_auto_push_remote": True,
            "cpa_management_base": "https://cpa.example.test",
            "cpa_management_key": "management-secret",
            "register_count": 1,
            "register_threads": 1,
        },
    )

    assert response.status_code == 200
    assert response.json()["cpa_management_key"] == "********"
    saved = tmp_path.joinpath("config.json").read_text(encoding="utf-8")
    assert "management-secret" in saved


def test_accounts_endpoint_lists_registered_accounts(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    tmp_path.joinpath("accounts_20260630_140000_job.txt").write_text(
        "user@example.com----Pass----sso-token----refresh-token\n",
        encoding="utf-8",
    )
    from web_app import app

    client = TestClient(app)
    response = client.get("/api/accounts")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["accounts"][0]["email"] == "user@example.com"
    assert "sso" not in payload["accounts"][0]
    assert "refresh_token" not in payload["accounts"][0]
    assert payload["accounts"][0]["sso_preview"] == "sso-to...-token"
    assert payload["accounts"][0]["has_refresh_token"] is True
    assert payload["accounts"][0]["refresh_token_preview"] == "refres...-token"


def test_delete_selected_accounts_removes_records_and_returns_remaining_accounts(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    tmp_path.joinpath("accounts_20260630_140000_job.txt").write_text(
        "first@example.com----Pass----sso-token-1----refresh-token-1\n"
        "second@example.com----Pass----sso-token-2----refresh-token-2\n",
        encoding="utf-8",
    )
    from web_app import app

    client = TestClient(app)
    accounts = client.get("/api/accounts").json()["accounts"]
    selected = next(account for account in accounts if account["email"] == "second@example.com")

    response = client.request("DELETE", "/api/accounts", json={"account_ids": [selected["id"]]})

    assert response.status_code == 200
    assert response.json()["deleted"] == 1
    assert response.json()["message"] == "已删除 1 个账号"
    assert [account["email"] for account in response.json()["accounts"]] == ["first@example.com"]
    assert [account["email"] for account in client.get("/api/accounts").json()["accounts"]] == [
        "first@example.com"
    ]


def test_import_selected_accounts_to_sub2api(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    tmp_path.joinpath("accounts_20260630_140000_job.txt").write_text(
        "user@example.com----Pass----sso-token----refresh-token\n",
        encoding="utf-8",
    )
    calls = []

    def fake_import(accounts, settings, log_callback=None):
        calls.append((accounts, settings))
        return {"imported": True, "total": len(accounts), "response": {"ok": True}}

    monkeypatch.setattr(reg, "import_accounts_to_sub2api", fake_import)
    from web_app import app

    client = TestClient(app)
    accounts = client.get("/api/accounts").json()["accounts"]
    response = client.post(
        "/api/accounts/import/sub2api",
        json={
            "account_ids": [accounts[0]["id"]],
            "sub2api_base": "https://sub2api.example/api/v1",
            "sub2api_auth_mode": "bearer",
            "sub2api_admin_token": "jwt-token",
        },
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["status"] == "pushed"
    assert "已推送" in response.json()["message"]
    assert calls[0][0][0]["email"] == "user@example.com"
    assert calls[0][0][0]["sso"] == "sso-token"
    assert calls[0][0][0]["refresh_token"] == "refresh-token"
    assert calls[0][1]["sub2api_auth_mode"] == "bearer"


def test_import_selected_accounts_persists_sub2api_status(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    tmp_path.joinpath("accounts_20260630_140000_job.txt").write_text(
        "user@example.com----Pass----sso-token----refresh-token\n",
        encoding="utf-8",
    )

    def fake_import(accounts, settings, log_callback=None):
        return {
            "imported": True,
            "total": len(accounts),
            "items": [{"email": accounts[0]["email"], "response": {"id": 101}}],
        }

    monkeypatch.setattr(reg, "import_accounts_to_sub2api", fake_import)
    from web_app import app

    client = TestClient(app)
    account = client.get("/api/accounts").json()["accounts"][0]

    response = client.post(
        "/api/accounts/import/sub2api",
        json={
            "account_ids": [account["id"]],
            "sub2api_base": "https://sub2api.example/api/v1",
            "sub2api_admin_token": "admin-key",
        },
    )

    assert response.status_code == 200
    # 列表接口 compact 会丢掉 response/error 大字段；状态与详情以导入接口返回为准
    body_acc = response.json()["accounts"][0]
    assert body_acc["sub2api_status"] == "pushed"
    assert body_acc["sub2api_status_text"] == "已推送"
    assert body_acc["sub2api_response"]["id"] == 101
    listed = client.get("/api/accounts").json()["accounts"][0]
    assert listed["sub2api_status"] == "pushed"
    assert listed["sub2api_status_text"] == "已推送"


def test_import_selected_accounts_persists_sub2api_failure_status(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    tmp_path.joinpath("accounts_20260630_140000_job.txt").write_text(
        "user@example.com----Pass----sso-token----refresh-token\n",
        encoding="utf-8",
    )

    def fake_import(accounts, settings, log_callback=None):
        return {
            "imported": False,
            "total": 0,
            "failed": 1,
            "items": [
                {
                    "email": accounts[0]["email"],
                    "status": "failed",
                    "error": "refresh-token HTTP 502: Bad Gateway",
                    "step": "refresh-token",
                }
            ],
        }

    monkeypatch.setattr(reg, "import_accounts_to_sub2api", fake_import)
    from web_app import app

    client = TestClient(app)
    account = client.get("/api/accounts").json()["accounts"][0]

    response = client.post(
        "/api/accounts/import/sub2api",
        json={
            "account_ids": [account["id"]],
            "sub2api_base": "https://sub2api.example/api/v1",
            "sub2api_admin_token": "admin-key",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "partial_failed"
    body_acc = response.json()["accounts"][0]
    assert body_acc["sub2api_status"] == "failed"
    assert body_acc["sub2api_status_text"].startswith("失败")
    assert "refresh-token HTTP 502" in body_acc["sub2api_error"]
    listed = client.get("/api/accounts").json()["accounts"][0]
    assert listed["sub2api_status"] == "failed"


def test_import_selected_accounts_to_cpa_uses_only_selected_accounts_and_persists_status(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    tmp_path.joinpath("accounts_20260713_120000_job.txt").write_text(
        "first@example.com----Pass----sso-token-1----refresh-token-1\n"
        "second@example.com----Pass----sso-token-2----refresh-token-2\n",
        encoding="utf-8",
    )
    calls = []

    def fake_import(accounts, settings, log_callback=None):
        calls.append((accounts, settings))
        return {
            "imported": True,
            "total": 1,
            "failed": 0,
            "items": [
                {
                    "email": accounts[0]["email"],
                    "status": "pushed",
                    "response": {"filename": "xai-second@example.com.json", "upload_status": 201},
                }
            ],
        }

    monkeypatch.setattr(reg, "import_accounts_to_cpa", fake_import)
    from web_app import app

    client = TestClient(app)
    accounts = client.get("/api/accounts").json()["accounts"]
    selected = next(account for account in accounts if account["email"] == "second@example.com")
    response = client.post(
        "/api/accounts/import/cpa",
        json={
            "account_ids": [selected["id"]],
            "cpa_management_base": "https://cpa.example.test",
            "cpa_management_key": "management-secret",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "pushed"
    assert response.json()["total"] == 1
    assert [account["email"] for account in calls[0][0]] == ["second@example.com"]
    assert calls[0][1]["cpa_management_key"] == "management-secret"
    assert "sso" not in response.json()["accounts"][0]
    # 详情以导入接口返回为准（列表 compact 会丢掉 cpa_response）
    body_accounts = response.json()["accounts"]
    second_body = next(account for account in body_accounts if account["id"] == selected["id"])
    assert second_body["cpa_status"] == "pushed"
    assert second_body["cpa_response"]["upload_status"] == 201
    refreshed = client.get("/api/accounts").json()["accounts"]
    second = next(account for account in refreshed if account["id"] == selected["id"])
    first = next(account for account in refreshed if account["id"] != selected["id"])
    assert second["cpa_status"] == "pushed"
    assert first["cpa_status"] == "not_pushed"


def test_check_selected_accounts_health_persists_status(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    tmp_path.joinpath("accounts_20260630_140000_job.txt").write_text(
        "user@example.com----Pass----sso-token----refresh-token\n",
        encoding="utf-8",
    )

    def fake_check(accounts, settings=None, log_callback=None):
        return {
            "checked": 1,
            "healthy": 1,
            "failed": 0,
            "items": [{"email": accounts[0]["email"], "status": "healthy"}],
        }

    monkeypatch.setattr(reg, "check_registered_accounts_health", fake_check)
    from web_app import app

    client = TestClient(app)
    account = client.get("/api/accounts").json()["accounts"][0]
    response = client.post(
        "/api/accounts/check-health",
        json={"account_ids": [account["id"]]},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["message"] == "健康检查完成：可用 1 个，异常 0 个"
    assert "sso" not in response.json()["accounts"][0]
    assert "refresh_token" not in response.json()["accounts"][0]
    refreshed = client.get("/api/accounts").json()["accounts"][0]
    assert refreshed["health_status"] == "healthy"
    assert refreshed["health_status_text"] == "可用"


def test_start_job_rejects_duplicate_active_job(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(reg, "start_browser", lambda log_callback=None: (object(), object()))
    monkeypatch.setattr(reg, "stop_browser", lambda: None)

    def slow_signup(log_callback=None, cancel_callback=None):
        while not cancel_callback():
            time.sleep(0.01)
        raise reg.RegistrationCancelled("stopped")

    monkeypatch.setattr(reg, "open_signup_page", slow_signup)
    from web_app import app

    client = TestClient(app)
    response = client.post(
        "/api/jobs/start",
        json={"email_provider": "duckmail", "register_count": 1, "register_threads": 1},
    )
    assert response.status_code == 200
    job_id = response.json()["job_id"]

    duplicate = client.post(
        "/api/jobs/start",
        json={"email_provider": "duckmail", "register_count": 1, "register_threads": 1},
    )
    # 已有任务时恢复跟踪（200 + already_running），不再硬 409
    assert duplicate.status_code == 200
    body = duplicate.json()
    assert body.get("already_running") is True
    assert body.get("job_id") == job_id

    stop_response = client.post(f"/api/jobs/{job_id}/stop")
    assert stop_response.status_code == 200
    assert wait_for_api_job(client, job_id)["status"] == "stopped"


def test_job_status_and_logs(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(reg, "start_browser", lambda log_callback=None: (object(), object()))
    monkeypatch.setattr(reg, "restart_browser", lambda log_callback=None: (object(), object()))
    monkeypatch.setattr(reg, "stop_browser", lambda: None)
    monkeypatch.setattr(reg, "open_signup_page", lambda log_callback=None, cancel_callback=None: None)
    monkeypatch.setattr(
        reg,
        "fill_email_and_submit",
        lambda log_callback=None, cancel_callback=None: ("user@example.com", "mail-token"),
    )
    monkeypatch.setattr(
        reg,
        "fill_code_and_submit",
        lambda email, token, log_callback=None, cancel_callback=None: "123456",
    )
    monkeypatch.setattr(
        reg,
        "fill_profile_and_submit",
        lambda log_callback=None, cancel_callback=None: {
            "given_name": "Ada",
            "family_name": "Lovelace",
            "password": "secret",
        },
    )
    monkeypatch.setattr(
        reg,
        "wait_for_sso_cookie",
        lambda log_callback=None, cancel_callback=None: "sso-token",
    )
    monkeypatch.setattr(
        reg,
        "fetch_xai_oauth_refresh_token",
        lambda sso, log_callback=None, cancel_callback=None: "refresh-token",
    )
    monkeypatch.setattr(
        reg,
        "add_token_to_grok2api_pools",
        lambda raw_token, email="", log_callback=None: None,
    )
    from web_app import app

    client = TestClient(app)
    response = client.post(
        "/api/jobs/start",
        json={"email_provider": "duckmail", "register_count": 1, "register_threads": 1},
    )
    assert response.status_code == 200
    job_id = response.json()["job_id"]

    status = wait_for_api_job(client, job_id)
    assert status["status"] == "completed"
    assert status["success_count"] == 1

    logs = client.get(f"/api/jobs/{job_id}/logs", params={"offset": 0})
    assert logs.status_code == 200
    payload = logs.json()
    assert payload["next_offset"] >= 1
    assert any("注册成功" in line for line in payload["lines"])

    tail = client.get(f"/api/jobs/{job_id}/logs", params={"offset": payload["next_offset"]})
    assert tail.status_code == 200
    assert tail.json()["lines"] == []


def test_ops_war_room_shape(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    import mail_domain_pool as mdp
    import web_app as web

    mdp.reset_runtime()
    monkeypatch.setattr(
        web.reg,
        "load_config",
        lambda: {
            "email_provider": "cloudmail",
            "mail_domains": "a.example,b.example",
            "enable_mail_domain_runtime_control": True,
            "turnstile_solver_enabled": True,
            "turnstile_solver_url": "http://127.0.0.1:5072",
            "turnstile_solver_fallback_click": True,
            "register_count": 3,
            "register_threads": 1,
            "signup_mode": "http",
            "proxy": "",
        },
    )
    monkeypatch.setattr(web.reg, "list_registered_accounts", lambda include_sso=False: [])
    monkeypatch.setattr(
        web.reg,
        "probe_local_turnstile_solver",
        lambda force=False, timeout=2.0: False,
    )
    monkeypatch.setattr(
        web.reg,
        "normalize_turnstile_solver_url",
        lambda url=None: "http://127.0.0.1:5072",
    )
    monkeypatch.setattr(
        web,
        "_current_job_payload",
        lambda: {
            "has_job": False,
            "job_id": None,
            "status": "idle",
            "running": False,
            "success_count": 0,
            "fail_count": 0,
            "register_count": 3,
        },
    )

    client = TestClient(web.app)
    response = client.get("/api/ops/war-room")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert "job" in payload
    assert "inventory" in payload
    assert "domains" in payload
    assert "solver" in payload
    assert "failures" in payload
    assert "charts" in payload
    assert "alerts" in payload
    assert "runtime" in payload
    assert payload["solver"]["enabled"] is True
    assert payload["solver"]["reachable"] is False
    assert payload["domains"]["ok"] is True
    assert payload["domains"]["total_count"] == 2
    assert payload["runtime"]["signup_mode"] in {"http", "api", "browser", "auto"}
    assert "timeline" in payload["charts"]
    assert "fail_stack" in payload["charts"]
    assert "reason_keys" in payload["charts"]


def test_build_chart_series_from_logs():
    import web_app as web

    lines = [
        "[10:00:01] [+] 注册成功: a@x.com",
        "[10:00:12] [-] 注册失败: 未收到验证码",
        "[10:00:20] [+] 注册成功: b@x.com",
        "[10:01:05] [!] 域名被拒，仅冷却主域: bad.com",
        "[10:01:08] [-] 注册失败: Turnstile Solver 不可达",
        "[10:01:30] [+] 注册成功: c@x.com",
    ]
    charts = web._build_chart_series(lines)
    assert charts["event_count"] == 6
    assert len(charts["timeline"]) == 6
    assert charts["timeline"][-1]["cum_success"] == 3
    assert charts["timeline"][-1]["cum_fail"] == 3
    assert charts["timeline"][-1]["success_rate"] == 50.0
    assert charts["reason_keys"]
    assert charts["fail_stack"]
    assert any(row.get("total", 0) > 0 for row in charts["fail_stack"])


def test_presets_list_and_apply(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    import web_app as web

    client = TestClient(web.app)
    listed = client.get("/api/ops/presets")
    assert listed.status_code == 200
    presets = listed.json()["presets"]
    assert any(p["id"] == "safe_first" for p in presets)

    applied = client.post("/api/ops/presets/safe_first/apply")
    assert applied.status_code == 200
    body = applied.json()
    assert body["ok"] is True
    assert body["config"]["register_count"] == 1
    assert body["config"]["register_threads"] == 1
    assert body["config"]["signup_mode"] in {"browser", "http", "api", "auto"}


def test_economics_and_autopilot_plan():
    import web_app as web

    job = {
        "success_count": 10,
        "fail_count": 5,
        "register_count": 30,
        "register_threads": 3,
        "running": True,
        "status": "running",
    }
    thr = {
        "elapsed_sec": 600,
        "rate_per_min": 1.0,
        "eta_sec": 1200,
        "success_rate": 66.7,
        "terminal": False,
    }
    signals = {
        "fail_hits": 5,
        "reasons": [
            {"reason": "domain_rejected", "count": 3},
            {"reason": "turnstile", "count": 2},
        ],
    }
    econ = web._economics_snapshot(job, thr, signals, {"register_threads": 3})
    assert econ["sec_per_success"] == 60.0
    assert econ["remain"] == 20
    assert econ["est_more_mail"] is not None
    assert "成功率" in econ["blurb"] or "s/成功" in econ["blurb"]

    thr_done = {
        "elapsed_sec": 600,
        "rate_per_min": 1.0,
        "eta_sec": 1200,
        "success_rate": 80.0,
        "terminal": True,
    }
    econ_done = web._economics_snapshot(
        {
            "success_count": 8,
            "fail_count": 2,
            "register_count": 10,
            "running": False,
            "status": "completed",
        },
        thr_done,
        signals,
        {},
    )
    assert econ_done["remain"] == 0
    assert econ_done["eta_more_sec"] is None
    assert "任务已结束" in econ_done["blurb"]


def test_throughput_freezes_after_finish():
    import web_app as web

    thr = web._throughput_estimate(
        {
            "success_count": 8,
            "fail_count": 2,
            "register_count": 10,
            "started_at": "2026-07-17T10:00:00",
            "finished_at": "2026-07-17T10:05:38",
            "status": "completed",
            "running": False,
        },
        {},
    )
    assert thr["terminal"] is True
    assert thr["elapsed_sec"] == 338
    assert thr["eta_sec"] is None
    assert thr["rate_per_min"] == round((8 / 338) * 60.0, 2)


def test_autopilot_plan_actions():
    import web_app as web

    plan = web._evaluate_autopilot(
        {
            "success_count": 10,
            "fail_count": 5,
            "register_count": 30,
            "register_threads": 3,
            "running": True,
            "status": "running",
        },
        {"available_count": 2, "total_count": 4, "cooldown_count": 1},
        {"enabled": True, "reachable": True, "url": "http://x"},
        {
            "fail_hits": 5,
            "reasons": [
                {"reason": "domain_rejected", "count": 3},
                {"reason": "turnstile", "count": 2},
            ],
        },
        {
            "register_threads": 3,
            "mail_domain_fail_threshold": 3,
            "mail_domain_fail_cooldown_sec": 600,
            "mail_domain_pinpoint_burst": False,
            "mail_domain_prefer_low_failure": True,
            "turnstile_solver_timeout": 120,
            "turnstile_solver_fallback_click": True,
            "signup_mode": "http",
        },
    )
    assert plan["actions"]
    keys = {a.get("key") for a in plan["actions"] if a.get("type") == "set"}
    assert "mail_domain_fail_threshold" in keys or "register_threads" in keys


def test_autopilot_toggle_api(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    import web_app as web

    client = TestClient(web.app)
    off = client.get("/api/ops/autopilot")
    assert off.status_code == 200
    on = client.post("/api/ops/autopilot", json={"enabled": True})
    assert on.status_code == 200
    assert on.json()["enabled"] is True
    state = client.get("/api/ops/autopilot")
    assert state.json()["enabled"] is True
    client.post("/api/ops/autopilot", json={"enabled": False})
