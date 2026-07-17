import notify_hub as nh


def setup_function():
    nh.reset_runtime_state()


def test_normalize_and_status():
    s = nh.normalize_notify_settings(
        {
            "notify_enabled": "true",
            "notify_min_level": "warn",
            "notify_cooldown_sec": 60,
            "notify_telegram_bot_token": "tok",
            "notify_telegram_chat_id": "123",
            "notify_milestone_success": "10, 20, x",
        }
    )
    assert s["notify_enabled"] is True
    assert s["notify_milestone_success"] == [10, 20]
    st = nh.status(s)
    assert st["configured"] is True
    assert st["token_set"] is True


def test_emit_respects_disabled_and_level(monkeypatch):
    calls = []

    def fake_send(token, chat, text, timeout=8.0):
        calls.append(text)
        return {"ok": True, "latency_ms": 1}

    monkeypatch.setattr(nh, "send_telegram", fake_send)
    settings = {
        "notify_enabled": False,
        "notify_min_level": "warn",
        "notify_telegram_bot_token": "t",
        "notify_telegram_chat_id": "1",
        "notify_cooldown_sec": 1,
    }
    assert nh.emit("job.failed", title="x", level="danger", settings=settings)["skipped"] == "disabled"

    settings["notify_enabled"] = True
    settings["notify_events"] = {
        **nh.DEFAULT_EVENTS,
        "autopilot.applied": True,
    }
    assert (
        nh.emit("autopilot.applied", title="ap", level="info", settings=settings)["skipped"]
        == "level"
    )
    r_ms = nh.emit(
        "milestone.success_n",
        title="成功达到 10",
        level="info",
        settings=settings,
        sync=True,
        dedupe_key="ms-test",
    )
    assert r_ms.get("ok") is True

    r = nh.emit(
        "job.failed",
        title="fail",
        level="danger",
        settings=settings,
        sync=True,
        dedupe_key="k1",
    )
    assert r.get("ok") is True
    assert calls

    r2 = nh.emit(
        "job.failed",
        title="fail",
        level="danger",
        settings=settings,
        sync=True,
        dedupe_key="k1",
    )
    assert r2.get("skipped") == "cooldown"


def test_milestone_once():
    seen = []

    def fake_emit(event_type, **kwargs):
        seen.append((event_type, kwargs.get("title")))
        return {"ok": True}

    import notify_hub as nh2

    old = nh2.emit
    nh2.emit = fake_emit
    try:
        s = {
            "notify_enabled": True,
            "notify_milestone_success": [10, 50],
            "notify_events": {"milestone.success_n": True},
        }
        nh2.maybe_milestone("j1", 5, s)
        assert not seen
        nh2.maybe_milestone("j1", 10, s)
        nh2.maybe_milestone("j1", 12, s)
        assert len(seen) == 1
        assert "10" in seen[0][1]
    finally:
        nh2.emit = old


def test_observe_runtime_edges(monkeypatch):
    fired = []

    def fake_emit(event_type, **kwargs):
        fired.append(event_type)
        return {"ok": True}

    monkeypatch.setattr(nh, "emit", fake_emit)
    s = {"notify_enabled": True, "notify_events": dict(nh.DEFAULT_EVENTS)}
    nh.observe_runtime_edges(
        solver_reachable=True,
        domain_available=4,
        domain_total=4,
        domain_cooldown=0,
        settings=s,
    )
    assert fired == []
    nh.observe_runtime_edges(
        solver_reachable=False,
        domain_available=0,
        domain_total=4,
        domain_cooldown=4,
        settings=s,
    )
    assert "solver.down" in fired
    assert "domain.pool_exhausted" in fired
    fired.clear()
    nh.observe_runtime_edges(
        solver_reachable=False,
        domain_available=0,
        domain_total=4,
        domain_cooldown=4,
        settings=s,
    )
    assert fired == []
    nh.observe_runtime_edges(
        solver_reachable=True,
        domain_available=2,
        domain_total=4,
        domain_cooldown=0,
        settings=s,
    )
    assert "solver.recovered" in fired


def test_notify_api(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    from fastapi.testclient import TestClient
    import web_app as web

    monkeypatch.setattr(
        web.reg,
        "load_config",
        lambda: {
            "notify_enabled": True,
            "notify_telegram_bot_token": "tok",
            "notify_telegram_chat_id": "1",
            "notify_min_level": "info",
            "notify_cooldown_sec": 60,
            "email_provider": "duckmail",
            "register_count": 1,
            "register_threads": 1,
        },
    )
    monkeypatch.setattr(
        web.reg,
        "validate_registration_config",
        lambda s: s,
    )

    def fake_send(token, chat, text, timeout=8.0):
        return {"ok": True, "latency_ms": 3}

    monkeypatch.setattr(nh, "send_telegram", fake_send)
    client = TestClient(web.app)
    st = client.get("/api/notify/status")
    assert st.status_code == 200
    assert st.json()["ok"] is True
    test = client.post("/api/notify/test")
    assert test.status_code == 200
    assert test.json()["ok"] is True
    hist = client.get("/api/notify/history")
    assert hist.status_code == 200
    assert isinstance(hist.json().get("items"), list)
