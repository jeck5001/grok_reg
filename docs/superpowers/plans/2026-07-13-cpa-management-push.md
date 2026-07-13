# CPA Management API Push Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate a CPA-compatible xAI credential from a successful registration and optionally upload it to the remote CPA Management API.

**Architecture:** The registration flow already obtains an xAI OAuth refresh token. A small helper in `grok_register_ttk.py` exchanges it for an access token, atomically writes `xai-<email>.json`, then uploads that exact file with multipart form data to CPA's Management API. The Web console persists and masks remote-push settings; remote failures are logged but never change registration success.

**Tech Stack:** Python 3.14, FastAPI, `curl_cffi`, pytest, httpx TestClient.

---

### Task 1: CPA Credential and Upload Helpers

**Files:**
- Modify: `grok_register_ttk.py:70-110`, `grok_register_ttk.py:1709-1732`
- Test: `tests/test_registration_job.py`

- [ ] **Step 1: Write failing tests**

```python
def test_push_cpa_credential_writes_and_uploads_management_auth_file(monkeypatch, tmp_path):
    captured = {}

    class Response:
        status_code = 201
        text = '{"status":"ok"}'

        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        captured["filename"] = kwargs["files"]["file"][0]
        return Response()

    monkeypatch.setattr(reg, "http_post", fake_post)
    monkeypatch.setattr(reg, "exchange_xai_refresh_token", lambda token, settings=None: {
        "access_token": "access-token", "refresh_token": "rotated-refresh-token"
    })

    result = reg.export_and_push_cpa_credential(
        "user@example.com", "refresh-token", {
            "cpa_auth_dir": str(tmp_path),
            "cpa_auto_push_remote": True,
            "cpa_management_base": "https://cpa.example.test/v0/management",
            "cpa_management_key": "management-secret",
        },
    )

    assert result["ok"] is True
    assert captured["url"] == "https://cpa.example.test/v0/management/auth-files"
    assert captured["headers"]["Authorization"] == "Bearer management-secret"
    assert captured["filename"] == "xai-user@example.com.json"
    assert json.loads(tmp_path.joinpath(captured["filename"]).read_text())["refresh_token"] == "rotated-refresh-token"


def test_push_cpa_credential_keeps_local_file_when_remote_upload_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(reg, "exchange_xai_refresh_token", lambda token, settings=None: {
        "access_token": "access-token", "refresh_token": "refresh-token"
    })
    monkeypatch.setattr(reg, "http_post", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("network down")))

    result = reg.export_and_push_cpa_credential(
        "user@example.com", "refresh-token", {
            "cpa_auth_dir": str(tmp_path),
            "cpa_auto_push_remote": True,
            "cpa_management_base": "https://cpa.example.test",
            "cpa_management_key": "management-secret",
        },
    )

    assert result["ok"] is True
    assert result["upload_error"] == "network down"
    assert tmp_path.joinpath("xai-user@example.com.json").is_file()
```

- [ ] **Step 2: Run the new tests and verify they fail because the helper does not exist**

Run: `python3 -m pytest tests/test_registration_job.py -k cpa -q`

Expected: FAIL with `AttributeError` for `export_and_push_cpa_credential`.

- [ ] **Step 3: Implement the minimum helper surface**

Add default settings `cpa_auth_dir`, `cpa_auto_push_remote`, `cpa_management_base`, and `cpa_management_key`. Implement a base URL normalizer that produces exactly `<base>/v0/management/auth-files`, CPA payload serialization with `type`, OAuth tokens, standard xAI endpoint metadata, atomic `0600` local writing, and a multipart `file` upload. Return `{ok: True, path: ...}` after a local write; append `upload_error` on remote failure.

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `python3 -m pytest tests/test_registration_job.py -k cpa -q`

Expected: PASS.

### Task 2: Registration and Web Configuration Integration

**Files:**
- Modify: `grok_register_ttk.py:2717-2768`, `grok_register_ttk.py:2903-2946`
- Modify: `web_app.py:12-45` and embedded configuration form
- Test: `tests/test_registration_job.py`, `tests/test_web_app.py`

- [ ] **Step 1: Write failing tests**

```python
def test_registration_pushes_cpa_after_refresh_token_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(reg, "open_signup_page", lambda **kwargs: None)
    monkeypatch.setattr(reg, "fill_email_and_submit", lambda **kwargs: ("user@example.com", "mail-token"))
    monkeypatch.setattr(reg, "fill_code_and_submit", lambda *args, **kwargs: "123456")
    monkeypatch.setattr(reg, "fill_profile_and_submit", lambda **kwargs: {"given_name": "Ada", "family_name": "Lovelace", "password": "secret"})
    monkeypatch.setattr(reg, "wait_for_sso_cookie", lambda **kwargs: "sso-token")
    monkeypatch.setattr(reg, "fetch_xai_oauth_refresh_token", lambda *args, **kwargs: "refresh-token")
    monkeypatch.setattr(reg, "add_token_to_grok2api_pools", lambda *args, **kwargs: None)
    monkeypatch.setattr(reg, "auto_push_registered_account", lambda *args, **kwargs: None)
    pushed = []
    monkeypatch.setattr(reg, "export_and_push_cpa_credential", lambda email, refresh_token, settings, log_callback=None: pushed.append((email, refresh_token, settings)) or {"ok": True})

    job = reg.RegistrationJob({
        "email_provider": "duckmail",
        "register_count": 1,
        "register_threads": 1,
        "cpa_auto_push_remote": True,
        "cpa_management_base": "https://cpa.example.test",
        "cpa_management_key": "management-secret",
    })
    job._run_single_registration(1, 1, lambda message: None)

    assert pushed[0][0] == "user@example.com"
    assert pushed[0][1] == "refresh-token"


def test_cpa_management_config_masks_management_key(monkeypatch, tmp_path):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    client = TestClient(app)

    response = client.put("/api/config", json={
        "email_provider": "duckmail",
        "cpa_auto_push_remote": True,
        "cpa_management_base": "https://cpa.example.test",
        "cpa_management_key": "management-secret",
        "register_count": 1,
        "register_threads": 1,
    })

    assert response.status_code == 200
    assert response.json()["cpa_management_key"] == "********"
    assert "management-secret" in tmp_path.joinpath("config.json").read_text(encoding="utf-8")
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python3 -m pytest tests/test_registration_job.py tests/test_web_app.py -k cpa -q`

Expected: FAIL because the registration flow never invokes the new helper and the key is not masked.

- [ ] **Step 3: Implement configuration and job integration**

Normalize the enable flag and require a base plus key only when CPA auto-push is enabled. Add the key to `SENSITIVE_KEYS`; add the base, key, destination folder, and toggle to the existing Web settings form. After `fetch_xai_oauth_refresh_token` succeeds, call the helper in a `try` block. Log CPA push completion or failure and continue the account registration in both cases.

- [ ] **Step 4: Run focused integration tests and verify they pass**

Run: `python3 -m pytest tests/test_registration_job.py tests/test_web_app.py -k cpa -q`

Expected: PASS.

### Task 3: Regression Verification and Documentation

**Files:**
- Modify: `README.md`
- Test: `tests/test_registration_job.py`, `tests/test_web_app.py`

- [ ] **Step 1: Document CPA Management API configuration**

Add a concise configuration note naming the base URL, Management API key, and auto-push toggle. State the upload target as `POST /v0/management/auth-files` with `Authorization: Bearer ...` and clarify that failed uploads retain the local credential and do not fail registration.

- [ ] **Step 2: Run the complete suite**

Run: `python3 -m pytest -q`

Expected: PASS with all tests green.

- [ ] **Step 3: Inspect the final change set**

Run: `git diff --check && git diff -- grok_register_ttk.py web_app.py tests/test_registration_job.py tests/test_web_app.py README.md`

Expected: no whitespace errors and no management key or credential content in logs or documentation.
