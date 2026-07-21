import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def no_real_nsfw_request(monkeypatch):
    import grok_register_ttk as reg

    monkeypatch.setattr(
        reg,
        "enable_nsfw_for_token",
        lambda token, cf_clearance="", log_callback=None: (True, "ok"),
    )


@pytest.fixture(autouse=True)
def disable_web_auth_for_tests(monkeypatch):
    """单测默认关闭 Web 密码，避免每个 client 都要先登录。"""
    monkeypatch.setenv("GROK_REG_WEB_PASSWORD", "")


@pytest.fixture(autouse=True)
def reset_web_job_state():
    """隔离 web_app 进程内任务全局状态，避免用例互相污染。"""
    import web_app

    with web_app._job_lock:
        web_app._jobs.clear()
        web_app._active_job_id = None
    web_app._AUTH_SESSIONS.clear()
    web_app._login_fail_count.clear()
    web_app._login_fail_until.clear()
    yield
    with web_app._job_lock:
        # 尽量停掉残留线程标记
        for job in list(web_app._jobs.values()):
            try:
                if hasattr(job, "stop"):
                    job.stop()
            except Exception:
                pass
        web_app._jobs.clear()
        web_app._active_job_id = None
