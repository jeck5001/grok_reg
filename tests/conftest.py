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
