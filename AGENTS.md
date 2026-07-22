# Agent / contributor notes (grok_reg)

## Layout

- **`web_app.py`** — FastAPI console (war room, accounts, jobs, CF helpers).
- **`grok_register_ttk.py`** — **compatibility facade** only: re-exports `core.*`, holds a few leftovers (page JS strings, NSFW, Tk GUI). Prefer new code under `core/`.
- **`core/`** — real implementation packages (accounts, email, turnstile, xai, browser, push, cf_global, jobs, …).
- **`mail_domain_pool.py` / `notify_hub.py` / `webhook_mail_store.py`** — standalone helpers (do not import jobs).

## Public API contract

Callers (including tests) use:

```python
import grok_register_ttk as reg
```

`reg.X` must keep working. When moving code into `core/`:

1. **Re-export** the symbol from the facade.
2. **Do not** break `reg.config` identity — always mutate via `reg.replace_config(...)` / `core.config.replace_config`, never `reg.config = new_dict`.
3. Prefer **`monkeypatch.setattr(reg, "name", ...)`** over patching `core.*` internals.

## Facade resolution (`_resolve`)

Several `core` modules (email, browser, push, jobs, …) resolve callables through the facade so tests can patch `reg.foo`:

```python
def _resolve(name, default):
    fac = sys.modules.get("grok_register_ttk")
    if fac is not None and hasattr(fac, name):
        val = getattr(fac, name)
        # Skip if fac only re-exports *this* module (avoids recursion)
        if callable(default) and callable(val) and getattr(val, "__module__", "") == __name__:
            return default
        if val is not None:
            return val
    return default
```

**Rules when adding wrappers:**

- Never re-export a stub from `core.X` that `_resolve`s back to the same stub via facade (infinite recursion).
- If facade re-exports `core.X.fn`, the real implementation must be the default argument to `_resolve`, and the recursion guard above must stay.
- Mutable module state used by tests (`reg._yyds_domain_index`, `reg._turnstile_solver_fail_until`, `reg._rejected_email_domains`) must update **facade attributes** or shared objects, not a disconnected copy of an `int`.

## Config

- Canonical dict: `core.config.config` (same object as `reg.config` after import).
- Load/save: `load_config` / `save_config` / `replace_config`.
- Data dir: `GROK_REG_DATA_DIR` (default project root; Docker `/app/data`).

## Tests

- Default: `pytest tests/ -q`
- Runtime data is gitignored; tests should use `tmp_path` + `GROK_REG_DATA_DIR`.
- Account **list** API is **compact** (drops `*_response` / `*_error` bodies). Assert large detail fields on the **import/action response**, not only on `GET /api/accounts`.

## Do not commit

- `config.json`, `accounts_*.txt`, `jobs/`, `local_data/`, `oauth_debug_*`, `cpa_auths/`, `.omo/`, `.workbuddy/`
