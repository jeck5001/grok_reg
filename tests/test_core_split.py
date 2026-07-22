"""Guards for the core package split + replace_config identity contract."""

from pathlib import Path

import grok_register_ttk as reg
from core.exceptions import (
    EmailDomainRejected,
    EmailProviderUnavailable,
    ProfileSessionLost,
    RegistrationCancelled,
    StaleNextActionError,
)
from core.paths import (
    APP_DIR,
    get_account_status_file,
    get_config_file,
    get_data_dir,
    get_rejected_email_domains_file,
)
from core.runtime import (
    _env_truthy,
    normalize_proxy_for_runtime,
    should_apply_container_chrome_flags,
    should_run_headless,
)


def test_exceptions_reexported_from_facade():
    assert reg.RegistrationCancelled is RegistrationCancelled
    assert reg.EmailDomainRejected is EmailDomainRejected
    assert reg.EmailProviderUnavailable is EmailProviderUnavailable
    assert reg.ProfileSessionLost is ProfileSessionLost
    assert reg.StaleNextActionError is StaleNextActionError


def test_paths_reexported_from_facade():
    assert reg.APP_DIR == APP_DIR
    assert Path(reg.APP_DIR).name == "grok_reg" or Path(reg.APP_DIR).is_dir()
    assert reg.get_data_dir is get_data_dir
    assert reg.get_config_file is get_config_file
    assert reg.get_account_status_file is get_account_status_file
    assert reg.get_rejected_email_domains_file is get_rejected_email_domains_file


def test_runtime_reexported_from_facade():
    assert reg.normalize_proxy_for_runtime is normalize_proxy_for_runtime
    assert reg._env_truthy is _env_truthy
    assert reg.should_run_headless is should_run_headless
    assert reg.should_apply_container_chrome_flags is should_apply_container_chrome_flags


def test_replace_config_keeps_dict_identity():
    original = reg.config
    reg.replace_config({**reg.DEFAULT_CONFIG, "proxy": "http://identity-check:9"})
    assert reg.config is original
    assert reg.config["proxy"] == "http://identity-check:9"
    # restore from disk/default for other tests
    reg.load_config()
    assert reg.config is original


def test_load_config_keeps_dict_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("GROK_REG_DATA_DIR", str(tmp_path))
    original = reg.config
    (tmp_path / "config.json").write_text(
        '{"proxy": "http://from-disk:1", "email_provider": "duckmail"}',
        encoding="utf-8",
    )
    loaded = reg.load_config()
    assert loaded is original
    assert reg.config is original
    assert reg.config["proxy"] == "http://from-disk:1"


def test_config_lives_in_core_module():
    import core.config as cfg

    assert reg.config is cfg.config
    assert reg.DEFAULT_CONFIG is cfg.DEFAULT_CONFIG
    assert reg.load_config is cfg.load_config
    assert reg.save_config is cfg.save_config
    assert reg.replace_config is cfg.replace_config
    assert reg.validate_registration_config is cfg.validate_registration_config


def test_accounts_store_lives_in_core_module():
    from core.accounts import store as accounts

    assert reg.list_registered_accounts is accounts.list_registered_accounts
    assert reg.query_registered_accounts is accounts.query_registered_accounts
    assert reg.delete_registered_accounts is accounts.delete_registered_accounts
    assert reg.parse_registered_account_line is accounts.parse_registered_account_line
    assert reg.persist_sub2api_push_status is accounts.persist_sub2api_push_status
    assert reg._registered_accounts_lock is accounts._registered_accounts_lock
    assert reg._account_id is accounts._account_id
