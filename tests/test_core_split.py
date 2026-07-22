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


def test_email_and_http_live_in_core_modules():
    from core.cancel import sleep_with_cancel
    from core.email import providers as email
    from core.http_client import get_proxies, http_get

    assert reg.get_email_and_token is email.get_email_and_token
    assert reg.get_oai_code is email.get_oai_code
    assert reg.compose_mail_address is email.compose_mail_address
    assert reg.remember_rejected_email_domain is email.remember_rejected_email_domain
    assert reg._rejected_email_domains is email._rejected_email_domains
    assert reg.http_get is http_get
    assert reg.get_proxies is get_proxies
    assert reg.sleep_with_cancel is sleep_with_cancel


def test_turnstile_lives_in_core_module():
    from core.turnstile import solver as turnstile

    assert reg.normalize_turnstile_solver_url is turnstile.normalize_turnstile_solver_url
    assert reg.solve_turnstile_via_local_solver is turnstile.solve_turnstile_via_local_solver
    assert reg.getTurnstileToken is turnstile.getTurnstileToken
    assert reg.scrape_turnstile_sitekey_text is turnstile.scrape_turnstile_sitekey_text
    assert reg.probe_local_turnstile_solver is turnstile.probe_local_turnstile_solver
    assert reg._proxy_for_turnstile_solver is turnstile._proxy_for_turnstile_solver


def test_xai_and_browser_live_in_core_modules():
    from core.browser import lifecycle as browser
    from core.xai import protocol as xai

    assert reg.register_via_pure_http is xai.register_via_pure_http
    assert reg.create_xai_account_via_http is xai.create_xai_account_via_http
    assert reg.resolve_signup_mode is xai.resolve_signup_mode
    assert reg.SIGNUP_URL == xai.SIGNUP_URL
    assert reg.start_browser is browser.start_browser
    assert reg.create_browser_options is browser.create_browser_options
    assert reg.fill_profile_and_submit is browser.fill_profile_and_submit
    assert reg._get_page is browser._get_page


def test_push_lives_in_core_module():
    from core.push import integrations as push

    assert reg.import_accounts_to_sub2api is push.import_accounts_to_sub2api
    assert reg.import_accounts_to_grok2api is push.import_accounts_to_grok2api
    assert reg.import_accounts_to_cpa is push.import_accounts_to_cpa
    assert reg.auto_push_registered_account is push.auto_push_registered_account
    assert reg.export_and_push_cpa_credential is push.export_and_push_cpa_credential
    assert reg.XAI_GROK_OAUTH_CLIENT_ID == push.XAI_GROK_OAUTH_CLIENT_ID


def test_cf_global_and_jobs_live_in_core_modules():
    from core.cf_global import api as cf_global
    from core.jobs import registration as jobs

    assert reg.deploy_cf_email_worker is cf_global.deploy_cf_email_worker
    assert reg.setup_cf_email_catch_all is cf_global.setup_cf_email_catch_all
    assert reg.is_private_or_local_webhook_url is cf_global.is_private_or_local_webhook_url
    assert reg.RegistrationJob is jobs.RegistrationJob
    assert reg.read_job_log_lines is jobs.read_job_log_lines
    assert reg.save_job_snapshot is jobs.save_job_snapshot
