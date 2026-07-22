"""Data-directory and well-known file paths."""

from __future__ import annotations

import os

# Package parent is the project / app root (same as former APP_DIR on the monolith).
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_data_dir():
    data_dir = os.environ.get("GROK_REG_DATA_DIR", APP_DIR)
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def get_config_file():
    return os.path.join(get_data_dir(), "config.json")


def get_account_status_file():
    return os.path.join(get_data_dir(), "account_status.json")


def get_rejected_email_domains_file():
    return os.path.join(get_data_dir(), "rejected_email_domains.json")
