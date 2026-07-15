import time

import mail_domain_pool as mdp


def setup_function():
    mdp.reset_runtime()


def test_parse_and_compose_subdomain():
    domains = mdp.parse_domain_list("a.com, b.net，c.org")
    assert domains == ["a.com", "b.net", "c.org"]
    addr = mdp.compose_email_address(
        "a.com",
        enable_sub_domains=True,
        sub_domain_level=2,
        local_part="user01",
    )
    assert addr.startswith("user01@")
    assert addr.endswith(".a.com")
    assert addr.count(".") >= 3  # user@x.y.a.com


def test_pinpoint_burst_sticks_to_one_domain():
    domains = ["a.com", "b.com", "c.com"]
    first = mdp.pick_main_domain(domains, pinpoint_burst=True, prefer_low_failure=True)
    second = mdp.pick_main_domain(domains, pinpoint_burst=True, prefer_low_failure=True)
    third = mdp.pick_main_domain(domains, pinpoint_burst=True, prefer_low_failure=True)
    assert first == second == third


def test_cooldown_skips_domain():
    domains = ["a.com", "b.com"]
    mdp.mark_domain_failure("a.com", threshold=2, cooldown_sec=60)
    mdp.mark_domain_failure("a.com", threshold=2, cooldown_sec=60)
    assert mdp.is_domain_cooling("a.com")
    picked = {mdp.pick_main_domain(domains, prefer_low_failure=False) for _ in range(5)}
    assert "a.com" not in picked
    assert "b.com" in picked


def test_main_domain_of_subdomain_email():
    assert mdp.main_domain_of("u@x.y.a.com", ["a.com", "b.com"]) == "a.com"
