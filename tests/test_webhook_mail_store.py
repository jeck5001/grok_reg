import webhook_mail_store as wms


def setup_function():
    wms.clear()


def test_store_and_pop_xai_code():
    raw = """
    From: no-reply@x.ai
    Subject: ABC-123 xAI confirmation code
    To: user@sub.a.com

    Your confirmation code is DEF-456
    """
    r = wms.store_webhook_mail(
        to_addr="user@sub.a.com",
        raw_content=raw,
        message_id="mid-1",
    )
    assert r["ok"] is True
    code = wms.pop_code_for_email("user@sub.a.com")
    assert code
    assert "DEF" in code.upper() or "ABC" in code.upper() or len(code.replace("-", "")) >= 6
    # consumed
    assert wms.pop_code_for_email("user@sub.a.com") is None


def test_dedup_message_id():
    raw = "code is 123456 for verification"
    a = wms.store_webhook_mail(to_addr="a@b.com", raw_content=raw, message_id="same")
    b = wms.store_webhook_mail(to_addr="a@b.com", raw_content=raw, message_id="same")
    assert a.get("dedup") is False
    assert b.get("dedup") is True


def test_peek_code_does_not_consume():
    raw = "SpaceXAI confirmation code: ZZ1-YY2"
    wms.store_webhook_mail(to_addr="p@e.com", raw_content=raw, message_id="peek-1")
    c1 = wms.peek_code_for_email("p@e.com")
    c2 = wms.peek_code_for_email("p@e.com")
    assert c1
    assert c1 == c2
    assert wms.stats()["mails"] >= 1
    assert "recent" in wms.stats()
