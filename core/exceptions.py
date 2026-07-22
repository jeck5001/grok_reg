"""Shared registration / email exceptions."""


class RegistrationCancelled(Exception):
    pass


class EmailDomainRejected(Exception):
    def __init__(self, domain):
        self.domain = str(domain or "").strip().lower()
        super().__init__(f"邮箱域名被 x.ai 拒收: {self.domain or 'unknown'}")


class EmailProviderUnavailable(Exception):
    pass


class ProfileSessionLost(Exception):
    pass


class StaleNextActionError(Exception):
    """next-action / server action 已过期（HTTP 404 Server action not found）。"""

    pass
