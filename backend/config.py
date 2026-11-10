from dataclasses import dataclass
from typing import Optional

@dataclass
class CrawlConfig:
    max_depth: int = 5
    max_pages: int = 200
    timeout_seconds: int = 15
    concurrency: int = 4
    rate_limit_per_second: float = 2.0

from dataclasses import field

@dataclass
class AuthWorkflowConfig:
    login_url: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    success_indicator: Optional[str] = None

    def is_configured(self) -> bool:
        return bool(str(self.login_url or "").strip()) and bool(str(self.username_field or "").strip()) and bool(str(self.password_field or "").strip())

    def to_login_payload(self, username: str, password: str, extra_fields: Optional[dict] = None) -> dict:
        payload = {}
        if extra_fields:
            payload.update({str(key): value for key, value in extra_fields.items() if key is not None})
        payload[str(self.username_field or "username")] = username
        payload[str(self.password_field or "password")] = password
        return payload


@dataclass
class ScanConfig:
    target_url: str
    agree_to_authorization: bool
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    include_subdomains: bool = False
    test_accounts: Optional[list[dict]] = None
    auth: AuthWorkflowConfig = field(default_factory=AuthWorkflowConfig)
