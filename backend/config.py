from dataclasses import dataclass
from typing import Optional

@dataclass
class CrawlConfig:
    max_depth: int = 3
    max_pages: int = 100
    timeout_seconds: int = 15
    concurrency: int = 4
    rate_limit_per_second: float = 2.0

from dataclasses import field

@dataclass
class ScanConfig:
    target_url: str
    agree_to_authorization: bool
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    include_subdomains: bool = False
    test_accounts: Optional[list[dict]] = None
