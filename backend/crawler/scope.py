from urllib.parse import urlparse, urljoin

class ScopeValidationError(ValueError):
    pass

class TargetScope:
    def __init__(self, target_url: str, include_subdomains: bool = False):
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeValidationError("Target URL must use http or https.")
        if not parsed.netloc:
            raise ScopeValidationError("Target URL must contain a valid host.")

        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.netloc = parsed.netloc
        self.base_url = f"{self.scheme}://{self.netloc}"
        self.include_subdomains = include_subdomains

    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(urljoin(self.base_url, url))
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        if self.include_subdomains:
            return parsed.hostname == self.host or parsed.hostname.endswith(f".{self.host}")
        return parsed.hostname == self.host

    def normalize(self, url: str) -> str:
        return urljoin(self.base_url, url)
