from urllib.parse import urlparse, urljoin

class ScopeValidationError(ValueError):
    pass

class TargetScope:
    def __init__(self, target_url: str, include_subdomains: bool = False):
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeValidationError("Target URL must use http or https.")
        if not parsed.netloc or not parsed.hostname:
            raise ScopeValidationError("Target URL must contain a valid host.")
        if parsed.username or parsed.password:
            raise ScopeValidationError("Target URL must not contain embedded credentials.")

        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.netloc = parsed.netloc
        try:
            self.port = parsed.port or (443 if self.scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeValidationError("Target URL contains an invalid port.") from exc
        self.base_url = f"{self.scheme}://{self.netloc}"
        self.include_subdomains = include_subdomains

    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(urljoin(self.base_url, url))
        if (
            parsed.scheme != self.scheme
            or parsed.username
            or parsed.password
            or not parsed.hostname
        ):
            return False
        if not parsed.netloc:
            return False
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False
        if port != self.port:
            return False
        if self.include_subdomains:
            return parsed.hostname == self.host or parsed.hostname.endswith(f".{self.host}")
        return parsed.hostname == self.host

    def normalize(self, url: str) -> str:
        return urljoin(self.base_url, url)
