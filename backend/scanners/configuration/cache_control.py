from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class CacheControlScanner(Scanner):
    name = "Cache-control issues"
    description = "Detects cache-control misconfigurations that may expose sensitive data or cache unsafe content."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers")) or bool(endpoint.get("url"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        headers = {k.lower(): v for k, v in endpoint.get("headers", {}).items()}
        url = endpoint.get("url", "")
        cache = headers.get("cache-control", "")
        evidence = []

        if not cache and any(url_contains_words(url, ["login", "logout", "password", "admin", "account", "api"])):
            evidence.append("Sensitive endpoint does not specify a cache-control policy.")
        if cache and "no-store" not in cache.lower() and any(url_contains_words(url, ["login", "logout", "password", "admin", "account"])):
            evidence.append(f"Sensitive endpoint cache-control may not prevent storage: {cache}")
        if cache and "max-age" in cache.lower() and "no-store" not in cache.lower() and "private" not in cache.lower():
            evidence.append(f"Cache-control may allow public caching: {cache}")

        if not evidence:
            return []

        self._findings.append({
            "id": f"cache-control-{url}",
            "category": "Configuration",
            "title": "Cache-control configuration issue",
            "severity": "Low",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": "Cache-Control",
            "evidence": " ".join(evidence),
            "explanation": "Incorrect cache-control settings can cause sensitive data to be stored in shared caches or browser history.",
            "verification_guidance": "Verify cache-control directives on sensitive pages and API responses.",
            "impact": "Improper caching may expose private data to unintended viewers.",
            "remediation": "Use no-store and private directives for sensitive content and avoid public caching of authenticated responses.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
