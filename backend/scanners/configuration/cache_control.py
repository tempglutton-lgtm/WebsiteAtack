from typing import Any, List
from urllib.parse import urlsplit

from backend.scanners.base import Scanner


SENSITIVE_PATH_SEGMENTS = {
    "account",
    "admin",
    "checkout",
    "login",
    "logout",
    "password",
    "profile",
    "session",
}


class CacheControlScanner(Scanner):
    name = "Cache-control issues"
    description = "Detects cache-control misconfigurations that may expose sensitive data or cache unsafe content."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers")) or bool(endpoint.get("url"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        headers = {
            str(key).lower(): str(value)
            for key, value in endpoint.get("headers", {}).items()
        }
        url = endpoint.get("url", "")
        cache = headers.get("cache-control", "")
        evidence = []
        path_segments = {
            segment.lower()
            for segment in urlsplit(url).path.split("/")
            if segment
        }
        looks_sensitive = bool(path_segments & SENSITIVE_PATH_SEGMENTS)
        directives = {
            part.strip().split("=", 1)[0].strip().lower()
            for part in cache.split(",")
            if part.strip()
        }

        if looks_sensitive and not cache:
            evidence.append(
                "Path name suggests potentially sensitive content, but no Cache-Control policy was observed."
            )
        elif looks_sensitive and not directives & {"no-store", "private"}:
            evidence.append(
                f"Potentially sensitive path has no no-store/private directive: {cache}"
            )

        if not evidence:
            return []

        self._findings.append({
            "id": f"cache-control-{url}",
            "category": "Configuration",
            "title": "Cache policy review recommended",
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
