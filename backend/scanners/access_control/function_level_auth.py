from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words

class MissingFunctionLevelAuthorizationScanner(Scanner):
    name = "Missing function-level authorization"
    description = "Flags endpoints that may expose internal or privileged functions without explicit protection."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return url_contains_words(endpoint.get("url", ""), ["admin", "manage", "settings", "config", "internal"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        self._findings.append({
            "id": f"function-auth-{endpoint['url']}",
            "category": "Access control",
            "title": "Missing function-level authorization indicator",
            "severity": "Medium",
            "confidence": 50,
            "status": "Needs Manual Verification",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": "",
            "evidence": "Endpoint path contains privileged or internal action keywords.",
            "explanation": "Sensitive functions should require explicit authorization checks beyond basic URL access.",
            "verification_guidance": "Review access rules for the endpoint and validate that role checks are enforced.",
            "impact": "Unauthorized users may reach privileged functionality.",
            "remediation": "Apply least-privilege authorization logic at the function level.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
