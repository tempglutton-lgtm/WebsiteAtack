from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, url_contains_words

class IdorBolaScanner(Scanner):
    name = "IDOR/BOLA"
    description = "Flags endpoints that may expose object IDs or account identifiers without sufficient authorization checks."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        path = urlparse(endpoint.get("url", "")).path
        return any(segment.isdigit() for segment in path.split("/")) or url_contains_words(path, ["user", "account", "order", "profile"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        path = urlparse(endpoint.get("url", "")).path
        if any(segment.isdigit() for segment in path.split("/")):
            self._findings.append({
                "id": f"idor-{endpoint['url']}",
                "category": "Access control",
                "title": "IDOR/BOLA indicator",
                "severity": "Medium",
                "confidence": 60,
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": path,
                "evidence": "The URL contains numeric identifiers or account-like path segments.",
                "explanation": "IDOR/BOLA issues occur when identifiers are directly exposed and not checked against requestor identity.",
                "verification_guidance": "Test adjacent resource IDs and verify whether access control is enforced consistently.",
                "impact": "Unauthorized data access or privilege escalation may occur.",
                "remediation": "Validate resource ownership and enforce authorization for each identifier.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
