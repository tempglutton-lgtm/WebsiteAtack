from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner

class MethodAccessControlScanner(Scanner):
    name = "Method Access Control"
    description = "Detects endpoints that may expose unsafe HTTP methods or lack proper method restrictions."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return True

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        path = urlparse(endpoint.get("url", "")).path.lower()
        if any(keyword in path for keyword in ["delete", "update", "remove", "admin", "config"]):
            self._findings.append({
                "id": f"method-access-{endpoint['url']}",
                "category": "Access control",
                "title": "Method access control indicator",
                "severity": "Medium",
                "confidence": 55,
                "status": "Potential",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": "This endpoint path suggests privileged or state-changing functionality.",
                "explanation": "Sensitive operations should restrict HTTP methods and enforce authorization.",
                "verification_guidance": "Check whether the endpoint accepts unsafe methods and whether proper authentication is enforced.",
                "impact": "Weak method controls can lead to unauthorized data modification or deletion.",
                "remediation": "Enforce strict method checking and authorization for sensitive routes.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
