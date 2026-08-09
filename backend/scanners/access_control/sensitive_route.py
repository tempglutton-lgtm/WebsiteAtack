from typing import Any, List

from backend.scanners.base import Scanner

class SensitiveRouteScanner(Scanner):
    name = "Sensitive Route Discovery"
    description = "Identifies likely administrative, authentication, or management routes for access control review."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return True

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        path = endpoint.get("url", "").lower()
        hints = ["admin", "login", "logout", "signup", "register", "reset", "management", "dashboard", "account"]
        if any(hint in path for hint in hints):
            self._findings.append({
                "id": f"sensitive-route-{endpoint['url']}",
                "category": "Access control",
                "title": "Sensitive route discovered",
                "severity": "Informational",
                "confidence": 75,
                "status": "Informational",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": f"The path contains sensitive keywords such as {', '.join([hint for hint in hints if hint in path])}.",
                "explanation": "Endpoints with administrative or authentication keywords should be manually reviewed for access control weaknesses.",
                "verification_guidance": "Verify that only authorized users can access these paths and that session controls are enforced.",
                "impact": "Unauthenticated access to sensitive routes can expose management interfaces or user data.",
                "remediation": "Protect sensitive endpoints with authentication and authorization checks.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
