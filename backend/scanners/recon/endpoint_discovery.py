from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class EndpointDiscoveryScanner(Scanner):
    name = "Endpoint discovery"
    description = "Flags endpoints likely discovered through reconnaissance and enumeration."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        path = endpoint.get("url", "").lower()
        return any(url_contains_words(path, ["admin", "dashboard", "login", "logout", "api", "graphql", "config", "backup", "secret", "wp-", ".git", ".env"]))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        path = endpoint.get("url", "")
        findings = []
        if self.applicable(endpoint):
            self._findings.append({
                "id": f"endpoint-discovery-{path}",
                "category": "Reconnaissance",
                "title": "Endpoint discovery indicator",
                "severity": "Informational",
                "confidence": 70,
                "status": "Informational",
                "url": path,
                "method": endpoint.get("method", "GET"),
                "parameter": "N/A",
                "evidence": "The endpoint URL contains sensitive discovery-related keywords.",
                "explanation": "Endpoints with login, admin, API, or hidden file patterns are common targets for reconnaissance.",
                "verification_guidance": "Review whether discovered endpoints are intended to be publicly accessible or should be protected.",
                "impact": "Discovered endpoints can guide attackers toward sensitive functionality or hidden resources.",
                "remediation": "Restrict access to administrative and hidden endpoints and avoid exposing them unnecessarily.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
