from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import is_json_endpoint, url_contains_words


class ApiDiscoveryScanner(Scanner):
    name = "API discovery"
    description = "Detects API endpoints and surface area that may require dedicated discovery or testing."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "").lower()
        return "/api" in url or "graphql" in url or is_json_endpoint(endpoint) or url_contains_words(url, ["/rest", "/v1", "/v2", "/json"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        if self.applicable(endpoint):
            self._findings.append({
                "id": f"api-discovery-{endpoint.get('url', '')}",
                "category": "Reconnaissance",
                "title": "API discovery indicator",
                "severity": "Informational",
                "confidence": 75,
                "status": "Informational",
                "url": endpoint.get("url", ""),
                "method": endpoint.get("method", "GET"),
                "parameter": "N/A",
                "evidence": "The endpoint appears to be an API or JSON service endpoint.",
                "explanation": "Public API endpoints represent a valuable attack surface and should be enumerated carefully.",
                "verification_guidance": "Review the API routes and document the available operations and parameters.",
                "impact": "API discovery helps identify endpoints for authentication, authorization, and data exposure testing.",
                "remediation": "Document and protect APIs, enforce proper authentication, and minimize unnecessary public endpoints.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
