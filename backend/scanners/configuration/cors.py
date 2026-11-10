from typing import Any, List

from backend.scanners.base import Scanner

class CorsScanner(Scanner):
    name = "CORS Configuration"
    description = "Detects permissive CORS headers that may expose the site to cross-origin abuse."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        headers = endpoint.get("headers", {})
        origin = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "")
        if origin.strip() == "*":
            self._findings.append({
                "id": f"cors-{endpoint['url']}",
                "category": "Configuration",
                "title": "CORS wildcard policy observed",
                "severity": "Informational",
                "confidence": 100,
                "status": "Informational",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": (
                    "Access-Control-Allow-Origin is '*'; this alone does not establish "
                    "a vulnerability or permit credentialed cross-origin reads."
                ),
                "explanation": "A wildcard origin may be intentional for public resources and is not proof of sensitive data exposure.",
                "verification_guidance": "Manually test the exact endpoint and data classification in an authorized browser context; assess credentials and origin behavior.",
                "impact": "No impact is confirmed by this header alone.",
                "remediation": "No change is required solely because a public endpoint uses a wildcard; restrict origins only when the resource requires it.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
