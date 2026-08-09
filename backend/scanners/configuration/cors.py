from typing import Any, List

from backend.scanners.base import Scanner

class CorsScanner(Scanner):
    name = "CORS Configuration"
    description = "Detects permissive CORS headers that may expose the site to cross-origin abuse."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        headers = endpoint.get("headers", {})
        origin = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "")
        if origin == "*" or "http://" in origin or "https://" in origin:
            self._findings.append({
                "id": f"cors-{endpoint['url']}",
                "category": "Configuration",
                "title": "Permissive CORS policy",
                "severity": "Low",
                "confidence": 60,
                "status": "Potential",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": f"CORS header exposed: Access-Control-Allow-Origin: {origin}",
                "explanation": "A permissive CORS configuration can allow untrusted origins to access responses in a browser.",
                "verification_guidance": "Inspect response headers and verify whether the site allows too many origins or unsafe credentials behavior.",
                "impact": "Permissive CORS may expose sensitive data to attacker-controlled web pages.",
                "remediation": "Restrict allowed origins and avoid unsafe wildcard settings unless necessary.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
