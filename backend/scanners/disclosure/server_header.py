from typing import Any, List

from backend.scanners.base import Scanner

class ServerHeaderScanner(Scanner):
    name = "Server Header Disclosure"
    description = "Detects the presence of server information leaked through HTTP headers."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        server_header = endpoint.get("headers", {}).get("server")
        if server_header:
            self._findings.append({
                "id": f"server-header-{endpoint['url']}",
                "category": "Information disclosure",
                "title": "Server header disclosure",
                "severity": "Low",
                "confidence": 70,
                "status": "Informational",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": f"The Server header contains: {server_header}",
                "explanation": "Explicit server information in headers can help attackers fingerprint the application stack.",
                "verification_guidance": "Review the response headers for technology or version disclosure.",
                "impact": "Information disclosure can make targeted attacks easier.",
                "remediation": "Remove or generalize server version information from HTTP headers.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
