from typing import Any, List

from backend.scanners.base import Scanner

class RobotsSitemapScanner(Scanner):
    name = "Robots / Sitemap Discovery"
    description = "Identifies discovery files that may leak unintentional paths or restrictions."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return endpoint.get("url", "").lower().endswith("/robots.txt") or endpoint.get("url", "").lower().endswith("/sitemap.xml")

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        self._findings.append({
            "id": f"robots-sitemap-{endpoint['url']}",
            "category": "Reconnaissance",
            "title": "Robots/sitemap file discovered",
            "severity": "Informational",
            "confidence": 80,
            "status": "Informational",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": "",
            "evidence": "A discovery file such as robots.txt or sitemap.xml was found.",
            "explanation": "Discovery files may expose sensitive endpoints and crawling rules.",
            "verification_guidance": "Inspect the file contents for hidden or disallowed paths.",
            "impact": "Discovery of hidden paths can guide further testing.",
            "remediation": "Keep sensitive paths out of discovery files and use access controls where needed.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
