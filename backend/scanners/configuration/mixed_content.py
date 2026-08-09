from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class MixedContentScanner(Scanner):
    name = "Mixed content"
    description = "Detects pages or endpoints that may include insecure HTTP resources alongside HTTPS." 

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return endpoint.get("body") is not None and endpoint.get("url", "").startswith("https://")

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        body = endpoint.get("body", "")
        insecure_sources = ["http://"]
        found = [src for src in insecure_sources if src in body]

        if not found:
            return []

        self._findings.append({
            "id": f"mixed-content-{endpoint.get('url', '')}",
            "category": "Configuration",
            "title": "Mixed content indicator",
            "severity": "Medium",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": endpoint.get("url", ""),
            "method": endpoint.get("method", "GET"),
            "parameter": "body",
            "evidence": f"Page includes insecure resources: {', '.join(found)}.",
            "explanation": "HTTPS pages loading HTTP resources can allow attackers to intercept or modify those assets.",
            "verification_guidance": "Inspect the page for insecure script, image, or stylesheet references.",
            "impact": "Mixed content breaks security guarantees and can expose page content to tampering.",
            "remediation": "Use HTTPS URLs for all included resources on secure pages.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
