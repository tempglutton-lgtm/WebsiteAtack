from typing import Any, List

from backend.scanners.base import Scanner

class ClickjackingScanner(Scanner):
    name = "Clickjacking"
    description = "Detects missing frame-embedding protection headers that may expose the site to clickjacking."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        headers = endpoint.get("headers", {})
        x_frame_options = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        csp_has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not x_frame_options and not csp_has_frame_ancestors:
            self._findings.append({
                "id": f"clickjacking-{endpoint['url']}",
                "category": "Client-side",
                "title": "Clickjacking protection missing",
                "severity": "Low",
                "confidence": 70,
                "status": "Potential",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": "Response does not include X-Frame-Options or CSP frame-ancestors directives.",
                "explanation": "Without frame-embedding protection headers, pages can be embedded in attacker-controlled frames.",
                "verification_guidance": "Verify whether the page can be framed by an attacker-controlled site.",
                "impact": "Clickjacking can trick users into performing unintended actions.",
                "remediation": "Set X-Frame-Options or Content-Security-Policy frame-ancestors directives.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
