from typing import Any, List

from backend.scanners.base import Scanner

class StoredXssScanner(Scanner):
    name = "Stored XSS"
    description = "Detects input-bearing forms that may store user input and later render it unsafely."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("forms"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        forms = endpoint.get("forms", [])
        if not forms:
            return []

        parameters = [input.get("name") for form in forms for input in form.get("inputs", []) if input.get("name")]
        if not parameters:
            return []

        self._findings.append({
            "id": f"stored-xss-{endpoint['url']}",
            "category": "Client-side",
            "title": "Stored XSS indicator",
            "severity": "Medium",
            "confidence": 45,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(parameters),
            "evidence": "The page contains forms that may persist user-submitted values for later rendering.",
            "explanation": "Stored XSS can occur when stored user input is rendered back to users without proper escaping or sanitization.",
            "verification_guidance": "Submit a safe string and monitor later pages or dashboards for echoed content.",
            "impact": "Stored XSS can execute scripts for multiple users when unsafe stored content is viewed.",
            "remediation": "Sanitize and encode all stored user content before rendering it in HTML contexts.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
