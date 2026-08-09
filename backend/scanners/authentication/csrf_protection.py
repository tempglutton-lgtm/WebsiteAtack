from typing import Any, List

from backend.scanners.base import Scanner

class CsrfProtectionScanner(Scanner):
    name = "CSRF Protection"
    description = "Flags forms that may be missing CSRF protection tokens and require manual verification."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("forms"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        forms = endpoint.get("forms", [])
        for index, form in enumerate(forms, start=1):
            field_names = [input.get("name", "").lower() for input in form.get("inputs", []) if input.get("name")]
            if not any(token in field_names for token in ["csrf", "authenticity_token", "xsrf", "csrf_token"]):
                self._findings.append({
                    "id": f"csrf-{endpoint['url']}-{index}",
                    "category": "Authentication/session",
                    "title": "Potential missing CSRF protection",
                    "severity": "Medium",
                    "confidence": 55,
                    "status": "Potential",
                    "url": endpoint["url"],
                    "method": endpoint.get("method", "GET"),
                    "parameter": ", ".join(field_names) or "N/A",
                    "evidence": "A form was found without a recognizable CSRF token field.",
                    "explanation": "Forms should include anti-CSRF tokens to prevent cross-site request forgery attacks.",
                    "verification_guidance": "Review form handling to confirm whether CSRF tokens are required and validated server-side.",
                    "impact": "Missing CSRF protection can allow attackers to trigger state-changing actions from authenticated users.",
                    "remediation": "Implement and validate CSRF tokens for all state-changing forms.",
                })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
