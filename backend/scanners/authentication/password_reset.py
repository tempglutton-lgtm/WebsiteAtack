from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, url_contains_words


class PasswordResetWorkflowScanner(Scanner):
    name = "Password-reset workflow weaknesses"
    description = "Detects password reset and forgotten password flows that may require manual review."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        return url_contains_words(url, ["reset", "forgot", "password"]) or any(
            field in ["reset_token", "token", "email", "username"] for field in [name.lower() for name in all_input_names(endpoint)]
        )

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        field_names = [name.lower() for name in all_input_names(endpoint)]

        if self.applicable(endpoint):
            evidence_parts = []
            if url_contains_words(url, ["reset", "forgot", "password"]):
                evidence_parts.append("The URL references password reset or forgotten password functionality.")
            if any(field in field_names for field in ["reset_token", "token", "email", "username"]):
                evidence_parts.append("The endpoint exposes password reset-related form fields.")

            self._findings.append({
                "id": f"password-reset-{url}",
                "category": "Authentication/session",
                "title": "Password-reset workflow weakness indicator",
                "severity": "Medium",
                "confidence": 50,
                "status": "Needs Manual Verification",
                "url": url,
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(field_names) or "N/A",
                "evidence": " ".join(evidence_parts) or "Password reset workflow detected.",
                "explanation": "Password reset flows are frequent targets for abuse and should be reviewed for token handling and account verification.",
                "verification_guidance": "Review password reset tokens, recovery flow, and whether account enumeration or weak reset links are possible.",
                "impact": "Weak password reset workflows can lead to account takeover or information disclosure.",
                "remediation": "Harden reset tokens, enforce expiration, and avoid exposing account enumeration through reset feedback.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
