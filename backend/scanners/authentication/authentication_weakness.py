from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, url_contains_words


class AuthenticationWeaknessScanner(Scanner):
    name = "Authentication weaknesses"
    description = "Flags likely authentication-related endpoints and common weak authentication patterns."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        if url_contains_words(url, ["login", "signin", "register", "signup", "auth", "logout", "password", "reset"]):
            return True
        field_names = [name.lower() for name in all_input_names(endpoint)]
        return any(name in field_names for name in ["username", "user", "email", "password"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        parsed = urlparse(url)
        field_names = [name.lower() for name in all_input_names(endpoint)]

        if self.applicable(endpoint):
            evidence_parts = []
            if url_contains_words(url, ["login", "signin", "auth", "register", "signup", "logout", "password", "reset"]):
                evidence_parts.append("The URL contains authentication-related path segments.")
            if any(name in field_names for name in ["username", "user", "email", "password"]):
                evidence_parts.append("The endpoint includes common login or account-related form fields.")

            self._findings.append({
                "id": f"authentication-weakness-{url}",
                "category": "Authentication/session",
                "title": "Authentication weaknesses indicator",
                "severity": "Medium",
                "confidence": 55,
                "status": "Needs Manual Verification",
                "url": url,
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(field_names) or "N/A",
                "evidence": " ".join(evidence_parts) or "The endpoint appears related to authentication.",
                "explanation": "Authentication endpoints require careful review for weak credential handling, session creation, and access control.",
                "verification_guidance": "Inspect the authentication flow, credential handling, and login/logout behavior for weak patterns.",
                "impact": "Weak authentication can allow unauthorized access and account takeover.",
                "remediation": "Harden authentication workflows, validate credentials securely, and enforce account lockout and MFA where appropriate.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
