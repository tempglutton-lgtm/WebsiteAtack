from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, url_contains_words


class AccountEnumerationScanner(Scanner):
    name = "Account-enumeration indicators"
    description = "Detects endpoints and fields that may be used for username/email enumeration in authentication flows."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        field_names = [name.lower() for name in all_input_names(endpoint)]
        return url_contains_words(url, ["login", "signin", "register", "signup", "password", "forgot", "reset"]) or any(
            field in field_names for field in ["email", "username", "user", "account"]
        )

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        field_names = [name.lower() for name in all_input_names(endpoint)]
        if self.applicable(endpoint):
            self._findings.append({
                "id": f"account-enum-{endpoint['url']}",
                "category": "Authentication/session",
                "title": "Account enumeration indicator",
                "severity": "Medium",
                "confidence": 55,
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(field_names) or "N/A",
                "evidence": "The endpoint uses username/email/account fields in an authentication-related flow.",
                "explanation": "Authentication endpoints that expose user lookup fields can be used to enumerate valid accounts if responses differ.",
                "verification_guidance": "Check whether different login or reset values produce distinguishable responses for valid vs invalid accounts.",
                "impact": "Account enumeration can support targeted attacks and credential stuffing.",
                "remediation": "Normalize responses for invalid accounts and avoid revealing existence through error messages or timing differences.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
