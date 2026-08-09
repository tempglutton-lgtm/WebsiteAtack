from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class SessionManagementWeaknessScanner(Scanner):
    name = "Session management weaknesses"
    description = "Detects likely session management issues such as logout via GET or missing expiration hints in session cookies."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        return "logout" in url.lower() or "session" in url.lower() or bool(endpoint.get("headers", {}).get("set-cookie"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        parsed = urlparse(url)
        set_cookie = endpoint.get("headers", {}).get("set-cookie", "")
        method = endpoint.get("method", "GET").upper()

        if "logout" in parsed.path.lower() and method == "GET":
            self._findings.append({
                "id": f"session-management-logout-get-{url}",
                "category": "Authentication/session",
                "title": "Session management weakness: logout via GET",
                "severity": "Medium",
                "confidence": 55,
                "status": "Needs Manual Verification",
                "url": url,
                "method": method,
                "parameter": "N/A",
                "evidence": "Logout behavior is exposed through a GET request.",
                "explanation": "Logout endpoints using GET are easier to abuse from third-party sites and may not ensure proper session invalidation.",
                "verification_guidance": "Verify that logout requires an explicit action and properly invalidates the session on the server.",
                "impact": "Improper logout handling can leave sessions active or allow CSRF-like logout abuse.",
                "remediation": "Use POST or state-changing methods for logout actions and verify session termination server-side.",
            })

        if set_cookie:
            if "expires" not in set_cookie.lower() and "max-age" not in set_cookie.lower():
                self._findings.append({
                    "id": f"session-management-cookie-expiry-{url}",
                    "category": "Authentication/session",
                    "title": "Session cookie may lack explicit expiration",
                    "severity": "Low",
                    "confidence": 45,
                    "status": "Potential",
                    "url": url,
                    "method": method,
                    "parameter": "set-cookie",
                    "evidence": "The Set-Cookie header does not specify Expires or Max-Age.",
                    "explanation": "Session cookies can be more difficult to manage if expiration is not clearly defined by the server.",
                    "verification_guidance": "Confirm whether the session cookie is intentionally a session-only cookie and whether expected logout behavior is enforced.",
                    "impact": "Undefined session lifetime can make invalidation and session expiry harder to enforce.",
                    "remediation": "Set explicit cookie expiration or max-age for session cookies when appropriate, and use secure logout handling.",
                })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
