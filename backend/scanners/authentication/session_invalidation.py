from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class SessionInvalidationScanner(Scanner):
    name = "Session invalidation"
    description = "Identifies endpoints where logout or session expiration may not be enforced correctly."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        return url_contains_words(url, ["logout", "signout", "session", "auth", "login", "password", "reset"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        parsed = urlparse(url)
        path = parsed.path.lower()

        if "logout" in path and method == "GET":
            self._findings.append({
                "id": f"session-invalidation-logout-get-{url}",
                "category": "Authentication/session",
                "title": "Session invalidation indicator",
                "severity": "Medium",
                "confidence": 55,
                "status": "Needs Manual Verification",
                "url": url,
                "method": method,
                "parameter": "N/A",
                "evidence": "Logout is exposed through a GET request.",
                "explanation": "Logout endpoints should invalidate sessions explicitly and avoid unsafe GET semantics.",
                "verification_guidance": "Manual test the logout endpoint and verify that it terminates the session immediately.",
                "impact": "Sessions may remain valid after logout or be vulnerable to cross-site abuse.",
                "remediation": "Implement logout as a state-changing action and ensure session state is removed on the server.",
            })

        if "login" in path and "token" not in endpoint.get("url", ""):
            self._findings.append({
                "id": f"session-invalidation-login-{url}",
                "category": "Authentication/session",
                "title": "Session invalidation review needed for login behavior",
                "severity": "Low",
                "confidence": 40,
                "status": "Potential",
                "url": url,
                "method": method,
                "parameter": "N/A",
                "evidence": "Login endpoints must ensure old sessions are invalidated before issuing new ones.",
                "explanation": "Failure to invalidate old sessions during login can allow session fixation or reuse of stale credentials.",
                "verification_guidance": "Verify that a new session ID is issued after login and old sessions are invalidated.",
                "impact": "Session fixation and replay attacks may be possible if session invalidation is incomplete.",
                "remediation": "Rotate session identifiers at authentication boundaries and invalidate prior sessions.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
