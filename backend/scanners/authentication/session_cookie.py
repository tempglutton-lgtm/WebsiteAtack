from typing import Any, List

from backend.scanners.base import Scanner

class SessionCookieScanner(Scanner):
    name = "Session Cookie Security"
    description = "Checks for session cookie settings that may indicate weak cookie protections."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        set_cookie = endpoint.get("headers", {}).get("set-cookie", "")
        if set_cookie:
            problems = []
            if "httponly" not in set_cookie.lower():
                problems.append("missing HttpOnly")
            if "secure" not in set_cookie.lower():
                problems.append("missing Secure")
            if "samesite" not in set_cookie.lower():
                problems.append("missing SameSite")
            if problems:
                self._findings.append({
                    "id": f"session-cookie-{endpoint['url']}",
                    "category": "Authentication/session",
                    "title": "Weak session cookie settings",
                    "severity": "Medium",
                    "confidence": 60,
                    "status": "Potential",
                    "url": endpoint["url"],
                    "method": endpoint.get("method", "GET"),
                    "parameter": "set-cookie",
                    "evidence": f"Set-Cookie header lacks: {', '.join(problems)}.",
                    "explanation": "Session cookies should include HttpOnly, Secure, and SameSite to reduce hijacking risk.",
                    "verification_guidance": "Inspect the Set-Cookie header in response headers and confirm cookie flags are set.",
                    "impact": "Weak cookie flags can increase session hijacking and CSRF risk.",
                    "remediation": "Set HttpOnly, Secure, and SameSite attributes for session cookies.",
                })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
