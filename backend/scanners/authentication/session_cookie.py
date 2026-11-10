from typing import Any, List
import re

from backend.scanners.base import Scanner

class SessionCookieScanner(Scanner):
    name = "Session Cookie Security"
    description = "Checks for session cookie settings that may indicate weak cookie protections."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers"))

    @staticmethod
    def _is_session_cookie(name: str) -> bool:
        normalized = re.sub(r"[^a-z0-9]", "", name.lower())
        if any(marker in normalized for marker in ("csrf", "xsrf", "nonce")):
            return False
        known_names = {
            "session", "sessionid", "sess", "sessid", "jsessionid", "phpsessid",
            "aspnetsessionid", "connectsid", "sid", "auth", "authtoken",
            "accesstoken", "refreshtoken", "idtoken", "jwt", "token",
            "identity", "login", "laravelsession",
        }
        return normalized in known_names or "session" in normalized

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        headers = {
            str(key).lower(): value
            for key, value in endpoint.get("headers", {}).items()
        }
        raw_set_cookie = headers.get("set-cookie", "")
        set_cookie_headers = (
            raw_set_cookie.splitlines()
            if isinstance(raw_set_cookie, str)
            else list(raw_set_cookie or [])
        )
        problems = []
        is_https = str(endpoint.get("url", "")).lower().startswith("https://")
        for cookie in set_cookie_headers:
            parts = [part.strip() for part in str(cookie).split(";") if part.strip()]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip()
            if not self._is_session_cookie(name):
                continue
            attributes = {
                part.split("=", 1)[0].strip().lower(): (
                    part.split("=", 1)[1].strip().lower()
                    if "=" in part else ""
                )
                for part in parts[1:]
            }
            missing = []
            if "httponly" not in attributes:
                missing.append("HttpOnly")
            if is_https and "secure" not in attributes:
                missing.append("Secure")
            if missing:
                problems.append(f"{name} lacks {', '.join(missing)}")
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
                "evidence": "Session cookie attributes to review: " + "; ".join(problems) + ".",
                "explanation": "Session cookie attributes should be reviewed in the context of the application and transport security policy.",
                "verification_guidance": "Inspect the Set-Cookie header in response headers and confirm cookie flags are set.",
                "impact": "Missing HttpOnly can expose a session token to scripts; missing Secure on HTTPS can expose it over unencrypted transport. This observation alone does not establish exploitability.",
                "remediation": "Review HttpOnly and Secure attributes for session cookies against the application's deployment and compatibility requirements.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
