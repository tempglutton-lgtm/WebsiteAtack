from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import has_restrictive_frame_ancestors

REQUIRED_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
]


class SecurityHeadersScanner(Scanner):
    name = "Security headers"
    description = "Detects missing or weak security headers in the HTTP response."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        headers = {
            str(key).lower(): str(value)
            for key, value in endpoint.get("headers", {}).items()
        }
        url = str(endpoint.get("url", ""))
        is_https = url.lower().startswith("https://")
        is_html = "text/html" in str(
            endpoint.get("content_type", headers.get("content-type", ""))
        ).lower()
        required_headers = [
            header
            for header in REQUIRED_HEADERS
            if (
                header == "strict-transport-security" and is_https
            ) or (
                header != "strict-transport-security" and is_html
            )
        ]
        missing = [header for header in required_headers if header not in headers]
        if has_restrictive_frame_ancestors(headers):
            missing = [header for header in missing if header != "x-frame-options"]
        evidence = []

        if missing:
            evidence.append(f"Missing security headers: {', '.join(missing)}.")
        if (
            is_html
            and
            "x-frame-options" in headers
            and headers["x-frame-options"].strip().lower() not in {"deny", "sameorigin"}
            and not has_restrictive_frame_ancestors(headers)
        ):
            evidence.append("X-Frame-Options has an unrecognized or permissive value.")
        if (
            is_html
            and "x-content-type-options" in headers
            and headers["x-content-type-options"].strip().lower() != "nosniff"
        ):
            evidence.append("X-Content-Type-Options is not set to nosniff.")
        if is_https and "strict-transport-security" in headers:
            max_age = next(
                (
                    part.strip().split("=", 1)[1]
                    for part in headers["strict-transport-security"].split(";")
                    if part.strip().lower().startswith("max-age=")
                ),
                None,
            )
            if not max_age or not max_age.isdigit() or int(max_age) <= 0:
                evidence.append(
                    "Strict-Transport-Security has no valid positive max-age."
                )

        if not evidence:
            return []

        self._findings.append({
            "id": f"security-headers-{endpoint.get('url', '')}",
            "category": "Configuration",
            "title": "Security header issue",
            "severity": "Low",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": endpoint.get("url", ""),
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(missing) or "N/A",
            "evidence": " ".join(evidence),
            "explanation": "Missing or weak security headers can expose the app to clickjacking, MIME sniffing, and other risks.",
            "verification_guidance": "Inspect response headers and verify required security headers are present with safe values.",
            "impact": "Inadequate security headers reduce browser-level protections against common attacks.",
            "remediation": "Add recommended response headers and ensure they are correctly configured.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
