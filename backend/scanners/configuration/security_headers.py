from typing import Any, List

from backend.scanners.base import Scanner

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

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        headers = {k.lower(): v for k, v in endpoint.get("headers", {}).items()}
        missing = [header for header in REQUIRED_HEADERS if header not in headers]
        evidence = []

        if missing:
            evidence.append(f"Missing security headers: {', '.join(missing)}.")
        if "x-frame-options" in headers and headers["x-frame-options"].lower() == "allow":
            evidence.append("X-Frame-Options is set to ALLOW, which disables frame protection.")
        if "x-content-type-options" in headers and headers["x-content-type-options"].lower() != "nosniff":
            evidence.append("X-Content-Type-Options is not set to nosniff.")
        if "strict-transport-security" in headers and "max-age" not in headers["strict-transport-security"].lower():
            evidence.append("Strict-Transport-Security header is present but missing max-age.")

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
