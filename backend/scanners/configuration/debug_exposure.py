from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import body_contains


class DebugExposureScanner(Scanner):
    name = "Debug/development exposure"
    description = "Detects debug and development traces or markers in responses."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("body")) or bool(endpoint.get("headers"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        body = endpoint.get("body", "").lower()
        headers = {k.lower(): v for k, v in endpoint.get("headers", {}).items()}
        evidence = []

        if body_contains(body, "debug") or body_contains(body, "stack trace") or body_contains(body, "exception"):
            evidence.append("Response body contains debug or error details.")
        if body_contains(body, "development mode") or body_contains(body, "debug mode"):
            evidence.append("Response body explicitly mentions development mode.")
        if "x-debug" in headers or "x-powered-by" in headers and "development" in headers.get("x-powered-by", "").lower():
            evidence.append("Response headers indicate debug or development mode.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"debug-exposure-{endpoint.get('url', '')}",
            "category": "Configuration",
            "title": "Debug/development exposure indicator",
            "severity": "Low",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": endpoint.get("url", ""),
            "method": endpoint.get("method", "GET"),
            "parameter": "body/headers",
            "evidence": " ".join(evidence),
            "explanation": "Development and debug information should not be exposed in production responses.",
            "verification_guidance": "Review server configuration and response content for debug traces or development indicators.",
            "impact": "Debug exposure can reveal implementation details and enable targeted attacks.",
            "remediation": "Disable debug mode and remove development traces from production responses.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
