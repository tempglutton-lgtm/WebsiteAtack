from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import body_contains


class CspScanner(Scanner):
    name = "CSP Configuration"
    description = "Detects missing or weak Content Security Policy headers and inline content patterns."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers")) or bool(endpoint.get("body"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        headers = endpoint.get("headers", {})
        body = endpoint.get("body", "")
        csp_header = headers.get("content-security-policy", "") or headers.get("content-security-policy-report-only", "")
        evidence = []

        if not csp_header:
            evidence.append("No Content-Security-Policy header was found.")
        else:
            evidence.append(f"CSP header present: {csp_header}")
            if "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
                evidence.append("CSP contains unsafe directives such as unsafe-inline or unsafe-eval.")

        if body and (body_contains(body.lower(), "<script") or body_contains(body.lower(), "onerror=") or body_contains(body.lower(), "onload=")):
            evidence.append("The page contains inline scripts or event handlers.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"csp-{endpoint.get('url', '')}",
            "category": "Configuration",
            "title": "CSP configuration issue",
            "severity": "Low",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": endpoint.get("url", ""),
            "method": endpoint.get("method", "GET"),
            "parameter": "Content-Security-Policy",
            "evidence": " ".join(evidence),
            "explanation": "A missing or weak CSP allows more cross-site scripting and content injection risk.",
            "verification_guidance": "Verify CSP headers and confirm inline script usage complies with policy.",
            "impact": "Poor CSP configuration can increase client-side attack surface and leakage of sensitive data.",
            "remediation": "Add or strengthen Content-Security-Policy headers and avoid unsafe inline script directives.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
