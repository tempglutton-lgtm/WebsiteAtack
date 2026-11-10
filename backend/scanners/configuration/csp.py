from typing import Any, List

from backend.scanners.base import Scanner


class CspScanner(Scanner):
    name = "CSP Configuration"
    description = "Detects missing or weak Content Security Policy headers and inline content patterns."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        content_type = str(endpoint.get("content_type", "")).lower()
        return "text/html" in content_type

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        headers = {str(key).lower(): value for key, value in endpoint.get("headers", {}).items()}
        csp_header = str(headers.get("content-security-policy", "") or "")
        evidence = []

        if not csp_header:
            if headers.get("content-security-policy-report-only"):
                evidence.append(
                    "Only Content-Security-Policy-Report-Only was found; it does not enforce a policy."
                )
            else:
                evidence.append("No Content-Security-Policy header was found.")
        else:
            directives = {}
            for directive in csp_header.split(";"):
                parts = directive.strip().lower().split()
                if parts:
                    directives.setdefault(parts[0], set()).update(parts[1:])

            effective_script_directive = next(
                (
                    directives[name]
                    for name in ("script-src-elem", "script-src", "default-src")
                    if name in directives
                ),
                set(),
            )
            has_nonce_or_hash = any(
                source.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                for source in effective_script_directive
            )
            if "'unsafe-inline'" in effective_script_directive and not has_nonce_or_hash:
                evidence.append(
                    "The effective script policy allows unsafe-inline without a nonce or hash."
                )
            if "'unsafe-eval'" in directives.get("script-src", set()):
                evidence.append("The script-src directive allows unsafe-eval.")

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
