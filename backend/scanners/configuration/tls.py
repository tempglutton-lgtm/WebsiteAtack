from typing import Any, List

from backend.scanners.base import Scanner


class TlsSecurityScanner(Scanner):
    name = "TLS/security configuration"
    description = "Detects weak TLS and transport security configuration indicators."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("url")) or bool(endpoint.get("headers"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        headers = {k.lower(): v for k, v in endpoint.get("headers", {}).items()}
        evidence = []

        if url.startswith("http://"):
            evidence.append("The endpoint uses an insecure HTTP scheme.")
        if url.startswith("https://") and "strict-transport-security" not in headers:
            evidence.append("HTTPS endpoint is missing Strict-Transport-Security header.")
        if "public-key-pins" in headers:
            evidence.append("Public Key Pinning header is present; PKP is deprecated and may be unsafe.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"tls-config-{url}",
            "category": "Configuration",
            "title": "TLS/security configuration issue",
            "severity": "Medium",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": "Strict-Transport-Security",
            "evidence": " ".join(evidence),
            "explanation": "TLS and transport security configuration are essential to prevent interception and downgrade attacks.",
            "verification_guidance": "Review service endpoints for HTTPS usage and HSTS policy coverage.",
            "impact": "Weak TLS configuration undermines the security of transported data and user sessions.",
            "remediation": "Use HTTPS everywhere and configure HSTS for all secure endpoints.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
