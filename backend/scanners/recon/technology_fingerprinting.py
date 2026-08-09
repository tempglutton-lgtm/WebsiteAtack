from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import parse_json_body, url_contains_words


class TechnologyFingerprintingScanner(Scanner):
    name = "Technology fingerprinting"
    description = "Detects application technology and server fingerprints from headers or page content."

    TECHNOLOGY_PATTERNS = {
        "nginx": ["nginx"],
        "apache": ["apache"],
        "php": ["php"],
        "asp.net": ["asp.net", "microsoft-asp.net"],
        "express": ["express"],
        "django": ["django"],
        "rails": ["rails"],
        "react": ["react"],
        "angular": ["angular"],
        "vue": ["vue"],
        "wordpress": ["wp-content", "wordpress"],
    }

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("headers")) or bool(endpoint.get("body"))

    def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        body = str(endpoint.get("body", "")).lower()
        headers = {k.lower(): str(v).lower() for k, v in endpoint.get("headers", {}).items()}
        findings = []

        for tech, patterns in self.TECHNOLOGY_PATTERNS.items():
            if any(pattern in body or pattern in headers.get("server", "") or pattern in headers.get("x-powered-by", "") for pattern in patterns):
                findings.append(tech)

        if findings:
            self._findings.append({
                "id": f"technology-fingerprint-{endpoint.get('url', '')}",
                "category": "Reconnaissance",
                "title": "Technology fingerprinting indicator",
                "severity": "Informational",
                "confidence": 70,
                "status": "Informational",
                "url": endpoint.get("url", ""),
                "method": endpoint.get("method", "GET"),
                "parameter": "headers/body",
                "evidence": f"Detected technologies: {', '.join(sorted(set(findings)))}.",
                "explanation": "Server and page content can reveal technology fingerprints useful for targeted testing.",
                "verification_guidance": "Inspect headers and content to confirm the identified technologies.",
                "impact": "Technology fingerprints can help attackers choose the right exploit techniques.",
                "remediation": "Reduce unnecessary technology disclosure and limit public metadata where possible.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
