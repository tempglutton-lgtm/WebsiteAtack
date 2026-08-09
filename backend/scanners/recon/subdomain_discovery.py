from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class SubdomainDiscoveryScanner(Scanner):
    name = "Subdomain discovery"
    description = "Flags subdomain endpoints when discovery is explicitly permitted."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        return urlparse(url).hostname is not None and urlparse(url).hostname.count(".") >= 2 and endpoint.get("allow_subdomain_discovery") is True

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        hostname = urlparse(endpoint.get("url", "")).hostname or ""
        if hostname:
            self._findings.append({
                "id": f"subdomain-discovery-{endpoint.get('url', '')}",
                "category": "Reconnaissance",
                "title": "Subdomain discovery indicator",
                "severity": "Informational",
                "confidence": 80,
                "status": "Informational",
                "url": endpoint.get("url", ""),
                "method": endpoint.get("method", "GET"),
                "parameter": "hostname",
                "evidence": f"Subdomain discovery allowed for hostname: {hostname}",
                "explanation": "Subdomain discovery is permitted and can reveal additional attack surface under the domain.",
                "verification_guidance": "Confirm target scope and subdomain permissions before conducting discovery.",
                "impact": "Subdomain enumeration can expand the set of assets under test.",
                "remediation": "Only test subdomains explicitly in scope and respect authorization boundaries.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
