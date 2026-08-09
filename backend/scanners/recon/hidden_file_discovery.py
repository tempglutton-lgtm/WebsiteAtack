from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class HiddenFileDiscoveryScanner(Scanner):
    name = "Hidden-file discovery"
    description = "Detects likely hidden files and backup artifacts exposed on the site."

    HIDDEN_PATTERNS = [".git", ".env", ".htaccess", "backup", ".bak", ".old", ".swp", ".gitignore", "/.env"]

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "").lower()
        return any(pattern in url for pattern in self.HIDDEN_PATTERNS)

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        self._findings.append({
            "id": f"hidden-file-discovery-{url}",
            "category": "Reconnaissance",
            "title": "Hidden-file discovery indicator",
            "severity": "Informational",
            "confidence": 80,
            "status": "Informational",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": "N/A",
            "evidence": "The URL includes a hidden file or backup artifact pattern.",
            "explanation": "Hidden files and backup artifacts can expose sensitive source, config, or credentials.",
            "verification_guidance": "Confirm whether the discovered file is accessible and contains sensitive data.",
            "impact": "Hidden-file exposure can leak secrets and internal implementation details.",
            "remediation": "Remove or restrict access to hidden files and backup artifacts on production systems.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
