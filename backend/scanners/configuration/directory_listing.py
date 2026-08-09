from typing import Any, List

from backend.scanners.base import Scanner


class DirectoryListingScanner(Scanner):
    name = "Directory listing"
    description = "Detects open directory listings or index-style pages that expose file structure."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("body"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        body = endpoint.get("body", "").lower()
        if "index of /" in body or "parent directory" in body:
            self._findings.append({
                "id": f"directory-listing-{endpoint.get('url', '')}",
                "category": "Configuration",
                "title": "Directory listing exposure",
                "severity": "Low",
                "confidence": 65,
                "status": "Needs Manual Verification",
                "url": endpoint.get("url", ""),
                "method": endpoint.get("method", "GET"),
                "parameter": "body",
                "evidence": "Response content looks like a directory listing.",
                "explanation": "Open directory listings can disclose file structure and sensitive files.",
                "verification_guidance": "Inspect the page to confirm whether it exposes directory contents.",
                "impact": "Directory listing exposure makes it easier to discover sensitive files and paths.",
                "remediation": "Disable directory listings and configure index pages for directories.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
