from typing import Any, List

from backend.scanners.base import Scanner


class SourceMapExposureScanner(Scanner):
    name = "Source-map exposure"
    description = "Detects source map files or references that may expose frontend source code." 

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("url")) or bool(endpoint.get("body"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        body = endpoint.get("body", "")
        evidence = []

        if url.lower().endswith(".map"):
            evidence.append("A source map file was directly requested.")
        if "sourceMappingURL=" in body or "//# sourceMappingURL=" in body:
            evidence.append("The response references a source map URL.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"source-map-exposure-{url}",
            "category": "Configuration",
            "title": "Source-map exposure indicator",
            "severity": "Low",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": "body/url",
            "evidence": " ".join(evidence),
            "explanation": "Source maps can reveal original frontend source code and build details.",
            "verification_guidance": "Check whether source maps are publicly accessible or referenced from production assets.",
            "impact": "Source-map exposure can leak application logic and make client-side attacks easier.",
            "remediation": "Remove source maps from production or restrict access to them.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
