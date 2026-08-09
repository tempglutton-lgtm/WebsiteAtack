from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, body_contains, probe_parameter, url_contains_words


class PathTraversalScanner(Scanner):
    name = "Path traversal"
    description = "Detects likely path traversal vulnerability vectors through file/path parameters."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        names = [name.lower() for name in all_input_names(endpoint)]
        return url_contains_words(url, ["file", "path", "dir", "download", "document"]) or any(
            keyword in name for name in names for keyword in ["file", "path", "dir", "download", "document"]
        )

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        names = [name.lower() for name in all_input_names(endpoint)]
        if not self.applicable(endpoint):
            return []

        evidence = []
        if any(keyword in url.lower() for keyword in ["file", "path", "dir", "download", "document"]):
            evidence.append("The URL suggests a file or path-based request.")
        if any(keyword in name for name in names for keyword in ["file", "path", "dir", "download", "document"]):
            evidence.append("Input field names suggest a file or path parameter.")

        if session and names:
            param = names[0]
            _, _, probe_body = await probe_parameter(session, endpoint, "../../../../etc/passwd", param)
            if probe_body and body_contains(probe_body.lower(), "root:"):
                evidence.append("Response body suggests access to /etc/passwd through path traversal.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"path-traversal-{url}",
            "category": "Server-side",
            "title": "Path traversal indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": names[0] if names else "N/A",
            "evidence": " ".join(evidence),
            "explanation": "Endpoints that accept file or path parameters may be vulnerable to directory traversal if input is not restricted.",
            "verification_guidance": "Test traversal payloads and verify the server does not return arbitrary filesystem contents.",
            "impact": "Path traversal can expose local files and sensitive data on the server.",
            "remediation": "Normalize and validate file paths, disallow traversal characters, and restrict access to allowed directories.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
