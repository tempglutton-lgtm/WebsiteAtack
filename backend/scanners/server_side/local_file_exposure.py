from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, body_contains, probe_parameter, url_contains_words


class LocalFileExposureScanner(Scanner):
    name = "Local-file exposure"
    description = "Detects endpoints that may expose local file contents through unsafe file or resource parameters."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        names = [name.lower() for name in all_input_names(endpoint)]
        return url_contains_words(url, ["file", "local", "download", "source", "path"]) or any(
            keyword in name for name in names for keyword in ["file", "local", "source", "path", "download"]
        )

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        names = [name.lower() for name in all_input_names(endpoint)]
        if not self.applicable(endpoint):
            return []

        evidence = []
        if any(keyword in url.lower() for keyword in ["file", "local", "download", "source", "path"]):
            evidence.append("The URL suggests local file retrieval behavior.")
        if any(keyword in name for name in names for keyword in ["file", "local", "source", "path", "download"]):
            evidence.append("Input field names suggest local file references.")

        if session and names:
            param = names[0]
            _, _, probe_body = await probe_parameter(session, endpoint, "file:///etc/passwd", param)
            if probe_body and body_contains(probe_body.lower(), "root:"):
                evidence.append("Response body suggests exposure of local file contents through file URI input.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"local-file-exposure-{url}",
            "category": "Server-side",
            "title": "Local-file exposure indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": names[0] if names else "N/A",
            "evidence": " ".join(evidence),
            "explanation": "Endpoints that accept local file URIs can expose server-side filesystem contents if improperly handled.",
            "verification_guidance": "Verify whether local file paths or file URIs are accepted and whether they return filesystem contents.",
            "impact": "Local file exposure may reveal secrets or configuration files from the host system.",
            "remediation": "Reject local file URIs and enforce strict file access policies on the server.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
