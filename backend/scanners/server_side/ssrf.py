from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, body_contains_error, probe_parameter, SSRF_ERROR_KEYWORDS, url_contains_words


class SsrfScanner(Scanner):
    name = "SSRF"
    description = "Detects likely server-side request forgery vectors and SSRF-related input fields."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        names = [name.lower() for name in all_input_names(endpoint)]
        return any(keyword in url.lower() for keyword in ["url", "uri", "redirect", "callback", "next", "dest", "return", "image", "img", "site"]) or any(
            keyword in name for name in names for keyword in ["url", "uri", "redirect", "callback", "next", "dest", "return", "image", "img", "site"]
        )

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        names = [name.lower() for name in all_input_names(endpoint)]
        if not self.applicable(endpoint):
            return []

        evidence = []
        if any(keyword in url.lower() for keyword in ["url", "uri", "redirect", "callback", "next", "dest", "return", "image", "img", "site"]):
            evidence.append("The URL contains a parameter-like path suggesting external resource fetching.")
        if any(keyword in name for name in names for keyword in ["url", "uri", "redirect", "callback", "next", "dest", "return", "image", "img", "site"]):
            evidence.append("Input field names suggest a resource fetch or redirect parameter.")

        if session and names:
            param = names[0]
            _, _, probe_body = await probe_parameter(session, endpoint, "http://example.com/", param)
            if body_contains_error(probe_body, SSRF_ERROR_KEYWORDS):
                evidence.append("The endpoint returned a response matching SSRF-related error output.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"ssrf-{url}",
            "category": "Server-side",
            "title": "SSRF indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": names[0] if names else "N/A",
            "evidence": " ".join(evidence),
            "explanation": "Parameters that accept external resources may be abused by SSRF if the server fetches arbitrary URLs.",
            "verification_guidance": "Inspect how the endpoint processes remote URLs and verify that requests are restricted to trusted destinations.",
            "impact": "SSRF can allow internal network scanning, data exfiltration, or server-side compromise.",
            "remediation": "Restrict external URL input, enforce allowlists, and validate destination hostnames before fetching.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
