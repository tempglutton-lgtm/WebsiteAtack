from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, body_contains_error, probe_parameter, XML_ERROR_KEYWORDS, url_contains_words


class XxeScanner(Scanner):
    name = "XXE indicators"
    description = "Detects likely XML parsing endpoints that may be susceptible to XXE or XML injection issues."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        if url_contains_words(url, ["xml", "soap", "rss", "sitemap", "document"]):
            return True
        names = [name.lower() for name in all_input_names(endpoint)]
        return any(keyword in name for name in names for keyword in ["xml", "dtd", "doctype", "soap", "sitemap", "document"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        names = [name.lower() for name in all_input_names(endpoint)]
        if not self.applicable(endpoint):
            return []

        evidence = []
        if url_contains_words(url, ["xml", "soap", "rss", "sitemap", "document"]):
            evidence.append("The endpoint URL references XML-like content or documents.")
        if any(keyword in name for name in names for keyword in ["xml", "dtd", "doctype", "soap", "sitemap", "document"]):
            evidence.append("Input field names suggest XML content or document processing.")

        if session and names:
            param = names[0]
            _, _, probe_body = await probe_parameter(session, endpoint, "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>", param)
            if body_contains_error(probe_body, XML_ERROR_KEYWORDS):
                evidence.append("The response contains XML parsing error output consistent with XXE processing.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"xxe-{url}",
            "category": "Server-side",
            "title": "XXE indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": names[0] if names else "N/A",
            "evidence": " ".join(evidence),
            "explanation": "XML parsing endpoints may expose XXE vulnerabilities if external entities are processed without restrictions.",
            "verification_guidance": "Review XML parser configuration and test XML payload handling for external entity resolution.",
            "impact": "XXE can expose local files, internal services, or allow remote code execution in some cases.",
            "remediation": "Disable external entity resolution and use safe XML parsing libraries.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
