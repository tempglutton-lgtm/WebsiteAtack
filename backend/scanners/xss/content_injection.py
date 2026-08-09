from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import HTML_INJECTION_MARKERS, is_html_endpoint

class ContentInjectionScanner(Scanner):
    name = "Content Injection"
    description = "Flags endpoints that may render user-provided values into HTML or script contexts without proper escaping."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("query_params")) or bool(endpoint.get("forms"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        fields = list(endpoint.get("query_params", {}).keys())
        if not fields:
            fields = [input.get("name") for form in endpoint.get("forms", []) for input in form.get("inputs", []) if input.get("name")]
        if not fields:
            return []

        body = endpoint.get("body", "") or ""
        if not is_html_endpoint(endpoint) and not any(marker in body.lower() for marker in HTML_INJECTION_MARKERS):
            return []

        self._findings.append({
            "id": f"content-injection-{endpoint['url']}",
            "category": "Client-side",
            "title": "Content injection indicator",
            "severity": "Low",
            "confidence": 50,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(fields),
            "evidence": "The endpoint accepts input values that may be inserted into rendered HTML or script content.",
            "explanation": "Content injection can lead to XSS or page manipulation if user-controlled values are rendered unsafely.",
            "verification_guidance": "Review how input values are inserted into HTML or client-side templates and test safe payloads.",
            "impact": "Injected content may execute scripts or mislead users if it is rendered without escaping.",
            "remediation": "Use strict output encoding and validate untrusted values before rendering them.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
