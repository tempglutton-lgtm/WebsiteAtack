from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import is_html_endpoint

DOM_XSS_SINKS = [
    "location.hash",
    "location.search",
    "document.write",
    "innerhtml",
    "outerhtml",
    "eval(",
    "setattribute(",
    "insertadjacenthtml",
    "document.url",
    "window.name",
    "location.href",
]

class DomXssScanner(Scanner):
    name = "DOM XSS"
    description = "Flags pages where client-side scripts may process untrusted input in DOM sinks."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return is_html_endpoint(endpoint) and (bool(endpoint.get("query_params")) or bool(endpoint.get("forms")))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        body = endpoint.get("body", "") or ""
        body_lower = body.lower()
        if not any(keyword in body_lower for keyword in DOM_XSS_SINKS):
            if "#" not in endpoint.get("url", "") and not any(name.lower() in ["hash", "fragment", "callback"] for name in endpoint.get("query_params", {})):
                return []

        parameter_names = list(endpoint.get("query_params", {}).keys())
        if not parameter_names:
            parameter_names = [input.get("name") for form in endpoint.get("forms", []) for input in form.get("inputs", []) if input.get("name")]
        if not parameter_names:
            return []

        self._findings.append({
            "id": f"dom-xss-{endpoint['url']}",
            "category": "Client-side",
            "title": "DOM XSS indicator",
            "severity": "Low",
            "confidence": 55,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(parameter_names),
            "evidence": "The page contains DOM sink patterns or fragment handling and accepts user-controlled input.",
            "explanation": "DOM XSS can occur when client-side code processes untrusted values and writes them into the DOM without sanitization.",
            "verification_guidance": "Analyze the page's JavaScript and test safe payloads in URL/query/hash values to confirm reflection behavior.",
            "impact": "DOM XSS can execute attacker-supplied JavaScript in the victim's browser.",
            "remediation": "Avoid using untrusted input in DOM APIs, and sanitize or encode data before inserting it into the page.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
