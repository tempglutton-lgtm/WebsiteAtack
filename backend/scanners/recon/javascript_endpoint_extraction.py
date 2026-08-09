import re
from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import body_contains, discover_script_urls, url_contains_words


class JavascriptEndpointExtractionScanner(Scanner):
    name = "JavaScript endpoint extraction"
    description = "Detects potential endpoints exposed through JavaScript assets or client-side code."

    JS_ENDPOINT_PATTERN = re.compile(r'(https?://[^"\s]+|/[^\s"\']+)')

    def __init__(self):
        self._findings: List[dict] = []

    def _find_js_endpoints(self, text: str) -> List[str]:
        endpoints = []
        for match in self.JS_ENDPOINT_PATTERN.findall(text):
            if any(keyword in match for keyword in ["/api", "graphql", "ws://", "wss://", ".json", "/login", "/logout", "/user", "/auth"]):
                endpoints.append(match)
        return list(dict.fromkeys(endpoints))

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("scripts")) or bool(endpoint.get("body"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        extracted = []
        scripts = discover_script_urls(endpoint)
        if scripts:
            extracted.extend(scripts)
        body = endpoint.get("body", "")
        if body_contains(body.lower(), "fetch(") or body_contains(body.lower(), "axios") or body_contains(body.lower(), "xmlhttprequest"):
            extracted.extend(self._find_js_endpoints(body))

        extracted = [url for url in extracted if url]
        if extracted:
            self._findings.append({
                "id": f"js-endpoint-extraction-{endpoint.get('url', '')}",
                "category": "Reconnaissance",
                "title": "JavaScript endpoint extraction",
                "severity": "Informational",
                "confidence": 70,
                "status": "Informational",
                "url": endpoint.get("url", ""),
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(extracted[:5]),
                "evidence": f"Extracted JavaScript endpoints: {', '.join(extracted[:5])}.",
                "explanation": "JavaScript code and script files can reveal API endpoints and client-side services.",
                "verification_guidance": "Inspect JavaScript sources and network calls for exposed endpoints.",
                "impact": "Extracted endpoints provide attackers with additional routes to test.",
                "remediation": "Avoid exposing sensitive endpoints in public JavaScript and protect API routes properly.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
