from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import body_changed, HTML_INJECTION_MARKERS, is_html_endpoint, payload_reflected, probe_parameter

class HtmlInjectionScanner(Scanner):
    name = "HTML Injection"
    description = "Detects pages that may accept untrusted input and render it without HTML escaping."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("forms")) or bool(endpoint.get("query_params"))

    async def run(self, endpoint: Any, session: Optional[object] = None) -> List[dict]:
        self._findings = []
        fields = list(endpoint.get("query_params", {}).keys())
        if not fields:
            fields = [i.get("name") for form in endpoint.get("forms", []) for i in form.get("inputs", []) if i.get("name")]
        if not fields:
            return []

        if not is_html_endpoint(endpoint) and not any(marker in endpoint.get("body", "").lower() for marker in HTML_INJECTION_MARKERS):
            return []

        evidence_items = []
        if session is not None:
            probe_marker = "<b>HTMLINJTEST</b>"
            baseline_status, baseline_headers, baseline_body = await probe_parameter(session, endpoint, "safevalue", fields[0])
            probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, probe_marker, fields[0])
            if payload_reflected(probe_body, probe_marker):
                evidence_items.append("HTML-like payload reflected in response")
            if body_changed(baseline_body, probe_body):
                evidence_items.append("Response changed after HTML-style payload")

        if evidence_items:
            confidence = min(90, 45 + len(evidence_items) * 15)
            status = "Needs Manual Verification"
            evidence = "; ".join(evidence_items)
        else:
            confidence = 35
            status = "Potential"
            evidence = "The endpoint accepts input that may be rendered in HTML contexts, indicating HTML injection risk."

        self._findings.append({
            "id": f"html-injection-{endpoint['url']}",
            "category": "Client-side",
            "title": "HTML injection indicator",
            "severity": "Low",
            "confidence": confidence,
            "status": status,
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(fields),
            "evidence": evidence,
            "explanation": "User-controlled HTML content should be escaped before rendering to avoid injection.",
            "verification_guidance": "Test with safe tag-like input and inspect the rendered output.",
            "impact": "HTML injection can lead to XSS or content spoofing.",
            "remediation": "Encode HTML output and filter disallowed markup.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
