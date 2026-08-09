from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import body_changed, payload_reflected, probe_parameter

class ReflectedXssScanner(Scanner):
    name = "Reflected XSS"
    description = "Detects reflected XSS risk when query parameters or form inputs may be rendered into HTML responses."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("query_params")) or bool(endpoint.get("forms"))

    async def run(self, endpoint: Any, session: Optional[object] = None) -> List[dict]:
        self._findings = []
        parameters = list(endpoint.get("query_params", {}).keys())
        if not parameters:
            parameters = [i.get("name") for form in endpoint.get("forms", []) for i in form.get("inputs", []) if i.get("name")]
        if not parameters:
            return []

        evidence_items = []
        if session is not None:
            probe_value = "REFLECTED_XSS_TEST_123"
            baseline_status, baseline_headers, baseline_body = await probe_parameter(session, endpoint, "safevalue", parameters[0])
            probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, probe_value, parameters[0])
            if payload_reflected(probe_body, probe_value):
                evidence_items.append("Payload reflected in response")
            if body_changed(baseline_body, probe_body):
                evidence_items.append("Response changed after reflected payload")

        if evidence_items:
            confidence = min(90, 50 + len(evidence_items) * 10)
            status = "Needs Manual Verification"
            evidence = "; ".join(evidence_items)
        else:
            confidence = 35
            status = "Potential"
            evidence = "Endpoint accepts user-controlled input that may be reflected in HTML output."

        self._findings.append({
            "id": f"reflected-xss-{endpoint['url']}",
            "category": "Client-side",
            "title": "Reflected XSS indicator",
            "severity": "Medium",
            "confidence": confidence,
            "status": status,
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(parameters),
            "evidence": evidence,
            "explanation": "Reflected XSS can occur when input values are rendered back into pages without proper escaping.",
            "verification_guidance": "Use a safe reflected payload and inspect the rendered HTML or response body for the submitted value.",
            "impact": "Browser-based script execution can occur under the victim's session.",
            "remediation": "Escape all user input before including it in HTML responses.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
