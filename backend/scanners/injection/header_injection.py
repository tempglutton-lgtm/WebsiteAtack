from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import (
    all_input_names,
    body_changed,
    payload_reflected,
    probe_parameter,
)

class HeaderInjectionScanner(Scanner):
    name = "Header Injection"
    description = "Probes inputs for header reflection and unsafe header behavior."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(all_input_names(endpoint))

    async def run(self, endpoint: Any, session: Optional[object] = None) -> List[dict]:
        self._findings = []
        if session is None:
            return []
        params = all_input_names(endpoint)
        if not params:
            return []

        payload = "header_injection_test%0d%0aX-Injection:1"
        baseline_status, baseline_headers, baseline_body = await probe_parameter(session, endpoint, "test", params[0])
        probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, payload, params[0])

        evidence_items = []
        if body_changed(baseline_body, probe_body):
            evidence_items.append("Response changed after header payload")
        if payload_reflected(probe_body, payload):
            evidence_items.append("Header payload reflected in response")
        if any(name in probe_body.lower() for name in ["x-injection", "header_injection_test"]):
            evidence_items.append("Injected header marker observed in response")

        if evidence_items:
            self._findings.append({
                "id": f"header-injection-{endpoint['url']}",
                "category": "Injection",
                "title": "Header injection indicator",
                "severity": "Medium",
                "confidence": min(90, 45 + len(evidence_items) * 10),
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": params[0],
                "evidence": "; ".join(evidence_items),
                "explanation": "The endpoint reacted to a header-style payload with response changes or reflected markers.",
                "verification_guidance": "Verify whether input values are incorporated into response headers or redirection locations.",
                "impact": "Header injection can enable response splitting or header-based attacks.",
                "remediation": "Sanitize all header-bound input and prevent CRLF characters in user-controlled values.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
