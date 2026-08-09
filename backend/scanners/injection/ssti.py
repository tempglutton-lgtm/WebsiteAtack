from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import (
    all_input_names,
    body_changed,
    payload_reflected,
    probe_parameter,
    EXPRESSION_LANGUAGE_PAYLOADS,
)

class SstiScanner(Scanner):
    name = "Server-side Template Injection"
    description = "Probes inputs for server-side template expression behavior."

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

        baseline_status, baseline_headers, baseline_body = await probe_parameter(session, endpoint, "1", params[0])
        for payload in ["{{7*7}}", "${7*7}", "#{7*7}"]:
            probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, payload, params[0])
            evidence_items = []
            if body_changed(baseline_body, probe_body):
                evidence_items.append("Response changed after template payload")
            if payload_reflected(probe_body, payload):
                evidence_items.append("Template payload reflected in response")
            if evidence_items:
                self._findings.append({
                    "id": f"ssti-{endpoint['url']}-{payload}",
                    "category": "Injection",
                    "title": "Server-side template injection indicator",
                    "severity": "Medium",
                    "confidence": min(85, 45 + len(evidence_items) * 15),
                    "status": "Needs Manual Verification",
                    "url": endpoint["url"],
                    "method": endpoint.get("method", "GET"),
                    "parameter": params[0],
                    "evidence": "; ".join(evidence_items),
                    "explanation": "The endpoint responded differently to an SSTI-style marker.",
                    "verification_guidance": "Review how the input is rendered by server-side templates and test authorized payloads carefully.",
                    "impact": "SSTI can lead to server-side code execution or data exposure.",
                    "remediation": "Escape template data and avoid evaluating untrusted input in templates.",
                })
                break
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
