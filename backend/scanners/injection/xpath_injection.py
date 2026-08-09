from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import (
    XML_ERROR_KEYWORDS,
    all_input_names,
    body_contains_error,
    body_changed,
    payload_reflected,
    probe_parameter,
)

class XPathInjectionScanner(Scanner):
    name = "XPath/XML Injection"
    description = "Probes inputs for XML or XPath parsing errors and reflection behavior."

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
        probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, "' or '1'='1", params[0])

        evidence_items = []
        if body_contains_error(probe_body, XML_ERROR_KEYWORDS):
            evidence_items.append("XPath/XML error keyword detected")
        if body_changed(baseline_body, probe_body):
            evidence_items.append("Response changed after XPath payload")
        if payload_reflected(probe_body, "' or '1'='1"):
            evidence_items.append("Payload reflected in response")

        if evidence_items:
            self._findings.append({
                "id": f"xpath-{endpoint['url']}",
                "category": "Injection",
                "title": "XPath/XML injection indicator",
                "severity": "Medium",
                "confidence": min(90, 45 + len(evidence_items) * 10),
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": params[0],
                "evidence": "; ".join(evidence_items),
                "explanation": "The endpoint responded differently to an XPath/XML-style payload.",
                "verification_guidance": "Review XML processing and test authorized XPath payloads safely.",
                "impact": "XPath/XML injection can expose data or bypass access controls.",
                "remediation": "Validate and escape XML input and avoid unsafe XPath concatenation.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
