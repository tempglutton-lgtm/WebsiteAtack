from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import (
    NOSQL_ERROR_KEYWORDS,
    all_input_names,
    body_contains_error,
    body_changed,
    payload_reflected,
    probe_parameter,
)

class NoSqlInjectionScanner(Scanner):
    name = "NoSQL Injection"
    description = "Probes inputs for NoSQL query error behavior and response differences."

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
        probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, "{'$ne':null}", params[0])

        evidence_items = []
        if body_contains_error(probe_body, NOSQL_ERROR_KEYWORDS):
            evidence_items.append("NoSQL error keyword detected")
        if body_changed(baseline_body, probe_body):
            evidence_items.append("Response changed after NoSQL payload")
        if payload_reflected(probe_body, "{'$ne':null}"):
            evidence_items.append("Payload reflected in response")

        if evidence_items:
            self._findings.append({
                "id": f"nosql-{endpoint['url']}",
                "category": "Injection",
                "title": "NoSQL injection indicator",
                "severity": "Medium",
                "confidence": min(90, 45 + len(evidence_items) * 10),
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": params[0],
                "evidence": "; ".join(evidence_items),
                "explanation": "The endpoint responded differently to a NoSQL-style payload.",
                "verification_guidance": "Compare responses for benign and NoSQL payloads in an authorized testing environment.",
                "impact": "NoSQL injection may allow attackers to bypass authorization or retrieve unauthorized data.",
                "remediation": "Validate query operators and use safe database APIs for NoSQL queries.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
