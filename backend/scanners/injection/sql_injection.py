from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import (
    SQL_ERROR_KEYWORDS,
    all_input_names,
    body_contains_error,
    body_changed,
    payload_reflected,
    probe_query_param,
)

class SqlInjectionScanner(Scanner):
    name = "SQL Injection"
    description = "Probes query or form parameters for SQL error behavior and reflection differences."

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

        baseline_status, baseline_headers, baseline_body = await probe_query_param(session, endpoint, params[0], "1")
        probe_status, probe_headers, probe_body = await probe_query_param(session, endpoint, params[0], "1'%20OR%20'1'='1")

        evidence_items = []
        if body_contains_error(probe_body, SQL_ERROR_KEYWORDS):
            evidence_items.append("SQL error keyword detected")
        if body_changed(baseline_body, probe_body):
            evidence_items.append("Response changed after SQL payload")
        if payload_reflected(probe_body, "1' OR '1'='1"):
            evidence_items.append("Payload reflected in response")

        if evidence_items:
            self._findings.append({
                "id": f"sql-{endpoint['url']}",
                "category": "Injection",
                "title": "SQL injection indicator",
                "severity": "Medium",
                "confidence": min(90, 50 + len(evidence_items) * 10),
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": params[0],
                "evidence": "; ".join(evidence_items),
                "explanation": "The endpoint responded to an SQL-like payload with error behavior or response differences.",
                "verification_guidance": "Use an authorized proxy and compare safe SQL payloads against baseline responses.",
                "impact": "SQL injection can expose or modify backend database data.",
                "remediation": "Use prepared statements, parameterized queries, and input validation.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
