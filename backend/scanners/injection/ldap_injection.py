from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import (
    LDAP_ERROR_KEYWORDS,
    all_input_names,
    body_contains_error,
    body_changed,
    payload_reflected,
    probe_parameter,
)

class LdapInjectionScanner(Scanner):
    name = "LDAP Injection"
    description = "Probes inputs for LDAP filter error behavior and response changes."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return any(term in endpoint.get("url", "").lower() for term in ["ldap", "directory", "search"]) or bool(all_input_names(endpoint))

    async def run(self, endpoint: Any, session: Optional[object] = None) -> List[dict]:
        self._findings = []
        if session is None:
            return []
        params = all_input_names(endpoint)
        if not params:
            return []

        baseline_status, baseline_headers, baseline_body = await probe_parameter(session, endpoint, "1", params[0])
        probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, "*(uid=*)", params[0])

        evidence_items = []
        if body_contains_error(probe_body, LDAP_ERROR_KEYWORDS):
            evidence_items.append("LDAP error keyword detected")
        if body_changed(baseline_body, probe_body):
            evidence_items.append("Response changed after LDAP payload")
        if payload_reflected(probe_body, "*(uid=*)"):
            evidence_items.append("Payload reflected in response")

        if evidence_items:
            self._findings.append({
                "id": f"ldap-{endpoint['url']}",
                "category": "Injection",
                "title": "LDAP injection indicator",
                "severity": "Medium",
                "confidence": min(90, 45 + len(evidence_items) * 10),
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": params[0],
                "evidence": "; ".join(evidence_items),
                "explanation": "The endpoint responded differently to an LDAP-style probe payload.",
                "verification_guidance": "Review LDAP filter handling and test authorized payloads safely.",
                "impact": "LDAP injection may expose directory data or allow query manipulation.",
                "remediation": "Sanitize LDAP input and avoid string concatenation in filters.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
