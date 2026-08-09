from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import body_changed, probe_parameter, response_has_redirect

REDIRECT_TEST_TARGET = "https://example.com/websiteattack-redirect-test"

class OpenRedirectScanner(Scanner):
    name = "Open Redirect"
    description = "Detects redirect parameters and paths that may allow unvalidated redirection."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        query_keys = [key.lower() for key in endpoint.get("query_params", {}).keys()]
        path = endpoint.get("url", "").lower()
        return any(name in query_keys for name in ["url", "next", "return", "redirect"]) or "redirect" in path

    async def run(self, endpoint: Any, session: Optional[object] = None) -> List[dict]:
        self._findings = []
        params = [key for key in endpoint.get("query_params", {}).keys() if key.lower() in ["url", "next", "return", "redirect"]]
        redirect_path = "redirect" in endpoint.get("url", "").lower()
        if not params and not redirect_path:
            return []

        evidence_items = []
        if session is not None and params:
            baseline_status, baseline_headers, baseline_body = await probe_parameter(session, endpoint, "safevalue", params[0])
            probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, REDIRECT_TEST_TARGET, params[0])
            if response_has_redirect(probe_headers, REDIRECT_TEST_TARGET):
                evidence_items.append("Redirect target returned in Location header")
            if body_changed(baseline_body, probe_body):
                evidence_items.append("Response changed after redirect parameter payload")

        if evidence_items:
            confidence = min(90, 45 + len(evidence_items) * 15)
            status = "Needs Manual Verification"
            evidence = "; ".join(evidence_items)
        else:
            confidence = 60 if params else 35
            status = "Potential"
            evidence = "The endpoint contains redirect-related parameters or path segments that may allow open redirection."

        self._findings.append({
            "id": f"open-redirect-{endpoint['url']}",
            "category": "Client-side",
            "title": "Open redirect indicator",
            "severity": "Medium",
            "confidence": confidence,
            "status": status,
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(params) or "N/A",
            "evidence": evidence,
            "explanation": "Open redirects can be abused when redirect targets are not validated.",
            "verification_guidance": "Test with a safe external URL to see whether the application redirects without checking the destination domain.",
            "impact": "Open redirects can facilitate phishing and session theft.",
            "remediation": "Validate redirect destinations against an allowlist and sanitize redirect parameters.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
