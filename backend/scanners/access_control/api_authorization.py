from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import extract_query_params, is_json_endpoint, response_has_redirect, strip_html, url_contains_words

class ApiAuthorizationInconsistencyScanner(Scanner):
    name = "API authorization inconsistencies"
    description = "Detects API endpoints with unusual patterns or exposed fields that may indicate inconsistent authorization."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return is_json_endpoint(endpoint) or url_contains_words(endpoint.get("url", ""), ["api", "graphql"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        if not self.applicable(endpoint):
            return []
        params = extract_query_params(endpoint)
        if params or is_json_endpoint(endpoint):
            self._findings.append({
                "id": f"api-auth-{endpoint['url']}",
                "category": "Access control",
                "title": "API authorization inconsistency indicator",
                "severity": "Medium",
                "confidence": 50,
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(params) if params else "N/A",
                "evidence": "The endpoint appears to be an API endpoint with exposed query or JSON behavior.",
                "explanation": "APIs may expose authorization weaknesses when different endpoints or parameters are handled inconsistently.",
                "verification_guidance": "Compare access control behavior across API endpoints and see whether similar requests return different data.",
                "impact": "Inconsistent API authorization can leak data or permit unauthorized actions.",
                "remediation": "Standardize API authorization and enforce consistent access control across endpoints.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
