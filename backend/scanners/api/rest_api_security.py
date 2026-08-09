from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, extract_query_params, is_json_endpoint, url_contains_words


class RestApiSecurityScanner(Scanner):
    name = "REST API security"
    description = "Flags REST API endpoints that may require stronger authentication or method restrictions."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return "/api" in endpoint.get("url", "").lower() or is_json_endpoint(endpoint)

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        params = extract_query_params(endpoint)
        inputs = [name.lower() for name in all_input_names(endpoint)]
        evidence = []

        if "/api" in url.lower():
            evidence.append("The endpoint is clearly a REST API route.")
        if is_json_endpoint(endpoint):
            evidence.append("The endpoint appears to return or accept JSON content.")
        if method == "GET" and params:
            evidence.append("The endpoint accepts query parameters on a GET request.")
        if any(word in inputs for word in ["token", "auth", "authorization", "api_key", "api-key"]):
            evidence.append("The request exposes API-like authentication parameters.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"rest-api-security-{url}",
            "category": "API / Modern web",
            "title": "REST API security indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": method,
            "parameter": ", ".join(params or inputs) or "N/A",
            "evidence": " ".join(evidence),
            "explanation": "REST APIs should be reviewed for authentication, authorization, and proper HTTP method usage.",
            "verification_guidance": "Verify that the API endpoints require appropriate authorization and use safe HTTP methods.",
            "impact": "Weak REST API security can allow unauthorized access to data or operations.",
            "remediation": "Enforce strong authentication, authorization checks, and method restrictions for API routes.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
