from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class HttpMethodConfigurationScanner(Scanner):
    name = "HTTP method/configuration issues"
    description = "Detects endpoints with potentially unsafe HTTP methods or configuration indicators."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return endpoint.get("method") is not None or bool(endpoint.get("headers"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        method = endpoint.get("method", "GET").upper()
        url = endpoint.get("url", "")
        evidence = []

        if method in ["PUT", "DELETE", "PATCH"] and "/api" in url.lower():
            evidence.append(f"The API endpoint accepts a state-changing HTTP method: {method}.")
        if method == "GET" and url_contains_words(url.lower(), ["update", "delete", "create", "action", "modify"]):
            evidence.append("A GET endpoint appears to perform or represent state-changing behavior.")
        if method == "POST" and "/delete" in url.lower():
            evidence.append("A POST endpoint appears to delete resources and should be reviewed for CSRF and authorization.")
        if endpoint.get("headers") and endpoint.get("headers", {}).get("allow"):
            evidence.append(f"The response specifies allowed methods: {endpoint.get('headers').get('allow')}")

        if not evidence:
            return []

        self._findings.append({
            "id": f"http-method-issues-{url}",
            "category": "API / Modern web",
            "title": "HTTP method/configuration issue indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": method,
            "parameter": "N/A",
            "evidence": " ".join(evidence),
            "explanation": "HTTP method misuse or poor method configuration can lead to unsafe API behavior.",
            "verification_guidance": "Review whether state-changing actions use appropriate verbs and whether allowed methods are restricted.",
            "impact": "Misconfigured methods can allow unintended operations or increase CSRF risk.",
            "remediation": "Follow RESTful method semantics, avoid state changes on GET, and restrict allowed methods server-side.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
