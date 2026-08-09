from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, parse_json_body, url_contains_words


class ExcessiveDataExposureScanner(Scanner):
    name = "Excessive data exposure"
    description = "Detects API responses or endpoints that may expose more data than needed."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return endpoint.get("body") is not None or "/api" in endpoint.get("url", "").lower()

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        body = endpoint.get("body", "")
        url = endpoint.get("url", "")
        json_data = parse_json_body(body)
        evidence = []

        if isinstance(json_data, dict) and len(json_data) > 10:
            evidence.append("JSON response contains many fields and may expose excessive data.")
        if isinstance(json_data, dict) and any(field in json_data for field in ["password", "secret", "token", "api_key", "credentials"]):
            evidence.append("JSON response contains sensitive fields that may be overexposed.")
        if "admin" in url.lower() or "user" in url.lower() and "/api" in url.lower():
            evidence.append("The endpoint appears to return user or admin-related data.")

        if not evidence:
            return []

        params = [name.lower() for name in all_input_names(endpoint)]
        self._findings.append({
            "id": f"excessive-data-{url}",
            "category": "API / Modern web",
            "title": "Excessive data exposure indicator",
            "severity": "Medium",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(params) or "N/A",
            "evidence": " ".join(evidence),
            "explanation": "APIs returning too many fields or sensitive data may expose more information than necessary.",
            "verification_guidance": "Review the response schema and ensure only required data is returned to each caller.",
            "impact": "Excessive data exposure can leak internal state, secrets, or personally identifiable information.",
            "remediation": "Implement output filtering and return only the fields needed for each endpoint.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
