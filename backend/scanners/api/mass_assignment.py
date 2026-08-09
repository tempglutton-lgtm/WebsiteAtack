from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, url_contains_words


class ApiMassAssignmentScanner(Scanner):
    name = "API mass-assignment indicators"
    description = "Detects API endpoints that may be vulnerable to mass assignment or object property injection."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "")
        return "/api" in url.lower() or any(field in ["role", "admin", "is_admin", "user_id", "owner_id", "account_id"] for field in [name.lower() for name in all_input_names(endpoint)])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        inputs = [name.lower() for name in all_input_names(endpoint)]
        mass_fields = [field for field in inputs if field in ["role", "admin", "is_admin", "user_id", "owner_id", "account_id", "permissions"]]

        if not mass_fields and "/api" not in endpoint.get("url", "").lower():
            return []

        evidence = []
        if mass_fields:
            evidence.append(f"Potentially dangerous fields detected: {', '.join(mass_fields)}.")
        if "/api" in endpoint.get("url", "").lower():
            evidence.append("The endpoint is a REST API route and may process JSON object payloads.")

        self._findings.append({
            "id": f"api-mass-assignment-{endpoint.get('url', '')}",
            "category": "API / Modern web",
            "title": "API mass-assignment indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": endpoint.get("url", ""),
            "method": endpoint.get("method", "POST"),
            "parameter": ", ".join(mass_fields) or "N/A",
            "evidence": " ".join(evidence),
            "explanation": "APIs that accept object-like parameters may be vulnerable to mass assignment if property filtering is missing.",
            "verification_guidance": "Review how the API maps request properties to objects and whether sensitive properties are filtered out.",
            "impact": "Mass assignment can allow attackers to modify sensitive fields such as roles or ownership.",
            "remediation": "Implement strong parameter whitelisting and avoid direct object binding from untrusted input.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
