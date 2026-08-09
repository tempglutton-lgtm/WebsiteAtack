from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, parse_json_body, url_contains_words


class GraphQLSecurityScanner(Scanner):
    name = "GraphQL security"
    description = "Detects GraphQL endpoints and common GraphQL security risk indicators."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        body = endpoint.get("body", "")
        return "/graphql" in endpoint.get("url", "").lower() or "graphql" in endpoint.get("url", "").lower() or "query" in body or "mutation" in body

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        body = endpoint.get("body", "")
        evidence = []

        if "/graphql" in url.lower() or "graphql" in url.lower():
            evidence.append("The endpoint URL references GraphQL.")
        if "__schema" in body or "__type" in body or "introspection" in body:
            evidence.append("The payload appears to include GraphQL introspection or schema information.")
        if "query" in body or "mutation" in body:
            evidence.append("The request body contains GraphQL query or mutation syntax.")

        parsed = parse_json_body(body)
        if isinstance(parsed, dict):
            if "query" in parsed:
                evidence.append("The JSON body contains a GraphQL query field.")
            if "mutation" in parsed:
                evidence.append("The JSON body contains a GraphQL mutation field.")

        if not evidence:
            return []

        params = [name.lower() for name in all_input_names(endpoint)]
        self._findings.append({
            "id": f"graphql-security-{url}",
            "category": "API / Modern web",
            "title": "GraphQL security indicator",
            "severity": "Medium",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "POST"),
            "parameter": ", ".join(params) or "N/A",
            "evidence": " ".join(evidence),
            "explanation": "GraphQL endpoints are sensitive and should be reviewed for introspection, authorization, and rate limiting.",
            "verification_guidance": "Verify schema exposure, field-level authorization, and whether introspection is restricted in production.",
            "impact": "GraphQL misconfigurations can expose excessive data or allow unauthorized queries.",
            "remediation": "Restrict GraphQL introspection, enforce authorization at the field level, and validate input queries.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
