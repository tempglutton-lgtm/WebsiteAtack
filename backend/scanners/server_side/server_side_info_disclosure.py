from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import parse_json_body, url_contains_words


class ServerSideInformationDisclosureScanner(Scanner):
    name = "Server-side information disclosure"
    description = "Detects server responses that leak potential internal or sensitive information."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("body")) or bool(endpoint.get("headers"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        body = str(endpoint.get("body", ""))
        headers = endpoint.get("headers", {})
        evidence = []

        if any(keyword in body.lower() for keyword in ["traceback", "exception", "stack trace", "sql error", "database error", "permission denied", "not found"]):
            evidence.append("Response body contains error or stack trace text.")

        if any(keyword in body.lower() for keyword in ["password", "secret", "api_key", "api key", "token", "connection string", "jdbc:", "mongodb://", "aws_access_key_id"]):
            evidence.append("Response body contains sensitive configuration or credentials.")

        for header, value in headers.items():
            if header.lower() in ["server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-node-version"]:
                evidence.append(f"Response header {header} discloses platform or version information.")
            if "traceback" in str(value).lower() or "exception" in str(value).lower():
                evidence.append(f"Response header {header} contains error details.")

        json_data = parse_json_body(body)
        if isinstance(json_data, dict):
            for field in ["password", "token", "secret", "api_key", "apiKey", "credential"]:
                if field in json_data:
                    evidence.append(f"Response JSON contains sensitive field {field}.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"server-info-disclosure-{endpoint.get('url', '')}",
            "category": "Server-side",
            "title": "Server-side information disclosure",
            "severity": "Medium",
            "confidence": 60,
            "status": "Needs Manual Verification",
            "url": endpoint.get("url", ""),
            "method": endpoint.get("method", "GET"),
            "parameter": "N/A",
            "evidence": " ".join(evidence),
            "explanation": "Server-side responses can leak internal details or credentials if error handling and output filtering are weak.",
            "verification_guidance": "Review response bodies and headers for internal stack traces, debug text, or secrets.",
            "impact": "Information disclosure can enable attackers to craft targeted exploits against the server.",
            "remediation": "Sanitize responses, remove debug output from production, and avoid returning internal configuration values.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
