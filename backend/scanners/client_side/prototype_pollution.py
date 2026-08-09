from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import extract_form_fields, extract_query_params, extract_response_fields, is_json_endpoint

PROTOTYPE_POLLUTION_KEYS = {"__proto__", "constructor", "prototype", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"}

class PrototypePollutionScanner(Scanner):
    name = "Prototype-pollution indicators"
    description = "Detects JSON endpoints that may expose property names or payloads prone to prototype pollution issues."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return is_json_endpoint(endpoint) or bool(extract_query_params(endpoint)) or bool(extract_form_fields(endpoint))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        risky_names = []
        if is_json_endpoint(endpoint):
            fields = extract_response_fields(endpoint.get("body", ""))
            risky_names.extend(name for name in fields if name in PROTOTYPE_POLLUTION_KEYS)

        query_keys = extract_query_params(endpoint)
        risky_names.extend(name for name in query_keys if name in PROTOTYPE_POLLUTION_KEYS)

        form_names = extract_form_fields(endpoint)
        risky_names.extend(name for name in form_names if name in PROTOTYPE_POLLUTION_KEYS)

        risky_names = list(dict.fromkeys(risky_names))
        if risky_names:
            self._findings.append({
                "id": f"prototype-pollution-{endpoint['url']}",
                "category": "Client-side",
                "title": "Prototype pollution indicator",
                "severity": "Low",
                "confidence": 55,
                "status": "Potential",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(risky_names),
                "evidence": "The endpoint exposes prototype-like property names in JSON or request inputs.",
                "explanation": "Prototype pollution risks increase when special property names are accepted or returned in JSON payloads.",
                "verification_guidance": "Inspect JSON payload handling and validate that object keys like __proto__ are rejected or normalized.",
                "impact": "Prototype pollution can lead to arbitrary code execution or data corruption in JavaScript applications.",
                "remediation": "Normalize and validate JSON keys before merging objects, and reject dangerous property names.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
