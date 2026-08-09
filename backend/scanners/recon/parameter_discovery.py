from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, extract_query_params, parse_json_body


class ParameterDiscoveryScanner(Scanner):
    name = "Parameter discovery"
    description = "Identifies endpoints with exposed parameters that can be enumerated or abused."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("query_params")) or bool(endpoint.get("forms")) or bool(endpoint.get("body"))

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        params = set(all_input_names(endpoint))
        json_body = parse_json_body(endpoint.get("body", ""))
        if isinstance(json_body, dict):
            params.update(json_body.keys())

        if params:
            self._findings.append({
                "id": f"parameter-discovery-{endpoint.get('url', '')}",
                "category": "Reconnaissance",
                "title": "Parameter discovery indicator",
                "severity": "Informational",
                "confidence": 70,
                "status": "Informational",
                "url": endpoint.get("url", ""),
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(sorted(params)),
                "evidence": f"Discovered parameters: {', '.join(sorted(params))}.",
                "explanation": "Exposed query, form, or JSON parameters can be used for further reconnaissance and injection testing.",
                "verification_guidance": "Review the endpoint for additional hidden parameters and access controls.",
                "impact": "Parameter discovery can help attackers enumerate functionality and craft targeted payloads.",
                "remediation": "Minimize exposed parameters and validate all user-supplied input.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
