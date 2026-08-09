from typing import Any, List, Optional

from backend.scanners.base import Scanner
from backend.scanners.utils import (
    COMMAND_INJECTION_KEYWORDS,
    all_input_names,
    body_contains_error,
    body_changed,
    payload_reflected,
    probe_parameter,
)

class CommandInjectionScanner(Scanner):
    name = "Command Injection"
    description = "Probes input fields for command injection indicators through shell-like payloads and response differences."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(all_input_names(endpoint))

    async def run(self, endpoint: Any, session: Optional[object] = None) -> List[dict]:
        self._findings = []
        if session is None:
            return []
        params = all_input_names(endpoint)
        if not params:
            return []

        baseline_status, baseline_headers, baseline_body = await probe_parameter(session, endpoint, "hello", params[0])
        probe_status, probe_headers, probe_body = await probe_parameter(session, endpoint, ";echoCOMMANDINJECTED", params[0])

        evidence_items = []
        if body_contains_error(probe_body, COMMAND_INJECTION_KEYWORDS):
            evidence_items.append("Command injection error keyword detected")
        if body_changed(baseline_body, probe_body):
            evidence_items.append("Response changed after command-style payload")
        if payload_reflected(probe_body, "COMMANDINJECTED"):
            evidence_items.append("Probe marker reflected in response")

        if evidence_items:
            self._findings.append({
                "id": f"cmd-{endpoint['url']}",
                "category": "Injection",
                "title": "Command injection indicator",
                "severity": "Medium",
                "confidence": min(90, 50 + len(evidence_items) * 10),
                "status": "Needs Manual Verification",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": params[0],
                "evidence": "; ".join(evidence_items),
                "explanation": "The endpoint reacted to a command-like payload with response changes or output markers.",
                "verification_guidance": "Use authorized non-destructive command-like probes and compare to baseline responses.",
                "impact": "Command injection can lead to remote code execution and system compromise.",
                "remediation": "Avoid shell execution with user input and sanitize all command arguments.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
