from typing import Any, List
from urllib.parse import urlparse

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words

class HorizontalPrivilegeEscalationScanner(Scanner):
    name = "Horizontal privilege escalation"
    description = "Detects endpoints that may allow users to access peer accounts or resources without proper isolation."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return url_contains_words(endpoint.get("url", ""), ["user", "account", "profile", "order"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        self._findings.append({
            "id": f"horizontal-{endpoint['url']}",
            "category": "Access control",
            "title": "Horizontal privilege escalation indicator",
            "severity": "Low",
            "confidence": 45,
            "status": "Needs Manual Verification",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": "",
            "evidence": "The endpoint represents user-facing or account-specific resources.",
            "explanation": "Horizontal escalation risk exists when peers can access each other’s resources if ownership checks are weak.",
            "verification_guidance": "Verify that users cannot access another user’s data or operations.",
            "impact": "Unauthorized access to other users’ accounts or records may result.",
            "remediation": "Enforce strict ownership and authorization checks on sensitive resources.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings


class VerticalPrivilegeEscalationScanner(Scanner):
    name = "Vertical privilege escalation"
    description = "Detects endpoints that may allow operations reserved for higher-privilege roles."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        path = urlparse(endpoint.get("url", "")).path.lower()
        return any(term in path for term in ["admin", "manage", "dashboard", "config", "user/delete"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        self._findings.append({
            "id": f"vertical-{endpoint['url']}",
            "category": "Access control",
            "title": "Vertical privilege escalation indicator",
            "severity": "Medium",
            "confidence": 50,
            "status": "Needs Manual Verification",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": "",
            "evidence": "The endpoint path suggests privileged functionality.",
            "explanation": "Vertical escalation risk exists when privileged endpoints lack proper role checks.",
            "verification_guidance": "Confirm that only administrators can access or execute the operation.",
            "impact": "Unauthorized privilege elevation may allow admin-level actions.",
            "remediation": "Implement role-based access controls and verify on every request.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
