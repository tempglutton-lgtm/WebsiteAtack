from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import url_contains_words


class WebSocketSecurityScanner(Scanner):
    name = "WebSocket security"
    description = "Detects WebSocket or socket-style endpoints and highlights potential insecurity."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        url = endpoint.get("url", "").lower()
        return url.startswith("ws://") or url.startswith("wss://") or url_contains_words(url, ["/ws", "/socket", "websocket"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        url = endpoint.get("url", "")
        evidence = []

        if url.startswith("ws://"):
            evidence.append("The WebSocket endpoint uses an insecure ws:// scheme.")
        if url.startswith("wss://"):
            evidence.append("The WebSocket endpoint uses a secure wss:// scheme.")
        if url_contains_words(url, ["/ws", "/socket", "websocket"]):
            evidence.append("The endpoint appears to be socket- or WebSocket-related.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"websocket-security-{url}",
            "category": "API / Modern web",
            "title": "WebSocket security indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": url,
            "method": endpoint.get("method", "GET"),
            "parameter": "N/A",
            "evidence": " ".join(evidence),
            "explanation": "WebSocket endpoints should be reviewed for authentication, transport security, and message validation.",
            "verification_guidance": "Verify that the socket endpoint enforces authentication and uses TLS in production.",
            "impact": "Unprotected WebSocket endpoints can allow unauthorized access to real-time application channels.",
            "remediation": "Use wss://, require authentication, and validate message payloads on the server.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
