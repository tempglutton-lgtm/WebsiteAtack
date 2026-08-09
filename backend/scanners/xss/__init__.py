from typing import Any, List

from backend.scanners.base import Scanner

class ReflectedXssScanner(Scanner):
    name = "Reflected XSS"
    description = "Detects reflected cross-site scripting indicators on pages that reflect user input."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("query_params")) or bool(endpoint.get("forms"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        parameter_names = list(endpoint.get("query_params", {}).keys())
        if not parameter_names:
            parameter_names = [i.get("name") for form in endpoint.get("forms", []) for i in form.get("inputs", []) if i.get("name")]
        if not parameter_names:
            return []

        self._findings.append({
            "id": f"xss-reflected-{endpoint['url']}",
            "category": "Client-side",
            "title": "Reflected XSS indicator",
            "severity": "Medium",
            "confidence": 50,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(parameter_names),
            "evidence": "The endpoint reflects or accepts user data that could be rendered in a page.",
            "explanation": "Reflected XSS can occur when input is displayed back to the browser without proper escaping.",
            "verification_guidance": "Submit a safe string containing script-like text and inspect the rendered response for reflection.",
            "impact": "Successful XSS can execute JavaScript in the context of the victim user.",
            "remediation": "Escape or sanitize all user-controlled data before rendering it in HTML responses.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings


class StoredXssScanner(Scanner):
    name = "Stored XSS"
    description = "Identifies endpoints that store user-submitted values which may be reflected later in an unsafe context."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return any(form for form in endpoint.get("forms", []))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        form_names = [input.get("name") for form in endpoint.get("forms", []) for input in form.get("inputs", []) if input.get("name")]
        if not form_names:
            return []

        self._findings.append({
            "id": f"xss-stored-{endpoint['url']}",
            "category": "Client-side",
            "title": "Stored XSS indicator",
            "severity": "Medium",
            "confidence": 45,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(form_names),
            "evidence": "The page contains forms which may store input for later rendering.",
            "explanation": "Stored XSS is possible when stored user input is output without encoding.",
            "verification_guidance": "Submit a safe XSS payload and review later pages or dashboards for reflection.",
            "impact": "Stored XSS can affect many users and steal session data.",
            "remediation": "Sanitize stored input and use output encoding when rendering values.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings


class DomXssScanner(Scanner):
    name = "DOM XSS"
    description = "Flags endpoints that include user-controlled parameters in client-side script paths or fragment handlers."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        query_keys = list(endpoint.get("query_params", {}).keys())
        return bool(query_keys) or bool(endpoint.get("forms"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        if "#" in endpoint["url"] or any(name.lower() in ["hash", "fragment", "callback"] for name in endpoint.get("query_params", {})):
            self._findings.append({
                "id": f"xss-dom-{endpoint['url']}",
                "category": "Client-side",
                "title": "DOM XSS indicator",
                "severity": "Low",
                "confidence": 40,
                "status": "Potential",
                "url": endpoint["url"],
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(list(endpoint.get("query_params", {}).keys())),
                "evidence": "The URL includes client-side fragment or callback parameters.",
                "explanation": "DOM XSS can occur when JavaScript processes untrusted input directly in the browser.",
                "verification_guidance": "Check how fragment or callback parameters are used by client-side scripts.",
                "impact": "DOM XSS can execute attacker-controlled scripts in the browser.",
                "remediation": "Avoid using untrusted input in DOM APIs and encode data before insertion.",
            })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings


class HtmlInjectionScanner(Scanner):
    name = "HTML Injection"
    description = "Detects endpoints that may render raw HTML from user input without proper sanitization."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("forms")) or bool(endpoint.get("query_params"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        fields = list(endpoint.get("query_params", {}).keys()) or [i.get("name") for form in endpoint.get("forms", []) for i in form.get("inputs", []) if i.get("name")]
        if not fields:
            return []

        self._findings.append({
            "id": f"html-injection-{endpoint['url']}",
            "category": "Client-side",
            "title": "HTML injection indicator",
            "severity": "Low",
            "confidence": 45,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(fields),
            "evidence": "The endpoint accepts input that may later be rendered as HTML.",
            "explanation": "User-controlled HTML content should be escaped before rendering to avoid injection.",
            "verification_guidance": "Test with safe tag-like input and inspect the rendered output.",
            "impact": "HTML injection can lead to XSS or content spoofing.",
            "remediation": "Encode HTML output and filter disallowed markup.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings


class OpenRedirectScanner(Scanner):
    name = "Open Redirect"
    description = "Detects redirect parameters and endpoints that may allow unsafe redirects."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        query_keys = [key.lower() for key in endpoint.get("query_params", {}).keys()]
        return any(key in query_keys for key in ["url", "next", "return", "redirect"])

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        params = [key for key in endpoint.get("query_params", {}).keys() if key.lower() in ["url", "next", "return", "redirect"]]
        if not params:
            return []
        self._findings.append({
            "id": f"open-redirect-{endpoint['url']}",
            "category": "Client-side",
            "title": "Open redirect indicator",
            "severity": "Medium",
            "confidence": 65,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(params),
            "evidence": "The endpoint includes common redirect-related parameters.",
            "explanation": "Open redirects can be abused to redirect users to malicious URLs.",
            "verification_guidance": "Send a safe external destination and verify whether the application redirects without validation.",
            "impact": "Open redirects can enable phishing and token theft.",
            "remediation": "Validate redirect destinations or use allowlisted URLs only.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings


class ContentInjectionScanner(Scanner):
    name = "Content Injection"
    description = "Flags endpoints that may serve user content in a way that allows injection into HTML or script contexts."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        return bool(endpoint.get("forms")) or bool(endpoint.get("query_params"))

    async def run(self, endpoint: Any) -> List[dict]:
        self._findings = []
        fields = list(endpoint.get("query_params", {}).keys())
        if not fields:
            fields = [i.get("name") for form in endpoint.get("forms", []) for i in form.get("inputs", []) if i.get("name")]
        if not fields:
            return []
        self._findings.append({
            "id": f"content-injection-{endpoint['url']}",
            "category": "Client-side",
            "title": "Content injection indicator",
            "severity": "Low",
            "confidence": 50,
            "status": "Potential",
            "url": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameter": ", ".join(fields),
            "evidence": "The endpoint accepts input values that may be inserted into rendered content.",
            "explanation": "Content injection can lead to XSS or page manipulation if rendered without encoding.",
            "verification_guidance": "Review how input is inserted into HTML and script templates.",
            "impact": "Injected content may execute scripts or mislead users.",
            "remediation": "Use strict output encoding for all user-supplied values.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
