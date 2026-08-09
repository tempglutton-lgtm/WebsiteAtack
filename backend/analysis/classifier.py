from urllib.parse import urlparse


def generate_findings(endpoints):
    findings = []
    for endpoint in endpoints:
        url = endpoint.get("url")
        params = endpoint.get("query_params", {})
        forms = endpoint.get("forms", [])
        headers = endpoint.get("headers", {})
        parsed = urlparse(url)
        path = parsed.path or "/"
        query_keys = list(params.keys())
        if params:
            findings.append({
                "id": f"qs-{len(findings)+1}",
                "category": "Input handling",
                "title": "User-controlled query parameter detected",
                "severity": "Medium",
                "confidence": 65,
                "status": "Potential",
                "url": url,
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join(query_keys),
                "evidence": "Query parameters are present and may affect server behavior.",
                "explanation": "User-controlled query arguments can be used for reflected XSS, injection, or unsafe redirects.",
                "verification_guidance": "Inspect each parameter in a browser or proxy and confirm how the application handles submitted values.",
                "impact": "Improper validation of query parameters may expose sensitive logic or enable client-side injection.",
                "remediation": "Validate, normalize, and escape all query parameters before use in responses or backend logic.",
            })
        if any(name.lower() in ["url", "next", "return", "redirect"] for name in query_keys) or "redirect" in path.lower():
            findings.append({
                "id": f"openredirect-{len(findings)+1}",
                "category": "Open redirect",
                "title": "Redirect parameter or route detected",
                "severity": "Medium",
                "confidence": 70,
                "status": "Potential",
                "url": url,
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join([k for k in query_keys if k.lower() in ["url", "next", "return", "redirect"]]) or "N/A",
                "evidence": "This endpoint includes redirect-related behavior or common redirect parameter names.",
                "explanation": "Redirect parameters can be abused if the application does not validate destination domains.",
                "verification_guidance": "Submit a safe external URL and observe whether the application redirects without validation.",
                "impact": "Open redirects can facilitate phishing and credential theft in authorized security contexts.",
                "remediation": "Restrict redirect targets to allowed locations and validate all redirect input values.",
            })
        if forms:
            findings.append({
                "id": f"form-{len(findings)+1}",
                "category": "Form input",
                "title": "HTML form discovered",
                "severity": "Low",
                "confidence": 55,
                "status": "Informational",
                "url": url,
                "method": endpoint.get("method", "GET"),
                "parameter": ", ".join({i.get("name") or "<unnamed>" for f in forms for i in f.get("inputs", [])}),
                "evidence": "This page contains one or more HTML forms.",
                "explanation": "Forms represent user-controlled input entry points and should be tested for validation issues.",
                "verification_guidance": "Use safe form submissions and inspect how the server processes the input.",
                "impact": "Improper handling of form submissions may expose injection or broken authorization issues.",
                "remediation": "Apply strong server-side validation and sanitize all form input values.",
            })
        if any(keyword in path.lower() for keyword in ["admin", "login", "signup", "register", "reset"]):
            findings.append({
                "id": f"sensitive-{len(findings)+1}",
                "category": "Sensitive endpoint",
                "title": "Authentication or admin route discovered",
                "severity": "Informational",
                "confidence": 75,
                "status": "Informational",
                "url": url,
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": "The endpoint path contains authentication or administrative keywords.",
                "explanation": "These routes should be validated for proper access control and session handling.",
                "verification_guidance": "Verify that only authorized users can access these endpoints.",
                "impact": "Insecure handling of authentication/admin routes can expose account or application control paths.",
                "remediation": "Ensure proper access control and session protections on sensitive routes.",
            })
        server_header = headers.get("server")
        if server_header:
            findings.append({
                "id": f"disclosure-{len(findings)+1}",
                "category": "Information disclosure",
                "title": "Server information exposed",
                "severity": "Low",
                "confidence": 80,
                "status": "Informational",
                "url": url,
                "method": endpoint.get("method", "GET"),
                "parameter": "",
                "evidence": f"Server header revealed: {server_header}",
                "explanation": "Exposed server information can give attackers more context about the application's technology stack.",
                "verification_guidance": "Review response headers and ensure no sensitive platform or version data is exposed.",
                "impact": "Excessive disclosure may make targeted attacks easier.",
                "remediation": "Remove or standardize server version banners in HTTP headers.",
            })
    if not findings:
        findings.append({
            "id": "no-findings",
            "category": "Scan summary",
            "title": "No potential issues automatically detected",
            "severity": "Informational",
            "confidence": 100,
            "status": "Informational",
            "url": "",
            "method": "",
            "parameter": "",
            "evidence": "The scan did not identify any immediate pattern-based indicators.",
            "explanation": "This does not guarantee the target is secure; manual verification is still necessary.",
            "verification_guidance": "Review the discovered endpoints and perform targeted security testing.",
            "impact": "No immediate automatic indicators were found.",
            "remediation": "Continue with manual verification and targeted tests for sensitive functionality.",
        })
    return findings
