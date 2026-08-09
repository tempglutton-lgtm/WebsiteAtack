from typing import Any, List

from backend.scanners.base import Scanner
from backend.scanners.utils import all_input_names, url_contains_words


class UnsafeFileUploadScanner(Scanner):
    name = "Unsafe file upload"
    description = "Identifies file upload endpoints and upload forms that require manual review for unsafe handling."

    def __init__(self):
        self._findings: List[dict] = []

    def applicable(self, endpoint: Any) -> bool:
        if any(form.get("enctype", "").lower() == "multipart/form-data" for form in endpoint.get("forms", [])):
            return True
        if any((input_field.get("type", "") or "").lower() == "file" for form in endpoint.get("forms", []) for input_field in form.get("inputs", [])):
            return True
        names = [name.lower() for name in all_input_names(endpoint)]
        return any(keyword in name for name in names for keyword in ["file", "upload", "image", "avatar", "document"])

    async def run(self, endpoint: Any, session=None) -> List[dict]:
        self._findings = []
        file_inputs = []
        for form in endpoint.get("forms", []):
            for input_field in form.get("inputs", []):
                if (input_field.get("type", "") or "").lower() == "file":
                    file_inputs.append(input_field.get("name", "file"))

        evidence = []
        if file_inputs:
            evidence.append(f"File upload form fields detected: {', '.join(file_inputs)}.")
        elif any(form.get("enctype", "").lower() == "multipart/form-data" for form in endpoint.get("forms", [])):
            evidence.append("Multipart upload form was detected.")
        else:
            names = [name.lower() for name in all_input_names(endpoint)]
            file_fields = [name for name in names if any(keyword in name for keyword in ["file", "upload", "image", "avatar", "document"])]
            if file_fields:
                evidence.append(f"Endpoint uses file-related parameter names: {', '.join(file_fields)}.")

        if not evidence:
            return []

        self._findings.append({
            "id": f"unsafe-file-upload-{endpoint.get('url', '')}",
            "category": "Server-side",
            "title": "Unsafe file upload indicator",
            "severity": "Medium",
            "confidence": 55,
            "status": "Needs Manual Verification",
            "url": endpoint.get("url", ""),
            "method": endpoint.get("method", "POST"),
            "parameter": ", ".join(file_inputs) if file_inputs else "N/A",
            "evidence": " ".join(evidence),
            "explanation": "File upload endpoints must validate file type, size, and storage path to prevent remote code execution or data exposure.",
            "verification_guidance": "Review upload handling and confirm that files are restricted, scanned, and stored safely.",
            "impact": "Unsafe uploads can lead to malware upload, remote code execution, or unauthorized file access.",
            "remediation": "Validate file uploads server-side, restrict allowed types, and store uploads outside the web root.",
        })
        return self._findings

    def return_findings(self) -> List[dict]:
        return self._findings
