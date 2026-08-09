import aiohttp
from typing import Any, Dict, List, Optional

from backend.scanners.registry import all_scanners

class ScanManager:
    def __init__(self):
        self.scanners = all_scanners()
        self.findings: List[dict] = []

    async def execute(self, endpoints: List[dict], progress: Optional[dict] = None) -> Dict[str, list]:
        self.findings = []
        found_names = []
        all_names = [scanner.name for scanner in self.scanners]
        async with aiohttp.ClientSession() as session:
            for scanner in self.scanners:
                if progress is not None:
                    progress["module"] = scanner.name
                module_findings = []
                for endpoint in endpoints:
                    try:
                        if scanner.applicable(endpoint):
                            findings = await scanner.run(endpoint, session=session)
                            module_findings.extend(findings)
                            self.findings.extend(findings)
                            if progress is not None:
                                progress["tests_performed"] = len(self.findings)
                    except Exception:
                        continue
                if module_findings:
                    found_names.append(scanner.name)
        summary = {
            "found": found_names,
            "not_detected": [name for name in all_names if name not in found_names],
        }
        return {"findings": self.findings, "summary": summary}
