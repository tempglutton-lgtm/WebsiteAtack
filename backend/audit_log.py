import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


RETENTION_DAYS = 90


def audit_log_path() -> Path:
    configured_path = os.environ.get("WEBSITEATTACK_AUDIT_PATH")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path.home() / ".websiteattack" / "audit.jsonl"


def append_audit_event(event: str, details: dict[str, Any]) -> Path:
    path = audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    retained_lines = []

    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            timestamp = datetime.fromisoformat(entry["timestamp"])
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            if timestamp >= cutoff:
                retained_lines.append(json.dumps(entry, ensure_ascii=False))

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    retained_lines.append(json.dumps(entry, ensure_ascii=False))
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write("\n".join(retained_lines) + "\n")
        os.replace(temporary_path, path)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()
    return path
