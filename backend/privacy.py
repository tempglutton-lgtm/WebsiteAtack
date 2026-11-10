import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|secret|authorization|cookie|session(?:id)?|csrf[_-]?token)"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&;,<>]+)"
)
BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
URL_QUERY_VALUE_RE = re.compile(r"([?&][^=&#\s]+)=([^&#\s]*)")


def redact_url_query_value(match: re.Match[str]) -> str:
    value = match.group(2)
    if value.lower() == "%5bredacted%5d" or value == "[redacted]":
        return match.group(0)
    return f"{match.group(1)}=[redacted]"


def redact_sensitive_text(value: str) -> str:
    value = BEARER_TOKEN_RE.sub("Bearer [redacted]", value)
    value = URL_QUERY_VALUE_RE.sub(redact_url_query_value, value)
    return SECRET_ASSIGNMENT_RE.sub(r"\1\2[redacted]", value)


def sanitized_target_url(target_url: str) -> str:
    parsed = urlsplit(target_url)
    query = urlencode(
        [(key, "[redacted]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
