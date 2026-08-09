import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import aiohttp

PROBE_TIMEOUT_SECONDS = 10

COMMON_SENSITIVE_FIELDS = ["password", "token", "secret", "api_key", "credit_card", "ssn", "social_security"]


def extract_query_params(endpoint: Dict[str, Any]) -> List[str]:
    return list(endpoint.get("query_params", {}).keys())


def extract_form_fields(endpoint: Dict[str, Any]) -> List[str]:
    fields = []
    for form in endpoint.get("forms", []):
        for field in form.get("inputs", []):
            name = field.get("name")
            if name:
                fields.append(name)
    return fields


def all_input_names(endpoint: Dict[str, Any]) -> List[str]:
    return list({*extract_query_params(endpoint), *extract_form_fields(endpoint)})


def build_probe_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def build_probe_url_if_none(url: str, param: Optional[str], value: str) -> Optional[str]:
    if not param:
        return None
    return build_probe_url(url, param, value)


def strip_html(body: str) -> str:
    return re.sub(r"<[^>]+>", "", body)


def body_contains(body: str, needle: str) -> bool:
    return needle in body


def find_common_keywords(body: str, keywords: List[str]) -> List[str]:
    found = []
    lowered = body.lower()
    for keyword in keywords:
        if keyword.lower() in lowered:
            found.append(keyword)
    return found


def parse_json_body(body: str) -> Optional[Any]:
    try:
        return json.loads(body)
    except Exception:
        return None

SQL_ERROR_KEYWORDS = [
    "sql syntax", "mysql", "syntax error", "database error", "unterminated string", "sqlite", "odbc", "jdbc", "sqlstate", "mysql_fetch", "oracle", "psql"
]

NOSQL_ERROR_KEYWORDS = [
    "mongodb", "mongo", "no such command", "unknown operator", "query failed", "bad query", "cannot parse", "invalid argument"
]

COMMAND_INJECTION_KEYWORDS = [
    "injection", "command not found", "sh: ", "bash: ", "cmd.exe", "syntax error", "permission denied"
]

SSRF_ERROR_KEYWORDS = [
    "ssrf", "unable to connect to", "connection refused", "connection timed out", "no route to host"
]

XML_ERROR_KEYWORDS = [
    "xml parser", "xpath", "xquery", "xml error", "malformed xml", "xml syntax", "entity not defined"
]

LDAP_ERROR_KEYWORDS = [
    "ldap", "dn=", "no such object", "invalid dn", "ldap query", "unwilling to perform", "protocol error"
]

HTML_INJECTION_MARKERS = ["<script", "<img", "<svg", "<iframe", "<b>", "<strong>", "<object>"]

EXPRESSION_LANGUAGE_PAYLOADS = ["${7*7}", "#{7*7}", "{{7*7}}", "#{(7*7)}"]


def body_contains_error(body: str, keywords: List[str]) -> bool:
    lower = body.lower()
    return any(keyword in lower for keyword in keywords)


def body_changed(baseline: str, probe: str, threshold: float = 0.02) -> bool:
    if baseline == probe:
        return False
    if not baseline or not probe:
        return bool(probe)
    delta = abs(len(probe) - len(baseline)) / max(len(baseline), 1)
    return delta >= threshold


def payload_reflected(body: str, payload: str) -> bool:
    return payload in body


def response_includes_header(headers: Dict[str, str], name: str) -> bool:
    return name.lower() in {k.lower(): v for k, v in headers.items()}


def find_fragment(body: str, value: str) -> bool:
    return value in body


async def fetch_url(session: aiohttp.ClientSession, url: str) -> Tuple[int, Dict[str, str], str]:
    try:
        async with session.get(url, timeout=PROBE_TIMEOUT_SECONDS, allow_redirects=False) as response:
            body = await response.text(errors="ignore")
            headers = {k.lower(): v for k, v in response.headers.items()}
            return response.status, headers, body
    except Exception:
        return 0, {}, ""


async def probe_parameter(session: aiohttp.ClientSession, endpoint: Dict[str, Any], payload: str, param: Optional[str] = None) -> Tuple[int, Dict[str, str], str]:
    if not param:
        params = extract_query_params(endpoint)
        if not params:
            params = extract_form_fields(endpoint)
        if not params:
            return 0, {}, ""
        param = params[0]
    target = build_probe_url(endpoint.get("url", ""), param, payload)
    return await fetch_url(session, target)


def is_html_endpoint(endpoint: Dict[str, Any]) -> bool:
    return "text/html" in endpoint.get("content_type", "")


def is_json_endpoint(endpoint: Dict[str, Any]) -> bool:
    return "application/json" in endpoint.get("content_type", "")


def url_contains_words(url: str, words: List[str]) -> bool:
    lowered = url.lower()
    return any(word in lowered for word in words)


def header_missing(endpoint: Dict[str, Any], header_name: str) -> bool:
    return header_name.lower() not in endpoint.get("headers", {})


def response_has_redirect(headers: Dict[str, str], location_substring: str) -> bool:
    location = headers.get("location", "")
    return location_substring in location


def get_host(url: str) -> str:
    return urlparse(url).hostname or ""


def is_subdomain(parent: str, target: str) -> bool:
    if parent == target:
        return False
    return target.endswith("." + parent)


def discover_script_urls(endpoint: Dict[str, Any]) -> List[str]:
    return [src for src in endpoint.get("scripts", []) if src]


def string_looks_like_json(body: str) -> bool:
    return body.strip().startswith("{") or body.strip().startswith("[")


def extract_response_fields(body: str) -> List[str]:
    data = parse_json_body(body)
    if isinstance(data, dict):
        return list(data.keys())
    return []

SQL_ERROR_KEYWORDS = [
    "sql syntax", "mysql", "syntax error", "database error", "unterminated string", "sqlite", "odbc", "jdbc", "sqlstate"
]

XML_ERROR_KEYWORDS = [
    "xml parser", "xpath", "xquery", "xml error", "malformed xml", "xml syntax"
]

LDAP_ERROR_KEYWORDS = [
    "ldap", "dn=", "no such object", "invalid dn", "ldap query"
]

HTML_INJECTION_MARKERS = ["<script", "<img", "<svg", "<iframe", "<b>", "<strong>"]


def body_contains_error(body: str, keywords: List[str]) -> bool:
    lower = body.lower()
    return any(keyword in lower for keyword in keywords)


def body_changed(baseline: str, probe: str, threshold: float = 0.02) -> bool:
    if baseline == probe:
        return False
    if not baseline or not probe:
        return bool(probe)
    delta = abs(len(probe) - len(baseline)) / max(len(baseline), 1)
    return delta >= threshold


def payload_reflected(body: str, payload: str) -> bool:
    return payload in body


async def probe_query_param(session: aiohttp.ClientSession, endpoint: Dict[str, Any], param: Optional[str], payload: str) -> Tuple[int, Dict[str, str], str]:
    if not param:
        params = extract_query_params(endpoint)
        if not params:
            return 0, {}, ""
        param = params[0]
    target = build_probe_url(endpoint.get("url", ""), param, payload)
    return await fetch_url(session, target)
