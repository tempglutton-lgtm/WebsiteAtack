import asyncio
from urllib.parse import urljoin

import aiohttp

from backend.crawler.scope import TargetScope


class RequestRateLimiter:
    def __init__(self, requests_per_second: float):
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than zero")
        self.interval = 1 / requests_per_second
        self._next_request_at = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            wait = max(0.0, self._next_request_at - now)
            self._next_request_at = max(now, self._next_request_at) + self.interval
        if wait:
            await asyncio.sleep(wait)


def rate_limit_trace_config(
    limiter: RequestRateLimiter,
    scope: TargetScope | None = None,
    progress: dict | None = None,
) -> aiohttp.TraceConfig:
    trace_config = aiohttp.TraceConfig()

    async def limit_request_start(session, context, params):
        if scope is not None and not scope.is_in_scope(str(params.url)):
            raise aiohttp.ClientError("Request is outside the authorized target scope.")
        await limiter.acquire()
        if progress is not None:
            progress["requests"] = progress.get("requests", 0) + 1

    async def validate_redirect(session, context, params):
        location = params.response.headers.get("Location")
        if scope is not None and location:
            destination = urljoin(str(params.url), location)
            if not scope.is_in_scope(destination):
                raise aiohttp.ClientError("Redirect is outside the authorized target scope.")
        await limiter.acquire()
        if progress is not None:
            progress["requests"] = progress.get("requests", 0) + 1

    trace_config.on_request_start.append(limit_request_start)
    trace_config.on_request_redirect.append(validate_redirect)
    return trace_config
