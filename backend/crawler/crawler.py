import asyncio
import logging
import re
from asyncio import Semaphore
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, parse_qs

import aiohttp

from backend.crawler.parser import SimpleHTMLLinkParser
from backend.crawler.scope import TargetScope
from backend.config import CrawlConfig
from backend.http_limits import read_response_body
from backend.privacy import sanitized_target_url
from backend.rate_limit import RequestRateLimiter, rate_limit_trace_config

logger = logging.getLogger(__name__)

class CrawlState:
    def __init__(self, scope: TargetScope, config: CrawlConfig):
        self.scope = scope
        self.config = config
        self.visited: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.endpoints: Dict[str, dict] = {}
        self.errors: List[dict] = []
        self.error_count = 0
        self.requests = 0

    def add_url(self, url: str, depth: int):
        normalized = self.scope.normalize(url)
        if normalized in self.visited:
            return
        if not self.scope.is_in_scope(normalized):
            return
        self.visited.add(normalized)
        self.queue.put_nowait((normalized, depth))

    async def add_url_async(self, url: str, depth: int):
        self.add_url(url, depth)

    def record_endpoint(self, url: str, method: str, status: int, headers: dict, body: str, forms: Optional[List[dict]] = None):
        self.endpoints[url] = {
            "url": url,
            "method": method,
            "status": status,
            "headers": headers,
            "body": body[:3000],
            "content_type": headers.get("content-type", ""),
            "query_params": parse_qs(urlparse(url).query),
            "forms": forms or [],
        }

class Crawler:
    def __init__(self, scope: TargetScope, config: CrawlConfig):
        self.state = CrawlState(scope, config)
        self.sem = Semaphore(config.concurrency)
        self.rate_limiter = RequestRateLimiter(config.rate_limit_per_second)
        self.progress: dict = {
            "module": "reconnaissance",
            "current_url": None,
            "discovered_endpoints": 0,
            "pages_limit": config.max_pages,
            "requests": 0,
            "error_count": 0,
            "completed": False,
        }

    async def crawl(
        self,
        start_url: str,
        session: aiohttp.ClientSession | None = None,
    ):
        self.state.add_url(start_url, depth=0)
        if session is None:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.state.config.timeout_seconds),
                trace_configs=[
                    rate_limit_trace_config(
                        self.rate_limiter,
                        self.state.scope,
                        self.progress,
                    )
                ],
            ) as session:
                await self._run_workers(session)
        else:
            await self._run_workers(session)
        self.progress["completed"] = True
        return list(self.state.endpoints.values())

    async def _run_workers(self, session: aiohttp.ClientSession):
        workers = [
            asyncio.create_task(self.worker(session))
            for _ in range(self.state.config.concurrency)
        ]
        try:
            await self.state.queue.join()
        finally:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    async def worker(self, session: aiohttp.ClientSession):
        while True:
            try:
                url, depth = await self.state.queue.get()
            except asyncio.CancelledError:
                return
            try:
                await self.fetch_page(session, url, depth)
            finally:
                self.state.queue.task_done()

    async def fetch_page(self, session: aiohttp.ClientSession, url: str, depth: int):
        if depth > self.state.config.max_depth:
            return
        self.progress["current_url"] = sanitized_target_url(url)
        try:
            async with self.sem:
                self.state.requests += 1
                async with session.get(
                    url,
                    timeout=self.state.config.timeout_seconds,
                    allow_redirects=False,
                ) as response:
                    text = await read_response_body(response)
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    set_cookie_headers = response.headers.getall("Set-Cookie", [])
                    if set_cookie_headers:
                        headers["set-cookie"] = "\n".join(set_cookie_headers)
                    forms = []
                    discovered = []
                    if "text/html" in headers.get("content-type", ""):
                        parser = SimpleHTMLLinkParser()
                        parser.feed(text)
                        forms = parser.forms
                        discovered = parser.links + parser.scripts + parser.meta_refresh
                        discovered += [form.get("action") for form in parser.forms if form.get("action")]
                        discovered = self.normalize_links(url, discovered)
                    if response.status in (301, 302, 303, 307, 308):
                        location = headers.get("location")
                        if location:
                            discovered.append(urljoin(url, location))
                    self.state.record_endpoint(url, response.method, response.status, headers, body=text, forms=forms)
                    self.progress["discovered_endpoints"] = len(self.state.endpoints)
                    for link in discovered:
                        if len(self.state.visited) >= self.state.config.max_pages:
                            break
                        await self.state.add_url_async(link, depth + 1)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Crawl request failed (%s)", type(exc).__name__)
            self.state.error_count += 1
            if len(self.state.errors) < 100:
                self.state.errors.append({
                    "stage": "crawl",
                    "component": "page request",
                    "error_type": type(exc).__name__,
                })
            self.progress["error_count"] = self.state.error_count
            return

    def normalize_links(self, base_url: str, links: List[str]) -> List[str]:
        normalized = []
        for link in links:
            if not link or link.startswith("#"):
                continue
            if link.startswith("javascript:"):
                continue
            normalized.append(urljoin(base_url, link))
        return normalized
