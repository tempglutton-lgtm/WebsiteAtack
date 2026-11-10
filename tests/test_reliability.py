import asyncio
import csv
import inspect
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiohttp
from aiohttp import web
from fastapi import HTTPException, Request
from pydantic import ValidationError
from starlette.responses import Response

from backend.crawler.crawler import Crawler
from backend.audit_log import append_audit_event
from backend.analysis.classifier import generate_findings
from backend.crawler.parser import SimpleHTMLLinkParser
from backend.crawler.scope import ScopeValidationError, TargetScope
from backend.config import AuthWorkflowConfig, CrawlConfig
from backend.http_limits import MAX_RESPONSE_BYTES
from backend.main import (
    FindingReviewRequest,
    StartScanRequest,
    current_scan,
    endpoint_inventory,
    export_findings,
    is_allowed_local_host,
    export_results,
    is_loopback_address,
    finish_report_metadata,
    new_report_metadata,
    require_loopback_client,
    run_crawl,
    review_finding,
    sanitized_findings,
    start_scan,
)
from backend.rate_limit import RequestRateLimiter, rate_limit_trace_config
from backend.scanners.manager import ScanManager
from backend.scanners.registry import all_scanners
from backend.scanners.utils import fetch_url
from backend.scanners.configuration.cache_control import CacheControlScanner
from backend.scanners.configuration.cors import CorsScanner
from backend.scanners.configuration.csp import CspScanner
from backend.scanners.configuration.security_headers import SecurityHeadersScanner
from backend.scanners.authentication.session_cookie import SessionCookieScanner
from backend.scanners.client_side.clickjacking import ClickjackingScanner
from backend.scanners.recon.endpoint_discovery import EndpointDiscoveryScanner
from backend.scanners.recon.technology_fingerprinting import TechnologyFingerprintingScanner


async def start_local_server(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


class RequestRateLimiterTests(unittest.IsolatedAsyncioTestCase):
    async def test_requests_are_spaced_by_configured_rate(self):
        limiter = RequestRateLimiter(25)
        started = time.monotonic()

        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()

        self.assertGreaterEqual(time.monotonic() - started, 0.065)

    async def test_non_positive_rate_is_rejected(self):
        with self.assertRaises(ValueError):
            RequestRateLimiter(0)

    async def test_requests_outside_scope_are_rejected_before_connection(self):
        scope = TargetScope("http://127.0.0.1:8000")
        trace_config = rate_limit_trace_config(RequestRateLimiter(100), scope)

        async with aiohttp.ClientSession(trace_configs=[trace_config]) as session:
            with self.assertRaises(aiohttp.ClientError):
                await session.get("http://127.0.0.1:8001/")

    async def test_actual_requests_are_counted(self):
        async def handler(request):
            return web.Response(text="ok")

        app = web.Application()
        app.router.add_get("/", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        progress = {"requests": 0}
        scope = TargetScope(f"http://127.0.0.1:{port}")

        try:
            async with aiohttp.ClientSession(
                trace_configs=[
                    rate_limit_trace_config(RequestRateLimiter(100), scope, progress)
                ]
            ) as session:
                async with session.get(f"http://127.0.0.1:{port}/") as response:
                    self.assertEqual(response.status, 200)
            self.assertEqual(progress["requests"], 1)
        finally:
            await runner.cleanup()

    async def test_http_client_never_follows_redirect_outside_scope(self):
        outside_requests = []

        async def outside_handler(request):
            outside_requests.append(request.path)
            return web.Response(text="outside")

        outside_app = web.Application()
        outside_app.router.add_get("/outside", outside_handler)
        outside_runner, outside_url = await start_local_server(outside_app)

        source_app = web.Application()

        async def redirect_outside(request):
            return web.Response(
                status=302,
                headers={"Location": f"{outside_url}/outside"},
            )

        source_app.router.add_get("/redirect", redirect_outside)
        source_runner, source_url = await start_local_server(source_app)

        try:
            scope = TargetScope(source_url)
            trace = rate_limit_trace_config(RequestRateLimiter(100), scope)
            async with aiohttp.ClientSession(trace_configs=[trace]) as session:
                with self.assertRaises(aiohttp.ClientError):
                    await session.get(f"{source_url}/redirect")
            self.assertEqual(outside_requests, [])
        finally:
            await source_runner.cleanup()
            await outside_runner.cleanup()

    async def test_rate_limit_applies_to_real_session_requests(self):
        request_times = []

        async def handler(request):
            request_times.append(asyncio.get_running_loop().time())
            return web.Response(text="ok")

        app = web.Application()
        app.router.add_get("/", handler)
        runner, url = await start_local_server(app)

        try:
            trace = rate_limit_trace_config(
                RequestRateLimiter(10),
                TargetScope(url),
            )
            async with aiohttp.ClientSession(trace_configs=[trace]) as session:
                for _ in range(2):
                    async with session.get(url) as response:
                        self.assertEqual(response.status, 200)
            self.assertGreaterEqual(request_times[1] - request_times[0], 0.08)
        finally:
            await runner.cleanup()

    async def test_each_followed_redirect_is_counted_and_rate_limited(self):
        request_times = []
        app = web.Application()

        async def redirect(request):
            request_times.append(asyncio.get_running_loop().time())
            raise web.HTTPFound("/done")

        async def done(request):
            request_times.append(asyncio.get_running_loop().time())
            return web.Response(text="done")

        app.router.add_get("/start", redirect)
        app.router.add_get("/done", done)
        runner, url = await start_local_server(app)
        progress = {"requests": 0}
        try:
            trace = rate_limit_trace_config(
                RequestRateLimiter(10),
                TargetScope(url),
                progress,
            )
            async with aiohttp.ClientSession(trace_configs=[trace]) as session:
                async with session.get(f"{url}/start") as response:
                    self.assertEqual(await response.text(), "done")
            self.assertEqual(progress["requests"], 2)
            self.assertGreaterEqual(request_times[1] - request_times[0], 0.08)
        finally:
            await runner.cleanup()

class TargetScopeTests(unittest.TestCase):
    def test_scope_is_limited_to_scheme_host_and_port(self):
        scope = TargetScope("https://example.test:8443")

        self.assertTrue(scope.is_in_scope("/login"))
        self.assertFalse(scope.is_in_scope("http://example.test:8443/"))
        self.assertFalse(scope.is_in_scope("https://example.test/"))
        self.assertFalse(scope.is_in_scope("https://other.example.test:8443/"))

    def test_subdomain_scope_does_not_accept_lookalike_hosts(self):
        scope = TargetScope("https://example.test", include_subdomains=True)

        self.assertTrue(scope.is_in_scope("https://api.example.test/v1"))
        self.assertFalse(scope.is_in_scope("https://notexample.test/"))
        self.assertFalse(scope.is_in_scope("https://example.test.attacker.invalid/"))

    def test_target_credentials_are_rejected(self):
        with self.assertRaises(ScopeValidationError):
            TargetScope("https://user:password@example.test")


    def test_api_client_must_be_loopback(self):
        self.assertTrue(is_loopback_address("127.0.0.1"))
        self.assertTrue(is_loopback_address("::1"))
        self.assertFalse(is_loopback_address("192.0.2.10"))
        self.assertFalse(is_loopback_address(None))
        self.assertTrue(is_allowed_local_host("127.0.0.1"))
        self.assertTrue(is_allowed_local_host("localhost"))
        self.assertFalse(is_allowed_local_host("scanner.example"))


class ApiMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def make_request(path, client, host="127.0.0.1:8000"):
        return Request({
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "query_string": b"",
            "headers": [(b"host", host.encode("ascii"))],
            "server": ("127.0.0.1", 8000),
            "client": client,
        })

    async def test_api_responses_are_not_cached(self):
        async def handler(request):
            return Response("ok")

        response = await require_loopback_client(
            self.make_request("/api/results", ("127.0.0.1", 50000)),
            handler,
        )

        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Pragma"], "no-cache")

    async def test_ui_assets_are_not_cached(self):
        async def handler(request):
            return Response("ok")

        for path in ("/", "/styles.css", "/app.js"):
            with self.subTest(path=path):
                response = await require_loopback_client(
                    self.make_request(path, ("127.0.0.1", 50000)),
                    handler,
                )
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(response.headers["Pragma"], "no-cache")

    async def test_api_rejects_non_loopback_clients(self):
        async def handler(request):
            self.fail("A remote client must be rejected before the route handler.")

        response = await require_loopback_client(
            self.make_request("/api/results", ("192.0.2.10", 50000)),
            handler,
        )

        self.assertEqual(response.status_code, 403)


class AuditLogTests(unittest.IsolatedAsyncioTestCase):
    def test_audit_log_prunes_events_beyond_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "audit.jsonl")
            with open(path, "w", encoding="utf-8") as audit_file:
                audit_file.write(json.dumps({
                    "timestamp": "2000-01-01T00:00:00+00:00",
                    "event": "old",
                }) + "\n")
                audit_file.write(json.dumps({
                    "timestamp": "2099-01-01T00:00:00+00:00",
                    "event": "retained",
                }) + "\n")
            with patch.dict(os.environ, {"WEBSITEATTACK_AUDIT_PATH": path}):
                append_audit_event("scan_started", {"assessment_id": "TEST-1"})

            with open(path, encoding="utf-8") as audit_file:
                events = [json.loads(line) for line in audit_file]
            self.assertEqual(
                [event["event"] for event in events],
                ["retained", "scan_started"],
            )

    async def test_review_status_and_note_are_saved_and_audited(self):
        previous_scan = dict(current_scan)
        with tempfile.TemporaryDirectory() as directory:
            audit_path = os.path.join(directory, "audit.jsonl")
            current_scan.update({
                "results": {
                    "report": {
                        "run_id": "run-1",
                        "assessment": {
                            "assessment_id": "TEST-1",
                            "operator": "operator",
                        },
                    },
                    "findings": [{
                        "review_id": "review-1",
                        "review_status": "pending",
                    }],
                },
            })
            try:
                with patch.dict(os.environ, {
                    "WEBSITEATTACK_AUDIT_PATH": audit_path,
                }):
                    with self.assertRaises(HTTPException):
                        await review_finding(
                            "review-1",
                            FindingReviewRequest(
                                status="confirmed",
                                reviewer="reviewer",
                            ),
                        )
                    result = await review_finding(
                        "review-1",
                        FindingReviewRequest(
                            status="confirmed",
                            reviewer="reviewer",
                            note="Reproduced; password=hunter2",
                        ),
                    )

                finding = current_scan["results"]["findings"][0]
                self.assertEqual(result["review_status"], "confirmed")
                self.assertIn("self-reported", result["verification_status"])
                self.assertEqual(finding["reviewer"], "reviewer")
                self.assertNotIn("hunter2", finding["review_note"])
                with open(audit_path, encoding="utf-8") as audit_file:
                    audit_entry = json.loads(audit_file.readline())
                self.assertEqual(audit_entry["event"], "finding_reviewed")
                self.assertNotIn("review_note", audit_entry)
            finally:
                current_scan.clear()
                current_scan.update(previous_scan)


class AuthWorkflowConfigTests(unittest.TestCase):
    def test_hidden_form_fields_are_included_without_csrf_configuration(self):
        config = AuthWorkflowConfig(login_url="http://127.0.0.1:8000/login")
        form_fields = ScanManager._extract_form_values(
            '<form method="post" action="/login"><input type="hidden" value="one-time-token" name="csrf_token">'
            '<input name="username"><input name="password" type="password"></form>'
        )

        payload = config.to_login_payload("test-user", "test-password", form_fields)

        self.assertEqual(payload["username"], "test-user")
        self.assertEqual(payload["password"], "test-password")
        self.assertEqual(payload["csrf_token"], "one-time-token")

    def test_configured_credential_fields_override_form_values(self):
        config = AuthWorkflowConfig(
            login_url="http://127.0.0.1:8000/login",
            username_field="email",
            password_field="passcode",
        )

        payload = config.to_login_payload(
            "test-user",
            "test-password",
            {"email": "stale-user", "passcode": "stale-password"},
        )

        self.assertEqual(payload["email"], "test-user")
        self.assertEqual(payload["passcode"], "test-password")

    def test_form_action_is_parsed_independent_of_attribute_order(self):
        action = ScanManager._extract_form_action(
            '<form method="post" action="/session"><input name="user"></form>'
        )
        self.assertEqual(action, "/session")

    def test_form_inputs_are_associated_with_the_correct_form(self):
        parser = SimpleHTMLLinkParser()
        parser.feed(
            '<input name="outside">'
            '<form action="/first"><input name="first"></form>'
            '<form action="/second"><input name="second"></form>'
        )

        self.assertEqual(parser.forms[0]["inputs"][0]["name"], "first")
        self.assertEqual(parser.forms[1]["inputs"][0]["name"], "second")


class AuthenticatedCrawlTests(unittest.IsolatedAsyncioTestCase):
    async def test_login_cookie_is_used_for_get_only_crawl(self):
        requests = []
        app = web.Application()

        async def login_form(request):
            requests.append((request.method, request.path))
            return web.Response(text=(
                '<form method="post" action="/session">'
                '<input type="hidden" name="csrf_token" value="one-time">'
                '<input name="username"><input name="password" type="password">'
                '</form>'
            ), content_type="text/html")

        async def login_submit(request):
            requests.append((request.method, request.path))
            form = await request.post()
            if (
                form.get("username") != "test-user"
                or form.get("password") != "test-password"
                or form.get("csrf_token") != "one-time"
            ):
                return web.Response(status=401)
            response = web.HTTPFound("/private")
            response.set_cookie("session", "authenticated", httponly=True, samesite="Lax")
            raise response

        async def root(request):
            requests.append((request.method, request.path))
            return web.Response(
                text='<a href="/private">private</a>',
                content_type="text/html",
            )

        async def private(request):
            requests.append((request.method, request.path))
            if request.cookies.get("session") != "authenticated":
                return web.Response(status=401, text="login required")
            response = web.Response(
                text='<p>Private dashboard</p><a href="/private/child">child</a>',
                content_type="text/html",
            )
            response.set_cookie(
                "session",
                "authenticated",
                httponly=True,
                samesite="Lax",
            )
            return response

        async def private_child(request):
            requests.append((request.method, request.path))
            if request.cookies.get("session") != "authenticated":
                return web.Response(status=401)
            return web.Response(text="Private child")

        app.router.add_get("/login", login_form)
        app.router.add_post("/session", login_submit)
        app.router.add_get("/", root)
        app.router.add_get("/private", private)
        app.router.add_get("/private/child", private_child)
        runner, base_url = await start_local_server(app)
        progress = {"requests": 0}
        limiter = RequestRateLimiter(100)
        scope = TargetScope(base_url)
        trace = rate_limit_trace_config(limiter, scope, progress)

        try:
            async with aiohttp.ClientSession(
                cookie_jar=aiohttp.CookieJar(unsafe=True),
                trace_configs=[trace],
            ) as session:
                auth_result = await ScanManager.authenticate_session(
                    session,
                    AuthWorkflowConfig(
                        login_url=f"{base_url}/login",
                        success_indicator="Private dashboard",
                    ),
                    "test-user",
                    "test-password",
                    scope=scope,
                )
                crawler = Crawler(
                    scope,
                    CrawlConfig(max_depth=2, rate_limit_per_second=100),
                )
                endpoints = await crawler.crawl(base_url, session=session)

            paths = {endpoint["url"].removeprefix(base_url) for endpoint in endpoints}
            self.assertTrue(auth_result["success"])
            self.assertIn("/private", paths)
            self.assertIn("/private/child", paths)
            self.assertEqual(
                [method for method, path in requests if method == "POST"],
                ["POST"],
            )
            self.assertTrue(all(
                method == "GET" or path == "/session"
                for method, path in requests
            ))
            self.assertEqual(
                progress["requests"],
                len(requests),
                msg=f"request count mismatch: {requests}",
            )
        finally:
            await runner.cleanup()

    async def test_missing_post_form_does_not_submit_credentials(self):
        requests = []
        app = web.Application()

        async def login_form(request):
            requests.append(request.method)
            return web.Response(
                text='<form method="get"><input name="username"></form>',
                content_type="text/html",
            )

        app.router.add_get("/login", login_form)
        runner, base_url = await start_local_server(app)
        scope = TargetScope(base_url)
        try:
            async with aiohttp.ClientSession() as session:
                with self.assertRaisesRegex(ValueError, "No POST login form"):
                    await ScanManager.authenticate_session(
                        session,
                        AuthWorkflowConfig(
                            login_url=f"{base_url}/login",
                            success_indicator="success",
                        ),
                        "test-user",
                        "test-password",
                        scope=scope,
                    )
            self.assertEqual(requests, ["GET"])
        finally:
            await runner.cleanup()

    async def test_307_login_redirect_does_not_resubmit_credentials(self):
        requests = []
        app = web.Application()

        async def login_form(request):
            requests.append((request.method, request.path))
            return web.Response(
                text=(
                    '<form method="post" action="/session">'
                    '<input name="username"><input name="password">'
                    '</form>'
                ),
                content_type="text/html",
            )

        async def submit(request):
            requests.append((request.method, request.path))
            raise web.HTTPTemporaryRedirect("/repeat")

        async def repeated(request):
            requests.append((request.method, request.path))
            return web.Response(text="should not be called")

        app.router.add_get("/login", login_form)
        app.router.add_post("/session", submit)
        app.router.add_route("*", "/repeat", repeated)
        runner, base_url = await start_local_server(app)
        try:
            async with aiohttp.ClientSession() as session:
                result = await ScanManager.authenticate_session(
                    session,
                    AuthWorkflowConfig(
                        login_url=f"{base_url}/login",
                        success_indicator="dashboard",
                    ),
                    "test-user",
                    "test-password",
                    scope=TargetScope(base_url),
                )
            self.assertFalse(result["success"])
            self.assertEqual(
                requests,
                [("GET", "/login"), ("POST", "/session")],
            )
        finally:
            await runner.cleanup()

    async def test_login_form_cannot_post_outside_scope(self):
        outside_requests = []
        outside_app = web.Application()

        async def outside_post(request):
            outside_requests.append(request.path)
            return web.Response(text="unexpected")

        outside_app.router.add_post("/session", outside_post)
        outside_runner, outside_url = await start_local_server(outside_app)
        source_app = web.Application()

        async def login_form(request):
            return web.Response(
                text=(
                    f'<form method="post" action="{outside_url}/session">'
                    '<input name="username"><input name="password"></form>'
                ),
                content_type="text/html",
            )

        source_app.router.add_get("/login", login_form)
        source_runner, source_url = await start_local_server(source_app)
        try:
            async with aiohttp.ClientSession() as session:
                with self.assertRaisesRegex(ValueError, "authorized scope"):
                    await ScanManager.authenticate_session(
                        session,
                        AuthWorkflowConfig(
                            login_url=f"{source_url}/login",
                            success_indicator="dashboard",
                        ),
                        "test-user",
                        "test-password",
                        scope=TargetScope(source_url),
                    )
            self.assertEqual(outside_requests, [])
        finally:
            await source_runner.cleanup()
            await outside_runner.cleanup()

    async def test_relative_login_action_uses_redirected_form_url(self):
        requests = []
        app = web.Application()

        async def initial_login(request):
            requests.append(request.path)
            raise web.HTTPFound("/auth/form")

        async def login_form(request):
            requests.append(request.path)
            return web.Response(
                text=(
                    '<form method="post" action="submit">'
                    '<input name="username"><input name="password"></form>'
                ),
                content_type="text/html",
            )

        async def submit(request):
            requests.append(request.path)
            return web.Response(text="Welcome dashboard")

        app.router.add_get("/login", initial_login)
        app.router.add_get("/auth/form", login_form)
        app.router.add_post("/auth/submit", submit)
        runner, base_url = await start_local_server(app)
        try:
            async with aiohttp.ClientSession() as session:
                result = await ScanManager.authenticate_session(
                    session,
                    AuthWorkflowConfig(
                        login_url=f"{base_url}/login",
                        success_indicator="dashboard",
                    ),
                    "test-user",
                    "test-password",
                    scope=TargetScope(base_url),
                )
            self.assertTrue(result["success"])
            self.assertEqual(requests, ["/login", "/auth/form", "/auth/submit"])
        finally:
            await runner.cleanup()

    async def test_authenticated_run_reports_limited_coverage_and_no_secrets(self):
        requests = []
        app = web.Application()

        async def login_form(request):
            requests.append((request.method, request.path))
            return web.Response(
                text=(
                    '<form method="post" action="/session">'
                    '<input type="hidden" name="csrf" value="one-time">'
                    '<input name="username"><input name="password" type="password">'
                    '</form>'
                ),
                content_type="text/html",
            )

        async def login_submit(request):
            requests.append((request.method, request.path))
            form = await request.post()
            if form.get("password") != "do-not-export-this-password":
                return web.Response(status=401)
            response = web.HTTPFound("/private")
            response.set_cookie("session", "valid", httponly=True)
            raise response

        async def index(request):
            requests.append((request.method, request.path))
            return web.Response(
                text='<a href="/private">private</a>',
                content_type="text/html",
            )

        async def private(request):
            requests.append((request.method, request.path))
            if request.cookies.get("session") != "valid":
                return web.Response(status=401)
            return web.Response(text="<p>Private dashboard</p>")

        app.router.add_get("/login", login_form)
        app.router.add_post("/session", login_submit)
        app.router.add_get("/", index)
        app.router.add_get("/private", private)
        runner, base_url = await start_local_server(app)

        previous_scan = dict(current_scan)
        try:
            request = StartScanRequest(
                target_url=base_url,
                agree_to_authorization=True,
            )
            crawler = Crawler(
                TargetScope(base_url),
                CrawlConfig(max_depth=1, rate_limit_per_second=100),
            )
            metadata = new_report_metadata(request)
            current_scan.update({
                "status": "running",
                "progress": crawler.progress,
                "results": None,
                "task": None,
            })

            await run_crawl(
                crawler,
                base_url,
                AuthWorkflowConfig(
                    login_url=f"{base_url}/login",
                    success_indicator="Private dashboard",
                ),
                "test-user",
                "do-not-export-this-password",
                {
                    "login_url": f"{base_url}/login",
                    "username_field": "username",
                    "password_field": "password",
                    "success_indicator_configured": True,
                },
                metadata,
                auth_requested=True,
            )

            results = current_scan["results"]
            serialized_results = json.dumps(results)
            self.assertEqual(current_scan["status"], "completed")
            self.assertEqual(results["auth"]["success"], True)
            self.assertEqual(results["summary"]["mode"], "passive_only")
            self.assertEqual(
                results["report"]["completeness"],
                "execution_complete",
            )
            self.assertEqual(
                results["report"]["coverage"]["authenticated_crawl"],
                "authenticated_get_only",
            )
            self.assertFalse(
                results["report"]["coverage"]["private_route_coverage_confirmed"]
            )
            self.assertEqual(
                results["report"]["coverage"]["observed_methods"],
                ["GET"],
            )
            self.assertIn("/private", [item["url"].split(base_url)[1] for item in results["endpoints"]])
            self.assertNotIn("do-not-export-this-password", serialized_results)
            self.assertEqual(
                [method for method, path in requests if method == "POST"],
                ["POST"],
            )
            self.assertEqual(current_scan["progress"]["requests"], len(requests))
        finally:
            current_scan.clear()
            current_scan.update(previous_scan)
            await runner.cleanup()


class CrawlerErrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_failures_are_counted_and_reported(self):
        crawler = Crawler(
            TargetScope("http://127.0.0.1:8000"),
            CrawlConfig(rate_limit_per_second=100),
        )

        class FailedRequest:
            async def __aenter__(self):
                raise aiohttp.ClientError("network detail")

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class FailedSession:
            def get(self, url, timeout, allow_redirects):
                return FailedRequest()

        await crawler.fetch_page(
            FailedSession(),
            "http://127.0.0.1:8000/?token=do-not-show",
            0,
        )

        self.assertEqual(crawler.state.error_count, 1)
        self.assertEqual(crawler.state.requests, 1)
        self.assertEqual(crawler.progress["error_count"], 1)
        self.assertNotIn("do-not-show", crawler.progress["current_url"])
        self.assertEqual(crawler.state.errors[0]["stage"], "crawl")
        self.assertNotIn("network detail", str(crawler.state.errors))

    async def test_response_body_limit_is_enforced(self):
        crawler = Crawler(
            TargetScope("http://127.0.0.1:8000"),
            CrawlConfig(rate_limit_per_second=100),
        )

        class LargeResponse:
            status = 200
            content_length = MAX_RESPONSE_BYTES + 1
            headers = {}

        class LargeRequest:
            async def __aenter__(self):
                return LargeResponse()

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class LargeSession:
            def get(self, url, timeout, allow_redirects):
                return LargeRequest()

        await crawler.fetch_page(LargeSession(), "http://127.0.0.1:8000/", 0)

        self.assertEqual(crawler.state.error_count, 1)
        self.assertEqual(crawler.state.endpoints, {})

    async def test_cancelling_crawl_stops_worker_tasks(self):
        crawler = Crawler(
            TargetScope("http://127.0.0.1:8000"),
            CrawlConfig(concurrency=2, rate_limit_per_second=100),
        )

        class SlowRequest:
            async def __aenter__(self):
                await asyncio.Future()

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class FakeSession:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

            def get(self, url, timeout, allow_redirects):
                return SlowRequest()

        with patch("backend.crawler.crawler.aiohttp.ClientSession", FakeSession):
            task = asyncio.create_task(crawler.crawl("http://127.0.0.1:8000/"))
            await asyncio.sleep(0.03)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        pending_tasks = [
            pending
            for pending in asyncio.all_tasks()
            if pending is not asyncio.current_task() and not pending.done()
        ]
        self.assertEqual(pending_tasks, [])


class ProbeResponseLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_probe_response_body_limit_is_enforced(self):
        class Content:
            async def read(self, size):
                return b"x" * size

        class LargeResponse:
            content_length = None
            content = Content()
            headers = {}
            status = 200

        class LargeRequest:
            async def __aenter__(self):
                return LargeResponse()

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class LargeSession:
            def get(self, url, timeout, allow_redirects):
                return LargeRequest()

        with self.assertRaises(ValueError):
            await fetch_url(LargeSession(), "http://127.0.0.1:8000/")

        self.assertGreater(MAX_RESPONSE_BYTES, 0)


class ScannerFixtureAccuracyTests(unittest.IsolatedAsyncioTestCase):
    async def test_passive_rule_fixtures_measure_false_positive_and_negative_rates(self):
        async def detected(scanner, endpoint):
            return bool(scanner.applicable(endpoint) and await scanner.run(endpoint))

        secure_html_headers = {
            "content-type": "text/html; charset=utf-8",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
            "strict-transport-security": "max-age=31536000",
        }
        cases = {
            "CSP Configuration": (
                CspScanner(),
                [
                    (True, {"url": "https://fixture.invalid/", "content_type": "text/html", "headers": {"content-type": "text/html"}}),
                    (True, {"url": "https://fixture.invalid/report-only", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy-report-only": "default-src 'self'"}}),
                    (True, {"url": "https://fixture.invalid/eval", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "default-src 'self'; script-src 'unsafe-eval'"}}),
                    (False, {"url": "https://fixture.invalid/style", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'"}}),
                    (False, {"url": "https://fixture.invalid/nonce", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "script-src 'unsafe-inline' 'nonce-abc123'"}}),
                    (False, {"url": "https://fixture.invalid/app.js", "content_type": "application/javascript", "headers": {"content-type": "application/javascript"}}),
                ],
            ),
            "Security headers": (
                SecurityHeadersScanner(),
                [
                    (True, {"url": "http://fixture.invalid/", "content_type": "text/html", "headers": {"content-type": "text/html"}}),
                    (True, {"url": "https://fixture.invalid/hsts", "content_type": "text/html", "headers": {**secure_html_headers, "strict-transport-security": "max-age=0"}}),
                    (False, {"url": "http://fixture.invalid/app.js", "content_type": "application/javascript", "headers": {"content-type": "application/javascript"}}),
                    (False, {"url": "https://fixture.invalid/ok", "content_type": "text/html", "headers": secure_html_headers}),
                    (False, {"url": "https://fixture.invalid/framed", "content_type": "text/html", "headers": {**secure_html_headers, "x-frame-options": "ALLOW-FROM https://trusted.invalid", "content-security-policy": "frame-ancestors 'self'"}}),
                    (True, {"url": "https://fixture.invalid/unrestricted-frames", "content_type": "text/html", "headers": {**{key: value for key, value in secure_html_headers.items() if key != "x-frame-options"}, "content-security-policy": "frame-ancestors *"}}),
                ],
            ),
            "Session Cookie Security": (
                SessionCookieScanner(),
                [
                    (True, {"url": "https://fixture.invalid/", "headers": {"set-cookie": "sessionid=secret"}}),
                    (True, {"url": "http://fixture.invalid/", "headers": {"set-cookie": "sessionid=secret"}}),
                    (False, {"url": "https://fixture.invalid/", "headers": {"set-cookie": "analytics_id=123"}}),
                    (False, {"url": "http://fixture.invalid/", "headers": {"set-cookie": "sessionid=secret; HttpOnly"}}),
                    (False, {"url": "https://fixture.invalid/", "headers": {"set-cookie": "sessionid=secret; Secure; HttpOnly"}}),
                    (False, {"url": "https://fixture.invalid/", "headers": {"set-cookie": "csrf_token=secret"}}),
                    (False, {"url": "https://fixture.invalid/", "headers": {"set-cookie": "sessionid=secret; Secure; HttpOnly\nanalytics_id=123"}}),
                ],
            ),
            "Cache-control issues": (
                CacheControlScanner(),
                [
                    (True, {"url": "https://fixture.invalid/account", "headers": {}}),
                    (True, {"url": "https://fixture.invalid/account", "headers": {"cache-control": "public, max-age=120"}}),
                    (False, {"url": "https://fixture.invalid/api/public-items", "headers": {"cache-control": "public, max-age=120"}}),
                    (False, {"url": "https://fixture.invalid/administer", "headers": {}}),
                    (False, {"url": "https://fixture.invalid/admin", "headers": {"cache-control": "private, max-age=120"}}),
                ],
            ),
            "Clickjacking": (
                ClickjackingScanner(),
                [
                    (True, {"url": "https://fixture.invalid/", "content_type": "text/html", "headers": {"content-type": "text/html"}}),
                    (True, {"url": "https://fixture.invalid/false-directive", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "default-src https://frame-ancestors.invalid"}}),
                    (True, {"url": "https://fixture.invalid/empty-directive", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "frame-ancestors"}}),
                    (True, {"url": "https://fixture.invalid/unrestricted-frames", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "frame-ancestors *"}}),
                    (False, {"url": "https://fixture.invalid/data.json", "content_type": "application/json", "headers": {"content-type": "application/json"}}),
                    (False, {"url": "https://fixture.invalid/safe", "content_type": "text/html", "headers": {"content-type": "text/html", "x-frame-options": "SAMEORIGIN"}}),
                    (False, {"url": "https://fixture.invalid/csp", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "default-src 'self'; frame-ancestors 'none'"}}),
                    (False, {"url": "https://fixture.invalid/multiple-csp", "content_type": "text/html", "headers": {"content-type": "text/html", "content-security-policy": "default-src 'self', frame-ancestors 'none'"}}),
                ],
            ),
        }

        for scanner_name, (scanner, scanner_cases) in cases.items():
            with self.subTest(scanner=scanner_name):
                matrix = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
                for expected, endpoint in scanner_cases:
                    actual = await detected(scanner, endpoint)
                    if expected and actual:
                        matrix["tp"] += 1
                    elif expected:
                        matrix["fn"] += 1
                    elif actual:
                        matrix["fp"] += 1
                    else:
                        matrix["tn"] += 1
                self.assertEqual(matrix["fp"], 0, msg=f"{scanner_name}: {matrix}")
                self.assertEqual(matrix["fn"], 0, msg=f"{scanner_name}: {matrix}")
                self.assertGreater(matrix["tp"], 0, msg=f"{scanner_name}: {matrix}")
                self.assertGreater(matrix["tn"], 0, msg=f"{scanner_name}: {matrix}")

    async def test_passive_indicators_match_labeled_local_cases(self):
        app = web.Application()

        async def index(request):
            return web.Response(
                text='<a href="/vulnerable">vulnerable</a><a href="/clean">clean</a>',
                content_type="text/html",
            )

        async def vulnerable(request):
            response = web.Response(
                text="<p>Fixture route with known weak response controls.</p>",
                content_type="text/html",
                headers={"Access-Control-Allow-Origin": "*"},
            )
            response.set_cookie("session", "fixture-session")
            return response

        async def clean(request):
            response = web.Response(
                text="<p>Fixture route with configured response controls.</p>",
                content_type="text/html",
                headers={
                    "Access-Control-Allow-Origin": "https://trusted.example",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "geolocation=()",
                },
            )
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
            response.set_cookie(
                "session",
                "fixture-session",
                httponly=True,
                secure=True,
                samesite="Lax",
            )
            return response

        app.router.add_get("/", index)
        app.router.add_get("/vulnerable", vulnerable)
        app.router.add_get("/clean", clean)
        runner, base_url = await start_local_server(app)

        expected = {
            "Security headers": {"vulnerable": True, "clean": False},
            "CSP Configuration": {"vulnerable": True, "clean": False},
            "Session Cookie Security": {"vulnerable": True, "clean": False},
        }
        scanners = {
            "Security headers": SecurityHeadersScanner(),
            "CSP Configuration": CspScanner(),
            "Session Cookie Security": SessionCookieScanner(),
        }
        matrix = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        outcomes = []
        try:
            crawler = Crawler(
                TargetScope(base_url),
                CrawlConfig(max_depth=1, rate_limit_per_second=100),
            )
            endpoints = await crawler.crawl(base_url)
            by_path = {
                endpoint["url"].rsplit("/", 1)[-1] or "root": endpoint
                for endpoint in endpoints
            }

            for scanner_name, scanner in scanners.items():
                for case_name, is_expected_positive in expected[scanner_name].items():
                    findings = await scanner.run(by_path[case_name])
                    detected = bool(findings)
                    outcomes.append((scanner_name, case_name, detected))
                    if detected and is_expected_positive:
                        matrix["tp"] += 1
                    elif detected:
                        matrix["fp"] += 1
                    elif is_expected_positive:
                        matrix["fn"] += 1
                    else:
                        matrix["tn"] += 1

            self.assertEqual(
                matrix,
                {"tp": 3, "fp": 0, "tn": 3, "fn": 0},
                msg=f"fixture outcomes: {outcomes}",
            )
            self.assertEqual(
                matrix["tp"] / (matrix["tp"] + matrix["fp"]),
                1.0,
            )
            self.assertEqual(
                matrix["tp"] / (matrix["tp"] + matrix["fn"]),
                1.0,
            )
            cors = CorsScanner()
            wildcard_observation = await cors.run(by_path["vulnerable"])
            trusted_origin = await cors.run(by_path["clean"])
            self.assertEqual(wildcard_observation[0]["severity"], "Informational")
            self.assertFalse(trusted_origin)

            clean_http_without_hsts = dict(by_path["clean"])
            clean_http_without_hsts["headers"] = dict(
                clean_http_without_hsts["headers"]
            )
            clean_http_without_hsts["headers"].pop("strict-transport-security", None)
            self.assertFalse(await scanners["Security headers"].run(clean_http_without_hsts))

            https_without_hsts = dict(clean_http_without_hsts)
            https_without_hsts["url"] = "https://fixture.invalid/clean"
            self.assertTrue(await scanners["Security headers"].run(https_without_hsts))

            report_only_csp = {
                "url": "https://fixture.invalid/report-only",
                "headers": {
                    "content-security-policy-report-only": "default-src 'self'",
                },
                "body": "<p>text</p>",
            }
            report_only_findings = await CspScanner().run(report_only_csp)
            self.assertIn("does not enforce", report_only_findings[0]["evidence"])
        finally:
            await runner.cleanup()


class ScanManagerErrorTests(unittest.IsolatedAsyncioTestCase):
    def test_registered_scanners_follow_the_session_run_contract(self):
        for scanner in all_scanners():
            with self.subTest(scanner=scanner.name):
                self.assertIn("session", inspect.signature(scanner.run).parameters)
                self.assertTrue(inspect.iscoroutinefunction(scanner.run))

    def test_independent_validation_template_matches_registered_scanners(self):
        template_path = (
            Path(__file__).parent
            / "data"
            / "scanner-validation-template.csv"
        )
        with template_path.open(encoding="utf-8", newline="") as template_file:
            rows = list(csv.DictReader(template_file))

        scanners = all_scanners()
        self.assertEqual(len(rows), len(scanners))
        for row, scanner in zip(rows, scanners):
            with self.subTest(scanner=scanner.name):
                self.assertEqual(row["scanner"], scanner.name)
                self.assertEqual(
                    row["family"],
                    scanner.__class__.__module__.split(".")[2],
                )
                self.assertEqual(
                    row["execution_mode"],
                    "passive"
                    if scanner.name in ScanManager.PASSIVE_SCANNER_NAMES
                    else "active",
                )
        self.assertEqual(
            sum(row["current_validation_status"] == "synthetic_only" for row in rows),
            5,
        )
        self.assertEqual(
            sum(
                row["current_validation_status"] == "not_independently_validated"
                for row in rows
            ),
            55,
        )

    async def test_passive_report_maps_every_scanner_without_claiming_validation(self):
        manager = ScanManager()
        result = await manager.execute([], passive_only=True)

        coverage = result["summary"]["scanner_coverage"]
        self.assertEqual(len(coverage), len(all_scanners()))
        self.assertTrue(all(entry["what_is_not_verified"] for entry in coverage))
        self.assertTrue(all(
            entry["validation_status"] in {
                "synthetic_fixtures_only",
                "not_independently_validated",
            }
            for entry in coverage
        ))
        self.assertTrue(all(
            not entry["selected"] and entry["checks_completed"] == 0
            for entry in coverage
            if entry["mode"] == "active"
        ))
        self.assertTrue(all(
            entry["selected"]
            for entry in coverage
            if entry["mode"] == "passive"
        ))
        self.assertTrue(all(
            entry["validation_status"] == "synthetic_fixtures_only"
            for entry in coverage
            if entry["name"] in {
                "Security headers",
                "CSP Configuration",
                "Session Cookie Security",
                "Cache-control issues",
                "Clickjacking",
            }
        ))

    async def test_registered_recon_and_cache_scanners_run_without_errors(self):
        manager = ScanManager()
        manager.scanners = [
            CacheControlScanner(),
            EndpointDiscoveryScanner(),
            TechnologyFingerprintingScanner(),
        ]

        result = await manager.execute(
            [{
                "url": "http://127.0.0.1:8000/admin",
                "headers": {},
                "body": "django",
            }],
            rate_limiter=RequestRateLimiter(100),
        )

        self.assertEqual(result["error_count"], 0)
        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual(len(result["summary"]["scanner_coverage"]), 3)
        self.assertTrue(all(
            item["endpoints_considered"] == 1
            and item["applicable_endpoints"] == 1
            and item["checks_completed"] == 1
            for item in result["summary"]["scanner_coverage"]
        ))

    async def test_authenticated_mode_excludes_active_scanners(self):
        called = []

        class FakeScanner:
            def __init__(self, name):
                self.name = name

            def applicable(self, endpoint):
                return True

            async def run(self, endpoint, session):
                called.append(self.name)
                return [{
                    "title": "test indicator",
                    "url": endpoint["url"],
                    "evidence": "observed",
                    "verification_guidance": "manual review",
                }]

            def return_findings(self):
                return []

        manager = ScanManager()
        manager.scanners = [FakeScanner("Security headers"), FakeScanner("SQL Injection")]
        result = await manager.execute(
            [{"url": "http://127.0.0.1:8000/"}],
            passive_only=True,
        )

        self.assertEqual(called, ["Security headers"])
        self.assertEqual(result["summary"]["mode"], "passive_only")
        self.assertEqual(result["summary"]["scanners"], ["Security headers"])
        coverage = {
            entry["name"]: entry
            for entry in result["summary"]["scanner_coverage"]
        }
        self.assertTrue(coverage["Security headers"]["selected"])
        self.assertFalse(coverage["SQL Injection"]["selected"])
        self.assertIn("não executado", coverage["SQL Injection"]["coverage_note"].lower())

    async def test_potential_findings_are_reported_as_unverified_indicators(self):
        class PotentialScanner:
            name = "test scanner"

            def applicable(self, endpoint):
                return True

            async def run(self, endpoint, session):
                return [{
                    "title": "Potential configuration indicator",
                    "url": endpoint["url"],
                    "evidence": "A test indicator was observed.",
                    "verification_guidance": "Review this behavior manually.",
                    "status": "Potential",
                    "confidence": 35,
                }]

        manager = ScanManager()
        manager.scanners = [PotentialScanner()]

        result = await manager.execute(
            [{"url": "http://127.0.0.1:8000/"}],
            progress={"tests_total": 1, "tests_performed": 0},
            rate_limiter=RequestRateLimiter(100),
            scope=TargetScope("http://127.0.0.1:8000"),
        )

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["status"], "Potential")
        self.assertEqual(
            result["findings"][0]["verification_status"],
            "Requires manual verification",
        )
        self.assertEqual(result["summary"]["findings_count"], 1)

    def test_verification_playbooks_are_specific_and_safely_bounded(self):
        injection = ScanManager._normalize_finding({
            "scanner": "SQL Injection",
            "title": "SQL injection indicator",
            "category": "Injection",
        })
        access_control = ScanManager._normalize_finding({
            "scanner": "IDOR/BOLA",
            "title": "IDOR/BOLA indicator",
            "category": "Access control",
        })
        configuration = ScanManager._normalize_finding({
            "scanner": "CSP Configuration",
            "title": "CSP configuration issue",
            "category": "Configuration",
        })
        redirect = ScanManager._normalize_finding({
            "scanner": "Open Redirect",
            "title": "Open redirect indicator",
            "category": "Client-side",
        })
        xss = ScanManager._normalize_finding({
            "scanner": "Reflected XSS",
            "title": "Reflected XSS indicator",
            "category": "Client-side",
        })
        reconnaissance = ScanManager._normalize_finding({
            "scanner": "Endpoint discovery",
            "title": "Endpoint discovery indicator",
            "category": "Reconnaissance",
        })

        self.assertIn("staging autorizado", injection["verification_playbook"]["tools"])
        self.assertIn("não confirmado", injection["assessment_type"].lower())
        self.assertNotIn("sqlmap", injection["verification_tool"].lower())
        self.assertTrue(injection["verification_playbook"]["confirmation_criteria"])
        self.assertTrue(injection["verification_playbook"]["false_positive_checks"])
        self.assertIn(
            "duas contas de teste",
            access_control["verification_playbook"]["tools"].lower(),
        )
        self.assertIn("curl.exe", configuration["verification_playbook"]["tools"])
        self.assertIn("impacto não confirmado", configuration["assessment_type"].lower())
        self.assertIn("não siga o redirecionamento", " ".join(redirect["verification_playbook"]["steps"]).lower())
        self.assertIn("não confirmado", redirect["assessment_type"].lower())
        self.assertIn("reflexão ou marcador inerte não bastam", xss["verification_playbook"]["confirmation_criteria"].lower())
        self.assertIn("não é, por si só, uma vulnerabilidade", reconnaissance["assessment_type"])
        classifier_findings = generate_findings([{
            "url": "https://restaurant.example/redirect?next=%2Fmenu",
            "query_params": {"next": "/menu"},
        }])
        redirect_finding = next(item for item in classifier_findings if item["category"] == "Open redirect")
        self.assertIn("Location", redirect_finding["verification_guidance"])
        self.assertIn("without following it", redirect_finding["verification_guidance"])
        for scanner in all_scanners():
            with self.subTest(scanner=scanner.name):
                playbook = ScanManager._normalize_finding({
                    "scanner": scanner.name,
                    "title": scanner.name,
                })["verification_playbook"]
                self.assertTrue(playbook["tools"])
                self.assertTrue(playbook["steps"])
                self.assertTrue(playbook["confirmation_criteria"])
                self.assertTrue(playbook["false_positive_checks"])

    async def test_scanner_failures_are_returned_and_counted(self):
        class FailedScanner:
            name = "test scanner"

            def applicable(self, endpoint):
                return True

            async def run(self, endpoint, session):
                raise RuntimeError("internal detail")

        progress = {"error_count": 0}
        manager = ScanManager()
        manager.scanners = [FailedScanner()]

        result = await manager.execute(
            [{"url": "http://127.0.0.1:8000/"}],
            progress=progress,
            rate_limiter=RequestRateLimiter(100),
        )

        self.assertEqual(result["error_count"], 1)
        self.assertEqual(progress["error_count"], 1)
        self.assertEqual(progress["tests_performed"], 1)
        self.assertEqual(result["errors"][0]["component"], "test scanner")
        self.assertNotIn("internal detail", str(result["errors"]))


class ScanRequestValidationTests(unittest.IsolatedAsyncioTestCase):
    def test_default_scan_profile_is_bounded_and_passive(self):
        request = StartScanRequest(target_url="http://127.0.0.1:8000")
        metadata = new_report_metadata(request)

        self.assertEqual(metadata["settings"]["scan_profile"], "broad_bounded")
        self.assertEqual(metadata["settings"]["max_depth"], 5)
        self.assertEqual(metadata["settings"]["max_pages"], 200)
        self.assertEqual(metadata["settings"]["concurrency"], 4)
        self.assertEqual(metadata["settings"]["rate_limit_per_second"], 2.0)
        self.assertFalse(metadata["settings"]["active_tests_enabled"])
        self.assertTrue(metadata["coverage"]["passive_checks_only"])
        self.assertEqual(metadata["coverage"]["authenticated_crawl"], "not_supported")
        self.assertFalse(metadata["authorization"]["independently_verified"])
        self.assertTrue(metadata["authorization"]["user_confirmation"] is False)
        self.assertNotIn("assessment", metadata)
        self.assertTrue(any("não avalia design visual" in item.lower() for item in metadata["limitations"]))
        self.assertTrue(any("não garante precisão absoluta" in item.lower() for item in metadata["limitations"]))

    def test_authentication_and_scan_options_are_rejected(self):
        for option in (
            {"operator": "tester"},
            {"assessment_id": "test-1"},
            {"authorization_reference": "ticket-1"},
            {"login_url": "https://example.test/login"},
            {"enable_active_tests": True},
            {"max_pages": 501},
        ):
            with self.subTest(option=option), self.assertRaises(ValidationError):
                StartScanRequest(
                    target_url="http://127.0.0.1:8000",
                    agree_to_authorization=True,
                    **option,
                )

    async def test_overlapping_scan_is_rejected(self):
        previous_status = current_scan["status"]
        current_scan["status"] = "running"
        request = StartScanRequest(
            target_url="http://127.0.0.1:8000",
            agree_to_authorization=True,
        )
        try:
            with self.assertRaises(HTTPException) as raised:
                await start_scan(request)
            self.assertEqual(raised.exception.status_code, 409)
        finally:
            current_scan["status"] = previous_status

    async def test_scan_requires_explicit_authorization_confirmation(self):
        request = StartScanRequest(target_url="http://127.0.0.1:8000")
        with patch.dict(current_scan, {"status": "idle"}):
            with self.assertRaises(HTTPException) as raised:
                await start_scan(request)
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("Authorization confirmation", raised.exception.detail)

    async def test_minimal_request_starts_unauthenticated_passive_scan(self):
        request = StartScanRequest(
            target_url="http://127.0.0.1:8000",
            agree_to_authorization=True,
        )
        self.assertTrue(new_report_metadata(request)["authorization"]["user_confirmation"])
        with (
            patch.dict(
                current_scan,
                {"status": "idle", "progress": {}, "results": None, "task": None},
            ),
            patch("backend.main.Crawler") as crawler_factory,
            patch("backend.main.run_crawl", new_callable=AsyncMock) as run_crawl_mock,
            patch("backend.main.append_audit_event"),
        ):
            crawler_factory.return_value.progress = {}
            response = await start_scan(request)
            task = current_scan["task"]
            await task

            self.assertEqual(response["status"], "started")
            run_crawl_mock.assert_awaited_once()
            self.assertIsNone(run_crawl_mock.await_args.args[3])
            self.assertIsNone(run_crawl_mock.await_args.args[4])
            self.assertFalse(run_crawl_mock.await_args.args[2].is_configured())
            self.assertEqual(run_crawl_mock.await_args.args[5], {"enabled": False})

    async def test_unknown_export_format_is_rejected(self):
        with self.assertRaises(HTTPException) as raised:
            await export_results("xml")
        self.assertEqual(raised.exception.status_code, 400)

    async def test_json_export_is_indented_and_preserves_report_structure(self):
        scan_results = {
            "report": {"run_id": "test-run", "tool": "WebsiteAttack"},
            "summary": {"findings_count": 1},
            "endpoints": [{"url": "https://example.test/"}],
            "findings": [{"title": "Indicador", "evidence": "Revisão manual"}],
            "errors": [],
            "error_count": 0,
        }
        with patch.dict(current_scan, {"results": scan_results}):
            response = await export_results("json")

        payload = json.loads(response.body)
        self.assertEqual(payload, scan_results)
        self.assertIn(b'\n  "report"', response.body)
        self.assertIn(b'"evidence": "Revis\xc3\xa3o manual"', response.body)
        self.assertTrue(response.media_type.startswith("application/json"))


class ExportSafetyTests(unittest.TestCase):
    def test_report_metadata_redacts_query_values_and_tracks_completeness(self):
        request = StartScanRequest(
            target_url="https://example.test/path?access_token=secret&view=full",
        )
        metadata = new_report_metadata(request)

        self.assertNotIn("secret", metadata["target"])
        self.assertIn("%5Bredacted%5D", metadata["target"])
        self.assertTrue(metadata["tool_version"])
        self.assertTrue(metadata["python_version"])
        validation = metadata["scanner_validation"]
        self.assertFalse(validation["general_precision_certified"])
        self.assertEqual(metadata["coverage"]["private_route_coverage_confirmed"], False)
        self.assertEqual(metadata["framework_mapping"]["mapping_level"], "family/category only")
        self.assertEqual(validation["fixture_observations"], 38)
        self.assertEqual(len(validation["scanners_covered"]), 5)
        self.assertEqual(
            validation["fixture_results"],
            {
                "expected_rule_findings": 17,
                "expected_no_findings": 21,
                "unexpected_findings": 0,
                "missed_expected_findings": 0,
            },
        )
        self.assertEqual(validation["registered_scanners"], len(all_scanners()))
        self.assertIn("não constituem benchmark independente", validation["scope_note"].lower())

        finished = finish_report_metadata(
            metadata,
            {
                "requests": 4,
                "discovered_endpoints": 2,
                "tests_performed": 3,
                "tests_total": 3,
            },
            "completed",
            [{"title": "indicator"}],
            0,
        )
        self.assertEqual(finished["completeness"], "execution_complete")
        self.assertEqual(finished["counts"]["requests"], 4)
        self.assertEqual(finished["counts"]["findings"], 1)

    def test_empty_scan_is_never_marked_complete(self):
        request = StartScanRequest(target_url="https://example.test")
        metadata = new_report_metadata(request)

        finished = finish_report_metadata(
            metadata,
            {
                "requests": 1,
                "discovered_endpoints": 0,
                "tests_performed": 0,
                "tests_total": 0,
            },
            "completed",
            [],
            0,
        )

        self.assertEqual(finished["completeness"], "partial")

    def test_endpoint_inventory_and_finding_urls_redact_query_values(self):
        endpoint = {
            "url": "https://example.test/item?id=123",
            "method": "GET",
            "status": 200,
            "content_type": "text/html",
            "body": "must not be exposed",
            "headers": {"Set-Cookie": "secret"},
        }

        inventory = endpoint_inventory([endpoint])
        findings = sanitized_findings([{"url": endpoint["url"]}])

        self.assertEqual(
            inventory[0]["url"],
            "https://example.test/item?id=%5Bredacted%5D",
        )
        self.assertNotIn("body", inventory[0])
        self.assertNotIn("headers", inventory[0])
        self.assertEqual(findings[0]["url"], inventory[0]["url"])

    def test_findings_redact_credentials_and_include_reproduction_metadata(self):
        finding = {
            "url": "https://example.test/item?token=secret",
            "id": "finding-https://example.test/item?record=private-value",
            "method": "GET",
            "evidence": "Observed password=hunter2 and Authorization: Bearer abc123",
        }

        sanitized = sanitized_findings([finding])[0]

        self.assertNotIn("secret", sanitized["url"])
        self.assertNotIn("private-value", sanitized["id"])
        self.assertNotIn("hunter2", sanitized["evidence"])
        self.assertNotIn("abc123", sanitized["evidence"])
        self.assertEqual(sanitized["reproduction"]["method"], "GET")
        self.assertIn("authorized test environment", sanitized["reproduction"]["instructions"])

    def test_csv_escapes_spreadsheet_formulas_and_preserves_zero(self):
        output = export_findings(
            [{"title": "=1+1", "confidence": 0}],
            output_format="csv",
        )

        self.assertIn("'=1+1", output)
        self.assertIn(",0,", output)

    def test_empty_csv_still_contains_scan_metadata(self):
        output = export_findings(
            [],
            output_format="csv",
            metadata={
                "run_id": "test-run",
                "target": "https://example.test/",
                "status": "completed",
                "completeness": "partial",
                "counts": {"requests": 3, "endpoints": 1, "errors": 2},
            },
        )

        self.assertIn("record_type", output.splitlines()[0])
        self.assertIn("test-run", output)
        self.assertIn("partial", output)
        self.assertIn("scan", output)

    def test_csv_includes_report_findings_and_sanitized_error_rows(self):
        output = export_findings(
            [{
                "title": "Indicator",
                "url": "https://example.test/?token=secret",
                "evidence": "password=hunter2",
                "method": "GET",
                "scanner": "SQL Injection",
                "assessment_type": "Indicador de possível injeção; não confirmado.",
                "verification_playbook": {
                    "tools": "Burp Repeater",
                    "steps": ["Compare apenas em staging."],
                    "confirmation_criteria": "Exija efeito repetível.",
                },
            }],
            output_format="csv",
            metadata={
                "run_id": "test-run",
                "authorization": {
                    "user_confirmation": True,
                    "independently_verified": False,
                },
                "coverage": {"authenticated_crawl": "unauthenticated"},
                "scanner_coverage": [{"name": "Scanner A"}],
                "framework_mapping": {"name": "OWASP WSTG"},
                "tool_version": "0.3.0",
                "python_version": "3.15.2",
                "settings": {"max_pages": 10},
                "limitations": ["Manual verification required"],
                "counts": {"requests": 1, "endpoints": 1, "errors": 1},
                "scanner_validation": {
                    "status": "not_certified",
                    "scope_note": "Synthetic fixtures only",
                },
            },
            errors=[{
                "stage": "testing",
                "component": "scanner",
                "error_type": "TimeoutError",
            }],
        )
        rows = list(csv.DictReader(output.splitlines()))

        self.assertEqual([row["record_type"] for row in rows], ["scan", "finding", "error"])
        self.assertTrue(all(row["tool_version"] == "0.3.0" for row in rows))
        self.assertIn("Compare apenas em staging.", rows[1]["verification_playbook"])
        self.assertIn("not_certified", rows[0]["scanner_validation"])
        self.assertIn('"user_confirmation": true', rows[0]["authorization"])
        self.assertNotIn("assessment_id", rows[0])
        self.assertIn("Scanner A", rows[1]["scanner_coverage"])
        self.assertNotIn("hunter2", output)
        self.assertNotIn("token=secret", output)
        self.assertIn("TimeoutError", output)

    def test_pdf_escapes_untrusted_markup(self):
        output = export_findings(
            [{"title": "<script>alert(1)</script>", "severity": "High"}],
            output_format="pdf",
            metadata={
                "status": "completed",
                "completeness": "execution_complete",
                "counts": {"endpoints": 1},
                "authorization": {"user_confirmation": True},
            },
        )

        self.assertTrue(output.getvalue().startswith(b"%PDF"))
        self.assertGreater(len(output.getvalue()), 1000)


if __name__ == "__main__":
    unittest.main()
