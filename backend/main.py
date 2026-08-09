import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, AnyHttpUrl

from backend.config import CrawlConfig
from backend.crawler.scope import TargetScope, ScopeValidationError
from backend.crawler.crawler import Crawler
from backend.scanners.manager import ScanManager

app = FastAPI(title="WebsiteAttack")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

class StartScanRequest(BaseModel):
    target_url: AnyHttpUrl
    agree_to_authorization: bool = False
    include_subdomains: bool = False
    max_depth: int = 3
    max_pages: int = 50
    concurrency: int = 4
    rate_limit_per_second: float = 2.0

current_scan = {
    "progress": {},
    "results": None,
    "task": None,
}

@app.get("/")
async def ui():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/styles.css")
async def styles():
    return FileResponse(FRONTEND_DIR / "styles.css")

@app.get("/app.js")
async def app_js():
    return FileResponse(FRONTEND_DIR / "app.js")

@app.post("/api/scan")
async def start_scan(request: StartScanRequest):
    if not request.agree_to_authorization:
        raise HTTPException(status_code=400, detail="Authorization confirmation is required.")
    try:
        scope = TargetScope(str(request.target_url), include_subdomains=request.include_subdomains)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    config = CrawlConfig(
        max_depth=request.max_depth,
        max_pages=request.max_pages,
        timeout_seconds=15,
        concurrency=request.concurrency,
        rate_limit_per_second=request.rate_limit_per_second,
    )
    crawler = Crawler(scope, config)
    current_scan["progress"] = crawler.progress
    task = asyncio.create_task(run_crawl(crawler, str(request.target_url)))
    current_scan["task"] = task
    return {"status": "started"}

@app.get("/api/progress")
async def scan_progress():
    return current_scan["progress"]

@app.post("/api/cancel")
async def cancel_scan():
    task = current_scan.get("task")
    if task and not task.done():
        task.cancel()
        return {"status": "cancelled"}
    return {"status": "no active scan"}

async def run_crawl(crawler: Crawler, start_url: str):
    try:
        results = await crawler.crawl(start_url)
        scanner = ScanManager()
        scan_result = await scanner.execute(results, progress=current_scan["progress"])
        current_scan["results"] = {
            "endpoints": results,
            "findings": scan_result["findings"],
            "summary": scan_result["summary"],
        }
    except asyncio.CancelledError:
        current_scan["progress"]["module"] = "cancelled"
    finally:
        current_scan["progress"]["completed"] = True

@app.get("/api/results")
async def scan_results():
    return current_scan.get("results") or {"endpoints": [], "findings": []}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
