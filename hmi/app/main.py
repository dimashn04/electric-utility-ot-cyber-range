import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


SCADA_BASE_URL = os.getenv("SCADA_BASE_URL", "http://scada-master:8000")
BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Electric Utility HMI")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


async def proxy(method: str, path: str) -> Any:
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.request(method, f"{SCADA_BASE_URL}{path}")
        response.raise_for_status()
        return response.json()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/status")
async def status() -> Any:
    return await proxy("GET", "/api/status")


@app.get("/api/events")
async def events() -> Any:
    return await proxy("GET", "/api/events")


@app.post("/api/commands/breaker/open")
async def open_breaker() -> Any:
    return await proxy("POST", "/api/commands/breaker/open")


@app.post("/api/commands/breaker/close")
async def close_breaker() -> Any:
    return await proxy("POST", "/api/commands/breaker/close")
