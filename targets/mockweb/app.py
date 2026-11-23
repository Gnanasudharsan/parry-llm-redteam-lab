"""Mock web + exfiltration recorder.

One service answers for every lab hostname (Docker network aliases): first-party pages on
`docs.harborview.test`, attacker-controlled pages on `attacker.test`, a backup endpoint on
`backup.harborview.test`. Every request is recorded, so "data reached the attacker" is a
lookup in `/_lab/hits`, never a guess.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from targets.lab.admin import require_token

PAGES_DIR = Path(__file__).parent / "pages"
DEFAULT_HOST = "docs.harborview.test"


class Page(BaseModel):
    host: str
    path: str
    html: str


class Hit(BaseModel):
    seq: int
    ts: float
    method: str
    host: str
    path: str
    query: str
    body: str


def _seed_pages() -> dict[tuple[str, str], str]:
    return {(DEFAULT_HOST, f"/{p.stem}"): p.read_text() for p in sorted(PAGES_DIR.glob("*.html"))}


def create_app() -> FastAPI:
    app = FastAPI(title="Parry lab mock web", docs_url=None, redoc_url=None)
    lock = threading.Lock()
    pages = _seed_pages()
    hits: list[Hit] = []

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/_lab/hits", dependencies=[Depends(require_token)])
    def list_hits(host: str | None = None, since: int = 0) -> list[Hit]:
        with lock:
            return [h for h in hits if h.seq > since and (host is None or h.host == host)]

    @app.put("/_lab/pages", dependencies=[Depends(require_token)])
    def put_page(page: Page) -> dict[str, str]:
        with lock:
            pages[(page.host.lower(), page.path)] = page.html
        return {"status": "stored", "url": f"http://{page.host}{page.path}"}

    @app.post("/_lab/reset", dependencies=[Depends(require_token)])
    def reset() -> dict[str, str]:
        with lock:
            hits.clear()
            pages.clear()
            pages.update(_seed_pages())
        return {"status": "reset"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT"])
    async def catch_all(path: str, request: Request) -> Response:
        host = (request.headers.get("host") or DEFAULT_HOST).split(":")[0].lower()
        body = (await request.body()).decode(errors="replace")[:10_000]
        with lock:
            hit = Hit(
                seq=len(hits) + 1,
                ts=time.time(),
                method=request.method,
                host=host,
                path="/" + path,
                query=request.url.query,
                body=body,
            )
            hits.append(hit)
            html = pages.get((host, "/" + path))
        if html is not None:
            return HTMLResponse(html)
        payload: dict[str, Any] = {"status": "recorded", "seq": hit.seq}
        return JSONResponse(payload, status_code=200 if request.method != "GET" else 404)

    return app


app = create_app()
