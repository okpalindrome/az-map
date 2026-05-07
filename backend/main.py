"""FastAPI application factory and static file serving."""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .database import init_db
from .api import scan as scan_api
from .api import graph_api, findings, export, snapshot, tenant

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="az-map",
    description="Azure Security Analysis Tool",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# API routers
app.include_router(scan_api.router)
app.include_router(graph_api.router)
app.include_router(findings.router)
app.include_router(export.router)
app.include_router(snapshot.router)
app.include_router(tenant.router)


# Serve frontend
_frontend = Path(__file__).parent.parent / "frontend"

if _frontend.exists():
    app.mount("/static", StaticFiles(directory=str(_frontend)), name="static")

    @app.get("/")
    def root():
        index = _frontend / "index.html"
        if index.exists():
            return FileResponse(
                str(index),
                headers={"Cache-Control": "no-store"},
            )
        return RedirectResponse("/docs")
else:
    @app.get("/")
    def root():
        return {"message": "az-map API", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}
