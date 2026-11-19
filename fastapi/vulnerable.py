"""FastAPI with the async trap and no body limit. Run: uvicorn vulnerable:app --port 8001"""
import re
import threading
import time

import bcrypt
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel, Field

app = FastAPI()

# MISTAKE: nested quantifier -> catastrophic backtracking (ReDoS).
SLUG = re.compile(r"^([a-z0-9]+-?)*$")
HASH = bcrypt.hashpw(b"correct horse battery staple", bcrypt.gensalt(10))


class Order(BaseModel):
    # These constraints run AFTER the whole body was read and parsed.
    # They are validation, not a size limit.
    sku: str = Field(max_length=64)
    qty: int = Field(ge=1, le=100)


class Login(BaseModel):
    username: str
    password: str


class Password(BaseModel):
    password: str


_hits: dict[str, tuple[float, int]] = {}
_lock = threading.Lock()


def rate_limited(key: str, limit: int = 5, window: float = 60.0) -> bool:
    now = time.monotonic()
    with _lock:
        start, n = _hits.get(key, (now, 0))
        if now - start > window:
            start, n = now, 0
        _hits[key] = (start, n + 1)
        return n + 1 > limit


@app.get("/healthz")
async def healthz():
    return Response("ok")


@app.get("/search")
async def search(q: str = ""):
    # MISTAKE: CPU-bound regex inside async def stalls the whole worker.
    return {"q": q, "valid": bool(SLUG.match(q))}


@app.post("/orders")
async def orders(order: Order):
    return Response(status_code=202)


@app.post("/login")
async def login(body: Login, request: Request):
    # MISTAKE: first X-Forwarded-For entry is whatever the client typed.
    key = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
    if rate_limited(key):
        return Response(status_code=429)
    # MISTAKE: blocking bcrypt inside async def.
    ok = body.username == "alice" and bcrypt.checkpw(body.password.encode(), HASH)
    return Response(status_code=200 if ok else 401)


@app.post("/hash")
async def hash_password(body: Password):
    # MISTAKE: ~50-100 ms of CPU on the event loop per call.
    return {"hash": bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(10)).decode()}
