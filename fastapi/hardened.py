"""FastAPI with the article's controls applied. Run: uvicorn hardened:app --port 8002

In Docker this also sits behind nginx (see nginx.conf), which supplies the
header timeout and the edge body cap that Uvicorn does not have.
"""
import asyncio
import re
import threading
import time

import bcrypt
from fastapi import FastAPI, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

MAX_BODY_BYTES = 64 * 1024


class BodyLimit:
    """Pure ASGI middleware: reject by Content-Length up front, and count
    bytes as they stream in for chunked bodies. Neither FastAPI nor Uvicorn
    caps the body by default."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await send({"type": "http.response.start", "status": 413,
                                "headers": [(b"connection", b"close")]})
                    await send({"type": "http.response.body", "body": b""})
                    return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # FastAPI re-raises HTTPException from body parsing as-is.
                    raise HTTPException(status_code=413)
            return message

        await self.app(scope, limited_receive, send)


app = FastAPI()
app.add_middleware(BodyLimit, max_bytes=MAX_BODY_BYTES)

SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")  # unambiguous -> linear
HASH = bcrypt.hashpw(b"correct horse battery staple", bcrypt.gensalt(10))


class Order(BaseModel):
    sku: str = Field(max_length=64)
    qty: int = Field(ge=1, le=100)


class Login(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)


class Password(BaseModel):
    password: str = Field(max_length=128)


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


async def save_order(order: Order) -> None:
    await asyncio.sleep(0.005)  # stand-in for an async DB call


@app.get("/healthz")
async def healthz():
    return Response("ok")


@app.get("/search")
async def search(q: str = Query("", max_length=64)):
    return {"q": q, "valid": bool(SLUG.match(q))}


@app.post("/orders")
async def orders(order: Order):
    try:
        async with asyncio.timeout(0.8):  # carry a deadline through every call
            await save_order(order)
    except TimeoutError:
        return Response(status_code=503)
    return Response(status_code=202)


@app.post("/login")
def login(body: Login, request: Request):
    # Plain `def`: FastAPI runs it in the thread pool, and bcrypt releases
    # the GIL while hashing, so the event loop keeps serving.
    # request.client.host is the socket peer, or -- with
    # `--proxy-headers --forwarded-allow-ips=<nginx ip>` -- the address our
    # own nginx wrote. Never the client's own X-Forwarded-For.
    if rate_limited(f"ip:{request.client.host}") or rate_limited(f"user:{body.username}"):
        return Response(status_code=429)
    ok = body.username == "alice" and bcrypt.checkpw(body.password.encode(), HASH)
    return Response(status_code=200 if ok else 401)


@app.post("/hash")
def hash_password(body: Password):
    return {"hash": bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(10)).decode()}
