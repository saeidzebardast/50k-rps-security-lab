# 50k RPS Security Lab

Companion code for **[50k RPS Is a Security Problem, Not a Benchmark](https://medium.com/@saeid/50k-rps-is-a-security-problem-not-a-benchmark-b7848751f9f7)**
(also on [zebardast.com](https://zebardast.com/blog/50k-rps-is-a-security-problem)).

The article looks at how Express.js, FastAPI, Gin and Spring Boot fail under hostile traffic. This repo lets
you reproduce those failures on your own machine. Each framework comes in two builds:

- **vulnerable**: the way tutorials and READMEs usually ship it
- **hardened**: with the article's controls applied

One script attacks all eight builds and prints a PASS/FAIL matrix.

> Only run the attack script against services you run yourself.

## Quick start

You need Podman or Docker, plus Python 3.9+ for the attack script (standard library only, no `pip install`).

```bash
git clone <this repo> && cd 50k-rps-security-lab
make up        # build and start 9 containers, wait until healthy
make attack    # run every attack against every target (~5 min)
make down
```

`make` picks `podman compose` when Podman is installed (including `/opt/podman/bin`, where the macOS
installer puts it) and `docker compose` otherwise. Force one with `make up ENGINE=docker`. Without `make`:

```bash
docker compose up -d --build      # or: podman compose up -d --build
python3 attacks/lab.py
```

### Podman notes

- `podman compose` needs a compose provider: either `docker-compose` or `podman-compose` on PATH
  (`brew install podman-compose`). Podman Desktop can install one for you.
- The Podman machine needs about 3 GB of RAM for all nine containers. The default machine (4 GB) is enough.
- If builds fail with `unable to retrieve auth token: invalid username/password`, Podman is sending stale
  Docker Hub credentials. Either run `podman login docker.io` again, or pre-pull the base images
  anonymously and build again:

  ```bash
  echo '{}' > /tmp/empty-auth.json
  for i in golang:1.26-alpine maven:3.9-eclipse-temurin-21 eclipse-temurin:21-jre python:3.13-slim \
           node:24-alpine nginx:1.29-alpine gcr.io/distroless/static-debian12:nonroot; do
    podman pull --authfile /tmp/empty-auth.json "$i"
  done
  ```

Run part of the matrix:

```bash
make attack T=express-vulnerable                 # one target
make attack T="gin-vulnerable gin-hardened" TESTS=slowloris,xff
make quick                                       # shorter runs, skips the 40 MB body
python3 attacks/lab.py --list                    # targets and tests
python3 attacks/lab.py --json > results.json
```

## Layout

| Path | What |
|---|---|
| [`express/`](express) | `vulnerable.js`, `hardened.js` (Express 5) |
| [`fastapi/`](fastapi) | `vulnerable.py`, `hardened.py`, and `nginx.conf` for the edge in front of the hardened build |
| [`gin/`](gin) | `vulnerable/main.go`; `hardened/main.go` is the article's listing (changes marked `LAB:`) |
| [`spring/`](spring) | One Spring Boot 4 app with `vulnerable` and `hardened` profiles |
| [`attacks/lab.py`](attacks/lab.py) | The attack harness |
| [`docker-compose.yml`](docker-compose.yml) | All 9 containers, 2 CPUs / 768 MB each so the frameworks are comparable |

| Framework | vulnerable | hardened |
|---|---|---|
| Express | `localhost:3001` | `localhost:3002` |
| FastAPI | `localhost:8001` | `localhost:8002` (nginx → uvicorn) |
| Gin | `localhost:8081` | `localhost:8082` |
| Spring Boot | `localhost:9001` | `localhost:9002` (Actuator on 9090, not published) |

Every app serves the same routes: `GET /healthz`, `GET /search?q=` (slug validation with a regex),
`POST /orders`, `POST /login` (bcrypt, rate limited to 5/min) and `POST /hash` (bcrypt). Test login:
`alice` / `correct horse battery staple`.

## What each test does

| Test | Article section | Attack | PASS when |
|---|---|---|---|
| `body` | "Bound the request before you parse it" | POST a 200 KB and a 40 MB order | 200 KB gets `413` |
| `redos` | Express, hero image | Find a `/search` payload costing ≥0.8 s, then send one per second during load | No such payload exists. FAIL if p99 rises >10× and above 250 ms |
| `blocking` | FastAPI "async trap", "Price your authentication" | 8 clients call `/hash` in a loop while `/healthz` is probed | `/healthz` p99 <100 ms (WARN <250 ms) |
| `slowloris` | Gin, Express timeouts | 40 connections each send one header line per second | All closed within 12 s |
| `xff` | Express story, Gin trusted proxies | 12 logins, each with a random `X-Forwarded-For` | ≥6 get `429` |
| `actuator` | Spring Boot | GET `/actuator/env`, `heapdump`, `threaddump` | None reachable on the app port |

## Results

Apple Silicon (M-series, 14 cores), 2 CPUs per container. Docker Desktop 29 and Podman 6.1 (libkrun)
give the same verdicts, and their numbers are within run-to-run noise of each other.

```
                    body       redos      blocking   slowloris  xff        actuator
express-vulnerable  FAIL       FAIL       FAIL       FAIL       FAIL       N/A
express-hardened    PASS       PASS       PASS       PASS       PASS       N/A
fastapi-vulnerable  FAIL       FAIL       FAIL       FAIL       FAIL       N/A
fastapi-hardened    PASS       PASS       PASS       PASS       PASS       N/A
gin-vulnerable      FAIL       PASS       PASS       FAIL       FAIL       N/A
gin-hardened        PASS       PASS       WARN       PASS       PASS       N/A
spring-vulnerable   FAIL       PASS       WARN       FAIL       FAIL       FAIL
spring-hardened     PASS       PASS       PASS       FAIL       PASS       PASS
```

Selected numbers:

- **Express ReDoS:** a 29-character payload costs 1.1 s of CPU. With one per second, p99 rises from **2 ms to
  1.1 s** and throughput falls from ~16,000 to ~19 req/s.
- **FastAPI ReDoS:** a 27-character payload costs 1.9 s. p99 rises from **5 ms to 3.8 s**.
- **FastAPI async trap:** `/healthz` p50 is **702 ms** with bcrypt inside `async def`, and **2 ms** after
  switching to plain `def`.
- **Spring Actuator:** `/actuator/heapdump` serves a **35 MB** heap dump to anyone.
- **Gin Slowloris:** the vulnerable build keeps 40/40 dripping connections open. The hardened build closes
  them all at **2 s** (`ReadHeaderTimeout`).

Absolute numbers depend on your machine. The Python load generator tops out around 15k req/s. That's enough
to show the effect, but it isn't a 50k RPS benchmark. The `blocking` verdict for Gin moves between PASS and
WARN from run to run (p99 87–132 ms), because it measures CPU contention on 2 cores, not blocking.

## What the lab found beyond the article

All of these come from running the code.

1. **Spring hardened still fails Slowloris.** Tomcat's `connection-timeout` applies to each read, not to
   the whole header. A client sending one byte per second keeps the connection open indefinitely.
   NIO's 8,192-connection ceiling is what protects you, not a timeout. The fix is an edge proxy with a
   whole-header timeout, like the nginx in front of FastAPI here.
2. **Java 21's regex engine did not ReDoS on these patterns.** `^([a-z0-9]+-?)*$`, `^(a+)+$`-style
   groups, `(a|aa)+` and `^(\w+\s?)*$` all match in under 1 ms on 24-character inputs, because the JDK
   memoizes these loops. Java isn't immune in general (backreferences and some bounded or polynomial
   cases still blow up), but the classic textbook payload doesn't work.
3. **Go is immune to ReDoS by design.** `regexp` is RE2, so it runs in linear time. The same "evil"
   pattern is harmless in `gin-vulnerable`.
4. **Virtual threads have their own async trap.** In `spring-vulnerable`, 8 CPU-bound bcrypt calls on
   virtual threads pin both carrier threads, and `/healthz` p50 reaches ~140–190 ms. The hardened build
   moves hashing to a bounded platform-thread pool (a bulkhead), and p99 drops to **2 ms**.
5. **bcryptjs's async API doesn't move the work off the event loop.** It yields between rounds, but the
   hashing still runs on the main thread. With it, `express-hardened` had a `/healthz` p99 of ~600 ms.
   Native `bcrypt` uses the libuv thread pool and brings that down to **43 ms**.
6. **Spring has no JSON body limit either.** Tomcat caps form posts (`max-http-form-post-size`), not JSON.
   The hardened build adds [`BodyLimitFilter`](spring/src/main/java/lab/BodyLimitFilter.java). Jackson's
   20 MB per-string limit only catches oversized single strings, not oversized documents.
7. **Node checks `headersTimeout` on a timer.** It only runs every `connectionsCheckingInterval` (30 s by
   default). Lowering `headersTimeout` alone doesn't help much. [`hardened.js`](express/hardened.js)
   lowers both.

## Running without containers

Express and FastAPI run natively. Note that the native hardened FastAPI has no nginx in front, so it will
fail `slowloris`, which is the article's point.

```bash
cd express && npm ci && npm run vulnerable    # :3001 (second terminal: npm run hardened -> :3002)
```

```bash
cd fastapi && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
uvicorn vulnerable:app --port 8001            # second terminal: uvicorn hardened:app --port 8002
```

Gin needs Go 1.26+ (`cd gin && go run ./hardened` with `TRUSTED_PROXIES=none`). Spring needs JDK 21+ and
Maven (`cd spring && mvn spring-boot:run -Dspring-boot.run.profiles=hardened`). Their ports differ from
the table above, so pass them explicitly: `python3 attacks/lab.py gin=http://127.0.0.1:8080`.

## License

[MIT](LICENSE)
