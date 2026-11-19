# Works with Podman or Docker; Podman wins when both are installed.
# The macOS Podman installer puts the binary in /opt/podman/bin, which is not
# always on PATH. Override with: make up ENGINE=docker
ENGINE  ?= $(shell command -v podman 2>/dev/null || { [ -x /opt/podman/bin/podman ] && echo /opt/podman/bin/podman; } || echo docker)
COMPOSE ?= $(ENGINE) compose
PY      ?= python3

.PHONY: help up down build ps logs attack quick list clean

help:
	@echo "make up       build and start all 9 containers ($(ENGINE))"
	@echo "make attack   run every attack against every target"
	@echo "make quick    same, shorter (skips the 40 MB body)"
	@echo "make attack T=express-vulnerable TESTS=redos,xff"
	@echo "make logs S=gin-hardened"
	@echo "make down     stop everything"

up:
	$(COMPOSE) up -d --build
	@echo "waiting for services..."
	@$(PY) -c "import sys; sys.path.insert(0, 'attacks'); import lab; \
	  bad=[n for n,u in lab.TARGETS.items() if not lab.wait_healthy(u, 180)]; \
	  print('all up' if not bad else 'not healthy: ' + ', '.join(bad)); sys.exit(1 if bad else 0)"

build:
	$(COMPOSE) build

down:
	$(COMPOSE) down

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f $(S)

attack:
	$(PY) attacks/lab.py $(T) $(if $(TESTS),--tests $(TESTS))

quick:
	$(PY) attacks/lab.py $(T) --quick --seconds 3 --slow-seconds 8 $(if $(TESTS),--tests $(TESTS))

list:
	$(PY) attacks/lab.py --list

clean:
	$(COMPOSE) down --rmi local --volumes
