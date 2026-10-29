#!/usr/bin/env bash
# demo_services.sh: start/stop two stand-ins for services researchers expose by accident,
# so the external scan has something to find before hardening and to prove blocked after.
#
#   sudo ./audit/demo_services.sh start   # :8000 plain process on 0.0.0.0, :8080 Docker -p
#   sudo ./audit/demo_services.sh stop
#
# :8000 tests the host firewall (INPUT); :8080 tests the Docker bypass (FORWARD/DOCKER-USER).
# Both serve a static "demo" page only. Run them only on a test instance.
set -Eeuo pipefail

SGS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
source "$SGS_ROOT/lib/common.sh"
SGS_MODULE=demo

HTTP_UNIT=sgs-demo-http
WEB_CONTAINER=sgs-demo-web
WEB_DIR=/run/sgs-demo

start() {
  install -d -m 0755 "$WEB_DIR"
  echo "secure-gpu-stack demo service: if you can read this from outside, it is exposed" >"$WEB_DIR/index.html"
  if ! systemctl is-active --quiet "$HTTP_UNIT"; then
    systemd-run --quiet --unit "$HTTP_UNIT" --property DynamicUser=yes \
      python3 -m http.server 8000 --bind 0.0.0.0 --directory "$WEB_DIR"
  fi
  ok "plain service listening on 0.0.0.0:8000 (stand-in for Jupyter/TensorBoard bound to all interfaces)"

  if command -v docker >/dev/null 2>&1; then
    docker rm -f "$WEB_CONTAINER" >/dev/null 2>&1 || true
    # Explicit 0.0.0.0 on purpose: it ignores a 127.0.0.1 default in daemon.json, so
    # only the DOCKER-USER rule stands between this container and the internet.
    docker run -d --name "$WEB_CONTAINER" -p 0.0.0.0:8080:80 \
      -v "$WEB_DIR:/usr/share/nginx/html:ro" nginx:alpine >/dev/null
    ok "container published on 0.0.0.0:8080 (docker run -p)"
  else
    warn "Docker not installed; skipping the container test"
  fi
}

stop() {
  systemctl stop "$HTTP_UNIT" 2>/dev/null || true
  if command -v docker >/dev/null 2>&1; then docker rm -f "$WEB_CONTAINER" >/dev/null 2>&1 || true; fi
  rm -rf "$WEB_DIR"
  ok "demo services stopped"
}

require_root
case ${1:-} in
  start) start ;;
  stop) stop ;;
  *) echo "usage: sudo $0 start|stop" >&2; exit 1 ;;
esac
