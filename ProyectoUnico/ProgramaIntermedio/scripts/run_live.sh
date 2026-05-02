#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUBLIC_PORT="${PUBLIC_PORT:-8090}"
DAEMON_PORT="${DAEMON_PORT:-8093}"
WATCH_DIR="${WATCH_DIR:-$ROOT_DIR/data/monitor_dir}"
BLACKLIST_FILE="${BLACKLIST_FILE:-$ROOT_DIR/data/hash_blacklist.json}"
RUN_AS_ROOT="${RUN_AS_ROOT:-1}"

DAEMON_PID=""
BACKEND_PID=""
CLEANED_UP=0

sudo_cmd() {
    if [[ "$EUID" -eq 0 ]]; then
        "$@"
        return
    fi

    if [[ -n "${SUDO_PASS:-}" ]]; then
        printf '%s\n' "$SUDO_PASS" | sudo -S "$@"
    else
        sudo "$@"
    fi
}

kill_all_stack() {
    set +e

    pkill -f "$ROOT_DIR/backend_server" 2>/dev/null || true
    pkill -f "$ROOT_DIR/security_daemon" 2>/dev/null || true

    if pgrep -f "$ROOT_DIR/backend_server" >/dev/null 2>&1; then
        sudo_cmd pkill -f "$ROOT_DIR/backend_server" 2>/dev/null || true
    fi

    if pgrep -f "$ROOT_DIR/security_daemon" >/dev/null 2>&1; then
        sudo_cmd pkill -f "$ROOT_DIR/security_daemon" 2>/dev/null || true
    fi

    set -e
}

cleanup() {
    if [[ "$CLEANED_UP" -eq 1 ]]; then
        return
    fi
    CLEANED_UP=1

    echo
    echo "[live] Apagando stack..."

    set +e
    if [[ -n "$BACKEND_PID" ]]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    if [[ -n "$DAEMON_PID" ]]; then
        if [[ "$RUN_AS_ROOT" == "1" ]]; then
            sudo_cmd kill "$DAEMON_PID" 2>/dev/null || true
        else
            kill "$DAEMON_PID" 2>/dev/null || true
        fi
    fi

    wait "$BACKEND_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    set -e

    kill_all_stack
    rm -f "$ROOT_DIR/security_daemon.pid" "$ROOT_DIR/backend_server.pid"

    echo "[live] Stack detenido."
}

trap cleanup INT TERM EXIT

mkdir -p "$WATCH_DIR"

echo "[live] Compilando binarios..."
make

echo "[live] Limpiando procesos previos de backend/daemon..."
kill_all_stack

if [[ "$RUN_AS_ROOT" == "1" && "$EUID" -ne 0 ]]; then
    echo "[live] Validando sudo para ejecutar daemon..."
    sudo_cmd -v
fi

echo "[live] Iniciando security_daemon en puerto interno ${DAEMON_PORT}"
if [[ "$RUN_AS_ROOT" == "1" ]]; then
    sudo_cmd "$ROOT_DIR/security_daemon" \
        -p "$DAEMON_PORT" \
        -w "$WATCH_DIR" \
        -b "$BLACKLIST_FILE" \
        -m 3 -s 5 &
else
    "$ROOT_DIR/security_daemon" \
        -p "$DAEMON_PORT" \
        -w "$WATCH_DIR" \
        -b "$BLACKLIST_FILE" \
        -m 3 -s 5 &
fi
DAEMON_PID=$!
echo "$DAEMON_PID" > "$ROOT_DIR/security_daemon.pid"

sleep 1

echo "[live] Iniciando backend_server en puerto publico ${PUBLIC_PORT}"
"$ROOT_DIR/backend_server" -p "$PUBLIC_PORT" -h 127.0.0.1 -u "$DAEMON_PORT" &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$ROOT_DIR/backend_server.pid"

echo "[live] Daemon PID=${DAEMON_PID} | Backend PID=${BACKEND_PID}"
echo "[live] API publica: http://0.0.0.0:${PUBLIC_PORT}"
echo "[live] Presiona Ctrl+C para apagar todo."

wait -n "$DAEMON_PID" "$BACKEND_PID"
echo "[live] Un proceso termino inesperadamente. Cerrando stack..."
exit 1