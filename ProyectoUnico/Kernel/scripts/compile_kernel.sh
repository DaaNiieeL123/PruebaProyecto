#!/usr/bin/env bash
set -euo pipefail

KERNEL_SRC="${1:-$HOME/linux}"
MODE="${2:-build}"
JOBS="${JOBS:-$(nproc)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="compile_proyecto_${TS}.log"

[[ -d "$KERNEL_SRC" ]] || { echo "ERROR: no existe KERNEL_SRC=$KERNEL_SRC"; exit 1; }
[[ -f "$KERNEL_SRC/Makefile" ]] || { echo "ERROR: $KERNEL_SRC no parece un kernel source tree"; exit 1; }

"$SCRIPT_DIR/prepare_kernel.sh" "$KERNEL_SRC"

if [[ "$MODE" == "prepare-only" ]]; then
    echo "[compile] modo prepare-only: no se compila"
    exit 0
fi

echo "[compile] Configurando kernel en $KERNEL_SRC"
cd "$KERNEL_SRC"
if [[ -f "/boot/config-$(uname -r)" ]]; then
    cp "/boot/config-$(uname -r)" .config
fi

make olddefconfig 2>&1 | tee "$LOG_FILE"

if [[ -x scripts/config ]]; then
    scripts/config --disable SYSTEM_TRUSTED_KEYS || true
    scripts/config --disable SYSTEM_REVOCATION_KEYS || true
    scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS "" || true
    scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS "" || true
fi

echo "[compile] Compilando kernel con -j$JOBS (esto puede tardar)"
time make -j"$JOBS" 2>&1 | tee -a "$LOG_FILE"

[[ -f arch/x86/boot/bzImage ]] || {
    echo "ERROR: no se genero arch/x86/boot/bzImage"
    exit 1
}

echo "[compile] OK: bzImage generado"
echo "[compile] Log: $KERNEL_SRC/$LOG_FILE"
