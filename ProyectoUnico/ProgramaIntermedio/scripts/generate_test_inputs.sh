#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="$(cd "$ROOT_DIR/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/data/monitor_dir}"
MODE="${2:-seed}"
SOURCE_DIR="${3:-$PROJECT_ROOT/pruebas/test_files}"

mkdir -p "$OUT_DIR"

seed_files() {
  if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "[tests] ERROR: no existe SOURCE_DIR=$SOURCE_DIR"
    exit 1
  fi

  find "$OUT_DIR" -maxdepth 1 -type f -delete
  cp -f "$SOURCE_DIR"/*.txt "$OUT_DIR"/

  if [[ ! -f "$OUT_DIR/safe_observed.txt" ]]; then
    printf 'archivo base para detectar cambios\n' > "$OUT_DIR/safe_observed.txt"
  fi

  echo "[tests] Archivos oficiales copiados desde: $SOURCE_DIR"
  echo "[tests] Directorio de monitoreo listo en: $OUT_DIR"
}

mutate_file() {
  if [[ ! -f "$OUT_DIR/safe_observed.txt" ]]; then
    printf 'archivo base para detectar cambios\n' > "$OUT_DIR/safe_observed.txt"
  fi

  printf 'mutacion_%s\n' "$(date +%s)" >> "$OUT_DIR/safe_observed.txt"
  echo "[tests] safe_observed.txt modificado para probar evento de archivo modificado"
}

print_hashes() {
  echo "[tests] Hashes actuales:"
  find "$OUT_DIR" -maxdepth 1 -type f | sort | while read -r f; do
    sha256sum "$f"
  done
}

case "$MODE" in
  seed)
    seed_files
    ;;
  mutate)
    mutate_file
    ;;
  *)
    echo "Uso: $0 [directorio_monitor] [seed|mutate] [directorio_test_files]"
    exit 1
    ;;
esac

print_hashes
