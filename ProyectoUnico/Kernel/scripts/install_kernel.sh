#!/usr/bin/env bash
set -euo pipefail

KERNEL_SRC="${1:-$HOME/linux}"

[[ $EUID -eq 0 ]] || { echo "ERROR: ejecutar con sudo"; exit 1; }
[[ -d "$KERNEL_SRC" ]] || { echo "ERROR: no existe KERNEL_SRC=$KERNEL_SRC"; exit 1; }
[[ -f "$KERNEL_SRC/arch/x86/boot/bzImage" ]] || {
    echo "ERROR: falta bzImage. Ejecuta compile_kernel.sh primero"
    exit 1
}

cd "$KERNEL_SRC"
NEW_VERSION="$(make kernelrelease)"

echo "[install] Instalando modulos para $NEW_VERSION"
make modules_install

echo "[install] Instalando imagen"
make install

echo "[install] Actualizando GRUB"
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub2-mkconfig >/dev/null 2>&1; then
    grub2-mkconfig -o /boot/grub2/grub.cfg
else
    echo "ADVERTENCIA: actualiza GRUB manualmente"
fi

echo "[install] OK: reinicia para usar $NEW_VERSION"
