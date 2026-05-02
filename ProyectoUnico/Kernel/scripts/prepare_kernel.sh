#!/usr/bin/env bash
set -euo pipefail

KERNEL_SRC="${1:-$HOME/linux}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -d "$PROJ_DIR/include/linux" && -d "$PROJ_DIR/kernel" && -d "$PROJ_DIR/arch/x86/entry/syscalls" ]]; then
    SRC_DIR="$PROJ_DIR"
elif [[ -d "$PROJ_DIR/src/include/linux" && -d "$PROJ_DIR/src/kernel" && -d "$PROJ_DIR/src/arch/x86/entry/syscalls" ]]; then
    SRC_DIR="$PROJ_DIR/src"
else
    echo "ERROR: no se encontro estructura valida de archivos modificados en Kernel/"
    exit 1
fi

[[ -d "$KERNEL_SRC" ]] || { echo "ERROR: no existe KERNEL_SRC=$KERNEL_SRC"; exit 1; }
[[ -f "$KERNEL_SRC/Makefile" ]] || { echo "ERROR: $KERNEL_SRC no parece un kernel source tree"; exit 1; }

echo "[prepare] Copiando archivos modificados..."
cp -v "$SRC_DIR/include/linux/process_info.h" "$KERNEL_SRC/include/linux/process_info.h"
cp -v "$SRC_DIR/include/linux/system_monitor.h" "$KERNEL_SRC/include/linux/system_monitor.h"
cp -v "$SRC_DIR/include/linux/security_monitor.h" "$KERNEL_SRC/include/linux/security_monitor.h"
cp -v "$SRC_DIR/kernel/process_info_syscall.c" "$KERNEL_SRC/kernel/process_info_syscall.c"
cp -v "$SRC_DIR/kernel/system_monitor_syscall.c" "$KERNEL_SRC/kernel/system_monitor_syscall.c"
cp -v "$SRC_DIR/kernel/security_monitor_syscalls.c" "$KERNEL_SRC/kernel/security_monitor_syscalls.c"

add_tbl_line() {
    local line="$1"
    local tag="$2"
    local tbl="$KERNEL_SRC/arch/x86/entry/syscalls/syscall_64.tbl"
    if grep -q "[[:space:]]${tag}[[:space:]]" "$tbl"; then
        echo "[prepare] syscall ${tag} ya existe"
    else
        echo "$line" >> "$tbl"
        echo "[prepare] syscall ${tag} agregada"
    fi
}

echo "[prepare] Parchando syscall_64.tbl..."
add_tbl_line "548     common  get_process_info        sys_get_process_info" "get_process_info"
add_tbl_line "549     common  get_system_monitor      sys_get_system_monitor" "get_system_monitor"
add_tbl_line "550     common  file_analize            sys_file_analize" "file_analize"
add_tbl_line "551     common  scan_processes          sys_scan_processes" "scan_processes"
add_tbl_line "552     common  quarantine_file         sys_quarantine_file" "quarantine_file"
add_tbl_line "553     common  restore_file            sys_restore_file" "restore_file"
add_tbl_line "554     common  get_quarantine_list     sys_get_quarantine_list" "get_quarantine_list"
add_tbl_line "556     common  simulate_panic          sys_simulate_panic" "simulate_panic"

SYSCALLS_H="$KERNEL_SRC/include/linux/syscalls.h"
[[ -f "$SYSCALLS_H" ]] || { echo "ERROR: no existe $SYSCALLS_H"; exit 1; }

echo "[prepare] Parchando include/linux/syscalls.h..."
if ! grep -q "#include <linux/process_info.h>" "$SYSCALLS_H"; then
    sed -i '/#include <uapi\/linux\/sched\/types.h>/a #include <linux\/process_info.h>' "$SYSCALLS_H"
fi
if ! grep -q "#include <linux/system_monitor.h>" "$SYSCALLS_H"; then
    sed -i '/#include <linux\/process_info.h>/a #include <linux\/system_monitor.h>' "$SYSCALLS_H"
fi
if ! grep -q "#include <linux/security_monitor.h>" "$SYSCALLS_H"; then
    sed -i '/#include <linux\/system_monitor.h>/a #include <linux\/security_monitor.h>' "$SYSCALLS_H"
fi

append_proto_if_missing() {
    local needle="$1"
    local proto="$2"
    if grep -q "$needle" "$SYSCALLS_H"; then
        echo "[prepare] prototipo $needle ya existe"
    else
        printf '\n%s\n' "$proto" >> "$SYSCALLS_H"
        echo "[prepare] prototipo $needle agregado"
    fi
}

append_proto_if_missing "sys_get_process_info" "asmlinkage long sys_get_process_info(pid_t pid, struct process_info __user *uinfo);"
append_proto_if_missing "sys_get_system_monitor" "asmlinkage long sys_get_system_monitor(struct system_monitor_info __user *uinfo);"
append_proto_if_missing "sys_file_analize" "asmlinkage long sys_file_analize(const char __user *upath, struct file_analysis_info __user *uinfo);"
append_proto_if_missing "sys_scan_processes" "asmlinkage long sys_scan_processes(struct process_scan_result __user *ures);"
append_proto_if_missing "sys_quarantine_file" "asmlinkage long sys_quarantine_file(const char __user *upath);"
append_proto_if_missing "sys_restore_file" "asmlinkage long sys_restore_file(const char __user *upath);"
append_proto_if_missing "sys_get_quarantine_list" "asmlinkage long sys_get_quarantine_list(struct quarantine_list __user *ulist);"
append_proto_if_missing "sys_simulate_panic" "asmlinkage long sys_simulate_panic(const char __user *umsg);"

KERNEL_MK="$KERNEL_SRC/kernel/Makefile"
[[ -f "$KERNEL_MK" ]] || { echo "ERROR: no existe $KERNEL_MK"; exit 1; }

echo "[prepare] Parchando kernel/Makefile..."
if ! grep -q "security_monitor_syscalls.o" "$KERNEL_MK"; then
    printf '\n# Proyecto Unico SO2\nobj-y += process_info_syscall.o system_monitor_syscall.o security_monitor_syscalls.o\n' >> "$KERNEL_MK"
fi

echo "[prepare] OK: arbol listo para compilar"
