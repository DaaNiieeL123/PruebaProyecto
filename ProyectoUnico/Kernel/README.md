# Kernel

Modificaciones de kernel para el Proyecto Unico.

Esta carpeta contiene unicamente los archivos modificados/agregados para integrar las syscalls del sistema.

## Estructura

- `kernel/process_info_syscall.c`
- `kernel/system_monitor_syscall.c`
- `kernel/security_monitor_syscalls.c` (Proyecto Unico)
- `include/linux/process_info.h`
- `include/linux/system_monitor.h`
- `include/linux/security_monitor.h`
- `arch/x86/entry/syscalls/syscall_64.tbl` (lineas a agregar)
- `scripts/prepare_kernel.sh`
- `scripts/compile_kernel.sh`
- `scripts/install_kernel.sh`

Compatibilidad:

- Se conserva `src/` como respaldo historico, pero los scripts priorizan la estructura `arch/`, `include/`, `kernel/` en la raiz de `Kernel/`.

## Syscalls registradas

- `548 sys_get_process_info`
- `549 sys_get_system_monitor`
- `550 sys_file_analize`
- `551 sys_scan_processes`
- `552 sys_quarantine_file`
- `553 sys_restore_file`
- `554 sys_get_quarantine_list`
- `556 sys_simulate_panic`

## Uso rapido

Preparar el arbol del kernel sin compilar:

```bash
cd ProyectoUnico/Kernel
./scripts/compile_kernel.sh /ruta/al/kernel prepare-only
```

Compilar kernel completo (una sola pasada):

```bash
cd ProyectoUnico/Kernel
./scripts/compile_kernel.sh /ruta/al/kernel
```

Instalar kernel compilado:

```bash
cd ProyectoUnico/Kernel
sudo ./scripts/install_kernel.sh /ruta/al/kernel
```
