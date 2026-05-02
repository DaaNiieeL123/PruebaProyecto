# ProgramaIntermedio

Daemon en C con dos hilos obligatorios:

- Hilo 1: monitoreo de metricas de sistema y procesos.
- Hilo 2: escaneo de archivos, hash SHA-256 y comparacion con blacklist.

Arquitectura aplicada en el proyecto:

Kernel (syscalls en C) -> Daemon en C (programa intermedio) -> Backend en C (separado) -> Dashboard web.

Separacion actual de responsabilidades:

- `security_daemon`: monitoreo, escaneo, analisis de firmas y acciones kernel.
- `backend_server`: API HTTP publica para Dashboard y proxy interno hacia daemon.

El daemon invoca periodicamente las syscalls del proyecto:

- `sys_get_system_monitor` (549)
- `sys_scan_processes` (551)
- `sys_file_analize` (550)
- `sys_quarantine_file` (552)
- `sys_restore_file` (553)
- `sys_get_quarantine_list` (554)
- `sys_get_process_info` (548)
- `sys_simulate_panic` (556)

## Endpoints

Todos los endpoints se consumen desde `backend_server` (puerto 8090 por defecto), que reenvia al daemon interno (puerto 8093 por defecto en el modo vivo).

- `POST /api/login`
- `GET /api/me`
- `GET /api/metrics`
- `GET /api/alerts`
- `GET /api/files`
- `GET /api/threats`
- `GET /api/report/summary` (reporte rapido exportable)
- `GET /api/quarantine` (solo admin)
- `POST /api/scan/start` (solo admin)
- `POST /api/scan/stop` (solo admin)
- `POST /api/scan/once` (solo admin)
- `POST /api/quarantine/add` (solo admin)
- `POST /api/quarantine/restore` (solo admin)
- `GET /api/process?pid=N` (solo admin)

## Compilar

```bash
cd ProyectoUnico/ProgramaIntermedio
make
```

PAM es obligatorio para autenticacion local. Instalar dependencias antes de compilar:

```bash
sudo apt update
sudo apt install -y libpam0g-dev
```

Configurar el servicio PAM del daemon:

```bash
sudo cp config/security_daemon.pam /etc/pam.d/security_daemon
```

## Ejecutar

### Modo vivo (recomendado para control por Ctrl+C)

Este modo mantiene daemon + backend encendidos mientras el script siga corriendo.
Cuando presionas `Ctrl+C`, el script apaga ambos procesos automaticamente.

```bash
cd ProyectoUnico/ProgramaIntermedio

# Si quieres evitar prompt de sudo, exporta primero tu clave
# export SUDO_PASS='TU_PASSWORD'

bash scripts/run_live.sh
```

Variables opcionales:

- `PUBLIC_PORT` (default: `8090`)
- `DAEMON_PORT` (default: `8093`)
- `RUN_AS_ROOT` (default: `1`)

Ejemplo:

```bash
PUBLIC_PORT=8090 DAEMON_PORT=8093 RUN_AS_ROOT=1 bash scripts/run_live.sh
```

## Pruebas reproducibles

Generar archivos oficiales de prueba (carpeta `ProyectoUnico/pruebas/test_files`):

```bash
bash scripts/generate_test_inputs.sh ./data/monitor_dir seed
```

Forzar un cambio sobre archivo observado (evento "modificado"):

```bash
bash scripts/generate_test_inputs.sh ./data/monitor_dir mutate
```

Nota: la blacklist activa del daemon se toma de `ProgramaIntermedio/data/hash_blacklist.json` y ya esta alineada con `ProyectoUnico/pruebas/hash_blacklist.json`.

Verificacion API manual (requiere usuario/password validos de PAM):

```bash
curl -s -X POST http://127.0.0.1:8090/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"TU_USUARIO","password":"TU_PASSWORD"}'
```

## Roles esperados

- `admin_user`
- `common_user`

El usuario autenticado via PAM debe pertenecer a alguno de esos grupos.
