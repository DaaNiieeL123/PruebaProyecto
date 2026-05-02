# Manual de Usuario - ProyectoUnico

**Universidad de San Carlos de Guatemala**  
**Facultad de Ingeniería - Sistemas Operativos 2**  
**Estudiante: 202203806**

---

## Tabla de contenido

1. [Introducción](#1-introducción)
2. [Requisitos previos](#2-requisitos-previos)
3. [Encendido del sistema](#3-encendido-del-sistema)
4. [Inicio de sesión](#4-inicio-de-sesión)
5. [Uso del dashboard paso a paso](#5-uso-del-dashboard-paso-a-paso)
6. [Acciones según rol](#6-acciones-según-rol)
7. [Operaciones administrativas (API)](#7-operaciones-administrativas-api)
8. [Solución de problemas](#8-solución-de-problemas)
9. [Cierre de sesión](#9-cierre-de-sesión)
10. [Conclusión](#10-conclusión)
11. [Referencias](#11-referencias)

---

## 1. Introducción

El presente Manual de Usuario describe el funcionamiento y la interacción con la interfaz gráfica del Proyecto Único desarrollado para el curso de Sistemas Operativos 2.

Este documento tiene como objetivo guiar al usuario en la operación de la plataforma web. La interfaz gráfica ha sido diseñada bajo el concepto de un "dashboard" de seguridad, permitiendo la monitorización del sistema y la respuesta ante amenazas de forma centralizada e intuitiva, abstrayendo la complejidad de las operaciones subyacentes del sistema operativo Linux.

---

## 2. Requisitos previos

Antes de iniciar, revisar lo siguiente:

1. Tener Linux con los paquetes básicos instalados.
2. Tener acceso a la carpeta `ProyectoUnico`.
3. Tener usuario del sistema con grupo válido:
    - `admin_user`
    - `common_user`

Si aún no existen los grupos:

```bash
sudo groupadd admin_user
sudo groupadd common_user
sudo usermod -aG admin_user TU_USUARIO
```

Después de agregar grupos, cerrar sesión y volver a entrar.

Configurar PAM para el login del daemon:

```bash
sudo cp ProyectoUnico/ProgramaIntermedio/config/security_daemon.pam /etc/pam.d/security_daemon
```

---

## 3. Encendido del sistema

### 3.0 Encendido controlado (recomendado para laboratorio)

Mientras el script este activo, backend + daemon siguen encendidos.
Al presionar `Ctrl+C`, se apagan ambos.

```bash
cd ProyectoUnico/ProgramaIntermedio
bash scripts/run_live.sh
```

Opcional (si quieres definir puertos):

```bash
PUBLIC_PORT=8090 DAEMON_PORT=8093 RUN_AS_ROOT=1 bash scripts/run_live.sh
```

### 3.1 Iniciar dashboard

```bash
cd ProyectoUnico/Dashboard
npm install
npm run dev
```

Abrir la URL que muestra Vite (normalmente `http://localhost:5173`).

### 3.2 Configuración de API

Crear o revisar archivo `.env.local` en `Dashboard`:

```env
VITE_API_BASE=http://IP_DE_LA_VM:8090
VITE_POLL_INTERVAL_MS=3000
```

---

## 4. Inicio de sesión

En la pantalla de login:

1. Escribir usuario.
2. Escribir contraseña.
3. Presionar **Ingresar**.

Si el usuario pertenece a `admin_user` o `common_user`, entra al panel principal.

![Pantalla de login](../assets/ev03_login_admin.png)

*Figura 1. Pantalla inicial de login.*

### 4.1 Credenciales de prueba (si fueron creadas)

- Admin: `admin_demo` / `AdminDemo2026`
- Common: `common_demo` / `CommonDemo2026`

---

## 5. Uso del dashboard paso a paso

### 5.1 Módulo Dashboard

- Muestra tarjetas de memoria, swap y fallos de página.
- Muestra gráficas de evolución en tiempo real.
- Muestra top procesos por memoria.

![Dashboard principal](../assets/ev04_dashboard_admin.png)

*Figura 2. Vista principal del dashboard con métricas y módulos.*

### 5.2 Módulo Alertas

- Lista eventos del sistema.
- Cada alerta trae tipo, descripción, severidad y hora.

Severidades visuales:

- LOW: informativo.
- MEDIUM: advertencia.
- HIGH: crítico.

![Alertas y amenazas](../assets/ev07_threat_high_detected.png)

*Figura 3. Registro de alertas y amenazas detectadas.*

### 5.3 Módulo Archivos

- Lista todos los archivos que han sido analizados por el Daemon dentro del directorio configurado.
- Muestra visualmente el estado de cada archivo (Limpio, Modificado, Sospechoso, o en **Cuarentena**), un fragmento de su hash SHA-256 y la fecha de su última modificación.
- **Acciones de Administrador:** Las cuentas con privilegios administrativos disponen de botones de acción integrados en la tabla. Esto permite enviar un archivo a cuarentena manualmente (botón **"Cuarentenar"**) o retirarlo de dicho estado (botón **"Restaurar"**), invocando las llamadas al sistema correspondientes.

### 5.4 Módulo Amenazas

- Lista detecciones de firmas por hash.
- Muestra nombre, archivo, severidad y descripción.

### 5.5 Módulo Controles (solo admin)

1. Entrar a **Controles**.
2. Activar o desactivar escaneo continuo.
3. Ejecutar escaneo puntual.
4. Consultar proceso por PID.

![Consulta PID](../assets/ev09_pid_lookup_admin.png)

*Figura 4. Consulta de proceso por PID para administrador.*

### 5.6 Exportar reporte

1. En la barra superior, presionar **Exportar**.
2. Se descarga un archivo JSON con el resumen del estado actual.

![Exportar desde interfaz](../assets/ev10a_report_export_ui.png)

*Figura 5. Botón de exportación en la interfaz.*

![Exportar reporte JSON](../assets/ev10_report_export_json.png)

*Figura 6. Archivo JSON descargado como reporte.*

---

## 6. Acciones según rol

| Acción | Admin | Common |
| --- | --- | --- |
| Ver métricas | Sí | Sí |
| Ver alertas | Sí | Sí |
| Ver archivos | Sí | Sí |
| Ver amenazas | Sí | Sí |
| Activar/desactivar escaneo | Sí | No |
| Escaneo puntual | Sí | No |
| Consulta por PID | Sí | No |
| Exportar reporte JSON | Sí | Sí |

![Restricciones common](../assets/ev05_role_common_restrictions.png)

*Figura 7. Restricciones visibles cuando se usa rol common.*

---

## 7. Operaciones administrativas (API)

Estas operaciones son solo para `admin`.

### 7.1 Listar cuarentena

```bash
curl -H "Authorization: Bearer TOKEN" http://IP_DE_LA_VM:8090/api/quarantine
```

### 7.2 Agregar archivo a cuarentena

```bash
curl -X POST \
   -H "Content-Type: application/json" \
   -H "Authorization: Bearer TOKEN" \
   -d '{"path":"/ruta/archivo"}' \
   http://IP_DE_LA_VM:8090/api/quarantine/add
```

![Agregar cuarentena](../assets/ev08a_quarantine_add.png)

*Figura 8. Operación para enviar archivo a cuarentena.*

### 7.3 Restaurar archivo de cuarentena

```bash
curl -X POST \
   -H "Content-Type: application/json" \
   -H "Authorization: Bearer TOKEN" \
   -d '{"path":"/ruta/archivo"}' \
   http://IP_DE_LA_VM:8090/api/quarantine/restore
```

![Restaurar cuarentena](../assets/ev08b_quarantine_restore.png)

*Figura 9. Restauración de archivo desde cuarentena.*

---

## 8. Solución de problemas

### 8.1 Login rechazado

- Revisar usuario y contraseña.
- Revisar que el usuario esté en `admin_user` o `common_user`.

### 8.2 Dashboard sin datos

- Revisar procesos activos:

```bash
pgrep -af '/ProyectoUnico/ProgramaIntermedio/security_daemon|/ProyectoUnico/ProgramaIntermedio/backend_server'
```

- Revisar `VITE_API_BASE` en `.env.local`.
- Revisar conectividad al puerto `8090`.

![Escaneo desactivado](../assets/ev06_scan_off_metrics_on.png)

*Figura 10. Ejemplo de monitoreo activo con escaneo desactivado.*

### 8.3 No aparecen controles de admin

- El login entró como usuario common.
- Revisar grupos del usuario en Linux.

### 8.4 Error de puerto ocupado

- Detener servicios actuales.
- Levantar de nuevo.

```bash
cd ProyectoUnico/ProgramaIntermedio
bash scripts/run_live.sh
```

---

## 9. Cierre de sesión

Presionar **Salir** en la parte superior del dashboard.

---

## 10. Conclusión

El desarrollo de esta interfaz demuestra la viabilidad de abstraer el monitoreo a nivel Kernel y presentarlo en una plataforma web accesible y funcional.

Mediante esta herramienta, se simplifican tareas de administración crítica, tales como la interpretación de métricas de memoria, la identificación de vulnerabilidades mediante firmas de hash y la gestión activa de la cuarentena de archivos. La integración con el módulo de autenticación de Linux (PAM) asegura que el control del sistema se mantenga restringido a los perfiles de administrador, cumpliendo satisfactoriamente con los objetivos del proyecto.

---

## 11. Referencias

1. Linux man pages: `man 2 syscall`, `man 5 proc`, `man pam`
2. React: <https://react.dev>
3. Vite: <https://vitejs.dev>
