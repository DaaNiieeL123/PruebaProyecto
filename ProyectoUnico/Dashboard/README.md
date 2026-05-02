# Dashboard

Frontend React para visualizacion en tiempo real.

## Funcionalidades

- Login (autenticacion contra daemon C).
- Visualizacion de metricas de memoria y page faults.
- Panel de alertas con severidad LOW/MEDIUM/HIGH.
- Vista de archivos analizados y amenazas detectadas.
- Control de escaneo continuo segun rol.
- Consulta de proceso por PID (solo admin).
- Escaneo puntual (admin) para validaciones inmediatas.
- Exportacion de reporte resumen en JSON desde la cabecera.

## Ejecutar

```bash
cd ProyectoUnico/Dashboard
npm install
npm run dev
```

## Configuracion

Se recomienda usar variables de entorno:

1. Crear `.env.local` basado en `.env.example`.
2. Definir `VITE_API_BASE` con la IP de la VM donde corre el daemon C.

Ejemplo cuando backend corre en VM y frontend en Windows:

```env
VITE_API_BASE=http://192.168.230.128:8090
VITE_POLL_INTERVAL_MS=3000
```
