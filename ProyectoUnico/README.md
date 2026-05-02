# ProyectoUnico

Implementacion del proyecto final de Sistemas Operativos 2.

## Modulos

- `Kernel/`: archivos modificados del kernel y scripts de integracion/compilacion.
- `ProgramaIntermedio/`: daemon en C con hilos, alertas, roles y API HTTP invocando syscalls.
- `Dashboard/`: frontend React para visualizacion y control.

## Estado actual

- Integracion de syscalls preparada en carpeta Kernel con estructura formal `arch/`, `include/`, `kernel/`.
- Programa intermedio integrado y validado para el flujo final del sistema.
- Dashboard listo para ejecutarse en VM o en Windows contra backend remoto.
- Scripts de pruebas reproducibles incluidos en `ProgramaIntermedio/scripts`.
- Ejecutables compilados incluidos en `ProgramaIntermedio/` para cumplir el entregable.
- Plantilla PAM incluida en `ProgramaIntermedio/config/security_daemon.pam`.
- Funcionalidad adicional implementada: escaneo puntual y exportacion de reporte resumen JSON.

## Arquitectura por capas

La arquitectura implementada sigue este flujo:

Kernel (syscalls en C)
-> Daemon en C (programa intermedio)
-> Backend en C (logica de analisis integrada en el daemon)
-> Dashboard web (visualizacion e interaccion por rol)
