/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/system_monitor.h
 *
 * Estructuras compartidas entre kernel y espacio de usuario para
 * sys_get_system_monitor() - Practica 6, SO2 USAC. Carne: 202203806
 *
 * Esta cabecera debe ser identica en el kernel y en los programas de usuario.
 */

#ifndef _LINUX_SYSTEM_MONITOR_H
#define _LINUX_SYSTEM_MONITOR_H

#include <linux/types.h>

/* Numero maximo de procesos en el top de consumo de memoria. */
#define SYSTEM_MONITOR_TOP       10
#define SYSTEM_MONITOR_COMM_LEN  16

/*
 * mem_percent_x100: porcentaje de RAM x100. Ej: 5.23% -> 523.
 */
struct top_proc_entry {
	char  comm[SYSTEM_MONITOR_COMM_LEN];
	pid_t pid;
	__u32 mem_percent_x100;
};

/*
 * Informacion global retornada por sys_get_system_monitor().
 * Memoria en KB, pages_active/inactive en numero de paginas.
 */
struct system_monitor_info {
	__u64 mem_used_kb;
	__u64 mem_free_kb;
	__u64 mem_cache_kb;
	__u64 swap_used_kb;
	__u64 minor_faults;
	__u64 major_faults;
	__u64 pages_active;
	__u64 pages_inactive;
	__u32 num_top_procs;
	struct top_proc_entry top_procs[SYSTEM_MONITOR_TOP];
};

#endif /* _LINUX_SYSTEM_MONITOR_H */
