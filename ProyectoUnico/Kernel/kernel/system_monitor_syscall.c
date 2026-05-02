// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/system_monitor_syscall.c
 * Syscall #549 sys_get_system_monitor() - Practica 6, SO2 USAC. Carne: 202203806
 *
 * Devuelve metricas globales de memoria del sistema y una lista con los
 * procesos que mas memoria consumen (top SYSTEM_MONITOR_TOP por RSS).
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched/task.h>
#include <linux/system_monitor.h>

#define LOG_TAG "[get_system_monitor] "

/* Inserta o reemplaza en top[] la entrada de menor consumo. */
static void update_top(struct top_proc_entry *top, int *count,
		       const char *comm, pid_t pid,
		       u64 total_kb, u64 rss_kb)
{
	u32 pct;
	int i, min_idx;

	if (total_kb == 0)
		return;

	/* x10000 para preservar 2 decimales en el porcentaje */
	pct = (u32)div64_u64(rss_kb * 10000, total_kb);

	if (*count < SYSTEM_MONITOR_TOP) {
		i = (*count)++;
		strncpy(top[i].comm, comm, SYSTEM_MONITOR_COMM_LEN - 1);
		top[i].comm[SYSTEM_MONITOR_COMM_LEN - 1] = '\0';
		top[i].pid = pid;
		top[i].mem_percent_x100 = pct;
		return;
	}

	min_idx = 0;
	for (i = 1; i < SYSTEM_MONITOR_TOP; i++) {
		if (top[i].mem_percent_x100 < top[min_idx].mem_percent_x100)
			min_idx = i;
	}

	if (pct > top[min_idx].mem_percent_x100) {
		strncpy(top[min_idx].comm, comm, SYSTEM_MONITOR_COMM_LEN - 1);
		top[min_idx].comm[SYSTEM_MONITOR_COMM_LEN - 1] = '\0';
		top[min_idx].pid = pid;
		top[min_idx].mem_percent_x100 = pct;
	}
}

SYSCALL_DEFINE1(get_system_monitor,
		struct system_monitor_info __user *, uinfo)
{
	struct system_monitor_info kinfo;
	struct sysinfo si;
	struct task_struct *task;
	unsigned long unit;
	u64 total_kb;
	int top_count = 0;

	if (!uinfo)
		return -EINVAL;

	memset(&kinfo, 0, sizeof(kinfo));

	si_meminfo(&si);
	unit = si.mem_unit;
	total_kb = (u64)si.totalram * unit / 1024;

	kinfo.mem_free_kb  = (u64)si.freeram  * unit / 1024;
	kinfo.mem_cache_kb = (u64)global_node_page_state(NR_FILE_PAGES)
			     * PAGE_SIZE / 1024;
	kinfo.mem_used_kb  = total_kb - kinfo.mem_free_kb - kinfo.mem_cache_kb;

	si_swapinfo(&si);
	kinfo.swap_used_kb = (u64)(si.totalswap - si.freeswap) * unit / 1024;

	kinfo.pages_active = global_node_page_state(NR_ACTIVE_ANON)
			   + global_node_page_state(NR_ACTIVE_FILE);
	kinfo.pages_inactive = global_node_page_state(NR_INACTIVE_ANON)
			     + global_node_page_state(NR_INACTIVE_FILE);

	/* tasklist_lock garantiza que ningun proceso desaparezca durante la iteracion */
	read_lock(&tasklist_lock);
	for_each_process(task) {
		char comm[TASK_COMM_LEN];
		u64 rss_kb = 0;

		kinfo.minor_faults += task->min_flt;
		kinfo.major_faults += task->maj_flt;

		if (task->mm)
			rss_kb = (u64)get_mm_rss(task->mm) * PAGE_SIZE / 1024;

		get_task_comm(comm, task);
		update_top(kinfo.top_procs, &top_count, comm,
			   task->pid, total_kb, rss_kb);
	}
	read_unlock(&tasklist_lock);

	kinfo.num_top_procs = (u32)top_count;

	pr_info(LOG_TAG "mem_used=%llu mem_free=%llu swap=%llu faults(min=%llu maj=%llu) top=%u\n",
		(unsigned long long)kinfo.mem_used_kb,
		(unsigned long long)kinfo.mem_free_kb,
		(unsigned long long)kinfo.swap_used_kb,
		(unsigned long long)kinfo.minor_faults,
		(unsigned long long)kinfo.major_faults,
		kinfo.num_top_procs);

	if (copy_to_user(uinfo, &kinfo, sizeof(kinfo)))
		return -EFAULT;

	return 0;
}
