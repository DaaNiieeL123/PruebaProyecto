// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/process_info_syscall.c
 * Syscall #548 sys_get_process_info() - Práctica 5, SO2 USAC. Carné: 202203806
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/process_info.h>

#define LOG_TAG "[get_process_info] "
SYSCALL_DEFINE2(get_process_info,
                pid_t,                       pid,
                struct process_info __user *, uinfo)
{
    struct task_struct *task;
    struct process_info kinfo;
    struct mm_struct   *mm;
    u64 utime_ns, stime_ns;

    if (pid <= 0 || !uinfo) {
        pr_warn(LOG_TAG "argumentos invalidos: pid=%d uinfo=%p\n", pid, uinfo);
        return -EINVAL;
    }

    memset(&kinfo, 0, sizeof(kinfo));

    /* RCU: incrementar refcount antes de salir de la sección critica */
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_info(LOG_TAG "proceso no encontrado: pid=%d\n", pid);
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    get_task_comm(kinfo.comm, task);
    kinfo.pid = task_pid_vnr(task);

    task_cputime_adjusted(task, &utime_ns, &stime_ns);
    kinfo.exec_time_ns = utime_ns + stime_ns;

    /* kernel threads tienen mm == NULL */
    mm = get_task_mm(task);
    if (mm) {
        kinfo.mem_kb = ((__u64)get_mm_rss(mm) * PAGE_SIZE) >> 10;
        mmput(mm);
    }

    put_task_struct(task);

    pr_info(LOG_TAG "pid=%d comm=%-16s exec_time_ns=%llu mem_kb=%llu\n",
            kinfo.pid, kinfo.comm,
            (unsigned long long)kinfo.exec_time_ns,
            (unsigned long long)kinfo.mem_kb);

    if (copy_to_user(uinfo, &kinfo, sizeof(kinfo)))
        return -EFAULT;

    return 0;
}
