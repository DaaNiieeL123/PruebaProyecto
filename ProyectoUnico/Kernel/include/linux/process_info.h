/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/process_info.h
 * Estructura para sys_get_process_info() - Práctica 5, SO2 USAC. Carné: 202203806
 */

#ifndef _LINUX_PROCESS_INFO_H
#define _LINUX_PROCESS_INFO_H

#include <linux/types.h>

#define PROCESS_INFO_COMM_LEN  16

struct process_info {
    char  comm[PROCESS_INFO_COMM_LEN];
    pid_t pid;
    __u64 exec_time_ns;
    __u64 mem_kb;
};

#endif /* _LINUX_PROCESS_INFO_H */
