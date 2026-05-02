/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/security_monitor.h
 *
 * Estructuras compartidas para syscalls del Proyecto Unico de SO2.
 */

#ifndef _LINUX_SECURITY_MONITOR_H
#define _LINUX_SECURITY_MONITOR_H

#include <linux/types.h>

#define SECURITY_MONITOR_COMM_LEN     16
#define SECURITY_MONITOR_PATH_LEN     256
#define SECURITY_SCAN_MAX_ENTRIES     128
#define SECURITY_QUARANTINE_MAX       128
#define SECURITY_SHA256_HEX_LEN       65

struct file_analysis_info {
	__u64 size_bytes;
	__u64 mtime_sec;
	char sha256[SECURITY_SHA256_HEX_LEN];
};

struct process_scan_entry {
	pid_t pid;
	char comm[SECURITY_MONITOR_COMM_LEN];
	__u64 rss_kb;
	__u64 minor_faults;
	__u64 major_faults;
};

struct process_scan_result {
	__u32 count;
	struct process_scan_entry entries[SECURITY_SCAN_MAX_ENTRIES];
};

struct quarantine_entry {
	char path[SECURITY_MONITOR_PATH_LEN];
	__u64 quarantined_at_sec;
};

struct quarantine_list {
	__u32 count;
	struct quarantine_entry entries[SECURITY_QUARANTINE_MAX];
};

#endif /* _LINUX_SECURITY_MONITOR_H */
