// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/security_monitor_syscalls.c
 *
 * Syscalls del Proyecto Unico SO2:
 *  - sys_file_analize
 *  - sys_scan_processes
 *  - sys_quarantine_file
 *  - sys_restore_file
 *  - sys_get_quarantine_list
 *  - sys_simulate_panic
 */

#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>

#include <linux/security_monitor.h>

#define LOG_TAG "[security_monitor] "

static DEFINE_MUTEX(quarantine_lock);
static struct quarantine_entry quarantine_entries[SECURITY_QUARANTINE_MAX];
static u32 quarantine_count;

static int copy_user_path(const char __user *upath, char *kpath)
{
	long copied;

	if (!upath || !kpath)
		return -EINVAL;

	copied = strncpy_from_user(kpath, upath, SECURITY_MONITOR_PATH_LEN);
	if (copied < 0)
		return (int)copied;
	if (copied == 0)
		return -EINVAL;
	if (copied >= SECURITY_MONITOR_PATH_LEN)
		return -ENAMETOOLONG;

	kpath[SECURITY_MONITOR_PATH_LEN - 1] = '\0';
	return 0;
}

static int file_exists(const char *kpath)
{
	struct path p;
	int ret;

	ret = kern_path(kpath, LOOKUP_FOLLOW, &p);
	if (!ret)
		path_put(&p);
	return ret;
}

static int compute_file_sha256(struct file *filp, char out_hex[SECURITY_SHA256_HEX_LEN])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 digest[SHA256_DIGEST_SIZE];
	char *buf;
	loff_t pos = 0;
	ssize_t nread;
	int ret = 0;
	int i;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_tfm;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out_desc;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_desc;
	}

	while ((nread = kernel_read(filp, buf, PAGE_SIZE, &pos)) > 0) {
		ret = crypto_shash_update(desc, buf, nread);
		if (ret)
			break;
	}

	kfree(buf);

	if (nread < 0 && !ret)
		ret = (int)nread;
	if (ret)
		goto out_desc;

	ret = crypto_shash_final(desc, digest);
	if (ret)
		goto out_desc;

	for (i = 0; i < SHA256_DIGEST_SIZE; i++)
		snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
	out_hex[SECURITY_SHA256_HEX_LEN - 1] = '\0';

out_desc:
	kfree(desc);
out_tfm:
	crypto_free_shash(tfm);
	return ret;
}

SYSCALL_DEFINE2(file_analize,
		const char __user *, upath,
		struct file_analysis_info __user *, uinfo)
{
	char kpath[SECURITY_MONITOR_PATH_LEN];
	struct file_analysis_info info;
	struct file *filp;
	int ret;

	if (!uinfo)
		return -EINVAL;

	ret = copy_user_path(upath, kpath);
	if (ret)
		return ret;

	filp = filp_open(kpath, O_RDONLY, 0);
	if (IS_ERR(filp))
		return PTR_ERR(filp);

	memset(&info, 0, sizeof(info));
	info.size_bytes = i_size_read(file_inode(filp));
	info.mtime_sec = (u64)inode_get_mtime_sec(file_inode(filp));

	ret = compute_file_sha256(filp, info.sha256);
	filp_close(filp, NULL);
	if (ret)
		return ret;

	if (copy_to_user(uinfo, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

SYSCALL_DEFINE1(scan_processes, struct process_scan_result __user *, ures)
{
	struct process_scan_result *res;
	struct task_struct *task;
	int ret = 0;

	if (!ures)
		return -EINVAL;

	res = kvzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	read_lock(&tasklist_lock);
	for_each_process(task) {
		struct process_scan_entry *e;

		if (res->count >= SECURITY_SCAN_MAX_ENTRIES)
			break;

		e = &res->entries[res->count];
		get_task_comm(e->comm, task);
		e->pid = task->pid;
		e->minor_faults = task->min_flt;
		e->major_faults = task->maj_flt;
		if (task->mm)
			e->rss_kb = (u64)get_mm_rss(task->mm) * PAGE_SIZE / 1024;
		res->count++;
	}
	read_unlock(&tasklist_lock);

	if (copy_to_user(ures, res, sizeof(*res)))
		ret = -EFAULT;

	kvfree(res);
	return ret;
}

SYSCALL_DEFINE1(quarantine_file, const char __user *, upath)
{
	char kpath[SECURITY_MONITOR_PATH_LEN];
	u32 i;
	int ret;

	ret = copy_user_path(upath, kpath);
	if (ret)
		return ret;

	ret = file_exists(kpath);
	if (ret)
		return ret;

	mutex_lock(&quarantine_lock);

	for (i = 0; i < quarantine_count; i++) {
		if (strcmp(quarantine_entries[i].path, kpath) == 0) {
			mutex_unlock(&quarantine_lock);
			return -EEXIST;
		}
	}

	if (quarantine_count >= SECURITY_QUARANTINE_MAX) {
		mutex_unlock(&quarantine_lock);
		return -ENOSPC;
	}

	strscpy(quarantine_entries[quarantine_count].path,
		kpath,
		sizeof(quarantine_entries[quarantine_count].path));
	quarantine_entries[quarantine_count].quarantined_at_sec =
		(u64)ktime_get_real_seconds();
	quarantine_count++;

	mutex_unlock(&quarantine_lock);
	return 0;
}

SYSCALL_DEFINE1(restore_file, const char __user *, upath)
{
	char kpath[SECURITY_MONITOR_PATH_LEN];
	u32 i;
	int ret;

	ret = copy_user_path(upath, kpath);
	if (ret)
		return ret;

	mutex_lock(&quarantine_lock);
	for (i = 0; i < quarantine_count; i++) {
		if (strcmp(quarantine_entries[i].path, kpath) == 0) {
			for (; i + 1 < quarantine_count; i++)
				quarantine_entries[i] = quarantine_entries[i + 1];
			quarantine_count--;
			mutex_unlock(&quarantine_lock);
			return 0;
		}
	}
	mutex_unlock(&quarantine_lock);

	return -ENOENT;
}

SYSCALL_DEFINE1(get_quarantine_list, struct quarantine_list __user *, ulist)
{
	struct quarantine_list *list;
	int ret = 0;

	if (!ulist)
		return -EINVAL;

	list = kvzalloc(sizeof(*list), GFP_KERNEL);
	if (!list)
		return -ENOMEM;

	mutex_lock(&quarantine_lock);
	list->count = quarantine_count;
	if (list->count > SECURITY_QUARANTINE_MAX)
		list->count = SECURITY_QUARANTINE_MAX;
	memcpy(list->entries,
	       quarantine_entries,
	       sizeof(struct quarantine_entry) * list->count);
	mutex_unlock(&quarantine_lock);

	if (copy_to_user(ulist, list, sizeof(*list)))
		ret = -EFAULT;

	kvfree(list);
	return ret;
}

SYSCALL_DEFINE1(simulate_panic, const char __user *, umsg)
{
	char msg[192];
	long copied;

	if (!umsg)
		return -EINVAL;

	copied = strncpy_from_user(msg, umsg, sizeof(msg));
	if (copied < 0)
		return (int)copied;
	if (copied == 0)
		return -EINVAL;

	msg[sizeof(msg) - 1] = '\0';
	pr_err(LOG_TAG "[SECURITY] Simulated kernel panic triggered: %s\n", msg);
	return 0;
}
