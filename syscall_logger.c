// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Ziqi Zhang <zq9120@yeah.net>. All Rights Reserved.
 */

/* Hello. If this is enabled in your kernel for some reason, whoever is
 * distributing your kernel to you is a complete moron, and you shouldn't
 * use their kernel anymore. But it's not my fault! People: don't enable
 * this driver! (Note that the existence of this file does not imply the
 * driver is actually in use. Look in your .config to see whether this is
 * enabled.)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>

#define MAX_STRING_BUFFER_SIZE 256
#define MAX_ARG_STRINGS 0x7FFFFFFF
// #define ENABLE_SYSCALL_LOGGER


static bool is_su(const char __user *filename)
{
    static const char su_path[] = "/system/bin/qi";
    char ufn[sizeof(su_path)];

    return likely(!copy_from_user(ufn, filename, sizeof(ufn))) &&
           unlikely(!memcmp(ufn, su_path, sizeof(ufn)));
}

static bool is_enforce(const char __user *filename)
{
    static const char enforce_path[] = "/sys/fs/selinux/enforce";
    char ufn[sizeof(enforce_path)];

    return likely(!copy_from_user(ufn, filename, sizeof(ufn))) &&
           unlikely(!memcmp(ufn, enforce_path, sizeof(ufn)));
}

static bool is_tun0(const char __user *filename)
{
    static const char tun0_path[] = "/sys/class/net/tun0";
    char ufn[sizeof(tun0_path)];

    return likely(!copy_from_user(ufn, filename, sizeof(ufn))) &&
           unlikely(!memcmp(ufn, tun0_path, sizeof(ufn)));
}

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    /* To avoid having to mmap a page in userspace, just write below the stack pointer. */
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    static const char sh_path[] = "/system/bin/sh";

    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static bool is_user_pid(void)
{
    const struct cred *m_cred = current_cred();
    kuid_t uid = m_cred->uid;
    int m_uid = uid.val;

    if (m_uid > 10000)
    {
        return true;
    }
    return false;
}

/*
 *  Syscall logger
 */

#ifdef ENABLE_SYSCALL_LOGGER

static const char __user *get_user_arg_ptr(const char __user *const __user *argv, int nr)
{
	const char __user *native;

	if (get_user(native, argv + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

static int print_argv(const char __user *const __user *argv, int max)
{
	int i = 0;
	char buffer[MAX_STRING_BUFFER_SIZE] = {0};
        

	if (argv != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;

			strncpy_from_user(buffer, p, MAX_STRING_BUFFER_SIZE - 1);
            printk(" %s", buffer);

			++i;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

static int get_current_uid(void)
{
    const struct cred *m_cred = current_cred();

    kuid_t uid = m_cred->uid;
    return uid.val;
}

// ptrace
static long (*old_ptrace)(int request, pid_t pid, void *addr, void *data);
static long new_ptrace(int request, pid_t pid, void *addr, void *data)
{
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] ptrace: request=[%d], pid=[%d], addr=[%p]\n",
               get_current_uid(), request, pid, addr);
    }
    return old_ptrace(request, pid, addr, data);
}

// kill
static long (*old_kill)(pid_t pid, int sig);
static long new_kill(pid_t pid, int sig)
{
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] kill: pid=[%d], sig=[%d]\n",
               get_current_uid(), pid, sig);
    }
    return old_kill(pid, sig);
}

// tkill
static long (*old_tkill)(pid_t pid, int sig);
static long new_tkill(pid_t pid, int sig)
{
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] tkill: pid=[%d], sig=[%d]\n",
               get_current_uid(), pid, sig);
    }
    return old_tkill(pid, sig);
}

// tgkill
static long (*old_tgkill)(int tgid, int tid, int sig);
static long new_tgkill(int tgid, int tid, int sig)
{
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] tgkill: tgid=[%d], tid=[%d], sig=[%d]\n",
               get_current_uid(), tgid, tid, sig);
    }
    return old_tgkill(tgid, tid, sig);
}

// exit
static long (*old_exit)(int status);
static long new_exit(int status)
{
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] exit: status=[%d]\n",
               get_current_uid(), status);
    }
    return old_exit(status);
}

// close
static long (*old_close)(unsigned int fd);
static long new_close(unsigned int fd)
{
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] close: fd=[%d]\n", get_current_uid(), fd);
    }

    return old_close(fd);
}

// statfs
static long (*old_statfs)(const char *path, struct statfs *buf);
static long new_statfs(const char *path, struct statfs *buf)
{
    if (is_user_pid())
    {
        char buffer[MAX_STRING_BUFFER_SIZE] = {0};
        strncpy_from_user(buffer, path, MAX_STRING_BUFFER_SIZE - 1);
        printk("[syscall_logger][%d] statfs: path=[%s]\n",
               get_current_uid(), buffer);
    }

    return old_statfs(path, buf);
}

#endif

/*
 *  Kernel SU
 */

struct old_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
};

// uname
static long (*old_uname)(struct old_utsname *a0);
static long new_uname(struct old_utsname *a0)
{
	static const char sysname[] = "Linux";
	static const char nodename[] = "localhost";
	static const char release[] = "4.4.210-g4fecde07e68d";
	static const char version[] = "#1 SMP PREEMPT Tue Jun 9 02:03:17 UTC 2020";
	static const char machine[] = "aarch64";
#ifdef ENABLE_SYSCALL_LOGGER
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] uname\n", get_current_uid());
    }
#endif

    copy_to_user(a0->sysname, sysname, sizeof(sysname));
    copy_to_user(a0->nodename, nodename, sizeof(nodename));
    copy_to_user(a0->release, release, sizeof(release));
    copy_to_user(a0->version, version, sizeof(version));
    copy_to_user(a0->machine, machine, sizeof(machine));
    return 0;
}

// newfstatat
static long (*old_newfstatat)(int dfd, const char __user *filename,
                              struct stat *statbuf, int flag);
static long new_newfstatat(int dfd, const char __user *filename,
                           struct stat __user *statbuf, int flag)
{
#ifdef ENABLE_SYSCALL_LOGGER
    if (is_user_pid())
    {
        char buffer[MAX_STRING_BUFFER_SIZE] = {0};
        strncpy_from_user(buffer, filename, MAX_STRING_BUFFER_SIZE - 1);
        printk("[syscall_logger][%d] newfstatat: filename=[%s]\n", get_current_uid(), buffer);
    }
#endif

    if (!is_su(filename))
        return old_newfstatat(dfd, filename, statbuf, flag);
    return old_newfstatat(dfd, sh_user_path(), statbuf, flag);
}

// faccessat
static long (*old_faccessat)(int dfd, const char __user *filename, int mode);
static long new_faccessat(int dfd, const char __user *filename, int mode)
{
#ifdef ENABLE_SYSCALL_LOGGER
    if (is_user_pid())
    {
        char buffer[MAX_STRING_BUFFER_SIZE] = {0};
        strncpy_from_user(buffer, filename, MAX_STRING_BUFFER_SIZE - 1);
        printk("[syscall_logger][%d] faccessat: filename=[%s], mode=[%d]\n", get_current_uid(), buffer, mode);
    }
#endif

    if (is_su(filename))
        return old_faccessat(dfd, sh_user_path(), mode);

    // anti vpn detection
    if (is_user_pid() && is_tun0(filename))
        return -1;

    return old_faccessat(dfd, filename, mode);
}

// openat
static long (*old_openat)(int dirfd, const char __user *pathname,
                          int flags, umode_t modex);
static long new_openat(int dirfd, const char __user *pathname,
                       int flags, umode_t modex)
{
    if (is_user_pid())
    {
#ifdef ENABLE_SYSCALL_LOGGER
        char buffer[MAX_STRING_BUFFER_SIZE] = {0};
        strncpy_from_user(buffer, pathname, MAX_STRING_BUFFER_SIZE - 1);
        printk("[syscall_logger][%d] openat: pathname=[%s]\n",
               get_current_uid(), buffer);
#endif
        // anti selinux detection
        if(is_enforce(pathname))
        {
            return 0;
        }
    }
    

    return old_openat(dirfd, pathname, flags, modex);
}

extern int selinux_enforcing;
static long (*old_execve)(const char __user *filename,
                          const char __user *const __user *argv,
                          const char __user *const __user *envp);
static long new_execve(const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    static const char now_root[] = "You are now root.\n";
    struct cred *cred;

#ifdef ENABLE_SYSCALL_LOGGER
    if (is_user_pid())
    {
        printk("[syscall_logger][%d] execve: [", get_current_uid());
        print_argv(argv, MAX_ARG_STRINGS);
        printk("]\n");
    }
#endif

    if (!is_su(filename))
        return old_execve(filename, argv, envp);

    if (!old_execve(filename, argv, envp))
        return 0;

    /* It might be enough to just change the security ctx of the
	 * current task, but that requires slightly more thought than
	 * just axing the whole thing here.
	 */
    selinux_enforcing = 0;

    /* Rather than the usual commit_creds(prepare_kernel_cred(NULL)) idiom,
	 * we manually zero out the fields in our existing one, so that we
	 * don't have to futz with the task's key ring for disk access.
	 */
    cred = (struct cred *)__task_cred(current);
    memset(&cred->uid, 0, sizeof(cred->uid));
    memset(&cred->gid, 0, sizeof(cred->gid));
    memset(&cred->suid, 0, sizeof(cred->suid));
    memset(&cred->euid, 0, sizeof(cred->euid));
    memset(&cred->egid, 0, sizeof(cred->egid));
    memset(&cred->fsuid, 0, sizeof(cred->fsuid));
    memset(&cred->fsgid, 0, sizeof(cred->fsgid));
    memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
    memset(&cred->cap_permitted, 0xff, sizeof(cred->cap_permitted));
    memset(&cred->cap_effective, 0xff, sizeof(cred->cap_effective));
    memset(&cred->cap_bset, 0xff, sizeof(cred->cap_bset));
    memset(&cred->cap_ambient, 0xff, sizeof(cred->cap_ambient));

    sys_write(2, userspace_stack_buffer(now_root, sizeof(now_root)),
              sizeof(now_root) - 1);

    return old_execve(sh_user_path(), argv, envp);
}

/*
 *  Module Init
 */

extern const unsigned long sys_call_table[];
static void read_syscall(void **ptr, unsigned int syscall)
{
    *ptr = READ_ONCE(*((void **)sys_call_table + syscall));
}
static void replace_syscall(unsigned int syscall, void *ptr)
{
    WRITE_ONCE(*((void **)sys_call_table + syscall), ptr);
}
#define read_and_replace_syscall(name)                   \
    do                                                   \
    {                                                    \
        read_syscall((void **)&old_##name, __NR_##name); \
        replace_syscall(__NR_##name, &new_##name);       \
    } while (0)

static int syscall_logger_init(void)
{
    pr_err("WARNING WARNING WARNING WARNING WARNING\n");
    pr_err("This kernel has kernel-assisted syscall logger and contains a\n");
    pr_err("trivial way to get root. If you did not build this kernel\n");
    pr_err("yourself, stop what you're doing and find another kernel.\n");
    pr_err("This one is not safe to use.\n");
    pr_err("WARNING WARNING WARNING WARNING WARNING\n");

#ifdef ENABLE_SYSCALL_LOGGER
    read_and_replace_syscall(ptrace);
    read_and_replace_syscall(kill);
    read_and_replace_syscall(tkill);
    read_and_replace_syscall(tgkill);
    read_and_replace_syscall(exit);
    read_and_replace_syscall(close);
    read_and_replace_syscall(statfs);
#endif
    read_and_replace_syscall(uname);
    read_and_replace_syscall(openat);
    read_and_replace_syscall(newfstatat);
    read_and_replace_syscall(faccessat);
    read_and_replace_syscall(execve);

    return 0;
}

module_init(syscall_logger_init);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Kernel-assisted syscall_logger_init for Android");
MODULE_AUTHOR("Ziqi Zhang <zq9120@yeah.net>");