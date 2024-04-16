/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Mr.lu
 * Create: 2021-09-28
 * Description: bpf header
 ******************************************************************************/
#ifndef __GOPHER_BPF_KERN_H__
#define __GOPHER_BPF_KERN_H__

#ifdef BPF_PROG_KERN

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define bpf_section(NAME) __attribute__((section(NAME), used))

#define KPROBE(func, type) \
    bpf_section("kprobe/" #func) \
    int bpf_##func(struct type *ctx)

#define KRETPROBE(func, type) \
    bpf_section("kretprobe/" #func) \
    int bpf_ret_##func(struct type *ctx)

#define KRAWTRACE(func, type) \
    bpf_section("raw_tracepoint/" #func) \
    int bpf_raw_trace_##func(struct type *ctx)

#define KPROBE_WITH_CONSTPROP(func, type) \
    bpf_section("kprobe/" #func ".constprop.0") \
    int bpf_constprop_##func(struct type *ctx)

#if defined(__BTF_ENABLE_ON)
#define _(P)                                   \
            ({                                         \
                typeof(P) val;                         \
                bpf_core_read((unsigned char *)&val, sizeof(val), (const void *)&P); \
                val;                                   \
            })
#elif defined(__BTF_ENABLE_OFF)
#define _(P)                                   \
            ({                                         \
                typeof(P) val;                         \
                bpf_probe_read((unsigned char *)&val, sizeof(val), (const void *)&P); \
                val;                                   \
            })
#endif

#if defined(__TARGET_ARCH_x86)
#ifndef PT_REGS_PARM6
#define PT_REGS_PARM6(x) ((x)->r9)
#endif

struct ia64_psr {
    __u64 reserved0 : 1;
    __u64 be : 1;
    __u64 up : 1;
    __u64 ac : 1;
    __u64 mfl : 1;
    __u64 mfh : 1;
    __u64 reserved1 : 7;
    __u64 ic : 1;
    __u64 i : 1;
    __u64 pk : 1;
    __u64 reserved2 : 1;
    __u64 dt : 1;
    __u64 dfl : 1;
    __u64 dfh : 1;
    __u64 sp : 1;
    __u64 pp : 1;
    __u64 di : 1;
    __u64 si : 1;
    __u64 db : 1;
    __u64 lp : 1;
    __u64 tb : 1;
    __u64 rt : 1;
    __u64 reserved3 : 4;
    __u64 cpl : 2;
    __u64 is : 1;
    __u64 mc : 1;
    __u64 it : 1;
    __u64 id : 1;
    __u64 da : 1;
    __u64 dd : 1;
    __u64 ss : 1;
    __u64 ri : 2;
    __u64 ed : 1;
    __u64 bn : 1;
    __u64 reserved4 : 19;
};

#define user_mode(regs) (((struct ia64_psr *) &(regs)->r9)->cpl != 0)
#define compat_user_mode(regs)  (0)
static __always_inline __maybe_unused char is_compat_task(struct task_struct *task) {return 0;}

#elif defined(__TARGET_ARCH_arm64)
#ifndef PT_REGS_PARM6
#define PT_REGS_ARM64 const volatile struct user_pt_regs
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif
#define PSR_MODE_EL0t   0x00000000
#define PSR_MODE_EL1t   0x00000004
#define PSR_MODE_EL1h   0x00000005
#define PSR_MODE_EL2t   0x00000008
#define PSR_MODE_EL2h   0x00000009
#define PSR_MODE_EL3t   0x0000000c
#define PSR_MODE_EL3h   0x0000000d
#define PSR_MODE_MASK   0x0000000f
/* AArch32 CPSR bits */
#define PSR_MODE32_BIT      0x00000010

#define user_mode(regs) \
    (((regs)->pstate & PSR_MODE_MASK) == PSR_MODE_EL0t)

#define compat_user_mode(regs)  \
    (((regs)->pstate & (PSR_MODE32_BIT | PSR_MODE_MASK)) == \
     (PSR_MODE32_BIT | PSR_MODE_EL0t))

#define TIF_32BIT       22  /* 32bit process */
#define TIF_32BIT_AARCH64   27  /* 32 bit process on AArch64(ILP32) */

static __always_inline __maybe_unused char is_compat_task(struct task_struct *task)
{
    unsigned long flags;

    flags = _(task->thread_info.flags);
    return (flags & TIF_32BIT) || (flags & TIF_32BIT_AARCH64);
}


#endif

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

static __always_inline __maybe_unused struct sock *sock_get_by_fd(int fd, struct task_struct *task)
{
    struct file *f;
    struct file **ff = BPF_CORE_READ(task, files, fdt, fd);
    unsigned int max_fds = BPF_CORE_READ(task, files, fdt, max_fds);

    if (fd >= max_fds) {
        return 0;
    }

    bpf_core_read(&f, sizeof(struct file *), (struct file *)(ff + fd));
    if (!f) {
        return 0;
    }

    struct inode *fi = _(f->f_inode);
    unsigned short imode = _(fi->i_mode);
    if (!S_ISSOCK(imode)) {
        return 0;
    }

    struct socket *sock = _(f->private_data);
    struct sock *sk = _(sock->sk);
    return sk;
}

#define KPROBE_PARMS_STASH(func, ctx, caller_type) \
    do { \
        int ret; \
        struct __probe_key __key = {0}; \
        struct __probe_val __val = {0}; \
        __get_probe_key(&__key, (const long)PT_REGS_FP(ctx), caller_type); \
        __get_probe_val(&__val, (const long)PT_REGS_PARM1(ctx), \
                               (const long)PT_REGS_PARM2(ctx), \
                               (const long)PT_REGS_PARM3(ctx), \
                               (const long)PT_REGS_PARM4(ctx), \
                               (const long)PT_REGS_PARM5(ctx), \
                               (const long)PT_REGS_PARM6(ctx)); \
        ret = __do_push_match_map(&__key, &__val); \
        if (ret < 0) { \
            bpf_printk("---KPROBE_RET[" #func "] push failed.\n"); \
        } \
    } while (0)

#define KPROBE_RET(func, type, caller_type) \
    bpf_section("kprobe/" #func) \
    void __kprobe_bpf_##func(struct type *ctx) { \
        KPROBE_PARMS_STASH(func, ctx, caller_type); \
    } \
    \
    bpf_section("kretprobe/" #func) \
    int __kprobe_ret_bpf_##func(struct type *ctx)

#endif

#endif
