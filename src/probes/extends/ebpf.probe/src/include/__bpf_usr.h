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
#ifndef __GOPHER_BPF_USR_H__
#define __GOPHER_BPF_USR_H__

#ifdef BPF_PROG_USER
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if defined(__TARGET_ARCH_x86)
#define PT_REGS_PARM6(x) ((x)->r9)
#elif defined(__TARGET_ARCH_arm64)
#define PT_REGS_ARM64 const volatile struct user_pt_regs
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

#define _(P)                                        \
    ({                                              \
        typeof(P) val;                              \
        bpf_core_read_user((unsigned char *)&val, sizeof(val), (const void *)&P); \
        val;                                        \
    })

#define bpf_section(NAME) __attribute__((section(NAME), used))

#define UPROBE_PARMS_STASH(func, ctx, prog_id) \
    do { \
        int ret; \
        struct __probe_key __key = {0}; \
        struct __probe_val __val = {0}; \
        __get_probe_key(&__key, prog_id, CTX_USER); \
        __get_probe_val(&__val, (const long)PT_REGS_PARM1(ctx), \
                               (const long)PT_REGS_PARM2(ctx), \
                               (const long)PT_REGS_PARM3(ctx), \
                               (const long)PT_REGS_PARM4(ctx), \
                               (const long)PT_REGS_PARM5(ctx), \
                               (const long)PT_REGS_PARM6(ctx)); \
        ret = __do_push_match_map(&__key, &__val); \
        if (ret < 0) { \
            bpf_printk("---UPROBE_RET[" #func "] push failed.\n"); \
        } \
        return 0; \
    } while (0)

#if (CURRENT_LIBBPF_VERSION  >= LIBBPF_VERSION(0, 8))
#define UPROBE(func, type) \
    bpf_section("uprobe") \
    int ubpf_##func(struct type *ctx)

#define URETPROBE(func, type) \
    bpf_section("uretprobe") \
    int ubpf_ret_##func(struct type *ctx)
#define UPROBE_RET(func, type, prog_id) \
    bpf_section("uprobe") \
    int __uprobe_bpf_##func(struct type *ctx) { \
        UPROBE_PARMS_STASH(func, ctx, prog_id); \
    } \
    \
    bpf_section("uretprobe") \
    int __uprobe_ret_bpf_##func(struct type *ctx)
#else
#define UPROBE(func, type) \
    bpf_section("uprobe/" #func) \
    int ubpf_##func(struct type *ctx)

#define URETPROBE(func, type) \
    bpf_section("uretprobe/" #func) \
    int ubpf_ret_##func(struct type *ctx)
#define UPROBE_RET(func, type, prog_id) \
    bpf_section("uprobe/" #func) \
    int __uprobe_bpf_##func(struct type *ctx) { \
        UPROBE_PARMS_STASH(func, ctx, prog_id); \
    } \
    \
    bpf_section("uretprobe/" #func) \
    int __uprobe_ret_bpf_##func(struct type *ctx)
#endif

#endif

#endif
