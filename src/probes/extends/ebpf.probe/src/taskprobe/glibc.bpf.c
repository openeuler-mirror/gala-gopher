/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-07-13
 * Description: GLIBC probe
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_USER

#include "bpf.h"
#include "task.h"
#include "proc_map.h"
#include "output_proc.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline void store_dns_op_start_ts(void)
{
    struct proc_data_s *proc;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return;
    }

    proc->dns_op.gethostname_start_ts = bpf_ktime_get_ns();
}

static __always_inline void update_gethostname_res(struct pt_regs* ctx)
{
    struct proc_data_s *proc;
    u64 ts = bpf_ktime_get_ns(), delta = 0;
    u32 proc_id = bpf_get_current_pid_tgid() >> INT_LEN;
    int ret = PT_REGS_RC(ctx);

    proc = get_proc_entry(proc_id);
    if (proc == NULL) {
        return;
    }

    if (ret) {
        __sync_fetch_and_add(&(proc->dns_op.gethostname_failed), 1);
    }

    if (proc->dns_op.gethostname_start_ts == 0) {
        return;
    }

    if (ts > proc->dns_op.gethostname_start_ts) {
        delta = ts - proc->dns_op.gethostname_start_ts;
    }

    proc->dns_op.gethostname_start_ts = 0;
    if (delta > proc->dns_op.gethostname_ns) {
        proc->dns_op.gethostname_ns = delta;
        report_proc(ctx, proc, TASK_PROBE_DNS_OP);
    }
}

#define UPROBE_GLIBC(func, start_fn, stop_fn) \
    UPROBE(func, pt_regs) \
    { \
        start_fn(); \
    } \
    \
    URETPROBE(func, pt_regs) \
    { \
        stop_fn(ctx); \
    }

UPROBE_GLIBC(getaddrinfo, store_dns_op_start_ts, update_gethostname_res)
UPROBE_GLIBC(gethostbyname2, store_dns_op_start_ts, update_gethostname_res)
UPROBE_GLIBC(gethostbyname, store_dns_op_start_ts, update_gethostname_res)

