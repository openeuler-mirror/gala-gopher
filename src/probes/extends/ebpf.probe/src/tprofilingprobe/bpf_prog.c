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
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: the user-side program of thread profiling probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "profiling_event.h"
#include "tprofiling.h"
#include "bpf_prog.h"
#include "syscall_file.skel.h"
#include "syscall_net.skel.h"
#include "syscall_lock.skel.h"
#include "syscall_sched.skel.h"
#include "oncpu.skel.h"

static char is_load_probe_ipc(struct ipc_body_s *ipc_body, u32 probe)
{
    if (ipc_body->probe_range_flags & probe) {
        return 1;
    }
    return 0;
}

static int perf_event_handler(void *ctx, void *data, __u32 size)
{
    output_profiling_event((trace_event_data_t *)data);
    return 0;
}

static int load_create_pb(struct bpf_prog_s *prog, struct bpf_map *map, struct bpf_map *heap)
{
    int ret;
    struct bpf_buffer *buffer = NULL;

    buffer = bpf_buffer__new(map, heap);
    if (buffer == NULL) {
        return -1;
    }

    ret = bpf_buffer__open(buffer, perf_event_handler, NULL, NULL);
    if (ret) {
        ERROR("[TPPROFILING] Open bpf_buffer failed.\n");
        bpf_buffer__free(buffer);
        return -1;
    }

    prog->buffers[prog->num] = buffer;
    return 0;
}

LOAD_SYSCALL_BPF_PROG(file)

LOAD_SYSCALL_BPF_PROG(net)

LOAD_SYSCALL_BPF_PROG(lock)

LOAD_SYSCALL_BPF_PROG(sched)

struct bpf_prog_s *load_syscall_bpf_prog(struct ipc_body_s *ipc_body)
{
    struct bpf_prog_s *prog;
    char is_load_syscall_file, is_load_syscall_net;
    char is_load_syscall_lock, is_load_syscall_sched;

    is_load_syscall_file = is_load_probe_ipc(ipc_body, TPROFILING_PROBE_SYSCALL_FILE);
    is_load_syscall_net = is_load_probe_ipc(ipc_body, TPROFILING_PROBE_SYSCALL_NET);
    is_load_syscall_lock = is_load_probe_ipc(ipc_body, TPROFILING_PROBE_SYSCALL_LOCK);
    is_load_syscall_sched = is_load_probe_ipc(ipc_body, TPROFILING_PROBE_SYSCALL_SCHED);

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return NULL;
    }

    if (__load_syscall_file_bpf_prog(prog, is_load_syscall_file)) {
        goto err;
    }

    if (__load_syscall_net_bpf_prog(prog, is_load_syscall_net)) {
        goto err;
    }

    if (__load_syscall_lock_bpf_prog(prog, is_load_syscall_lock)) {
        goto err;
    }

    if (__load_syscall_sched_bpf_prog(prog, is_load_syscall_sched)) {
        goto err;
    }

    return prog;

err:
    unload_bpf_prog(&prog);
    return NULL;
}

static int __load_oncpu_bpf_prog(struct bpf_prog_s *prog, char is_load)
{
    int ret = 0;

    LOAD_ONCPU_PROBE(oncpu, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = oncpu_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)oncpu_bpf__destroy;
        prog->custom_btf_paths[prog->num] = oncpu_open_opts.btf_custom_path;

        int is_attach_tp = (probe_kernel_version() >= KERNEL_VERSION(6, 4, 0));
        PROG_ENABLE_ONLY_IF(oncpu, bpf_raw_trace_sched_switch, is_attach_tp);
        PROG_ENABLE_ONLY_IF(oncpu, bpf_finish_task_switch, !is_attach_tp);

        ret = load_create_pb(prog, oncpu_skel->maps.event_map, oncpu_skel->maps.heap);
        if (ret) {
            goto err;
        }

        LOAD_ATTACH(tprofiling, oncpu, err, is_load);

        prog->num++;
    }

    return ret;
err:
    UNLOAD(oncpu);
    CLEANUP_CUSTOM_BTF(oncpu);
    return -1;
}

struct bpf_prog_s *load_oncpu_bpf_prog(struct ipc_body_s *ipc_body)
{

    struct bpf_prog_s *prog;
    char is_load_oncpu;

    is_load_oncpu = is_load_probe_ipc(ipc_body, TPROFILING_PROBE_ONCPU);

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return NULL;
    }

    if (__load_oncpu_bpf_prog(prog, is_load_oncpu)) {
        goto err;
    }

    return prog;

err:
    unload_bpf_prog(&prog);
    return NULL;
}