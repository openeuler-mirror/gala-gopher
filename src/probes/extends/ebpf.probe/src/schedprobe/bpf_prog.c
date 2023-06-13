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
 * Create: 2023-06-12
 * Description: the probe load program
 ******************************************************************************/
#include <stdio.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "sched_systime.skel.h"
#include "sched_syscall.skel.h"
#include "bpf_prog.h"

static char is_load_probe(struct ipc_body_s *ipc_body, u32 probe)
{
    if (ipc_body->probe_range_flags & probe) {
        return 1;
    }
    return 0;
}

extern void rcv_sched_report(void *ctx, int cpu, void *data, __u32 size);

int load_create_pb(struct bpf_prog_s *prog, int fd)
{
    struct perf_buffer *pb;

    if (prog->pb == NULL) {
        pb = create_pref_buffer(fd, rcv_sched_report);
        if (pb == NULL) {
            fprintf(stderr, "ERROR: create sched perf buffer failed\n");
            return -1;
        }
        prog->pb = pb;
        printf("INFO: Success to create sched perf buffer.\n");
    }

    return 0;
}

int load_sched_bpf_prog_syscall(struct bpf_prog_s *prog, char is_load, struct sched_probe_s *sched_probe)
{
    int ret = 0;

    __LOAD_SCHED_LATENCY(sched_syscall, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = sched_syscall_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)sched_syscall_bpf__destroy;
        prog->num++;

        sched_probe->sched_syscall_stackmap_fd = GET_MAP_FD(sched_syscall, syscall_latency_stackmap);
        sched_probe->sched_args_fd = GET_MAP_FD(sched_syscall, sched_args_map);

        ret = load_create_pb(prog, GET_MAP_FD(sched_syscall, sched_report_channel_map));
        if (ret) {
            goto err;
        }
    }

    return ret;
err:
    UNLOAD(sched_syscall);
    return -1;
}

int load_sched_bpf_prog_systime(struct bpf_prog_s *prog, char is_load, struct sched_probe_s *sched_probe)
{
    int ret = 0;

    __LOAD_SCHED_LATENCY(sched_systime, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = sched_systime_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)sched_systime_bpf__destroy;
        prog->num++;

        sched_probe->sched_systime_stackmap_fd = GET_MAP_FD(sched_systime, systime_latency_stackmap);
        sched_probe->sched_args_fd = GET_MAP_FD(sched_systime, sched_args_map);

        ret = load_create_pb(prog, GET_MAP_FD(sched_systime, sched_report_channel_map));
        if (ret) {
            goto err;
        }
    }

    return ret;
err:
    UNLOAD(sched_systime);
    return -1;
}

int load_sched_bpf_prog(struct ipc_body_s *ipc_body, struct sched_probe_s *sched_probe)
{
    struct bpf_prog_s *prog;
    char is_load_syscall, is_load_systime;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

    is_load_syscall = is_load_probe(ipc_body, SCHED_PROBE_SYSCALL);
    is_load_systime = is_load_probe(ipc_body, SCHED_PROBE_SYSTIME);

    if (load_sched_bpf_prog_syscall(prog, is_load_syscall, sched_probe)) {
        unload_bpf_prog(&prog);
        return -1;
    }

    if (load_sched_bpf_prog_systime(prog, is_load_systime, sched_probe)) {
        unload_bpf_prog(&prog);
        return -1;
    }

    sched_probe->sched_prog = prog;

    return 0;
}

void clean_map_files()
{
    FILE *fp;

    fp = popen(RM_SCHED_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
}